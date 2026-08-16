"""The TCP state machine, client side only.

Scope for the thin slice: active open, in-order data with cumulative ACK,
retransmission with an RFC 6298 timer, and a full close in both directions.

Deliberately absent, and arriving in the hardening pass:

* congestion control (NewReno) and window scaling
* out-of-order reassembly -- segments arriving ahead of ``rcv_nxt`` are
  dropped and recovered by the peer's retransmission, which is correct but
  costs an RTO per reordering event
* SACK, timestamps, delayed ACK

Also absent permanently: ``LISTEN`` and ``SYN_RECEIVED``. Nothing here ever
accepts a connection, so the shipping code never grows that attack surface. A
passive-open TCB exists in the test tree only, to give the harness a peer.

Sans-IO throughout: ``now`` is milliseconds as an int, and the only outputs
are segments to send and events to report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

from pyac.errors import ConnectionRefused, ConnectionReset, ConnectionTimeout, NetworkError
from pyac.net.tcp import (
    DEFAULT_MSS,
    MAX_WINDOW,
    Flag,
    TcpSegment,
    build_tcp,
    seq_add,
    seq_diff,
    seq_geq,
    seq_gt,
    seq_leq,
    seq_lt,
)


class State(Enum):
    CLOSED = auto()
    SYN_SENT = auto()
    ESTABLISHED = auto()
    FIN_WAIT_1 = auto()
    FIN_WAIT_2 = auto()
    CLOSING = auto()
    TIME_WAIT = auto()
    CLOSE_WAIT = auto()
    LAST_ACK = auto()

    @property
    def is_closed(self) -> bool:
        return self is State.CLOSED

    @property
    def can_send(self) -> bool:
        return self in (State.ESTABLISHED, State.CLOSE_WAIT)


@dataclass(slots=True)
class TcbConfig:
    """Per-connection tunables, injected so tests can shrink them."""

    mss: int = 1343  # tunnel MTU 1383 - 20 IP - 20 TCP

    # 64 KiB, not the 256 KiB the design calls for, because the thin slice has
    # no window scaling and the window field is 16 bits. A larger buffer would
    # simply be unadvertisable. The hardening pass raises both together.
    rx_buffer: int = 64 * 1024
    tx_buffer: int = 64 * 1024

    rto_initial_ms: int = 1000
    rto_min_ms: int = 250
    rto_max_ms: int = 60_000
    max_retransmits: int = 8
    syn_retransmits: int = 4
    connect_timeout_ms: int = 15_000
    time_wait_ms: int = 30_000


@dataclass(slots=True)
class _Unacked:
    """A segment held for retransmission until it is acknowledged."""

    seq: int
    payload: bytes
    flags: Flag
    sent_at: int
    retransmitted: bool = False


@dataclass(slots=True)
class Tcb:
    """One TCP connection.

    Drive it with :meth:`on_segment` and :meth:`on_tick`, then drain
    :attr:`pending_segments` and :attr:`pending_events`.
    """

    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    config: TcbConfig = field(default_factory=TcbConfig)
    isn: int = 0

    state: State = State.CLOSED

    # Send sequence space (RFC 9293 3.3.1)
    snd_una: int = 0
    snd_nxt: int = 0
    snd_wnd: int = 0

    # Receive sequence space
    rcv_nxt: int = 0

    peer_mss: int = DEFAULT_MSS

    send_buffer: bytearray = field(default_factory=bytearray)
    recv_buffer: bytearray = field(default_factory=bytearray)

    # RFC 6298 retransmission timer
    srtt_ms: float = 0.0
    rttvar_ms: float = 0.0
    rto_ms: int = 1000
    retransmit_count: int = 0
    retransmit_deadline: int | None = None

    time_wait_deadline: int | None = None
    connect_deadline: int | None = None

    close_requested: bool = False
    fin_sent_seq: int | None = None
    peer_fin_seen: bool = False

    _unacked: list[_Unacked] = field(default_factory=list)
    pending_segments: list[bytes] = field(default_factory=list)
    pending_events: list[tuple[str, object]] = field(default_factory=list)
    """``(name, detail)`` pairs the stack translates into typed events. Kept as
    plain tuples so ``pyac.net.tcb`` need not import the event classes."""
    error: NetworkError | None = None

    # --- public API --------------------------------------------------------

    def connect(self, now: int) -> None:
        """Begin an active open."""
        if self.state is not State.CLOSED:
            raise RuntimeError(f"connect() in state {self.state.name}")

        self.snd_una = self.isn
        self.snd_nxt = self.isn
        self.rto_ms = self.config.rto_initial_ms
        self.connect_deadline = now + self.config.connect_timeout_ms
        self.state = State.SYN_SENT
        self._emit(Flag.SYN, now, mss=self.config.mss, track=True)

    def send(self, data: bytes | memoryview, now: int) -> int:
        """Queue application data; returns how many bytes were accepted."""
        if not self.state.can_send or self.close_requested:
            return 0
        space = self.config.tx_buffer - len(self.send_buffer)
        accepted = min(space, len(data))
        if accepted > 0:
            self.send_buffer += bytes(data[:accepted])
            self._pump(now)
        return accepted

    def recv(self, max_bytes: int) -> bytes:
        """Take received data out of the receive buffer."""
        if not self.recv_buffer:
            return b""
        take = min(max_bytes, len(self.recv_buffer))
        data = bytes(self.recv_buffer[:take])
        del self.recv_buffer[:take]
        return data

    @property
    def rx_available(self) -> int:
        return len(self.recv_buffer)

    @property
    def tx_space(self) -> int:
        return max(0, self.config.tx_buffer - len(self.send_buffer))

    @property
    def recv_window(self) -> int:
        """Advertised window: whatever is still free in the receive buffer.

        Computed at ACK time from the *unread* backlog, which is what makes
        flow control real -- draining into an unbounded queue elsewhere would
        keep this permanently wide open.
        """
        return max(0, self.config.rx_buffer - len(self.recv_buffer))

    @property
    def advertised_window(self) -> int:
        """:attr:`recv_window`, clamped to what the 16-bit field can carry."""
        return min(self.recv_window, MAX_WINDOW)

    def close(self, now: int) -> None:
        """Begin a graceful close; the FIN follows any queued data."""
        if self.close_requested or self.state.is_closed:
            return
        self.close_requested = True
        self._pump(now)

    def abort(self, now: int, reason: str = "aborted") -> None:
        """Send RST and drop the connection immediately."""
        if self.state in (State.CLOSED, State.TIME_WAIT):
            self.state = State.CLOSED
            return
        self._emit(Flag.RST | Flag.ACK, now)
        self._fail(ConnectionReset(reason))

    # --- inbound -----------------------------------------------------------

    def on_segment(self, segment: TcpSegment, now: int) -> None:
        """Process one inbound segment."""
        if self.state.is_closed:
            return

        if segment.has(Flag.RST):
            self._on_reset(segment)
            return

        if self.state is State.SYN_SENT:
            self._on_syn_sent(segment, now)
            return

        # Anything arriving now must acknowledge data we actually sent.
        if segment.has(Flag.ACK):
            if seq_gt(segment.ack, self.snd_nxt):
                return  # acknowledges something unsent: ignore
            self._on_ack(segment, now)

        self.snd_wnd = segment.window

        if segment.segment_length > 0 or segment.has(Flag.FIN):
            self._on_data(segment, now)

        self._pump(now)
        self._check_close_completion(now)

    def _on_syn_sent(self, segment: TcpSegment, now: int) -> None:
        if not segment.has(Flag.SYN):
            return
        if segment.has(Flag.ACK) and segment.ack != seq_add(self.isn, 1):
            return  # not our handshake

        self.rcv_nxt = seq_add(segment.seq, 1)
        self.snd_wnd = segment.window
        # Clamp to the peer's advertised MSS: sending larger is the classic
        # silent-hang bug, where the handshake works and bulk data never does.
        if segment.mss:
            self.peer_mss = max(DEFAULT_MSS, min(segment.mss, self.config.mss))
        else:
            self.peer_mss = min(DEFAULT_MSS, self.config.mss)

        if segment.has(Flag.ACK):
            self._ack_through(segment.ack, now)
            self.state = State.ESTABLISHED
            self.connect_deadline = None
            self._emit(Flag.ACK, now)
            self.pending_events.append(("connected", None))
            self._pump(now)
        # Simultaneous open (SYN without ACK) is out of scope; ignoring it
        # leaves the connect timeout to report the failure.

    def _on_reset(self, segment: TcpSegment) -> None:
        if self.state is State.SYN_SENT:
            self._fail(ConnectionRefused(f"{self.remote_ip}:{self.remote_port} refused"))
            return
        # Only accept an in-window RST, per RFC 5961, so a blind off-path
        # guess cannot tear down the connection.
        if seq_geq(segment.seq, self.rcv_nxt) and seq_lt(
            segment.seq, seq_add(self.rcv_nxt, max(1, self.recv_window))
        ):
            self._fail(ConnectionReset("connection reset by peer"))

    def _on_ack(self, segment: TcpSegment, now: int) -> None:
        if seq_leq(segment.ack, self.snd_una):
            return  # duplicate or stale ACK; nothing new is acknowledged
        self._ack_through(segment.ack, now)

    def _ack_through(self, ack: int, now: int) -> None:
        """Retire acknowledged segments and update the RTT estimate."""
        newly = seq_diff(ack, self.snd_una)
        if newly <= 0:
            return
        self.snd_una = ack

        remaining: list[_Unacked] = []
        for entry in self._unacked:
            end = seq_add(entry.seq, len(entry.payload))
            if entry.flags & (Flag.SYN | Flag.FIN):
                end = seq_add(end, 1)
            if seq_leq(end, ack):
                # Karn: a retransmitted segment gives no usable RTT sample,
                # because we cannot tell which copy was acknowledged.
                if not entry.retransmitted:
                    self._update_rtt(now - entry.sent_at)
            else:
                remaining.append(entry)
        self._unacked = remaining

        self.retransmit_count = 0
        self.retransmit_deadline = now + self.rto_ms if self._unacked else None

    def _on_data(self, segment: TcpSegment, now: int) -> None:
        if segment.seq != self.rcv_nxt:
            # Out of order. The thin slice drops it and lets the peer
            # retransmit; the ACK below re-advertises what we actually want.
            if segment.segment_length > 0:
                self._emit(Flag.ACK, now)
            return

        if segment.payload:
            space = self.config.rx_buffer - len(self.recv_buffer)
            accepted = min(space, len(segment.payload))
            if accepted > 0:
                self.recv_buffer += segment.payload[:accepted]
                self.rcv_nxt = seq_add(self.rcv_nxt, accepted)
                self.pending_events.append(("readable", None))

        if segment.has(Flag.FIN) and not self.peer_fin_seen:
            self.peer_fin_seen = True
            self.rcv_nxt = seq_add(self.rcv_nxt, 1)
            self.pending_events.append(("peer_closed", None))
            if self.state is State.ESTABLISHED:
                self.state = State.CLOSE_WAIT
            elif self.state is State.FIN_WAIT_1:
                self.state = State.CLOSING
            elif self.state is State.FIN_WAIT_2:
                self._enter_time_wait(now)

        self._emit(Flag.ACK, now)

    # --- timers ------------------------------------------------------------

    def on_tick(self, now: int) -> None:
        """Fire whatever is due."""
        if self.state.is_closed:
            return

        if self.connect_deadline is not None and now >= self.connect_deadline:
            self._fail(
                ConnectionTimeout(f"connect to {self.remote_ip}:{self.remote_port} timed out")
            )
            return

        if self.time_wait_deadline is not None and now >= self.time_wait_deadline:
            self.state = State.CLOSED
            self.pending_events.append(("closed", "time-wait expired"))
            return

        if self.retransmit_deadline is not None and now >= self.retransmit_deadline:
            self._retransmit(now)

    def next_deadline(self) -> int | None:
        candidates = [
            deadline
            for deadline in (
                self.retransmit_deadline,
                self.time_wait_deadline,
                self.connect_deadline,
            )
            if deadline is not None
        ]
        return min(candidates) if candidates else None

    def _retransmit(self, now: int) -> None:
        limit = (
            self.config.syn_retransmits
            if self.state is State.SYN_SENT
            else (self.config.max_retransmits)
        )
        if self.retransmit_count >= limit:
            self._fail(
                ConnectionTimeout(
                    f"{self.remote_ip}:{self.remote_port} stopped responding "
                    f"after {self.retransmit_count} retransmissions"
                )
            )
            return

        self.retransmit_count += 1
        # Exponential backoff, capped. The RTO stays backed off until a fresh
        # (non-retransmitted) sample replaces it.
        self.rto_ms = min(self.rto_ms * 2, self.config.rto_max_ms)

        if self._unacked:
            entry = self._unacked[0]
            entry.retransmitted = True
            entry.sent_at = now
            self._transmit(
                entry.seq, entry.flags, entry.payload, mss_option=bool(entry.flags & Flag.SYN)
            )
        self.retransmit_deadline = now + self.rto_ms

    def _update_rtt(self, sample_ms: int) -> None:
        """RFC 6298 with Jacobson/Karels smoothing."""
        sample = float(max(1, sample_ms))
        if self.srtt_ms == 0.0:
            self.srtt_ms = sample
            self.rttvar_ms = sample / 2
        else:
            self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * abs(self.srtt_ms - sample)
            self.srtt_ms = 0.875 * self.srtt_ms + 0.125 * sample
        computed = int(self.srtt_ms + 4 * self.rttvar_ms)
        self.rto_ms = max(self.config.rto_min_ms, min(computed, self.config.rto_max_ms))

    # --- outbound ----------------------------------------------------------

    def _pump(self, now: int) -> None:
        """Send whatever the window and buffer allow."""
        if self.state not in (State.ESTABLISHED, State.CLOSE_WAIT, State.FIN_WAIT_1):
            return

        in_flight = seq_diff(self.snd_nxt, self.snd_una)
        while self.send_buffer:
            usable = self.snd_wnd - in_flight
            if usable <= 0:
                break
            size = min(self.peer_mss, usable, len(self.send_buffer))
            if size <= 0:
                break
            chunk = bytes(self.send_buffer[:size])
            del self.send_buffer[:size]
            self._emit(Flag.ACK | Flag.PSH, now, payload=chunk, track=True)
            in_flight += size

        if self.close_requested and not self.send_buffer and self.fin_sent_seq is None:
            self.fin_sent_seq = self.snd_nxt
            self._emit(Flag.FIN | Flag.ACK, now, track=True)
            if self.state is State.ESTABLISHED:
                self.state = State.FIN_WAIT_1
            elif self.state is State.CLOSE_WAIT:
                self.state = State.LAST_ACK

    def _check_close_completion(self, now: int) -> None:
        """Advance the closing states once our FIN has been acknowledged."""
        if self.fin_sent_seq is None:
            return
        fin_acked = seq_gt(self.snd_una, self.fin_sent_seq)
        if not fin_acked:
            return

        if self.state is State.FIN_WAIT_1:
            self.state = State.FIN_WAIT_2 if not self.peer_fin_seen else State.TIME_WAIT
            if self.state is State.TIME_WAIT:
                self._enter_time_wait(now)
        elif self.state is State.CLOSING:
            self._enter_time_wait(now)
        elif self.state is State.LAST_ACK:
            self.state = State.CLOSED
            self.pending_events.append(("closed", "closed"))

    def _enter_time_wait(self, now: int) -> None:
        self.state = State.TIME_WAIT
        self.retransmit_deadline = None
        self.time_wait_deadline = now + self.config.time_wait_ms

    def _emit(
        self,
        flags: Flag,
        now: int,
        *,
        payload: bytes = b"",
        mss: int | None = None,
        track: bool = False,
    ) -> None:
        seq = self.snd_nxt
        self._transmit(seq, flags, payload, mss_option=mss is not None, mss_value=mss)

        consumed = len(payload) + (1 if flags & (Flag.SYN | Flag.FIN) else 0)
        if consumed:
            self.snd_nxt = seq_add(seq, consumed)
        if track and consumed:
            self._unacked.append(_Unacked(seq=seq, payload=payload, flags=flags, sent_at=now))
            if self.retransmit_deadline is None:
                self.retransmit_deadline = now + self.rto_ms

    def _transmit(
        self,
        seq: int,
        flags: Flag,
        payload: bytes,
        *,
        mss_option: bool = False,
        mss_value: int | None = None,
    ) -> None:
        self.pending_segments.append(
            build_tcp(
                source_ip=self.local_ip,
                destination_ip=self.remote_ip,
                source_port=self.local_port,
                destination_port=self.remote_port,
                seq=seq,
                ack=self.rcv_nxt if flags & Flag.ACK or self.state is not State.SYN_SENT else 0,
                flags=flags,
                window=self.advertised_window,
                payload=payload,
                mss=(mss_value or self.config.mss) if mss_option else None,
            )
        )

    def _fail(self, error: NetworkError) -> None:
        self.error = error
        self.state = State.CLOSED
        self.retransmit_deadline = None
        self.connect_deadline = None
        self.pending_events.append(("error", error))
