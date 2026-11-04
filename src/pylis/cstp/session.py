"""One CSTP tunnel over one TLS connection.

Owns the socket, the framing, and the DPD/keepalive timers, and presents an
:class:`~usernet.link.IpLink`. Reconnection and rekey live one layer up, in
``ReconnectingLink``, precisely so this class can stay "one connection, from
handshake to close".
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket as _socket
import ssl
import time
from collections import Counter, deque
from types import TracebackType

from usernet.pcap import PcapWriter

from pylis.cstp.config import TunnelConfig, parse_tunnel_config
from pylis.cstp.framing import (
    FRAME_DISCONN,
    FRAME_DPD_OUT,
    FRAME_DPD_RESP,
    FRAME_KEEPALIVE,
    FrameDecoder,
    PacketType,
    encode_frame,
)
from pylis.cstp.handshake import build_connect_request, parse_connect_response, split_header_block
from pylis.errors import ProtocolParseError, TunnelClosed

log = logging.getLogger("pylis.cstp")

READ_SIZE = 65536

# Inbound packets accumulate here between driver passes. Dropping the tail
# when it overflows is exactly what a congested link does, and TCP recovers.
MAX_INBOUND_BACKLOG = 512

# Bounded so a stalled TLS socket cannot grow the queue without limit; the
# stack's own retransmission queues are the correct place for that backlog.
MAX_OUTBOUND_BACKLOG = 256


class CstpSession:
    """A live CSTP tunnel, satisfying :class:`~usernet.link.IpLink`."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        session_token: str,
        ssl_context: ssl.SSLContext,
        user_agent: str,
        local_hostname: str | None = None,
        mtu: int = 1406,
        pcap: PcapWriter | None = None,
        client_dpd: bool = True,
        coalesce: bool = False,
    ) -> None:
        self._host = host
        self._port = port
        self._token = session_token
        self._ssl_context = ssl_context
        self._user_agent = user_agent
        self._local_hostname = local_hostname or _socket.gethostname()
        self._requested_mtu = mtu
        self._pcap = pcap
        self._client_dpd = client_dpd

        # One CSTP frame per TLS record. This is not a tuning knob: a real ASA
        # (5.1.5) silently drops the connection the moment two frames arrive in
        # one record. See docs/protocol.md -- openconnect issues one SSL_write
        # per packet, so gateways have never had to handle batched frames.
        self._coalesce = coalesce

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._config: TunnelConfig | None = None
        self._decoder = FrameDecoder()

        self._inbound: list[bytes] = []
        self._outbound: deque[bytes] = deque()
        self._wake = asyncio.Event()
        self._writer_wake = asyncio.Event()
        self._closed = asyncio.Event()
        self._close_reason = ""
        self._tasks: list[asyncio.Task[None]] = []

        self._dpd_outstanding = 0
        self.dropped_inbound = 0
        self.dropped_outbound = 0

        # Frame accounting. Control frames are invisible in packet counts, so
        # without this a tunnel that dies from a missed keepalive looks
        # identical to one that was simply idle.
        self.frames_in: Counter[str] = Counter()
        self.frames_out: Counter[str] = Counter()
        # IP bytes carried in DATA frames, inner headers included.
        self.bytes_in = 0
        self.bytes_out = 0
        self.started_at = 0.0
        self.last_frame_at = 0.0

    # --- IpLink ------------------------------------------------------------

    @property
    def config(self) -> TunnelConfig:
        if self._config is None:
            raise RuntimeError("tunnel is not connected yet")
        return self._config

    @property
    def wake(self) -> asyncio.Event:
        return self._wake

    @property
    def closed(self) -> asyncio.Event:
        return self._closed

    @property
    def close_reason(self) -> str:
        return self._close_reason

    def send(self, packet: bytes) -> None:
        if len(self._outbound) >= MAX_OUTBOUND_BACKLOG:
            self.dropped_outbound += 1
            return
        self._outbound.append(encode_frame(PacketType.DATA, packet))
        self.frames_out["DATA"] += 1
        self.bytes_out += len(packet)
        # Captured here rather than in the writer task, which holds encoded
        # frames rather than IP packets. A one-sided capture is half a
        # diagnostic: Wireshark cannot compute RTT, spot a retransmission, or
        # learn our window scale without having seen both directions.
        if self._pcap is not None:
            self._pcap.write(packet)
        self._writer_wake.set()

    def take_inbound(self) -> list[bytes]:
        packets = self._inbound
        self._inbound = []
        self._wake.clear()
        return packets

    # --- lifecycle ---------------------------------------------------------

    async def connect(self) -> TunnelConfig:
        """Open TLS, perform the CONNECT handshake, and start the tasks."""
        self._reader, self._writer = await asyncio.open_connection(
            self._host, self._port, ssl=self._ssl_context, server_hostname=self._host
        )

        request = build_connect_request(
            host=self._host,
            port=self._port,
            session_token=self._token,
            local_hostname=self._local_hostname,
            user_agent=self._user_agent,
            mtu=self._requested_mtu,
        )
        self._writer.write(request)
        await self._writer.drain()

        buffer = b""
        block = b""
        remainder = b""
        while True:
            chunk = await self._reader.read(READ_SIZE)
            if not chunk:
                raise TunnelClosed("gateway closed the connection during the CONNECT handshake")
            buffer += chunk
            split = split_header_block(buffer)
            if split is not None:
                block, remainder = split
                break

        headers = parse_connect_response(block)
        self._config = parse_tunnel_config(headers)

        if self._config.content_encoding:
            # We never advertised Accept-Encoding, so this should be impossible.
            # Failing loudly beats silently mangling every packet.
            raise ProtocolParseError(
                f"gateway enabled {self._config.content_encoding!r} compression "
                f"despite no X-CSTP-Accept-Encoding being offered"
            )

        # The gateway often packs the first frames into the same segment as the
        # response headers; dropping them would desynchronise the stream at once.
        if remainder:
            self._consume(remainder)

        self.started_at = time.monotonic()
        self.last_frame_at = self.started_at

        for coroutine, name in (
            (self._read_loop(), "cstp-reader"),
            (self._write_loop(), "cstp-writer"),
            (self._timer_loop(), "cstp-timers"),
        ):
            task = asyncio.create_task(coroutine, name=name)
            # Without this an exception in a background task vanishes: the
            # tunnel would stop sending keepalives and simply wait to be
            # dropped, with nothing to say why.
            task.add_done_callback(self._on_task_done)
            self._tasks.append(task)

        return self._config

    def _on_task_done(self, task: asyncio.Task[None]) -> None:
        if task.cancelled():
            return
        exception = task.exception()
        if exception is not None:
            log.error("%s failed: %r", task.get_name(), exception)
            self._mark_closed(f"{task.get_name()} failed: {exception!r}")

    async def aclose(self) -> None:
        """Tell the gateway we are going, then tear everything down."""
        self._mark_closed("client disconnect")

        if self._writer is not None and not self._writer.is_closing():
            with contextlib.suppress(OSError, ssl.SSLError):
                self._writer.write(FRAME_DISCONN)
                await asyncio.wait_for(self._writer.drain(), timeout=2.0)

        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []

        if self._writer is not None:
            self._writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._writer.wait_closed(), timeout=2.0)

    async def __aenter__(self) -> CstpSession:
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # --- internals ---------------------------------------------------------

    def _mark_closed(self, reason: str) -> None:
        if not self._closed.is_set():
            self._close_reason = reason
            self._closed.set()
        self._wake.set()  # release a driver waiting for packets

    def _queue(self, frame: bytes, name: str, *, urgent: bool = False) -> None:
        """Queue an outbound control frame and record it."""
        if urgent:
            self._outbound.appendleft(frame)
        else:
            self._outbound.append(frame)
        self.frames_out[name] += 1
        log.debug("-> %s", name)
        self._writer_wake.set()

    def _consume(self, data: bytes) -> None:
        """Feed raw stream bytes through the framer and dispatch each frame."""
        for frame in self._decoder.feed(data):
            self.last_frame_at = time.monotonic()
            try:
                name = PacketType(frame.type).name
            except ValueError:
                name = f"UNKNOWN({frame.type})"
            self.frames_in[name] += 1
            log.debug("<- %s (%d bytes)", name, len(frame.payload))

            if frame.type == PacketType.DATA:
                if len(self._inbound) >= MAX_INBOUND_BACKLOG:
                    self.dropped_inbound += 1
                    continue
                self._inbound.append(frame.payload)
                self.bytes_in += len(frame.payload)
                if self._pcap is not None:
                    self._pcap.write(frame.payload)
                self._wake.set()

            elif frame.type == PacketType.DPD_OUT:
                # Jump the queue. A full data backlog must never delay a DPD
                # response -- that is how tunnels die under load.
                self._queue(FRAME_DPD_RESP, "DPD_RESP", urgent=True)

            elif frame.type == PacketType.DPD_RESP:
                self._dpd_outstanding = 0

            elif frame.type == PacketType.KEEPALIVE:
                pass

            elif frame.type == PacketType.DISCONN:
                self._mark_closed("gateway sent DISCONNECT")

            elif frame.type == PacketType.TERM_SERVER:
                self._mark_closed("gateway terminated the session")

            elif frame.type == PacketType.COMPRESSED:
                raise ProtocolParseError(
                    "gateway sent a COMPRESSED frame although compression was never offered"
                )

    async def _read_loop(self) -> None:
        assert self._reader is not None
        try:
            while True:
                chunk = await self._reader.read(READ_SIZE)
                if not chunk:
                    self._mark_closed("gateway closed the tunnel")
                    return
                self._consume(chunk)
        except asyncio.CancelledError:
            raise
        except (OSError, ssl.SSLError) as exc:
            self._mark_closed(f"tunnel read failed: {exc}")
        except ProtocolParseError as exc:
            # The stream has desynchronised and CSTP has no delimiter to
            # resynchronise on, so the tunnel cannot be salvaged.
            self._mark_closed(f"protocol error: {exc}")

    async def _flush_outbound(self) -> None:
        """Write every queued frame.

        One ``write()`` call per frame, which asyncio turns into one
        ``SSLObject.write()`` and therefore one TLS record. That mapping is
        the whole point: an ASA that receives two frames in a single record
        drops the connection without warning. See docs/protocol.md.
        """
        writer = self._writer
        if writer is None:
            return

        if self._coalesce:
            # Opt-in only, and known to break ASA. Retained because a gateway
            # that tolerates it would see a real throughput win.
            batch = b"".join(self._outbound)
            self._outbound.clear()
            writer.write(batch)
            await writer.drain()
            return

        while self._outbound:
            writer.write(self._outbound.popleft())
            await writer.drain()

    async def _write_loop(self) -> None:
        assert self._writer is not None
        try:
            while True:
                await self._writer_wake.wait()
                self._writer_wake.clear()

                if not self._outbound:
                    continue

                await self._flush_outbound()
        except asyncio.CancelledError:
            raise
        except (OSError, ssl.SSLError) as exc:
            self._mark_closed(f"tunnel write failed: {exc}")

    async def _timer_loop(self) -> None:
        """Send keepalives and DPD probes, and notice a dead peer.

        Driven off absolute deadlines rather than an accumulator, so each
        timer fires on its own period instead of being rounded up to a
        multiple of the shorter one -- with dpd=30 and keepalive=20 an
        accumulator would not send the first DPD until t=40.
        """
        config = self.config
        dpd = max(1, config.dpd or 30)
        keepalive = max(1, config.keepalive or 20)

        now = time.monotonic()
        next_dpd = now + dpd
        next_keepalive = now + keepalive

        while True:
            now = time.monotonic()
            await asyncio.sleep(max(0.1, min(next_dpd, next_keepalive) - now))
            now = time.monotonic()

            if now >= next_dpd and self._client_dpd:
                next_dpd = now + dpd
                if self._dpd_outstanding >= 2:
                    self._mark_closed(f"no DPD response after {self._dpd_outstanding} probes")
                    return
                self._dpd_outstanding += 1
                self._queue(FRAME_DPD_OUT, "DPD_OUT")
            elif now >= next_dpd:
                next_dpd = now + dpd

            if now >= next_keepalive:
                next_keepalive = now + keepalive
                self._queue(FRAME_KEEPALIVE, "KEEPALIVE")

    def stats(self) -> str:
        """A one-line account of what actually crossed the tunnel."""
        elapsed = time.monotonic() - self.started_at if self.started_at else 0.0
        quiet = time.monotonic() - self.last_frame_at if self.last_frame_at else 0.0

        def render(counter: Counter[str]) -> str:
            return ", ".join(f"{name}={count}" for name, count in sorted(counter.items())) or "none"

        return (
            f"up {elapsed:.1f}s, last frame {quiet:.1f}s ago\n"
            f"  received  {render(self.frames_in)}\n"
            f"  sent      {render(self.frames_out)}"
        )
