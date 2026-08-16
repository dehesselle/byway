"""The TCP state machine, driven deterministically.

The clock is an integer advanced by hand, so every timing assertion is exact
and nothing depends on wall time. A test here that sleeps, or that passes only
sometimes, is a bug in the test.
"""

from __future__ import annotations

import pytest

from pyac.errors import ConnectionRefused, ConnectionReset, ConnectionTimeout
from pyac.net.ipv4 import PROTO_TCP
from pyac.net.tcb import State, Tcb, TcbConfig
from pyac.net.tcp import DEFAULT_MSS, Flag, TcpSegment, parse_tcp, seq_add, verify_tcp_checksum

LOCAL_IP = "172.29.29.5"
REMOTE_IP = "10.221.188.32"
LOCAL_PORT = 51000
REMOTE_PORT = 80
ISN = 1000
PEER_ISN = 500_000


class Harness:
    """One TCB, a frozen clock, and helpers to speak to it as the peer."""

    def __init__(self, **config: object) -> None:
        self.now = 0
        self.tcb = Tcb(
            local_ip=LOCAL_IP,
            local_port=LOCAL_PORT,
            remote_ip=REMOTE_IP,
            remote_port=REMOTE_PORT,
            isn=ISN,
            config=TcbConfig(**config),  # type: ignore[arg-type]
        )

    # --- driving -------------------------------------------------------

    def advance(self, milliseconds: int) -> None:
        self.now += milliseconds
        self.tcb.on_tick(self.now)

    def sent(self) -> list[TcpSegment]:
        """Drain and parse everything the TCB wants to send."""
        segments = [parse_tcp(raw) for raw in self.tcb.pending_segments]
        self.tcb.pending_segments.clear()
        return segments

    def one(self) -> TcpSegment:
        segments = self.sent()
        assert len(segments) == 1, f"expected exactly one segment, got {len(segments)}"
        return segments[0]

    def events(self) -> list[object]:
        drained = list(self.tcb.pending_events)
        self.tcb.pending_events.clear()
        return drained

    def event_names(self) -> list[str]:
        return [name for name, _ in self.events()]  # type: ignore[misc]

    def peer(
        self,
        *,
        seq: int,
        ack: int,
        flags: Flag,
        payload: bytes = b"",
        window: int = 65535,
        mss: int | None = None,
    ) -> None:
        self.tcb.on_segment(
            TcpSegment(
                source_port=REMOTE_PORT,
                destination_port=LOCAL_PORT,
                seq=seq,
                ack=ack,
                flags=flags,
                window=window,
                payload=payload,
                mss=mss,
            ),
            self.now,
        )

    # --- shortcuts -----------------------------------------------------

    def establish(self, *, peer_mss: int | None = 1460, rtt_ms: int = 0) -> None:
        """Complete a handshake, optionally taking ``rtt_ms`` to do it.

        The handshake itself yields the connection's first RTT sample, so
        ``rtt_ms`` seeds the estimator deliberately rather than leaving tests
        to trip over an implicit near-zero sample.
        """
        self.tcb.connect(self.now)
        self.sent()
        self.now += rtt_ms
        self.peer(seq=PEER_ISN, ack=seq_add(ISN, 1), flags=Flag.SYN | Flag.ACK, mss=peer_mss)
        self.sent()
        self.events()
        assert self.tcb.state is State.ESTABLISHED


@pytest.fixture
def h() -> Harness:
    return Harness()


# --- handshake -------------------------------------------------------------


def test_connect_sends_syn_with_mss(h: Harness) -> None:
    h.tcb.connect(h.now)
    syn = h.one()

    assert syn.flags == Flag.SYN
    assert syn.seq == ISN
    assert syn.source_port == LOCAL_PORT
    assert syn.destination_port == REMOTE_PORT
    assert syn.mss == h.tcb.config.mss
    assert h.tcb.state is State.SYN_SENT


def test_syn_ack_completes_the_handshake(h: Harness) -> None:
    h.tcb.connect(h.now)
    h.sent()
    h.peer(seq=PEER_ISN, ack=seq_add(ISN, 1), flags=Flag.SYN | Flag.ACK, mss=1460)

    ack = h.one()
    assert ack.flags & Flag.ACK
    assert ack.seq == seq_add(ISN, 1)
    assert ack.ack == seq_add(PEER_ISN, 1)
    assert h.tcb.state is State.ESTABLISHED
    assert h.event_names() == ["connected"]


def test_our_mss_is_clamped_to_the_peers(h: Harness) -> None:
    """Sending above the peer's MSS is the classic silent-hang bug."""
    h.establish(peer_mss=536)
    assert h.tcb.peer_mss == 536


def test_peer_mss_larger_than_ours_does_not_raise_ours(h: Harness) -> None:
    h.establish(peer_mss=9000)
    assert h.tcb.peer_mss == h.tcb.config.mss


def test_missing_mss_option_falls_back_to_the_rfc_floor(h: Harness) -> None:
    h.establish(peer_mss=None)
    assert h.tcb.peer_mss == DEFAULT_MSS


def test_syn_ack_for_a_different_handshake_is_ignored(h: Harness) -> None:
    h.tcb.connect(h.now)
    h.sent()
    h.peer(seq=PEER_ISN, ack=99999, flags=Flag.SYN | Flag.ACK)

    assert h.tcb.state is State.SYN_SENT
    assert h.sent() == []


def test_rst_during_connect_is_connection_refused(h: Harness) -> None:
    h.tcb.connect(h.now)
    h.sent()
    h.peer(seq=0, ack=seq_add(ISN, 1), flags=Flag.RST | Flag.ACK)

    assert h.tcb.state is State.CLOSED
    assert isinstance(h.tcb.error, ConnectionRefused)


def test_syn_is_retransmitted_with_backoff_then_gives_up(h: Harness) -> None:
    h = Harness(rto_initial_ms=1000, syn_retransmits=3, connect_timeout_ms=999_999)
    h.tcb.connect(h.now)
    h.sent()

    for expected_delay in (1000, 2000, 4000):
        h.advance(expected_delay)
        assert h.one().flags == Flag.SYN

    h.advance(8000)
    assert h.tcb.state is State.CLOSED
    assert isinstance(h.tcb.error, ConnectionTimeout)


def test_connect_timeout_fires_independently_of_retransmits(h: Harness) -> None:
    h = Harness(connect_timeout_ms=5000, rto_initial_ms=100_000)
    h.tcb.connect(h.now)
    h.sent()

    h.advance(5000)
    assert h.tcb.state is State.CLOSED
    assert isinstance(h.tcb.error, ConnectionTimeout)


# --- data transfer ---------------------------------------------------------


def test_send_produces_a_data_segment(h: Harness) -> None:
    h.establish()
    assert h.tcb.send(b"GET / HTTP/1.1\r\n\r\n", h.now) == 18

    segment = h.one()
    assert segment.payload == b"GET / HTTP/1.1\r\n\r\n"
    assert segment.flags & Flag.PSH
    assert segment.flags & Flag.ACK
    assert segment.seq == seq_add(ISN, 1)


def test_send_is_split_at_the_peer_mss(h: Harness) -> None:
    h.establish(peer_mss=536)
    h.tcb.send(b"x" * 1200, h.now)

    segments = h.sent()
    assert [len(s.payload) for s in segments] == [536, 536, 128]
    assert b"".join(s.payload for s in segments) == b"x" * 1200
    # Sequence numbers must be contiguous across the split.
    assert segments[1].seq == seq_add(segments[0].seq, 536)


def test_send_respects_the_peer_window(h: Harness) -> None:
    h.tcb.connect(h.now)
    h.sent()
    h.peer(seq=PEER_ISN, ack=seq_add(ISN, 1), flags=Flag.SYN | Flag.ACK, mss=1460, window=100)
    h.sent()

    h.tcb.send(b"y" * 500, h.now)
    segments = h.sent()

    assert sum(len(s.payload) for s in segments) == 100
    assert len(h.tcb.send_buffer) == 400  # the rest stays queued


def test_window_reopening_releases_queued_data(h: Harness) -> None:
    h.tcb.connect(h.now)
    h.sent()
    h.peer(seq=PEER_ISN, ack=seq_add(ISN, 1), flags=Flag.SYN | Flag.ACK, mss=1460, window=100)
    h.sent()
    h.tcb.send(b"y" * 500, h.now)
    h.sent()

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 101), flags=Flag.ACK, window=400)
    assert sum(len(s.payload) for s in h.sent()) == 400


def test_send_is_bounded_by_the_transmit_buffer(h: Harness) -> None:
    h = Harness(tx_buffer=100)
    h.establish(peer_mss=1460)
    # Window is wide open, so everything accepted is sent immediately.
    assert h.tcb.send(b"z" * 500, h.now) == 100


def test_receiving_data_buffers_it_and_acks(h: Harness) -> None:
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"hello")

    ack = h.one()
    assert ack.ack == seq_add(PEER_ISN, 6)
    assert h.tcb.recv(100) == b"hello"
    assert "readable" in h.event_names()


def test_recv_takes_only_what_is_asked_for(h: Harness) -> None:
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"abcdef")

    assert h.tcb.recv(2) == b"ab"
    assert h.tcb.recv(2) == b"cd"
    assert h.tcb.recv(100) == b"ef"
    assert h.tcb.recv(100) == b""


def test_out_of_order_segment_is_dropped_and_reacked(h: Harness) -> None:
    """The thin slice has no reassembly queue; the ACK re-asks for rcv_nxt."""
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 100), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"future")

    ack = h.one()
    assert ack.ack == seq_add(PEER_ISN, 1)  # still asking for the gap
    assert h.tcb.recv(100) == b""


def test_advertised_window_shrinks_as_the_buffer_fills(h: Harness) -> None:
    """Flow control is only real if the window reflects unread bytes."""
    h = Harness(rx_buffer=1000)
    h.establish()

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"a" * 400)
    assert h.one().window == 600

    h.tcb.recv(400)
    h.peer(seq=seq_add(PEER_ISN, 401), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"b" * 10)
    assert h.one().window == 990


def test_data_beyond_the_receive_buffer_is_not_accepted(h: Harness) -> None:
    h = Harness(rx_buffer=100)
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"c" * 250)

    assert len(h.tcb.recv_buffer) == 100
    assert h.one().window == 0


# --- retransmission --------------------------------------------------------


def test_unacked_data_is_retransmitted(h: Harness) -> None:
    h = Harness(rto_initial_ms=1000)
    h.establish()
    h.tcb.send(b"payload", h.now)
    first = h.one()

    h.advance(1000)
    again = h.one()
    assert again.payload == first.payload
    assert again.seq == first.seq


def test_acked_data_is_not_retransmitted(h: Harness) -> None:
    h = Harness(rto_initial_ms=1000)
    h.establish()
    h.tcb.send(b"payload", h.now)
    h.sent()

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 8), flags=Flag.ACK)
    h.sent()

    h.advance(5000)
    assert h.sent() == []


def test_retransmission_backs_off_exponentially(h: Harness) -> None:
    h = Harness(rto_initial_ms=1000, max_retransmits=5)
    h.establish()
    h.tcb.send(b"data", h.now)
    h.sent()

    for delay in (1000, 2000, 4000):
        h.advance(delay)
        assert len(h.sent()) == 1


def test_giving_up_reports_a_timeout(h: Harness) -> None:
    h = Harness(rto_initial_ms=1000, max_retransmits=2)
    h.establish()
    h.tcb.send(b"data", h.now)
    h.sent()

    h.advance(1000)
    h.advance(2000)
    h.advance(4000)

    assert h.tcb.state is State.CLOSED
    assert isinstance(h.tcb.error, ConnectionTimeout)


def test_the_handshake_provides_the_first_rtt_sample(h: Harness) -> None:
    """RFC 6298: the SYN exchange is a legitimate first measurement."""
    h = Harness(rto_min_ms=1)
    h.establish(rtt_ms=100)

    # First sample: srtt=100, rttvar=50, rto=srtt+4*rttvar=300.
    assert h.tcb.srtt_ms == 100
    assert h.tcb.rttvar_ms == 50
    assert h.tcb.rto_ms == 300


def test_later_samples_are_smoothed_into_the_estimate(h: Harness) -> None:
    h = Harness(rto_min_ms=1)
    h.establish(rtt_ms=100)
    h.tcb.send(b"data", h.now)
    h.sent()

    h.now += 200
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 5), flags=Flag.ACK)

    # srtt = 0.875*100 + 0.125*200 = 112.5, moving toward the new sample.
    assert h.tcb.srtt_ms == pytest.approx(112.5)
    assert 100 < h.tcb.rto_ms < 400


def test_karn_ignores_the_rtt_of_a_retransmitted_segment(h: Harness) -> None:
    """We cannot tell which copy was acknowledged, so the sample is unusable."""
    h = Harness(rto_initial_ms=1000, rto_min_ms=1)
    h.establish(rtt_ms=100)
    before = h.tcb.srtt_ms
    h.tcb.send(b"data", h.now)
    h.sent()

    h.advance(1000)  # retransmit
    h.sent()
    h.now += 10
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 5), flags=Flag.ACK)

    assert h.tcb.srtt_ms == before  # the ambiguous sample was discarded


def test_rto_is_clamped_to_the_minimum(h: Harness) -> None:
    """A fast LAN RTT would otherwise compute an RTO below Windows' timer
    granularity, turning every minor delay into a spurious retransmission."""
    h = Harness(rto_min_ms=250)
    h.establish(rtt_ms=1)
    assert h.tcb.rto_ms == 250


# --- closing ---------------------------------------------------------------


def test_active_close_walks_fin_wait_to_time_wait(h: Harness) -> None:
    h.establish()
    h.tcb.close(h.now)

    fin = h.one()
    assert fin.flags & Flag.FIN
    assert h.tcb.state is State.FIN_WAIT_1

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 2), flags=Flag.ACK)
    h.sent()
    assert h.tcb.state is State.FIN_WAIT_2

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 2), flags=Flag.FIN | Flag.ACK)
    h.sent()
    assert h.tcb.state is State.TIME_WAIT


def test_time_wait_expires_into_closed(h: Harness) -> None:
    h = Harness(time_wait_ms=30_000)
    h.establish()
    h.tcb.close(h.now)
    h.sent()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 2), flags=Flag.FIN | Flag.ACK)
    h.sent()

    h.advance(29_999)
    assert h.tcb.state is State.TIME_WAIT
    h.advance(1)
    assert h.tcb.state is State.CLOSED


def test_passive_close_walks_close_wait_to_last_ack(h: Harness) -> None:
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.FIN | Flag.ACK)
    h.sent()

    assert h.tcb.state is State.CLOSE_WAIT
    assert "peer_closed" in h.event_names()

    h.tcb.close(h.now)
    assert h.one().flags & Flag.FIN
    assert h.tcb.state is State.LAST_ACK

    h.peer(seq=seq_add(PEER_ISN, 2), ack=seq_add(ISN, 2), flags=Flag.ACK)
    assert h.tcb.state is State.CLOSED


def test_simultaneous_close_goes_through_closing(h: Harness) -> None:
    h.establish()
    h.tcb.close(h.now)
    h.sent()

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.FIN | Flag.ACK)
    h.sent()
    assert h.tcb.state is State.CLOSING

    h.peer(seq=seq_add(PEER_ISN, 2), ack=seq_add(ISN, 2), flags=Flag.ACK)
    assert h.tcb.state is State.TIME_WAIT


def test_queued_data_is_flushed_before_the_fin(h: Harness) -> None:
    h.establish(peer_mss=536)
    h.tcb.send(b"q" * 1000, h.now)
    h.sent()
    h.tcb.close(h.now)

    # Everything was already sent, so only the FIN remains.
    assert h.one().flags & Flag.FIN


def test_close_before_the_window_allows_sending_defers_the_fin(h: Harness) -> None:
    h.tcb.connect(h.now)
    h.sent()
    h.peer(seq=PEER_ISN, ack=seq_add(ISN, 1), flags=Flag.SYN | Flag.ACK, mss=1460, window=10)
    h.sent()

    h.tcb.send(b"w" * 100, h.now)
    h.sent()
    h.tcb.close(h.now)
    assert not any(s.flags & Flag.FIN for s in h.sent())

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 11), flags=Flag.ACK, window=1000)
    assert any(s.flags & Flag.FIN for s in h.sent())


def test_send_after_close_is_refused(h: Harness) -> None:
    h.establish()
    h.tcb.close(h.now)
    assert h.tcb.send(b"too late", h.now) == 0


# --- resets ----------------------------------------------------------------


def test_in_window_reset_tears_down_the_connection(h: Harness) -> None:
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.RST)

    assert h.tcb.state is State.CLOSED
    assert isinstance(h.tcb.error, ConnectionReset)


def test_out_of_window_reset_is_ignored(h: Harness) -> None:
    """RFC 5961: a blind off-path guess must not kill the connection."""
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 999_999), ack=seq_add(ISN, 1), flags=Flag.RST)

    assert h.tcb.state is State.ESTABLISHED
    assert h.tcb.error is None


def test_abort_sends_a_reset(h: Harness) -> None:
    h.establish()
    h.tcb.abort(h.now, "user abort")

    assert h.one().flags & Flag.RST
    assert h.tcb.state is State.CLOSED


# --- correctness of what goes on the wire ----------------------------------


def test_every_emitted_segment_has_a_valid_checksum(h: Harness) -> None:
    h.establish()
    h.tcb.send(b"checksummed payload", h.now)
    h.tcb.close(h.now)

    raw_segments = list(h.tcb.pending_segments)
    assert raw_segments
    for raw in raw_segments:
        assert verify_tcp_checksum(LOCAL_IP, REMOTE_IP, raw), "bad TCP checksum"


def test_acknowledging_unsent_data_is_ignored(h: Harness) -> None:
    h.establish()
    before = h.tcb.snd_una
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 5000), flags=Flag.ACK)
    assert h.tcb.snd_una == before


def test_protocol_number_is_tcp() -> None:
    assert PROTO_TCP == 6
