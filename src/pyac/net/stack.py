"""The userspace stack: packet demultiplexing, socket table, and timers.

Skeleton as of M0 -- the queue and event plumbing below is final, while the
protocol handling arrives with ICMP/UDP in M3 and TCP in M4.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from pyac.net.events import Event, SocketId

# Defaults are the values argued for in the design; see docs/protocol.md.
DEFAULT_MTU = 1406  # what ASA typically advertises as X-CSTP-MTU
IP_HEADER_LEN = 20
TCP_HEADER_LEN = 20


@dataclass(frozen=True, slots=True)
class StackConfig:
    """Tunables for one stack instance.

    Every value that would otherwise be a module constant lives here so tests
    can shrink buffers and timers to keep scenarios small and fast.
    """

    local_ip: str
    netmask: str = "255.255.255.255"
    mtu: int = DEFAULT_MTU

    # 256 KiB with window scale 7 gives roughly 2.5 MB/s per connection at a
    # 100 ms RTT, which is the regime a corporate VPN actually operates in.
    rx_buffer: int = 256 * 1024
    tx_buffer: int = 256 * 1024

    max_sockets: int = 512
    max_total_buffer: int = 128 * 1024 * 1024

    # RFC 6298's 1 s floor is painful at 50 ms RTT; 250 ms still clears
    # Windows' ~15.6 ms timer granularity comfortably.
    rto_min_ms: int = 250
    rto_max_ms: int = 60_000
    rto_initial_ms: int = 1_000
    max_retransmits: int = 8

    delayed_ack_ms: int = 40
    time_wait_ms: int = 30_000
    connect_timeout_ms: int = 15_000

    nodelay_default: bool = True
    # The tunnel is already authenticated end to end by TLS, so skipping
    # inbound checksum verification is defensible when chasing throughput.
    verify_checksums: bool = True

    # Injected so tests can pin ISNs and ephemeral ports; production supplies
    # a `secrets`-backed callable from the driver.
    rng: Callable[[], int] = field(default=lambda: 0, repr=False, compare=False)

    @property
    def mss(self) -> int:
        """Maximum segment size derived from the tunnel MTU.

        Also clamped against the peer's advertised MSS once the SYN-ACK
        arrives -- getting this wrong is the classic silent-hang bug.
        """
        return self.mtu - IP_HEADER_LEN - TCP_HEADER_LEN


class PyStack:
    """Pure-Python :class:`~pyac.net.backend.NetworkBackend` implementation."""

    def __init__(self, config: StackConfig) -> None:
        self.config = config
        self._out: list[bytes] = []
        self._events: list[Event] = []

    # --- link side ---------------------------------------------------------

    def handle_input(self, packet: bytes | memoryview, now: int) -> None:
        raise NotImplementedError("IP demultiplexing arrives in M3")

    def poll(self, now: int) -> None:
        raise NotImplementedError("timer wheel arrives in M3")

    def poll_at(self) -> int | None:
        return None

    def take_output(self) -> list[bytes]:
        out = self._out
        self._out = []
        return out

    def take_events(self) -> list[Event]:
        events = self._events
        self._events = []
        return events

    # --- TCP ---------------------------------------------------------------

    def tcp_connect(self, dst: tuple[str, int], *, nodelay: bool = True) -> SocketId:
        raise NotImplementedError("TCP arrives in M4")

    def tcp_send(self, sid: SocketId, data: memoryview) -> int:
        raise NotImplementedError("TCP arrives in M4")

    def tcp_recv(self, sid: SocketId, max_bytes: int) -> bytes:
        raise NotImplementedError("TCP arrives in M4")

    def tcp_tx_space(self, sid: SocketId) -> int:
        raise NotImplementedError("TCP arrives in M4")

    def tcp_rx_available(self, sid: SocketId) -> int:
        raise NotImplementedError("TCP arrives in M4")

    def tcp_shutdown_write(self, sid: SocketId) -> None:
        raise NotImplementedError("TCP arrives in M4")

    def tcp_abort(self, sid: SocketId) -> None:
        raise NotImplementedError("TCP arrives in M4")

    def tcp_close(self, sid: SocketId) -> None:
        raise NotImplementedError("TCP arrives in M4")

    # --- UDP ---------------------------------------------------------------

    def udp_open(self, local_port: int | None = None) -> SocketId:
        raise NotImplementedError("UDP arrives in M3")

    def udp_send_to(self, sid: SocketId, dst: tuple[str, int], data: bytes) -> None:
        raise NotImplementedError("UDP arrives in M3")

    def udp_recv_from(self, sid: SocketId) -> tuple[tuple[str, int], bytes] | None:
        raise NotImplementedError("UDP arrives in M3")

    def udp_close(self, sid: SocketId) -> None:
        raise NotImplementedError("UDP arrives in M3")

    # --- ICMP --------------------------------------------------------------

    def icmp_echo(self, dst: str, ident: int, seq: int, payload: bytes) -> None:
        raise NotImplementedError("ICMP arrives in M3")
