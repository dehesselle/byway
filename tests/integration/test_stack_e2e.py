"""The stack and driver end to end, over a virtual link.

No TLS, no gateway, no network -- but the real IPv4 codec, the real TCP state
machine, and the real asyncio driver, talking through the same
:class:`~pyac.cstp.link.IpLink` interface the CSTP tunnel presents.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

from pyac.errors import ConnectionRefused, ConnectionTimeout
from pyac.net.ipv4 import parse_ipv4
from pyac.net.tcp import Flag, parse_tcp
from pyac.runtime.driver import Driver
from tests.vnet import TcpPeer, VirtualLink
from tests.vnet.peer import http_handler

SERVER_IP = "10.221.188.32"
CLIENT_IP = "172.29.29.5"


def make(peer: TcpPeer, **link_kwargs: object) -> tuple[VirtualLink, Driver]:
    link = VirtualLink(peer, address=CLIENT_IP, **link_kwargs)  # type: ignore[arg-type]
    driver = Driver(link)
    driver.start()
    return link, driver


@pytest_asyncio.fixture
async def http() -> AsyncIterator[tuple[VirtualLink, Driver, TcpPeer]]:
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"hello from inside the vpn"))
    link, driver = make(peer)
    try:
        yield link, driver, peer
    finally:
        await driver.aclose()


# --- the milestone ---------------------------------------------------------


async def test_a_complete_http_request_and_response(
    http: tuple[VirtualLink, Driver, TcpPeer],
) -> None:
    """The thin slice's whole reason for existing."""
    _link, driver, _peer = http

    stream = await driver.connect(SERVER_IP, 80)
    await stream.write(b"GET / HTTP/1.1\r\nHost: internal\r\n\r\n")
    response = await stream.read_all()

    assert response.startswith(b"HTTP/1.1 200 OK")
    assert response.endswith(b"hello from inside the vpn")
    assert b"Content-Length: 25" in response


async def test_the_request_arrives_intact_at_the_peer(
    http: tuple[VirtualLink, Driver, TcpPeer],
) -> None:
    _link, driver, peer = http

    stream = await driver.connect(SERVER_IP, 80)
    await stream.write(b"GET /things HTTP/1.1\r\nHost: internal\r\n\r\n")
    await stream.read_all()

    (connection,) = peer.connections.values()
    assert bytes(connection.received) == b"GET /things HTTP/1.1\r\nHost: internal\r\n\r\n"


async def test_a_large_body_survives_segmentation(
    http: tuple[VirtualLink, Driver, TcpPeer],
) -> None:
    """Bigger than one MSS in both directions, so it must be split and rejoined."""
    body = bytes(range(256)) * 400  # 100 KB
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(body))
    _link, driver = make(peer)
    try:
        stream = await driver.connect(SERVER_IP, 80)
        await stream.write(b"GET /big HTTP/1.1\r\n" + b"X-Pad: " + b"p" * 4000 + b"\r\n\r\n")
        response = await stream.read_all()
    finally:
        await driver.aclose()

    assert response.split(b"\r\n\r\n", 1)[1] == body

    (connection,) = peer.connections.values()
    assert b"p" * 4000 in bytes(connection.received)


async def test_no_emitted_packet_exceeds_the_tunnel_mtu() -> None:
    """An oversized packet is the silent-hang failure mode; assert it directly."""
    oversized: list[int] = []
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"x" * 50_000))
    link = VirtualLink(
        peer,
        address=CLIENT_IP,
        mtu=1383,
        on_send=lambda packet: oversized.append(len(packet)) if len(packet) > 1383 else None,
    )
    driver = Driver(link)
    driver.start()
    try:
        stream = await driver.connect(SERVER_IP, 80)
        await stream.write(b"GET / HTTP/1.1\r\n" + b"X-Pad: " + b"q" * 20_000 + b"\r\n\r\n")
        await stream.read_all()
    finally:
        await driver.aclose()

    assert oversized == [], f"packets exceeded the {1383}-byte tunnel MTU: {oversized}"


# --- connection lifecycle --------------------------------------------------


async def test_connect_to_a_closed_port_times_out() -> None:
    """Nothing answers port 81, so the SYN goes unanswered."""
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b""))
    _link, driver = make(peer)
    try:
        with pytest.raises(ConnectionTimeout):
            await driver.connect(SERVER_IP, 81, timeout=1.5)
    finally:
        await driver.aclose()


async def test_peer_close_is_reported_as_end_of_stream(
    http: tuple[VirtualLink, Driver, TcpPeer],
) -> None:
    _link, driver, _peer = http

    stream = await driver.connect(SERVER_IP, 80)
    await stream.write(b"GET / HTTP/1.1\r\n\r\n")
    await stream.read_all()

    assert stream.eof
    assert await stream.read() == b""


async def test_sequential_connections_use_distinct_ports(
    http: tuple[VirtualLink, Driver, TcpPeer],
) -> None:
    _link, driver, peer = http

    for _ in range(3):
        stream = await driver.connect(SERVER_IP, 80)
        await stream.write(b"GET / HTTP/1.1\r\n\r\n")
        await stream.read_all()

    ports = {port for _ip, port in peer.connections}
    assert len(ports) == 3


async def test_concurrent_connections_are_demultiplexed() -> None:
    """Two sockets at once must not receive each other's data."""
    import asyncio

    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"shared body"))
    _link, driver = make(peer)
    try:

        async def fetch(path: bytes) -> bytes:
            stream = await driver.connect(SERVER_IP, 80)
            await stream.write(b"GET " + path + b" HTTP/1.1\r\n\r\n")
            return await stream.read_all()

        first, second = await asyncio.gather(fetch(b"/one"), fetch(b"/two"))
    finally:
        await driver.aclose()

    assert first.endswith(b"shared body")
    assert second.endswith(b"shared body")
    assert len(peer.connections) == 2


# --- resilience ------------------------------------------------------------


async def test_a_request_completes_despite_packet_loss() -> None:
    """Retransmission must carry the transfer through a lossy link."""
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"survived"))
    link = VirtualLink(peer, address=CLIENT_IP, loss=0.2, seed=7)
    driver = Driver(link)
    driver.start()
    try:
        stream = await driver.connect(SERVER_IP, 80, timeout=20)
        await stream.write(b"GET / HTTP/1.1\r\n\r\n")
        response = await stream.read_all()
    finally:
        await driver.aclose()

    assert response.endswith(b"survived")
    assert link.dropped_count > 0, "the test did not actually drop anything"


async def test_duplicate_packets_do_not_corrupt_the_stream() -> None:
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"exactly once"))
    link = VirtualLink(peer, address=CLIENT_IP, duplicate=0.5, seed=3)
    driver = Driver(link)
    driver.start()
    try:
        stream = await driver.connect(SERVER_IP, 80, timeout=20)
        await stream.write(b"GET / HTTP/1.1\r\n\r\n")
        response = await stream.read_all()
    finally:
        await driver.aclose()

    assert response.endswith(b"exactly once")
    (connection,) = peer.connections.values()
    # A duplicated request must not be delivered to the application twice.
    assert bytes(connection.received).count(b"GET /") == 1


async def test_tunnel_loss_fails_open_streams() -> None:
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=lambda _received: None)
    link, driver = make(peer)
    try:
        stream = await driver.connect(SERVER_IP, 80)
        link.close("gateway sent DISCONNECT")
        await stream.wait_closed()
    finally:
        await driver.aclose()

    assert stream.error is not None
    assert "DISCONNECT" in str(stream.error)


# --- what goes on the wire -------------------------------------------------


async def test_the_handshake_looks_like_tcp() -> None:
    captured: list[bytes] = []
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"ok"))
    link = VirtualLink(peer, address=CLIENT_IP, on_send=captured.append)
    driver = Driver(link)
    driver.start()
    try:
        stream = await driver.connect(SERVER_IP, 80)
        await stream.write(b"GET / HTTP/1.1\r\n\r\n")
        await stream.read_all()
        # Close explicitly: reading to EOF only means the *peer* has finished.
        stream.close()
        await stream.wait_closed()
    finally:
        await driver.aclose()

    segments = [parse_tcp(parse_ipv4(packet)[1]) for packet in captured]

    syn = segments[0]
    assert syn.flags == Flag.SYN
    assert syn.mss == 1383 - 40
    assert syn.destination_port == 80

    assert segments[1].flags & Flag.ACK
    assert any(s.flags & Flag.PSH for s in segments)
    assert any(s.flags & Flag.FIN for s in segments)


async def test_refused_connection_surfaces_as_connection_refused() -> None:
    """A peer that RSTs the SYN must fail fast, not wait out the timeout."""

    class RefusingPeer(TcpPeer):
        def handle(self, packet: bytes) -> list[bytes]:
            header, payload = parse_ipv4(packet)
            segment = parse_tcp(payload)
            if not segment.has(Flag.SYN):
                return []
            from pyac.net.ipv4 import PROTO_TCP, build_ipv4
            from pyac.net.tcp import build_tcp, seq_add

            reset = build_tcp(
                source_ip=self.ip,
                destination_ip=header.source,
                source_port=segment.destination_port,
                destination_port=segment.source_port,
                seq=0,
                ack=seq_add(segment.seq, 1),
                flags=Flag.RST | Flag.ACK,
                window=0,
            )
            return [
                build_ipv4(
                    source=self.ip,
                    destination=header.source,
                    protocol=PROTO_TCP,
                    payload=reset,
                )
            ]

    peer = RefusingPeer(ip=SERVER_IP, port=80, handler=http_handler(b""))
    _link, driver = make(peer)
    try:
        with pytest.raises(ConnectionRefused):
            await driver.connect(SERVER_IP, 80, timeout=5)
    finally:
        await driver.aclose()
