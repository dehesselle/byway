"""The SOCKS5 proxy, end to end.

A real client socket speaks RFC 1928 to the server, which opens a connection
through the userspace stack, across the CSTP tunnel, to a peer serving HTTP.
That is the whole path an ordinary tool takes, so what passes here is what
``curl --socks5`` will do.
"""

from __future__ import annotations

import asyncio
import struct
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
import pytest_asyncio
from usernet.runtime.driver import Driver
from usernet.socks import Socks5Server
from usernet.socks.protocol import (
    ATYP_DOMAIN,
    ATYP_IPV4,
    ATYP_IPV6,
    AUTH_NONE,
    AUTH_UNACCEPTABLE,
    AUTH_USERPASS,
    CMD_BIND,
    CMD_CONNECT,
    VERSION,
    Reply,
)
from usernet.testing.peer import TcpPeer, http_handler

from pyac.errors import NetworkError
from tests.fakegw import FakeGateway
from tests.fakegw.server import DEFAULT_TUNNEL_HEADERS
from tests.integration.test_tunnel import session_for

CLIENT_IP = "10.20.30.40"  # what DEFAULT_TUNNEL_HEADERS assigns
SERVER_IP = "10.11.12.13"  # inside the advertised 10.0.0.0/8
OUTSIDE_IP = "8.8.8.8"  # outside every advertised route

TUNNEL_HEADERS = [(n, v) for n, v in DEFAULT_TUNNEL_HEADERS if n != "X-CSTP-Banner"]


@pytest.fixture
def certs(tmp_path: Path) -> Path:
    return tmp_path


@asynccontextmanager
async def proxy_for(
    certs: Path,
    body: bytes = b"hello from inside",
    port: int = 80,
    **options: object,
) -> AsyncIterator[tuple[Socks5Server, TcpPeer]]:
    peer = TcpPeer(ip=SERVER_IP, port=port, handler=http_handler(body))
    async with (
        FakeGateway([], certs_dir=certs, peer=peer, tunnel_headers=TUNNEL_HEADERS) as gateway,
        session_for(gateway) as session,
    ):
        driver = Driver(session)
        driver.start()
        server = Socks5Server(driver, port=0, **options)  # type: ignore[arg-type]
        await server.start()
        try:
            yield server, peer
        finally:
            await server.aclose()
            await driver.aclose()


@pytest_asyncio.fixture
async def proxy(certs: Path) -> AsyncIterator[tuple[Socks5Server, TcpPeer]]:
    async with proxy_for(certs) as pair:
        yield pair


# --- a minimal SOCKS5 client, for tests only --------------------------------


async def greet(
    server: Socks5Server, methods: tuple[int, ...] = (AUTH_NONE,)
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, int]:
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    writer.write(bytes((VERSION, len(methods), *methods)))
    await writer.drain()
    _version, method = await reader.readexactly(2)
    return reader, writer, method


async def authenticate(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, user: str, password: str
) -> int:
    writer.write(
        bytes((0x01, len(user))) + user.encode() + bytes((len(password),)) + password.encode()
    )
    await writer.drain()
    _version, status = await reader.readexactly(2)
    return int(status)


async def request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str = SERVER_IP,
    port: int = 80,
    *,
    atyp: int = ATYP_IPV4,
    command: int = CMD_CONNECT,
) -> tuple[Reply, str, int]:
    if atyp == ATYP_IPV4:
        address = bytes(int(part) for part in host.split("."))
    elif atyp == ATYP_DOMAIN:
        address = bytes((len(host),)) + host.encode()
    else:
        address = bytes(16)
    writer.write(bytes((VERSION, command, 0x00, atyp)) + address + struct.pack("!H", port))
    await writer.drain()

    head = await reader.readexactly(4)
    body = await reader.readexactly(6)  # replies always carry an IPv4 BND.ADDR
    bound = ".".join(str(octet) for octet in body[:4])
    return Reply(head[1]), bound, struct.unpack("!H", body[4:6])[0]


async def fetch_through(
    server: Socks5Server, path: str = "/", host: str = SERVER_IP, port: int = 80
) -> bytes:
    reader, writer, _method = await greet(server)
    reply, _bound, _bound_port = await request(reader, writer, host, port)
    assert reply is Reply.SUCCESS, reply

    writer.write(f"GET {path} HTTP/1.1\r\nHost: internal\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    body = await reader.read(-1)
    writer.close()
    return body


# --- the milestone ----------------------------------------------------------


async def test_an_http_request_travels_through_the_proxy(
    proxy: tuple[Socks5Server, TcpPeer],
) -> None:
    """Exactly what `curl --socks5 127.0.0.1:1080 http://10.11.12.13/` does."""
    server, _peer = proxy
    response = await fetch_through(server)

    assert response.startswith(b"HTTP/1.1 200 OK")
    assert response.endswith(b"hello from inside")


async def test_the_request_reaches_the_server_intact(
    proxy: tuple[Socks5Server, TcpPeer],
) -> None:
    server, peer = proxy
    await fetch_through(server, path="/v1/things")

    (connection,) = peer.connections.values()
    assert bytes(connection.received).startswith(b"GET /v1/things HTTP/1.1\r\n")
    assert connection.remote_ip == CLIENT_IP


async def test_a_large_response_survives_the_relay(certs: Path) -> None:
    """Many segments in one direction, so both windows and drains matter."""
    body = b"".join(bytes([index % 251]) * 1000 for index in range(80))  # 80 KB
    async with proxy_for(certs, body=body) as (server, _peer):
        response = await fetch_through(server)

    assert response.split(b"\r\n\r\n", 1)[1] == body


async def test_concurrent_clients_are_independent(certs: Path) -> None:
    async with proxy_for(certs, body=b"shared") as (server, peer):
        first, second = await asyncio.gather(
            fetch_through(server, path="/one"), fetch_through(server, path="/two")
        )

    assert first.endswith(b"shared")
    assert second.endswith(b"shared")
    assert len(peer.connections) == 2
    assert server.connections == 2


async def test_the_reply_reports_the_tunnel_address(
    proxy: tuple[Socks5Server, TcpPeer],
) -> None:
    """BND.ADDR is informational, but reporting the tunnel address is what
    makes a proxy log line line up with a pcap."""
    server, _peer = proxy
    reader, writer, _method = await greet(server)
    reply, bound, bound_port = await request(reader, writer)
    writer.close()

    assert reply is Reply.SUCCESS
    assert bound == CLIENT_IP
    assert bound_port == 80


# --- refusals that clients can act on ---------------------------------------


async def test_an_address_outside_the_routes_is_not_allowed(
    proxy: tuple[Socks5Server, TcpPeer],
) -> None:
    server, _peer = proxy
    reader, writer, _method = await greet(server)
    reply, _bound, _port = await request(reader, writer, host=OUTSIDE_IP)
    writer.close()

    assert reply is Reply.NOT_ALLOWED
    assert server.rejected == 1


async def test_route_policy_all_bypasses_the_check(certs: Path) -> None:
    """The escape hatch for a gateway whose advertised routes are wrong."""
    async with proxy_for(certs, route_policy="all", connect_timeout=2.0) as (server, _peer):
        reader, writer, _method = await greet(server)
        reply, _bound, _port = await request(reader, writer, host=OUTSIDE_IP)
        writer.close()

    # The connection is attempted rather than refused -- and then nothing
    # answers, which is precisely what a real split-tunnel gateway does with an
    # out-of-scope packet. A timeout here rather than an instant NOT_ALLOWED is
    # the cost of the escape hatch, and the argument for the default policy.
    assert reply is Reply.TTL_EXPIRED


async def test_a_hostname_is_refused_because_there_is_no_resolver(
    proxy: tuple[Socks5Server, TcpPeer],
) -> None:
    """`--socks5-hostname` cannot work against a gateway advertising no DNS."""
    server, _peer = proxy
    reader, writer, _method = await greet(server)
    reply, _bound, _port = await request(reader, writer, host="api.internal", atyp=ATYP_DOMAIN)
    writer.close()

    assert reply is Reply.HOST_UNREACHABLE


async def test_an_address_sent_as_a_hostname_still_works(
    proxy: tuple[Socks5Server, TcpPeer],
) -> None:
    server, _peer = proxy
    reader, writer, _method = await greet(server)
    reply, _bound, _port = await request(reader, writer, host=SERVER_IP, atyp=ATYP_DOMAIN)
    writer.close()

    assert reply is Reply.SUCCESS


async def test_ipv6_is_refused(proxy: tuple[Socks5Server, TcpPeer]) -> None:
    server, _peer = proxy
    reader, writer, _method = await greet(server)
    reply, _bound, _port = await request(reader, writer, atyp=ATYP_IPV6)
    writer.close()

    assert reply is Reply.ADDRESS_TYPE_NOT_SUPPORTED


async def test_bind_is_refused(proxy: tuple[Socks5Server, TcpPeer]) -> None:
    """A client-only stack cannot accept inbound connections, and says so."""
    server, _peer = proxy
    reader, writer, _method = await greet(server)
    reply, _bound, _port = await request(reader, writer, command=CMD_BIND)
    writer.close()

    assert reply is Reply.COMMAND_NOT_SUPPORTED


async def test_a_dead_port_reports_a_timeout(certs: Path) -> None:
    async with proxy_for(certs, connect_timeout=1.0) as (server, _peer):
        reader, writer, _method = await greet(server)
        reply, _bound, _port = await request(reader, writer, port=81)
        writer.close()

    assert reply is Reply.TTL_EXPIRED


async def test_a_malformed_client_does_not_take_down_the_listener(
    proxy: tuple[Socks5Server, TcpPeer],
) -> None:
    """One bad client is one bad connection, not an outage."""
    server, _peer = proxy
    _reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    writer.write(b"\x04\x01\x00\x50GET / HTTP/1.0\r\n\r\n")  # SOCKS4, then nonsense
    await writer.drain()
    writer.close()

    assert (await fetch_through(server)).endswith(b"hello from inside")


# --- authentication ---------------------------------------------------------


async def test_credentials_are_accepted(certs: Path) -> None:
    async with proxy_for(certs, username="alice", password="hunter2") as (server, _peer):
        reader, writer, method = await greet(server, methods=(AUTH_NONE, AUTH_USERPASS))
        assert method == AUTH_USERPASS
        assert await authenticate(reader, writer, "alice", "hunter2") == 0

        reply, _bound, _port = await request(reader, writer)
        writer.close()

    assert reply is Reply.SUCCESS


async def test_a_wrong_password_is_refused(certs: Path) -> None:
    async with proxy_for(certs, username="alice", password="hunter2") as (server, _peer):
        reader, writer, _method = await greet(server, methods=(AUTH_USERPASS,))
        status = await authenticate(reader, writer, "alice", "wrong")
        writer.close()

    assert status == 1


async def test_no_auth_is_not_offered_when_credentials_are_set(certs: Path) -> None:
    """Otherwise the password is decorative: a client simply asks for no auth."""
    async with proxy_for(certs, username="alice", password="hunter2") as (server, _peer):
        _reader, writer, method = await greet(server, methods=(AUTH_NONE,))
        writer.close()

    assert method == AUTH_UNACCEPTABLE


# --- binding ----------------------------------------------------------------


async def test_a_non_loopback_bind_is_refused_by_default(certs: Path) -> None:
    """The listener is an unauthenticated way into the corporate network."""
    async with proxy_for(certs) as (server, _peer):
        driver = server._driver
        with pytest.raises(NetworkError, match="refusing to bind"):
            Socks5Server(driver, host="0.0.0.0", port=0)

        # ...but it is a policy, not an impossibility.
        Socks5Server(driver, host="0.0.0.0", port=0, allow_non_loopback=True)
