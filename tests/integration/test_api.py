"""The public API, end to end against the fake gateway.

``pyac.connect`` is the whole product in one call: authenticate, open the
tunnel, hand back something that behaves like a socket, and release the session
on the way out. That last part is the one worth testing hardest -- a leaked
session eventually locks a user out of their own VPN, and nothing about the
symptom points at the cause.

The transport contract itself is covered in tests/unit/test_transport.py
against a fake stream; here the stream is the real stack over a real tunnel.
"""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from usernet.runtime.driver import Driver
from usernet.testing.peer import TcpPeer, http_handler

import pyac
from pyac.api import VpnClient
from pyac.config import GatewayConfig
from pyac.cstp.link import ReconnectingLink
from pyac.cstp.session import CstpSession
from pyac.errors import NetworkError, PyacError
from tests.fakegw import FakeGateway
from tests.fakegw.server import DEFAULT_TUNNEL_HEADERS
from tests.integration.test_get import auth_exchange

SERVER_IP = "10.11.12.13"
TUNNEL_HEADERS = [(n, v) for n, v in DEFAULT_TUNNEL_HEADERS if n != "X-CSTP-Banner"]


@pytest.fixture
def certs(tmp_path: Path) -> Path:
    return tmp_path


@asynccontextmanager
async def client_for(gateway: FakeGateway) -> AsyncIterator[VpnClient]:
    """A VpnClient over the fake gateway, without going through auth.

    ``connect`` covers the authenticated path; this covers everything above it,
    and keeps the majority of the tests free of credential handling.
    """
    context = ssl.create_default_context(cafile=gateway.ca_path)

    async def open_session() -> CstpSession:
        session = CstpSession(
            host="127.0.0.1",
            port=gateway.port,
            session_token="TESTTOKEN",
            ssl_context=context,
            user_agent="AnyConnect Windows 4.10.07061",
            local_hostname="testhost",
        )
        await session.connect()
        return session

    link = ReconnectingLink(open_session, reconnect=False)
    await link.start()
    driver = Driver(link)
    driver.start()
    client = VpnClient(link, driver)
    try:
        yield client
    finally:
        await client.aclose()


def serving(body: bytes, certs: Path, port: int = 80) -> FakeGateway:
    peer = TcpPeer(ip=SERVER_IP, port=port, handler=http_handler(body))
    return FakeGateway([], certs_dir=certs, peer=peer, tunnel_headers=TUNNEL_HEADERS)


# --- the streams ------------------------------------------------------------


async def test_open_connection_returns_a_usable_stdlib_pair(certs: Path) -> None:
    """The point of the whole transport bridge: code written against
    ``asyncio.open_connection`` works without knowing pyac exists."""
    async with serving(b"through the tunnel", certs) as gateway, client_for(gateway) as vpn:
        reader, writer = await vpn.open_connection(SERVER_IP, 80, timeout=10)

        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        status = await asyncio.wait_for(reader.readline(), timeout=10)
        body = await asyncio.wait_for(reader.read(), timeout=10)

        assert status.startswith(b"HTTP/1.1 200")
        assert body.endswith(b"through the tunnel")
        writer.close()


async def test_readuntil_works_which_means_the_reader_is_genuine(certs: Path) -> None:
    """``readuntil`` exercises StreamReader's own buffering against our
    transport, which is where a half-implemented bridge falls apart."""
    async with serving(b"body-here", certs) as gateway, client_for(gateway) as vpn:
        reader, writer = await vpn.open_connection(SERVER_IP, 80, timeout=10)
        writer.write(b"GET / HTTP/1.1\r\n\r\n")
        await writer.drain()

        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        assert head.endswith(b"\r\n\r\n")
        assert b"content-length" in head.lower()
        writer.close()


async def test_an_unreachable_port_raises_rather_than_hanging(certs: Path) -> None:
    """The fake peer drops packets for ports it does not serve, as a filtered
    port does; a real kernel's RST is covered by the conformance suite, which
    has an actual TCP stack to refuse with."""
    async with serving(b"x", certs) as gateway, client_for(gateway) as vpn:
        with pytest.raises(NetworkError):
            await vpn.open_connection(SERVER_IP, 9999, timeout=2)


async def test_open_stream_skips_the_asyncio_machinery(certs: Path) -> None:
    async with serving(b"raw", certs) as gateway, client_for(gateway) as vpn:
        stream = await vpn.open_stream(SERVER_IP, 80, timeout=10)
        await stream.write(b"GET / HTTP/1.1\r\n\r\n")
        assert (await stream.read_all()).endswith(b"raw")


# --- what the gateway told us ------------------------------------------------


async def test_tunnel_configuration_is_exposed(certs: Path) -> None:
    async with serving(b"x", certs) as gateway, client_for(gateway) as vpn:
        assert vpn.tunnel.address == "10.20.30.40"
        assert vpn.tunnel.mtu == 1406


async def test_route_scope_can_be_checked_before_connecting(certs: Path) -> None:
    """Better than a connect timeout: a split-tunnel gateway drops out-of-scope
    packets silently, so asking first is the only way to get a reason."""
    async with serving(b"x", certs) as gateway, client_for(gateway) as vpn:
        assert vpn.reaches(SERVER_IP)
        assert not vpn.reaches("8.8.8.8")
        assert "10.0.0.0" in vpn.routes


# --- http --------------------------------------------------------------------


async def test_httpx_client_reaches_inside_the_tunnel(certs: Path) -> None:
    async with serving(b"json-ish", certs) as gateway, client_for(gateway) as vpn:
        async with vpn.httpx_client() as http:
            response = await http.get(f"http://{SERVER_IP}/things", timeout=10)

        assert response.status_code == 200
        assert response.content.endswith(b"json-ish")


# --- the proxy ---------------------------------------------------------------


async def test_serve_socks5_binds_loopback_and_closes_with_the_client(certs: Path) -> None:
    async with serving(b"via socks", certs) as gateway:
        async with client_for(gateway) as vpn:
            proxy = await vpn.serve_socks5(port=0)
            assert proxy.address.startswith("127.0.0.1:")
            port = proxy.port
        # aclose() on the client must take the listener with it, or a caller
        # that forgot leaves an unauthenticated hole into the VPN behind.
        with pytest.raises(OSError):
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()


# --- names --------------------------------------------------------------------


async def test_resolve_refuses_rather_than_using_the_host_resolver(certs: Path) -> None:
    """Silently resolving through the machine's DNS would leak internal names
    outside the VPN and return the wrong answers -- worse than not offering it."""
    async with serving(b"x", certs) as gateway, client_for(gateway) as vpn:
        with pytest.raises(PyacError, match="no in-tunnel resolver"):
            await vpn.resolve("intranet.corp")


# --- the authenticated path ---------------------------------------------------


async def test_connect_authenticates_opens_and_logs_out(certs: Path) -> None:
    """The full public entry point, including the logout that keeps a user from
    exhausting their own gateway's session limit."""
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"end to end"))
    async with FakeGateway(
        auth_exchange(), certs_dir=certs, peer=peer, tunnel_headers=TUNNEL_HEADERS
    ) as gateway:
        config = GatewayConfig(
            host="127.0.0.1", port=gateway.port, verify=gateway.ca_path, user_agent="test"
        )
        async with pyac.connect(config, "rene", "secret") as vpn:
            assert vpn.tunnel.address == "10.20.30.40"
            reader, writer = await vpn.open_connection(SERVER_IP, 80, timeout=10)
            writer.write(b"GET / HTTP/1.1\r\n\r\n")
            await writer.drain()
            assert (await asyncio.wait_for(reader.read(), timeout=10)).endswith(b"end to end")
            writer.close()

    targets = [request.target for request in gateway.requests]
    assert any("logout" in target for target in targets), (
        f"the session was never released; gateway saw {targets}"
    )


async def test_connect_logs_out_even_when_the_body_raises(certs: Path) -> None:
    """The case that leaks sessions in practice is the one that went wrong."""
    async with FakeGateway(
        auth_exchange(), certs_dir=certs, tunnel_headers=TUNNEL_HEADERS
    ) as gateway:
        config = GatewayConfig(
            host="127.0.0.1", port=gateway.port, verify=gateway.ca_path, user_agent="test"
        )
        with pytest.raises(RuntimeError, match="boom"):
            async with pyac.connect(config, "rene", "secret"):
                raise RuntimeError("boom")

    assert any("logout" in request.target for request in gateway.requests)


# --- the package surface ------------------------------------------------------


def test_the_package_exports_what_the_readme_promises() -> None:
    """Lazily, so that `import pyac` does not drag in httpx and the whole stack
    for a program that only wanted the version."""
    assert pyac.__version__
    for name in ("connect", "VpnClient", "GatewayConfig", "Credentials", "TunnelConfig"):
        assert getattr(pyac, name) is not None

    with pytest.raises(AttributeError):
        _ = pyac.does_not_exist  # type: ignore[attr-defined]


def test_importing_the_package_pulls_in_nothing_heavy() -> None:
    """`import pyac` must stay cheap for a program that only wants the version;
    a lazy __getattr__ that quietly stopped being lazy would go unnoticed."""
    import subprocess
    import sys

    probe = (
        "import sys, pyac; "
        "print(pyac.__version__); "
        "assert 'httpx' not in sys.modules, 'httpx imported eagerly'; "
        "assert 'usernet.net.tcb' not in sys.modules, 'the stack imported eagerly'"
    )
    done = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
