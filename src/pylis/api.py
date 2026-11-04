# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The in-process API: a VPN scoped to one Python program.

    async with pylis.connect("vpn.corp.example", user, password) as vpn:
        reader, writer = await vpn.open_connection("10.0.0.5", 22)
        async with vpn.httpx_client() as http:
            response = await http.get("http://10.0.0.9/v1/things")

Everything here is a thin arrangement of parts that already exist -- auth, the
reconnecting link, the driver, the transport bridge -- so this module carries
no protocol logic of its own. That is deliberate: the CLI and the API run the
same code, and neither is a reimplementation of the other.

**Addresses, or names from a fixed table.** There is no in-tunnel DNS, so a
host argument is an IPv4 address or a name from the ``hosts`` table given to
:func:`connect`. See ``resolve`` below for why a method that quietly used the
host's DNS would be worse than none.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import AsyncIterator, Mapping
from typing import Any

import httpx
from usernet.http import TunnelTransport, httpx_client, httpx_transport
from usernet.resolve import StaticResolver
from usernet.routing import describe_routes, route_allows
from usernet.runtime.driver import Driver, TcpStream
from usernet.runtime.tls import wrap as wrap_tls
from usernet.runtime.transport import wrap_stream
from usernet.socks import Socks5Server

from pylis.auth.client import authenticate, build_ssl_context, logout
from pylis.config import DEFAULT_USER_AGENT, Credentials, GatewayConfig
from pylis.cstp.config import TunnelConfig
from pylis.cstp.link import ReconnectingLink
from pylis.cstp.session import CstpSession

__all__ = [
    "Credentials",
    "GatewayConfig",
    "TunnelConfig",
    "VpnClient",
    "connect",
]

DEFAULT_MTU = 1406


class VpnClient:
    """A live tunnel, and the ways to send traffic through it.

    Build one with :func:`connect` rather than directly; the constructor takes
    an already-authenticated link because separating those two makes the class
    testable against the fake gateway without any credentials in play.
    """

    def __init__(self, link: ReconnectingLink, driver: Driver) -> None:
        self._link = link
        self._driver = driver
        self._proxies: list[Socks5Server] = []

    # --- what the gateway told us ------------------------------------------

    @property
    def tunnel(self) -> TunnelConfig:
        """Address, netmask, MTU, routes, timeouts, banner."""
        return self._link.config

    @property
    def driver(self) -> Driver:
        """The stack driver, for anything this API does not wrap."""
        return self._driver

    def reaches(self, host: str) -> bool:
        """Whether ``host`` is inside the gateway's split-tunnel scope.

        Worth asking before connecting: a split-tunnel gateway discards
        out-of-scope packets in silence, so the alternative to this check is a
        connect timeout that names no cause.
        """
        return route_allows(self.tunnel, host)

    @property
    def routes(self) -> str:
        return describe_routes(self.tunnel)

    # --- streams ------------------------------------------------------------

    async def open_connection(
        self,
        host: str,
        port: int,
        *,
        timeout: float = 30.0,  # noqa: ASYNC109 - a failed connect must abort the socket
        limit: int = 65536,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """A stdlib reader/writer pair, indistinguishable from a real socket's.

        Which is the point: ``asyncssh``, ``asyncpg`` and anything else written
        against ``asyncio.open_connection`` work unchanged, including flow
        control -- the reader's high-water mark closes our receive window.
        """
        stream = await self._driver.connect(host, port, timeout=timeout)
        return await wrap_stream(stream, peername=(host, port), limit=limit)

    async def open_tls_connection(
        self,
        host: str,
        port: int,
        *,
        ssl_context: ssl.SSLContext | None = None,
        server_hostname: str | None = None,
        timeout: float = 30.0,  # noqa: ASYNC109 - a failed connect must abort the socket
        limit: int = 65536,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """The same, with TLS negotiated inside the tunnel.

        Connecting by a name from the ``hosts`` table checks the certificate
        against that name. Connecting by address needs ``server_hostname``:
        certificates are issued for names, so verification fails on a mismatch
        unless you say which name to expect.

        This trust decision has nothing to do with the gateway's certificate;
        the two are deliberately separate.
        """
        stream = await self._driver.connect(host, port, timeout=timeout)
        context = ssl_context or ssl.create_default_context()
        tls = await wrap_tls(stream, context, server_hostname=server_hostname or host)
        return await wrap_stream(tls, peername=(host, port), limit=limit)

    async def open_stream(
        self,
        host: str,
        port: int,
        *,
        timeout: float = 30.0,  # noqa: ASYNC109 - as above
    ) -> TcpStream:
        """The raw stream, without the asyncio machinery.

        Lower overhead and a smaller surface; use it when nothing needs a
        ``StreamReader``.
        """
        return await self._driver.connect(host, port, timeout=timeout)

    # --- other traffic ------------------------------------------------------

    async def ping(
        self,
        host: str,
        *,
        count: int = 4,
        timeout: float = 2.0,  # noqa: ASYNC109 - the timeout is the result
        interval: float = 1.0,
    ) -> list[float | None]:
        """ICMP echo. ``None`` for a probe that went unanswered.

        A lost echo is an ordinary outcome rather than an error, which is why
        this returns ``None`` entries instead of raising.
        """
        results: list[float | None] = []
        for sequence in range(1, count + 1):
            results.append(await self._driver.ping(host, sequence, timeout=timeout))
            if sequence != count:
                await asyncio.sleep(interval)
        return results

    async def resolve(self, name: str) -> list[str]:
        """The address for ``name`` from the ``hosts`` table, and nothing else.

        There is no in-tunnel DNS: the gateways seen so far advertise no DNS
        servers, so there is nothing to ask. Falling back to the host's
        resolver would leak internal hostnames to whatever DNS the machine
        happens to use, and would resolve them to the wrong answers besides.
        A name missing from the table raises :class:`~pylis.errors.ResolveError`.
        """
        return [await self._driver.resolve(name)]

    # --- HTTP ----------------------------------------------------------------

    def httpx_transport(self, **kwargs: Any) -> TunnelTransport:
        """An httpx transport whose connections all run through the tunnel."""
        return httpx_transport(self._driver, **kwargs)

    def httpx_client(self, **kwargs: Any) -> httpx.AsyncClient:
        """An ``httpx.AsyncClient`` that reaches only inside the VPN."""
        return httpx_client(self._driver, **kwargs)

    # --- the proxy ----------------------------------------------------------

    async def serve_socks5(
        self,
        host: str = "127.0.0.1",
        port: int = 1080,
        *,
        username: str | None = None,
        password: str | None = None,
        allow_non_loopback: bool = False,
        route_policy: str = "auto",
    ) -> Socks5Server:
        """Expose the tunnel to other processes over SOCKS5.

        Loopback by default, and non-loopback requires saying so: an
        unauthenticated proxy on a routable address is an open door into the
        corporate network for anything that can reach the machine.
        """
        proxy = Socks5Server(
            self._driver,
            host=host,
            port=port,
            username=username,
            password=password,
            allow_non_loopback=allow_non_loopback,
            route_policy=route_policy,
        )
        await proxy.start()
        self._proxies.append(proxy)
        return proxy

    # --- lifecycle ----------------------------------------------------------

    @property
    def closed(self) -> asyncio.Event:
        """Set when the tunnel has ended for good; :attr:`close_reason` says why."""
        return self._link.closed

    @property
    def close_reason(self) -> str:
        return self._link.close_reason

    async def wait_closed(self) -> None:
        await self._link.closed.wait()

    async def aclose(self) -> None:
        for proxy in self._proxies:
            with contextlib.suppress(Exception):
                await proxy.aclose()
        self._proxies.clear()
        await self._driver.aclose()
        await self._link.aclose()


@contextlib.asynccontextmanager
async def connect(
    gateway: str | GatewayConfig,
    username: str,
    password: str,
    *,
    group: str | None = None,
    port: int = 443,
    verify: bool | str | ssl.SSLContext = True,
    server_cert_pin: str | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    mtu: int = DEFAULT_MTU,
    buffer: int | None = None,
    reconnect: bool = True,
    hosts: Mapping[str, str] | None = None,
) -> AsyncIterator[VpnClient]:
    """Authenticate, bring the tunnel up, and tear it down again afterwards.

    The teardown matters as much as the setup: gateways enforce
    concurrent-session limits, and a leaked session eventually locks the user
    out of their own VPN with nothing to point at. Leaving here always posts
    the logout, whatever went wrong.

    ``buffer`` is the per-socket send and receive buffer in bytes. One
    connection cannot exceed ``buffer / RTT``, so a distant gateway is the
    reason to raise it.

    ``hosts`` maps names to addresses inside the tunnel, like ``/etc/hosts``
    for this one connection: ``{"node-1.orka": "10.221.188.11"}``. Every
    method taking a host, and the SOCKS proxy, resolves names from it and
    refuses the rest. Raises :class:`ValueError` for a malformed table, before
    authenticating.
    """
    resolver = StaticResolver(hosts or {}, source="the hosts table given to pylis.connect()")
    config = (
        gateway
        if isinstance(gateway, GatewayConfig)
        else GatewayConfig(
            host=gateway,
            port=port,
            verify=verify,
            server_cert_pin=server_cert_pin,
            user_agent=user_agent,
        )
    )
    success = await authenticate(
        config, Credentials(username=username, password=password, group=group)
    )

    async def open_session() -> CstpSession:
        # The same cookie every time, never a fresh login: re-authenticating
        # per reconnect would burn the gateway's session limit, and a
        # background task must never prompt for a password.
        session = CstpSession(
            host=config.host,
            port=config.port,
            session_token=success.session_token,
            ssl_context=build_ssl_context(config),
            user_agent=config.user_agent,
            mtu=mtu,
        )
        await session.connect()
        return session

    link = ReconnectingLink(open_session, reconnect=reconnect)
    await link.start()
    driver = Driver(link, buffer=buffer, resolver=resolver)
    driver.start()
    client = VpnClient(link, driver)
    try:
        yield client
    finally:
        await client.aclose()
        with contextlib.suppress(Exception):
            await logout(config, success.session_token)
