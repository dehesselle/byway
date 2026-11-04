# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""A blocking facade over :mod:`pylis.api`, for callers that cannot use asyncio.

    with pylis.connect_sync("vpn.corp.example", user, password) as vpn:
        response = vpn.get("http://10.0.0.9/v1/things")

    # or, when the VPN outlives any one block:
    vpn = pylis.SyncVpnClient.connect("vpn.corp.example", user, password)
    ...
    vpn.close()

pylis's core -- the driver, the in-process TCP/IP stack, the CSTP session -- is
asyncio throughout, so there is no protocol logic to duplicate here, only a
bridge: a dedicated background thread runs one event loop for the life of the
connection, and every :class:`SyncVpnClient` call is a coroutine submitted to
that loop with ``run_coroutine_threadsafe``, blocked on until it returns.
Exceptions cross the bridge unchanged -- ``Future.result()`` re-raises
whatever the coroutine raised, in the calling thread.

Scope is HTTP only. Raw streams and ``serve_socks5`` stay async-only; use
:func:`pylis.connect` for those.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import threading
from collections.abc import Coroutine, Iterator, Mapping
from typing import Any, TypeVar

import httpx

from pylis.api import connect as _connect_async
from pylis.config import GatewayConfig
from pylis.errors import PylisError

__all__ = ["SyncVpnClient", "connect_sync"]

_T = TypeVar("_T")


class _LoopThread:
    """One event loop, one background thread, for the life of a connection."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True, name="pylis-sync")
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def run(self, coro: Coroutine[Any, Any, _T]) -> _T:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    def stop(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join()
        self._loop.close()


class SyncVpnClient:
    """A blocking way to call REST APIs inside the tunnel.

    Build one with :meth:`connect` for a VPN that outlives any single block,
    or with the :func:`connect_sync` context manager for the common case of
    one connect/use/disconnect scope. Both share the same teardown, in
    :meth:`close`: never construct this directly.
    """

    def __init__(
        self,
        loop: _LoopThread,
        manager: contextlib.AbstractAsyncContextManager[Any],
        http: httpx.AsyncClient,
    ) -> None:
        self._loop = loop
        self._manager = manager
        self._http = http
        self._closed = False

    @classmethod
    def connect(
        cls,
        gateway: str | GatewayConfig,
        username: str,
        password: str,
        *,
        group: str | None = None,
        port: int = 443,
        verify: bool | str | ssl.SSLContext = True,
        server_cert_pin: str | None = None,
        mtu: int = 1406,
        buffer: int | None = None,
        reconnect: bool = True,
        hosts: Mapping[str, str] | None = None,
    ) -> SyncVpnClient:
        """Authenticate and bring the tunnel up, without a ``with`` block.

        Use this when the VPN is used from many places in the code rather
        than scoped to one block -- a long-running service that connects at
        startup and disconnects at shutdown, say. Whatever holds the
        returned client is responsible for calling :meth:`close` exactly
        once; nothing here closes it for you, including garbage collection.
        """
        loop = _LoopThread()
        try:
            manager = _connect_async(
                gateway,
                username,
                password,
                group=group,
                port=port,
                verify=verify,
                server_cert_pin=server_cert_pin,
                mtu=mtu,
                buffer=buffer,
                reconnect=reconnect,
                hosts=hosts,
            )
            vpn = loop.run(manager.__aenter__())
            http = vpn.httpx_client()
            loop.run(http.__aenter__())
        except BaseException:
            loop.stop()
            raise
        return cls(loop, manager, http)

    def close(self) -> None:
        """Tear the tunnel down and post the logout. Safe to call more than once.

        Leaked sessions are the failure mode this whole bridge exists to
        avoid: a gateway enforces concurrent-session limits, and a session
        that never logs out eventually locks the user out of their own VPN.
        """
        if self._closed:
            return
        self._closed = True
        try:
            self._loop.run(self._http.__aexit__(None, None, None))
        finally:
            try:
                self._loop.run(self._manager.__aexit__(None, None, None))
            finally:
                self._loop.stop()

    def __enter__(self) -> SyncVpnClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        if self._closed:
            raise PylisError("this SyncVpnClient is closed")
        return self._loop.run(self._http.request(method, url, **kwargs))

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("HEAD", url, **kwargs)


@contextlib.contextmanager
def connect_sync(
    gateway: str | GatewayConfig,
    username: str,
    password: str,
    *,
    group: str | None = None,
    port: int = 443,
    verify: bool | str | ssl.SSLContext = True,
    server_cert_pin: str | None = None,
    mtu: int = 1406,
    buffer: int | None = None,
    reconnect: bool = True,
    hosts: Mapping[str, str] | None = None,
) -> Iterator[SyncVpnClient]:
    """Blocking equivalent of :func:`pylis.connect`, scoped to HTTP.

    For the common case: connect, use, disconnect, all in one block. Closes
    on exit even if the block raises -- the same guarantee :func:`pylis.connect`
    makes. For a VPN that outlives one block, use :meth:`SyncVpnClient.connect`
    directly and call :meth:`~SyncVpnClient.close` yourself when done.
    """
    vpn = SyncVpnClient.connect(
        gateway,
        username,
        password,
        group=group,
        port=port,
        verify=verify,
        server_cert_pin=server_cert_pin,
        mtu=mtu,
        buffer=buffer,
        reconnect=reconnect,
        hosts=hosts,
    )
    try:
        yield vpn
    finally:
        vpn.close()
