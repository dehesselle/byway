# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""pylis.connect_sync, end to end against the fake gateway.

Mirrors the authenticated-path tests in test_api.py, but proves the sync
facade needs no asyncio in the calling code: ``connect_sync()`` and
``SyncVpnClient.get()`` are plain, blocking calls with no ``await``. Each
test drives them via ``asyncio.to_thread`` from an ``async def`` test
function -- not because the sync API needs an event loop, but because the
fake gateway's own listener runs on *this* test's loop, and connect_sync
deliberately blocks whatever thread calls it. Running the blocking call on a
worker thread keeps the gateway's loop free to accept and serve the CSTP
connection connect_sync's background thread makes.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
from usernet.testing.peer import TcpPeer, http_handler

import pylis
from pylis.config import GatewayConfig
from pylis.errors import PylisError
from tests.fakegw import FakeGateway
from tests.fakegw.server import DEFAULT_TUNNEL_HEADERS
from tests.integration.test_http import auth_exchange

SERVER_IP = "10.11.12.13"
TUNNEL_HEADERS = [(n, v) for n, v in DEFAULT_TUNNEL_HEADERS if n != "X-CSTP-Banner"]


@pytest.fixture
def certs(tmp_path: Path) -> Path:
    return tmp_path


async def test_connect_sync_authenticates_gets_and_logs_out(certs: Path) -> None:
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"end to end"))
    async with FakeGateway(
        auth_exchange(), certs_dir=certs, peer=peer, tunnel_headers=TUNNEL_HEADERS
    ) as gateway:
        config = GatewayConfig(
            host="127.0.0.1", port=gateway.port, verify=gateway.ca_path, user_agent="test"
        )

        def blocking() -> httpx.Response:
            with pylis.connect_sync(config, "rene", "secret") as vpn:
                return vpn.get(f"http://{SERVER_IP}/things", timeout=10)

        response = await asyncio.to_thread(blocking)

    assert response.status_code == 200
    assert response.content.endswith(b"end to end")
    assert any("logout" in request.target for request in gateway.requests)


async def test_connect_sync_logs_out_even_when_the_body_raises(certs: Path) -> None:
    """The case that leaks sessions in practice is the one that went wrong."""
    async with FakeGateway(
        auth_exchange(), certs_dir=certs, tunnel_headers=TUNNEL_HEADERS
    ) as gateway:
        config = GatewayConfig(
            host="127.0.0.1", port=gateway.port, verify=gateway.ca_path, user_agent="test"
        )

        def blocking() -> None:
            with pylis.connect_sync(config, "rene", "secret"):
                raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            await asyncio.to_thread(blocking)

    assert any("logout" in request.target for request in gateway.requests)


async def test_sync_vpn_client_connect_works_without_a_with_block(certs: Path) -> None:
    """The lifecycle for callers that use the VPN from many places in their
    code, not one scoped block: connect now, close whenever."""
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"still here"))
    async with FakeGateway(
        auth_exchange(), certs_dir=certs, peer=peer, tunnel_headers=TUNNEL_HEADERS
    ) as gateway:
        config = GatewayConfig(
            host="127.0.0.1", port=gateway.port, verify=gateway.ca_path, user_agent="test"
        )

        def blocking() -> httpx.Response:
            vpn = pylis.SyncVpnClient.connect(config, "rene", "secret")
            try:
                return vpn.get(f"http://{SERVER_IP}/things", timeout=10)
            finally:
                vpn.close()

        response = await asyncio.to_thread(blocking)

    assert response.status_code == 200
    assert response.content.endswith(b"still here")
    assert any("logout" in request.target for request in gateway.requests)


async def test_closed_sync_vpn_client_refuses_further_calls(certs: Path) -> None:
    async with FakeGateway(
        auth_exchange(), certs_dir=certs, tunnel_headers=TUNNEL_HEADERS
    ) as gateway:
        config = GatewayConfig(
            host="127.0.0.1", port=gateway.port, verify=gateway.ca_path, user_agent="test"
        )

        def blocking() -> None:
            vpn = pylis.SyncVpnClient.connect(config, "rene", "secret")
            vpn.close()
            vpn.close()  # idempotent -- must not raise or hang
            with pytest.raises(PylisError, match="closed"):
                vpn.get("http://10.11.12.13/things")

        await asyncio.to_thread(blocking)
