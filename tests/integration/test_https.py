# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""HTTPS through the tunnel: the M7 milestone, end to end.

Auth, CSTP, framing, the userspace IPv4 stack, TCP, a real TLS session
terminated by real OpenSSL on the far side, and httpx driving all of it. The
two halves are each proven elsewhere -- ``test_tls.py`` for the MemoryBIO
wrapper, ``test_http.py`` for httpx over the tunnel -- so what this file is for
is the composition, which is where glue bugs live.
"""

from __future__ import annotations

import argparse
import json
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import trustme
from usernet.http import TunnelTransport
from usernet.runtime.driver import Driver
from usernet.testing.peer import TcpPeer
from usernet.testing.tls_endpoint import TlsHttpEndpoint

from byway.cli.cmd_http import Target, _run
from byway.config import Credentials, GatewayConfig
from tests.fakegw import FakeGateway
from tests.fakegw.server import DEFAULT_TUNNEL_HEADERS
from tests.integration.test_http import auth_exchange
from tests.integration.test_tunnel import session_for

SERVER_IP = "10.11.12.13"
SERVER_NAME = "api.internal"
TUNNEL_HEADERS = [(n, v) for n, v in DEFAULT_TUNNEL_HEADERS if n != "X-CSTP-Banner"]


@pytest.fixture
def certs(tmp_path: Path) -> Path:
    return tmp_path


class Endpoint:
    """A certificate plus the peer that serves it, behind the tunnel."""

    def __init__(self, certs: Path, body: bytes, hostname: str = SERVER_NAME) -> None:
        ca = trustme.CA()
        cert = ca.issue_cert(hostname)
        self.ca_path = certs / "ca.pem"
        ca.cert_pem.write_to_path(self.ca_path)
        self.chain = certs / "server.pem"
        cert.private_key_and_cert_chain_pem.write_to_path(self.chain)

        self.body = body
        self.endpoints: list[TlsHttpEndpoint] = []
        self.peer = TcpPeer(
            ip=SERVER_IP,
            port=443,
            handler=lambda _received: None,
            stream_factory=self._make,
        )

    def _make(self) -> TlsHttpEndpoint:
        made = TlsHttpEndpoint(self.chain, self.body)
        self.endpoints.append(made)
        return made

    def trusting(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=str(self.ca_path))


def endpoint(certs: Path, body: bytes = b'{"status":"ok"}') -> Endpoint:
    return Endpoint(certs, body)


@asynccontextmanager
async def tunnel_to(endpoint: Endpoint, certs: Path) -> AsyncIterator[Driver]:
    async with (
        FakeGateway(
            [], certs_dir=certs / "gw", peer=endpoint.peer, tunnel_headers=TUNNEL_HEADERS
        ) as gateway,
        session_for(gateway) as session,
    ):
        driver = Driver(session)
        driver.start()
        try:
            yield driver
        finally:
            await driver.aclose()


@pytest.fixture
def gw_certs(tmp_path: Path) -> Path:
    (tmp_path / "gw").mkdir()
    return tmp_path


# --- the milestone ----------------------------------------------------------


async def test_an_https_request_completes_through_the_tunnel(gw_certs: Path) -> None:
    """The other half of the original goal: an authenticated REST call."""
    api = endpoint(gw_certs, b'{"vms":[]}')
    async with tunnel_to(api, gw_certs) as driver:
        transport = TunnelTransport(driver, verify=api.trusting())
        async with httpx.AsyncClient(transport=transport) as client:
            response = await client.get(
                f"https://{SERVER_IP}/v1/vms",
                headers={"Host": SERVER_NAME},
                extensions={"sni_hostname": SERVER_NAME},
            )

    assert response.status_code == 200
    assert response.json() == {"vms": []}


async def test_the_request_arrives_decrypted_at_the_far_side(gw_certs: Path) -> None:
    api = endpoint(gw_certs)
    async with tunnel_to(api, gw_certs) as driver:
        transport = TunnelTransport(driver, verify=api.trusting())
        async with httpx.AsyncClient(transport=transport) as client:
            await client.get(
                f"https://{SERVER_IP}/v1/things",
                headers={"Host": SERVER_NAME, "X-Token": "secret-value"},
                extensions={"sni_hostname": SERVER_NAME},
            )

    (served,) = api.endpoints
    (request,) = served.requests
    assert request.startswith(b"GET /v1/things HTTP/1.1\r\n")
    assert b"x-token: secret-value" in request.lower()


async def test_a_body_spanning_many_tls_records_arrives_whole(gw_certs: Path) -> None:
    """Bigger than a TLS record and far bigger than the tunnel MTU, so both
    the record layer and TCP segmentation are in play."""
    body = (b"0123456789abcdef" * 64 + b"\n") * 60  # ~62 KB
    api = endpoint(gw_certs, body)
    async with tunnel_to(api, gw_certs) as driver:
        transport = TunnelTransport(driver, verify=api.trusting())
        async with httpx.AsyncClient(transport=transport) as client:
            response = await client.get(
                f"https://{SERVER_IP}/big",
                headers={"Host": SERVER_NAME},
                extensions={"sni_hostname": SERVER_NAME},
            )

    assert response.content == body


async def test_keep_alive_reuses_one_connection(gw_certs: Path) -> None:
    """The payoff for handing framing to httpx: the second request skips both
    the TCP handshake and the TLS one."""
    api = endpoint(gw_certs)
    async with tunnel_to(api, gw_certs) as driver:
        transport = TunnelTransport(driver, verify=api.trusting())
        async with httpx.AsyncClient(transport=transport) as client:
            for path in ("/one", "/two", "/three"):
                response = await client.get(
                    f"https://{SERVER_IP}{path}",
                    headers={"Host": SERVER_NAME},
                    extensions={"sni_hostname": SERVER_NAME},
                )
                assert response.status_code == 200

    assert transport.backend.connections == 1, "each request opened its own connection"
    assert len(api.peer.connections) == 1
    (served,) = api.endpoints
    assert len(served.requests) == 3


async def test_an_untrusted_certificate_is_refused_through_the_tunnel(gw_certs: Path) -> None:
    """Verification must not quietly stop applying just because we carry the
    bytes ourselves."""
    api = endpoint(gw_certs)
    async with tunnel_to(api, gw_certs) as driver:
        transport = TunnelTransport(driver)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(Exception, match="certificate verification failed"):
                await client.get(
                    f"https://{SERVER_IP}/",
                    headers={"Host": SERVER_NAME},
                    extensions={"sni_hostname": SERVER_NAME},
                )


# --- through the command ----------------------------------------------------


async def test_byway_get_fetches_an_https_url(
    gw_certs: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    api = endpoint(gw_certs, b'{"ok":true}')
    async with FakeGateway(
        auth_exchange(), certs_dir=gw_certs / "gw", peer=api.peer, tunnel_headers=TUNNEL_HEADERS
    ) as gateway:
        args = argparse.Namespace(
            verbose=0,
            pcap=None,
            json=True,
            mtu=None,
            method="GET",
            header=[],
            output=None,
            timeout=10.0,
            route_policy="auto",
            location=False,
            insecure=False,
            cacert=str(api.ca_path),
            tls_name=None,  # derived from the Host header below
        )
        result = await _run(
            args,
            GatewayConfig(host="127.0.0.1", port=gateway.port, verify=gateway.ca_path),
            Credentials(username="alice", password="hunter2"),
            Target(scheme="https", host=SERVER_IP, port=443, path="/v1/status"),
            [("Host", SERVER_NAME)],
        )

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == 200
    assert report["url"] == f"https://{SERVER_IP}/v1/status"
