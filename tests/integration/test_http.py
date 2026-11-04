"""``pylis http`` against the fake gateway: every layer at once.

Aggregate-auth, ``CONNECT``, CSTP framing, the userspace IPv4 stack, the TCP
state machine, and an HTTP request served by a peer sitting behind the tunnel.
Nothing here is stubbed except the gateway itself, and no VPN is involved --
this is the test that says the product works, and it runs in about a second on
both operating systems.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest
from usernet.net.ipv4 import parse_ipv4
from usernet.net.tcp import Flag, parse_tcp
from usernet.resolve import StaticResolver
from usernet.testing.peer import TcpPeer, http_handler

from pylis.cli.cmd_http import Target, _run
from pylis.config import Credentials, GatewayConfig
from pylis.errors import ConnectionTimeout, RouteNotAllowed
from tests.fakegw import FakeGateway
from tests.fakegw.server import DEFAULT_TUNNEL_HEADERS
from tests.integration.test_tunnel import pcap_packets

CORPUS = Path(__file__).parent.parent / "corpus"

CLIENT_IP = "10.20.30.40"
SERVER_IP = "10.11.12.13"


@pytest.fixture
def certs(tmp_path: Path) -> Path:
    return tmp_path


def corpus(name: str) -> str:
    return (CORPUS / name).read_text(encoding="utf-8")


def auth_exchange() -> list[str]:
    """The two documents a full login consumes: the form, then the success."""
    return [corpus("asa_main_form.xml"), corpus("asa_success.xml")]


def options(**overrides: object) -> argparse.Namespace:
    defaults: dict[str, object] = {
        "verbose": 0,
        "pcap": None,
        "json": False,
        "mtu": None,
        "method": None,
        "data": None,
        "header": [],
        "output": None,
        "timeout": 10.0,
        "route_policy": "auto",
        "location": False,
        "insecure": False,
        "cacert": None,
        "tls_name": None,
    }
    return argparse.Namespace(**{**defaults, **overrides})


async def fetch(
    gateway: FakeGateway,
    path: str = "/",
    host: str = SERVER_IP,
    hosts: dict[str, str] | None = None,
    **overrides: object,
) -> int:
    config = GatewayConfig(host="127.0.0.1", port=gateway.port, verify=gateway.ca_path)
    return await _run(
        options(**overrides),
        config,
        Credentials(username="alice", password="hunter2"),
        Target(host=host, port=80, path=path),
        [],
        StaticResolver(hosts or {}),
    )


def serving(body: bytes, certs: Path, **overrides: object) -> FakeGateway:
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(body))
    headers = [(name, value) for name, value in DEFAULT_TUNNEL_HEADERS if name != "X-CSTP-Banner"]
    return FakeGateway(
        auth_exchange(),
        certs_dir=certs,
        peer=peer,
        tunnel_headers=headers,
        **overrides,  # type: ignore[arg-type]
    )


# --- the milestone ---------------------------------------------------------


async def test_a_page_is_fetched_through_the_whole_stack(
    certs: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Auth, tunnel, framing, IP, TCP, HTTP. The whole reason for the project."""
    async with serving(b"it works from inside the vpn", certs) as gateway:
        result = await fetch(gateway)

    assert result == 0
    assert capsys.readouterr().out.endswith("it works from inside the vpn")


async def test_a_name_from_the_host_table_is_fetched(
    certs: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    async with serving(b"fetched by name", certs) as gateway:
        result = await fetch(gateway, host="web.orka", hosts={"web.orka": SERVER_IP})

    assert result == 0
    assert capsys.readouterr().out.endswith("fetched by name")


async def test_the_request_reaches_the_server_intact(certs: Path) -> None:
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"ok"))
    headers = [(name, value) for name, value in DEFAULT_TUNNEL_HEADERS if name != "X-CSTP-Banner"]
    async with FakeGateway(
        auth_exchange(), certs_dir=certs, peer=peer, tunnel_headers=headers
    ) as gateway:
        await fetch(gateway, path="/v1/things")

    (connection,) = peer.connections.values()
    request = bytes(connection.received)
    assert request.startswith(b"GET /v1/things HTTP/1.1\r\n")
    assert b"host: 10.11.12.13\r\n" in request.lower()
    # No `Connection: close`: since M7 the request is httpx's, and it keeps the
    # connection alive. The response is framed by Content-Length, not by EOF.
    assert b"connection: close" not in request.lower()


async def test_a_body_is_posted_byte_for_byte(certs: Path) -> None:
    """What a REST call needs: the body, its length, and the caller's type."""
    body = b'{"name": "thing", "tags": ["a", "b"]}'
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"created"))
    headers = [(name, value) for name, value in DEFAULT_TUNNEL_HEADERS if name != "X-CSTP-Banner"]
    async with FakeGateway(
        auth_exchange(), certs_dir=certs, peer=peer, tunnel_headers=headers
    ) as gateway:
        config = GatewayConfig(host="127.0.0.1", port=gateway.port, verify=gateway.ca_path)
        result = await _run(
            options(data="(read by run)"),
            config,
            Credentials(username="alice", password="hunter2"),
            Target(host=SERVER_IP, port=80, path="/v1/things"),
            [("Content-Type", "application/json")],
            StaticResolver({}),
            body,
        )

    assert result == 0
    (connection,) = peer.connections.values()
    request = bytes(connection.received)
    assert request.startswith(b"POST /v1/things HTTP/1.1\r\n")
    assert b"content-type: application/json\r\n" in request.lower()
    assert f"content-length: {len(body)}\r\n".encode() in request.lower()
    assert request.endswith(b"\r\n\r\n" + body)


async def test_a_body_larger_than_one_segment_arrives_whole(certs: Path, tmp_path: Path) -> None:
    """Many MTUs of binary data, so framing, segmentation and reassembly all
    matter -- and ``-o`` is how you would actually fetch something like it."""
    body = bytes(range(256)) * 300  # 75 KB, every byte value
    destination = tmp_path / "payload.bin"
    async with serving(body, certs) as gateway:
        result = await fetch(gateway, output=str(destination))

    assert result == 0
    assert destination.read_bytes() == body


async def test_frames_split_across_tls_records_still_work(
    certs: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The gateway writes in 100-byte pieces, so no frame arrives whole."""
    async with serving(b"reassembled", certs, write_chunk_size=100) as gateway:
        result = await fetch(gateway)

    assert result == 0
    assert capsys.readouterr().out.endswith("reassembled")


# --- what the tunnel is told ------------------------------------------------


async def test_the_client_address_is_the_one_the_gateway_assigned(certs: Path) -> None:
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"ok"))
    headers = [(name, value) for name, value in DEFAULT_TUNNEL_HEADERS if name != "X-CSTP-Banner"]
    async with FakeGateway(
        auth_exchange(), certs_dir=certs, peer=peer, tunnel_headers=headers
    ) as gateway:
        await fetch(gateway)

    (connection,) = peer.connections.values()
    assert connection.remote_ip == CLIENT_IP


async def test_no_packet_exceeds_the_advertised_mtu(certs: Path) -> None:
    """The silent-hang failure mode; assert it rather than hope."""
    async with serving(b"z" * 50_000, certs) as gateway:
        await fetch(gateway)
        oversized = [len(p) for p in gateway.received_packets if len(p) > 1406]

    assert oversized == [], f"packets above the 1406-byte tunnel MTU: {oversized}"


async def test_the_tunnel_is_closed_and_the_session_logged_out(certs: Path) -> None:
    """A leaked session counts against the gateway's concurrency limit and can
    lock the user out of their own VPN."""
    async with serving(b"ok", certs) as gateway:
        await fetch(gateway)
        targets = [r.target for r in gateway.requests]

    assert "/+webvpn+/webvpn_logout.html" in targets


async def test_the_pcap_captures_both_sides_of_the_conversation(
    certs: Path, tmp_path: Path
) -> None:
    """What `--pcap` is for: opening the file and seeing a whole exchange.

    Only the inbound half used to be recorded, which is enough to read a single
    header but not enough for Wireshark to pair requests with responses,
    measure an RTT, or notice a retransmission.
    """
    path = tmp_path / "get.pcap"
    async with serving(b"captured", certs) as gateway:
        assert await fetch(gateway, pcap=str(path)) == 0

    directions = set()
    handshake = set()
    for packet in pcap_packets(path):
        header, payload = parse_ipv4(packet)
        directions.add((header.source, header.destination))
        segment = parse_tcp(payload)
        if segment.has(Flag.SYN):
            handshake.add((header.source, str(segment.flags)))

    assert (CLIENT_IP, SERVER_IP) in directions, "nothing we sent was captured"
    assert (SERVER_IP, CLIENT_IP) in directions, "nothing we received was captured"
    # Both halves of the handshake, which is what makes option negotiation
    # readable: our SYN carries the window scale we offered, theirs the reply.
    assert (CLIENT_IP, str(Flag.SYN)) in handshake
    assert (SERVER_IP, str(Flag.SYN | Flag.ACK)) in handshake


# --- failures that must be legible ------------------------------------------


async def test_an_address_outside_the_split_routes_is_refused(certs: Path) -> None:
    """Better than the 15-second hang a split-tunnel gateway would give us."""
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"unreachable"))
    headers = [
        (name, value)
        for name, value in DEFAULT_TUNNEL_HEADERS
        if not name.startswith("X-CSTP-Split") and name != "X-CSTP-Banner"
    ]
    headers.append(("X-CSTP-Split-Include", "192.168.0.0/255.255.0.0"))

    async with FakeGateway(
        auth_exchange(), certs_dir=certs, peer=peer, tunnel_headers=headers
    ) as gateway:
        with pytest.raises(RouteNotAllowed, match="outside the gateway's split routes"):
            await fetch(gateway)

        # A name is checked by what it resolves to, and the message says both.
        gateway.responses = auth_exchange()
        with pytest.raises(RouteNotAllowed, match=rf"web\.orka \({SERVER_IP}\) is outside"):
            await fetch(gateway, host="web.orka", hosts={"web.orka": SERVER_IP})

        # ...and the escape hatch really does bypass the check.
        gateway.responses = auth_exchange()
        assert await fetch(gateway, route_policy="all") == 0


async def test_a_port_with_nothing_listening_times_out_naming_the_address(certs: Path) -> None:
    """The peer only answers 8080, and stays silent on 80 rather than sending a
    RST -- so this is the connect timeout doing its job, and the message has to
    say which address gave up."""
    peer = TcpPeer(ip=SERVER_IP, port=8080, handler=http_handler(b"elsewhere"))
    headers = [(name, value) for name, value in DEFAULT_TUNNEL_HEADERS if name != "X-CSTP-Banner"]
    async with FakeGateway(
        auth_exchange(), certs_dir=certs, peer=peer, tunnel_headers=headers
    ) as gateway:
        with pytest.raises(ConnectionTimeout, match=f"{SERVER_IP}:80"):
            await fetch(gateway, timeout=2.0)


async def test_json_output_is_machine_readable(
    certs: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    async with serving(b"payload", certs) as gateway:
        await fetch(gateway, json=True)

    report = json.loads(capsys.readouterr().out)
    assert report["status"] == 200
    assert report["body_bytes"] == 7
    assert report["url"] == "http://10.11.12.13/"
    # httpx normalises header names to lower case, which is correct: HTTP
    # header names are case-insensitive.
    assert {"name": "content-length", "value": "7"} in report["headers"]
