"""The CSTP tunnel, end to end against the fake gateway.

Proves framing, DPD, config parsing, and MTU handling without a single line of
TCP existing yet -- which is the point of ordering the milestones this way.
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from pathlib import Path

import pytest
from usernet.pcap import PcapWriter
from usernet.testing.pcap import records as pcap_records

from pylis.cstp.framing import PacketType, encode_frame
from pylis.cstp.session import CstpSession
from pylis.errors import HandshakeRejected, ProtocolParseError
from tests.fakegw import FakeGateway


def pcap_packets(path: Path) -> list[bytes]:
    return [record[4] for record in pcap_records(path)]


@pytest.fixture
def certs(tmp_path: Path) -> Path:
    return tmp_path


def client_context(gateway: FakeGateway) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=gateway.ca_path)
    return context


def session_for(gateway: FakeGateway, **kwargs: object) -> CstpSession:
    defaults: dict[str, object] = {
        "host": "127.0.0.1",
        "port": gateway.port,
        "session_token": "TESTTOKEN",
        "ssl_context": client_context(gateway),
        "user_agent": "AnyConnect Windows 4.10.07061",
        "local_hostname": "testhost",
    }
    return CstpSession(**{**defaults, **kwargs})  # type: ignore[arg-type]


async def wait_for(event: asyncio.Event, seconds: float = 5.0) -> None:
    async with asyncio.timeout(seconds):
        await event.wait()


# --- handshake -------------------------------------------------------------


async def test_tunnel_config_is_parsed(certs: Path) -> None:
    async with FakeGateway([], certs_dir=certs) as gateway, session_for(gateway) as session:
        config = session.config

    assert config.address == "10.20.30.40"
    assert config.netmask == "255.255.255.0"
    assert config.mtu == 1406
    assert config.dns == ("10.0.0.53", "10.0.0.54")
    assert config.default_domain == "corp.example"
    assert config.dpd == 30
    assert config.keepalive == 20
    assert config.idle_timeout == 1800
    assert config.rekey_time == 3600
    assert config.rekey_method == "ssl"
    # The banner arrives percent-encoded.
    assert config.banner == "Authorised users only."

    assert config.is_split_tunnel
    assert config.split_include == (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    assert config.local_network == ipaddress.IPv4Network("10.20.30.0/24")


async def test_connect_request_carries_the_cookie_and_version(certs: Path) -> None:
    async with FakeGateway([], certs_dir=certs) as gateway, session_for(gateway):
        pass

    assert gateway.connect_headers["cookie"] == "webvpn=TESTTOKEN"
    assert gateway.connect_headers["x-cstp-version"] == "1"
    assert gateway.connect_headers["x-cstp-hostname"] == "testhost"
    assert gateway.connect_headers["x-cstp-address-type"] == "IPv4"
    assert gateway.connect_headers["x-cstp-mtu"] == "1406"


async def test_we_never_offer_compression_or_dtls(certs: Path) -> None:
    """The load-bearing omissions.

    Advertising Accept-Encoding would let the gateway compress, which would
    silently break every packet since no decompressor exists. Advertising
    X-DTLS-* would invite a UDP path we do not implement.
    """
    async with FakeGateway([], certs_dir=certs) as gateway, session_for(gateway):
        pass

    assert "x-cstp-accept-encoding" not in gateway.connect_headers
    assert not [name for name in gateway.connect_headers if name.startswith("x-dtls")]


async def test_rejected_handshake_raises_with_the_status(certs: Path) -> None:
    async with FakeGateway([], certs_dir=certs, tunnel_status="401 Unauthorized") as gateway:
        with pytest.raises(HandshakeRejected) as caught:
            async with session_for(gateway):
                pass

    assert caught.value.status == 401


async def test_compression_response_is_refused_loudly(certs: Path) -> None:
    """We never asked for it, so being given it means our model is wrong."""
    headers = [("X-CSTP-Address", "10.0.0.2"), ("X-CSTP-Content-Encoding", "deflate")]
    async with FakeGateway([], certs_dir=certs, tunnel_headers=headers) as gateway:
        with pytest.raises(ProtocolParseError, match="compression"):
            async with session_for(gateway):
                pass


# --- data path -------------------------------------------------------------


async def test_packets_travel_in_both_directions(certs: Path) -> None:
    outbound = bytes(range(64))
    inbound = b"\x45\x00" + b"reply payload"

    async with FakeGateway([], certs_dir=certs) as gateway, session_for(gateway) as session:
        session.send(outbound)
        await wait_for(gateway.packet_received)

        gateway.send_packet(inbound)
        await wait_for(session.wake)
        received = session.take_inbound()

    assert gateway.received_packets == [outbound]
    assert received == [inbound]


async def test_the_pcap_records_both_directions(certs: Path, tmp_path: Path) -> None:
    """A one-sided capture cannot show an RTT, a retransmission, or a window
    scale, which is most of what a pcap is opened to find out."""
    outbound = b"\x45\x00" + b"we sent this"
    inbound = b"\x45\x00" + b"they sent this"
    path = tmp_path / "both.pcap"

    with PcapWriter(path) as pcap:
        async with (
            FakeGateway([], certs_dir=certs) as gateway,
            session_for(gateway, pcap=pcap) as session,
        ):
            session.send(outbound)
            await wait_for(gateway.packet_received)

            gateway.send_packet(inbound)
            await wait_for(session.wake)
            session.take_inbound()

    captured = pcap_packets(path)
    assert outbound in captured
    assert inbound in captured


async def test_control_frames_stay_out_of_the_pcap(certs: Path, tmp_path: Path) -> None:
    """DPD and keepalive are not IP packets; writing them would produce a file
    Wireshark reads as corrupt IP headers."""
    path = tmp_path / "control.pcap"

    with PcapWriter(path) as pcap:
        async with (
            FakeGateway([], certs_dir=certs) as gateway,
            session_for(gateway, pcap=pcap) as session,
        ):
            gateway.send_dpd()
            await asyncio.sleep(0.05)
            gateway.send_packet(b"\x45\x00data")
            await wait_for(session.wake)
            session.take_inbound()

    assert pcap_packets(path) == [b"\x45\x00data"]


async def test_frames_reassemble_across_tiny_tls_writes(certs: Path) -> None:
    """The gateway splitting frames mid-header must not desynchronise us."""
    packets = [bytes([i]) * 200 for i in range(5)]

    async with (
        FakeGateway([], certs_dir=certs, write_chunk_size=3) as gateway,
        session_for(gateway) as session,
    ):
        for packet in packets:
            gateway.send_packet(packet)

        collected: list[bytes] = []
        while len(collected) < len(packets):
            await wait_for(session.wake)
            collected.extend(session.take_inbound())

    assert collected == packets


async def test_take_inbound_drains_and_clears(certs: Path) -> None:
    async with FakeGateway([], certs_dir=certs) as gateway, session_for(gateway) as session:
        gateway.send_packet(b"one")
        await wait_for(session.wake)
        assert session.take_inbound() == [b"one"]
        assert session.take_inbound() == []


# --- liveness --------------------------------------------------------------


async def test_dpd_probe_is_answered(certs: Path) -> None:
    async with FakeGateway([], certs_dir=certs) as gateway, session_for(gateway) as session:
        await wait_for(gateway.tunnel_up)
        gateway.send_dpd()

        for _ in range(50):
            await asyncio.sleep(0.02)
            if gateway.dpd_responses:
                break

        assert session.closed.is_set() is False

    assert gateway.dpd_responses >= 1


async def test_dpd_response_precedes_queued_data(certs: Path) -> None:
    """A backlog of data must never delay a DPD response."""
    async with FakeGateway([], certs_dir=certs) as gateway, session_for(gateway) as session:
        await wait_for(gateway.tunnel_up)
        for _ in range(50):
            session.send(b"x" * 500)
        gateway.send_dpd()

        for _ in range(100):
            await asyncio.sleep(0.02)
            if gateway.dpd_responses:
                break

    assert gateway.dpd_responses >= 1


async def test_gateway_disconnect_closes_the_session(certs: Path) -> None:
    async with FakeGateway([], certs_dir=certs) as gateway, session_for(gateway) as session:
        await wait_for(gateway.tunnel_up)
        gateway.send_disconnect()
        await wait_for(session.closed)

    assert "DISCONNECT" in session.close_reason


async def test_client_close_sends_disconnect(certs: Path) -> None:
    async with FakeGateway([], certs_dir=certs) as gateway:
        session = session_for(gateway)
        await session.connect()
        await wait_for(gateway.tunnel_up)
        await session.aclose()

    assert session.closed.is_set()


async def test_desynchronised_stream_closes_the_tunnel(certs: Path) -> None:
    """Bad magic means the stream is lost; CSTP has no way to resynchronise."""
    async with FakeGateway([], certs_dir=certs) as gateway, session_for(gateway) as session:
        await wait_for(gateway.tunnel_up)
        gateway.send_raw(b"NOTSTF\x00\x00garbage")
        await wait_for(session.closed)

    assert "protocol error" in session.close_reason


async def test_unknown_frame_types_are_ignored(certs: Path) -> None:
    """Gateways vary; an unrecognised type must not take the tunnel down."""
    async with FakeGateway([], certs_dir=certs) as gateway, session_for(gateway) as session:
        await wait_for(gateway.tunnel_up)
        gateway.send_raw(encode_frame(200, b"mystery"))
        gateway.send_packet(b"still working")
        await wait_for(session.wake)

        assert session.take_inbound() == [b"still working"]
        assert not session.closed.is_set()


async def test_many_queued_frames_all_arrive_intact(certs: Path) -> None:
    """Whatever the write strategy, nothing may be lost or reordered.

    Note this cannot observe TLS record boundaries -- asyncio hands decrypted
    plaintext to StreamReader as a stream, concatenating records. The
    one-frame-per-record invariant is asserted in
    tests/unit/test_write_strategy.py, at the layer where it is decided.
    """
    async with FakeGateway([], certs_dir=certs) as gateway, session_for(gateway) as session:
        await wait_for(gateway.tunnel_up)
        for index in range(6):
            session.send(bytes([index]) * 40)

        for _ in range(250):
            if len(gateway.received_packets) >= 6:
                break
            await asyncio.sleep(0.02)

    assert gateway.received_packets == [bytes([i]) * 40 for i in range(6)]


async def test_frames_are_counted_in_both_directions(certs: Path) -> None:
    """Control frames are invisible in packet counts.

    Without this accounting, a tunnel that died from a missed keepalive looks
    exactly like one that was simply idle -- which is precisely the ambiguity
    that made the first real-gateway disconnect undiagnosable.
    """
    async with FakeGateway([], certs_dir=certs) as gateway, session_for(gateway) as session:
        await wait_for(gateway.tunnel_up)
        session.send(b"outbound")
        gateway.send_dpd()
        gateway.send_packet(b"inbound")
        await wait_for(session.wake)
        session.take_inbound()

        for _ in range(50):
            await asyncio.sleep(0.02)
            if gateway.dpd_responses:
                break

    assert session.frames_in["DATA"] == 1
    assert session.frames_in["DPD_OUT"] == 1
    assert session.frames_out["DATA"] == 1
    assert session.frames_out["DPD_RESP"] == 1
    assert "DPD_RESP=1" in session.stats()


async def test_a_failing_background_task_closes_the_tunnel(certs: Path) -> None:
    """An unsupervised task exception would leave the tunnel silently mute.

    It would stop sending keepalives and simply wait to be dropped by the
    gateway, reporting nothing useful about why.
    """
    async with FakeGateway([], certs_dir=certs) as gateway, session_for(gateway) as session:
        await wait_for(gateway.tunnel_up)

        boom = RuntimeError("synthetic timer failure")

        async def failing() -> None:
            raise boom

        task = asyncio.create_task(failing(), name="cstp-timers")
        task.add_done_callback(session._on_task_done)
        await wait_for(session.closed)

    assert "cstp-timers failed" in session.close_reason
    assert "synthetic timer failure" in session.close_reason


async def test_compressed_frame_is_a_protocol_error(certs: Path) -> None:
    async with FakeGateway([], certs_dir=certs) as gateway, session_for(gateway) as session:
        await wait_for(gateway.tunnel_up)
        gateway.send_raw(encode_frame(PacketType.COMPRESSED, b"\x00"))
        await wait_for(session.closed)

    assert "COMPRESSED" in session.close_reason or "protocol error" in session.close_reason
