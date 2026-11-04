# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""A TLS server that speaks enough AnyConnect to test against.

Handles both halves of the protocol: the aggregate-auth XML POST, and
``CONNECT /CSCOSSLC/tunnel`` followed by CSTP framing. Tests drive the gateway
side directly -- sending packets, DPD probes, and disconnects -- so failure
modes that are hard to provoke against a real gateway are ordinary test cases.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType

import trustme
from usernet.testing.peer import TcpPeer

from pylis.cstp.framing import FrameDecoder, PacketType, encode_frame
from pylis.errors import ProtocolParseError

MAX_REQUEST_BYTES = 256 * 1024

DEFAULT_TUNNEL_HEADERS: list[tuple[str, str]] = [
    ("X-CSTP-Version", "1"),
    ("X-CSTP-Address", "10.20.30.40"),
    ("X-CSTP-Netmask", "255.255.255.0"),
    ("X-CSTP-MTU", "1406"),
    ("X-CSTP-Base-MTU", "1500"),
    ("X-CSTP-DNS", "10.0.0.53"),
    ("X-CSTP-DNS", "10.0.0.54"),
    ("X-CSTP-Default-Domain", "corp.example"),
    ("X-CSTP-Split-Include", "10.0.0.0/255.0.0.0"),
    ("X-CSTP-Split-Include", "192.168.0.0/255.255.0.0"),
    ("X-CSTP-DPD", "30"),
    ("X-CSTP-Keepalive", "20"),
    ("X-CSTP-Idle-Timeout", "1800"),
    ("X-CSTP-Rekey-Time", "3600"),
    ("X-CSTP-Rekey-Method", "ssl"),
    ("X-CSTP-Banner", "Authorised%20users%20only."),
]


@dataclass
class Request:
    """One HTTP request the fake gateway received."""

    method: str
    target: str
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@dataclass
class FakeGateway:
    """An HTTPS server speaking aggregate-auth and, optionally, CSTP.

    ``responses`` is consumed one per POST, so a test can script a whole
    exchange: the form first, then the success document.
    """

    responses: list[str]
    certs_dir: Path
    status: int = 200
    tunnel_headers: list[tuple[str, str]] = field(
        default_factory=lambda: list(DEFAULT_TUNNEL_HEADERS)
    )
    tunnel_status: str = "200 OK"
    write_chunk_size: int | None = None
    """Split every tunnel write into chunks of this size, to prove the client
    reassembles frames across arbitrary TLS record boundaries."""

    peer: TcpPeer | None = None
    """If set, inbound IP packets are terminated here and the replies sent back
    down the tunnel -- which turns the fake gateway into a whole network, so a
    real HTTP request can be served through the full stack."""

    address_per_connect: bool = False
    """Hand out a fresh ``X-CSTP-Address`` each time, as a real ASA does --
    which is what makes reconnection visible to everything above the link."""

    requests: list[Request] = field(default_factory=list)
    connects: int = 0
    connect_headers: dict[str, str] = field(default_factory=dict)
    received_packets: list[bytes] = field(default_factory=list)
    dpd_responses: int = 0
    keepalives: int = 0

    _server: asyncio.AbstractServer | None = field(default=None, repr=False)
    _ca_path: Path = field(init=False, repr=False)
    _tunnel_writer: asyncio.StreamWriter | None = field(default=None, repr=False)
    tunnel_up: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    packet_received: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    # --- lifecycle ---------------------------------------------------------

    async def __aenter__(self) -> FakeGateway:
        ca = trustme.CA()
        cert = ca.issue_cert("localhost", "127.0.0.1")

        self._ca_path = self.certs_dir / "ca.pem"
        ca.cert_pem.write_to_path(self._ca_path)
        cert_path = self.certs_dir / "server.pem"
        cert.private_key_and_cert_chain_pem.write_to_path(cert_path)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path)

        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=context)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._server is not None:
            self._server.close()
            # Bounded: from Python 3.12 wait_closed() also waits for in-flight
            # handlers, so a client still holding the tunnel open would hang
            # teardown indefinitely rather than fail the test.
            with contextlib.suppress(Exception):
                async with asyncio.timeout(2):
                    await self._server.wait_closed()

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.sockets[0].getsockname()[1])

    @property
    def ca_path(self) -> str:
        """CA bundle a client should trust, for ``GatewayConfig.verify``."""
        return str(self._ca_path)

    # --- driving the gateway side -----------------------------------------

    def send_packet(self, packet: bytes) -> None:
        """Send one IP packet down the tunnel."""
        self._write_frames(encode_frame(PacketType.DATA, packet))

    def send_dpd(self) -> None:
        """Probe the client; it must answer with DPD_RESP."""
        self._write_frames(encode_frame(PacketType.DPD_OUT))

    def send_disconnect(self) -> None:
        self._write_frames(encode_frame(PacketType.DISCONN))

    def send_raw(self, data: bytes) -> None:
        """Write arbitrary bytes, for malformed-stream tests."""
        self._write_frames(data)

    def _write_frames(self, data: bytes) -> None:
        writer = self._tunnel_writer
        if writer is None or writer.is_closing():
            return
        if self.write_chunk_size:
            for start in range(0, len(data), self.write_chunk_size):
                writer.write(data[start : start + self.write_chunk_size])
        else:
            writer.write(data)

    # --- request handling --------------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await self._read_head(reader)
            if request is None:
                return
            if request.method == "CONNECT":
                await self._serve_tunnel(request, reader, writer)
            else:
                await self._serve_auth(request, reader, writer)
        except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
            pass  # a client hanging up is itself a case under test
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _serve_auth(
        self, request: Request, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        length = min(int(request.headers.get("content-length", "0")), MAX_REQUEST_BYTES)
        body = await reader.readexactly(length) if length else b""
        self.requests.append(Request(request.method, request.target, request.headers, body))

        payload = (self.responses.pop(0) if self.responses else "<config-auth/>").encode()
        writer.write(
            b"HTTP/1.1 %d OK\r\n"
            b"Content-Type: text/xml\r\n"
            b"Content-Length: %d\r\n"
            b"X-Aggregate-Auth: 1\r\n"
            b"Connection: close\r\n"
            b"\r\n" % (self.status, len(payload))
        )
        writer.write(payload)
        await writer.drain()

    async def _serve_tunnel(
        self, request: Request, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.connect_headers = dict(request.headers)
        self.connects += 1
        self._tunnel_writer = writer

        head = f"HTTP/1.1 {self.tunnel_status}\r\n"
        head += "".join(f"{name}: {value}\r\n" for name, value in self._headers_for_connect())
        writer.write((head + "\r\n").encode())
        await writer.drain()

        if not self.tunnel_status.startswith("200"):
            return

        self.tunnel_up.set()
        decoder = FrameDecoder()

        while True:
            chunk = await reader.read(65536)
            if not chunk:
                return
            # Note: this cannot observe TLS record boundaries. asyncio's SSL
            # transport concatenates decrypted records into the stream, so the
            # one-frame-per-record invariant is tested in
            # tests/unit/test_write_strategy.py instead.
            for frame in decoder.feed(chunk):
                if frame.type == PacketType.DATA:
                    self.received_packets.append(frame.payload)
                    self.packet_received.set()
                    self._route(frame.payload)
                elif frame.type == PacketType.DPD_OUT:
                    self._write_frames(encode_frame(PacketType.DPD_RESP))
                elif frame.type == PacketType.DPD_RESP:
                    self.dpd_responses += 1
                elif frame.type == PacketType.KEEPALIVE:
                    self.keepalives += 1
                elif frame.type == PacketType.DISCONN:
                    return
            await writer.drain()

    def _headers_for_connect(self) -> list[tuple[str, str]]:
        if not self.address_per_connect:
            return self.tunnel_headers
        assigned = f"10.20.30.{39 + self.connects}"
        return [
            (name, assigned if name.lower() == "x-cstp-address" else value)
            for name, value in self.tunnel_headers
        ]

    def _route(self, packet: bytes) -> None:
        """Hand an inbound packet to the peer, if there is one."""
        if self.peer is None:
            return
        try:
            replies = self.peer.handle(packet)
        except ProtocolParseError:
            return  # a real network drops what it cannot parse, silently
        for reply in replies:
            self._write_frames(encode_frame(PacketType.DATA, reply))

    async def _read_head(self, reader: asyncio.StreamReader) -> Request | None:
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        method, _, rest = lines[0].partition(" ")
        target = rest.partition(" ")[0]

        headers = {}
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            if separator:
                headers[name.strip().lower()] = value.strip()

        return Request(method=method, target=target, headers=headers, body=b"")
