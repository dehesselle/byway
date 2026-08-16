"""A minimal TLS server that speaks enough AnyConnect to test against."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType

import trustme

MAX_REQUEST_BYTES = 256 * 1024


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
    """An HTTPS server that replies to the aggregate-auth POST.

    ``responses`` is consumed one per POST, so a test can script a whole
    exchange: the form first, then the success document.
    """

    responses: list[str]
    certs_dir: Path
    host: str = "localhost"
    status: int = 200
    requests: list[Request] = field(default_factory=list)

    _server: asyncio.AbstractServer | None = field(default=None, repr=False)
    _ca_path: Path = field(init=False, repr=False)

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
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.sockets[0].getsockname()[1])

    @property
    def ca_path(self) -> str:
        """CA bundle a client should trust, for ``GatewayConfig.verify``."""
        return str(self._ca_path)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await self._read_request(reader)
            if request is None:
                return
            self.requests.append(request)

            body = self.responses.pop(0) if self.responses else "<config-auth/>"
            payload = body.encode("utf-8")
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
        except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
            pass  # a client hanging up mid-handshake is a case under test
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _read_request(self, reader: asyncio.StreamReader) -> Request | None:
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        method, _, rest = lines[0].partition(" ")
        target = rest.partition(" ")[0]

        headers = {}
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if sep:
                headers[name.strip().lower()] = value.strip()

        length = min(int(headers.get("content-length", "0")), MAX_REQUEST_BYTES)
        body = await reader.readexactly(length) if length else b""
        return Request(method=method, target=target, headers=headers, body=body)
