"""One CSTP tunnel over one TLS connection.

Owns the socket, the framing, and the DPD/keepalive timers, and presents an
:class:`~pyac.cstp.link.IpLink`. Reconnection and rekey live one layer up, in
``ReconnectingLink``, precisely so this class can stay "one connection, from
handshake to close".
"""

from __future__ import annotations

import asyncio
import contextlib
import socket as _socket
import ssl
from collections import deque
from types import TracebackType

from pyac._pcap import PcapWriter
from pyac.cstp.config import TunnelConfig, parse_tunnel_config
from pyac.cstp.framing import (
    FRAME_DISCONN,
    FRAME_DPD_OUT,
    FRAME_DPD_RESP,
    FRAME_KEEPALIVE,
    FrameDecoder,
    PacketType,
    encode_frame,
)
from pyac.cstp.handshake import build_connect_request, parse_connect_response, split_header_block
from pyac.errors import ProtocolParseError, TunnelClosed

READ_SIZE = 65536

# Inbound packets accumulate here between driver passes. Dropping the tail
# when it overflows is exactly what a congested link does, and TCP recovers.
MAX_INBOUND_BACKLOG = 512

# Bounded so a stalled TLS socket cannot grow the queue without limit; the
# stack's own retransmission queues are the correct place for that backlog.
MAX_OUTBOUND_BACKLOG = 256


class CstpSession:
    """A live CSTP tunnel, satisfying :class:`~pyac.cstp.link.IpLink`."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        session_token: str,
        ssl_context: ssl.SSLContext,
        user_agent: str,
        local_hostname: str | None = None,
        mtu: int = 1406,
        pcap: PcapWriter | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._token = session_token
        self._ssl_context = ssl_context
        self._user_agent = user_agent
        self._local_hostname = local_hostname or _socket.gethostname()
        self._requested_mtu = mtu
        self._pcap = pcap

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._config: TunnelConfig | None = None
        self._decoder = FrameDecoder()

        self._inbound: list[bytes] = []
        self._outbound: deque[bytes] = deque()
        self._wake = asyncio.Event()
        self._writer_wake = asyncio.Event()
        self._closed = asyncio.Event()
        self._close_reason = ""
        self._tasks: list[asyncio.Task[None]] = []

        self._dpd_outstanding = 0
        self.dropped_inbound = 0
        self.dropped_outbound = 0

    # --- IpLink ------------------------------------------------------------

    @property
    def config(self) -> TunnelConfig:
        if self._config is None:
            raise RuntimeError("tunnel is not connected yet")
        return self._config

    @property
    def wake(self) -> asyncio.Event:
        return self._wake

    @property
    def closed(self) -> asyncio.Event:
        return self._closed

    @property
    def close_reason(self) -> str:
        return self._close_reason

    def send(self, packet: bytes) -> None:
        if len(self._outbound) >= MAX_OUTBOUND_BACKLOG:
            self.dropped_outbound += 1
            return
        self._outbound.append(encode_frame(PacketType.DATA, packet))
        self._writer_wake.set()

    def take_inbound(self) -> list[bytes]:
        packets = self._inbound
        self._inbound = []
        self._wake.clear()
        return packets

    # --- lifecycle ---------------------------------------------------------

    async def connect(self) -> TunnelConfig:
        """Open TLS, perform the CONNECT handshake, and start the tasks."""
        self._reader, self._writer = await asyncio.open_connection(
            self._host, self._port, ssl=self._ssl_context, server_hostname=self._host
        )

        request = build_connect_request(
            host=self._host,
            port=self._port,
            session_token=self._token,
            local_hostname=self._local_hostname,
            user_agent=self._user_agent,
            mtu=self._requested_mtu,
        )
        self._writer.write(request)
        await self._writer.drain()

        buffer = b""
        block = b""
        remainder = b""
        while True:
            chunk = await self._reader.read(READ_SIZE)
            if not chunk:
                raise TunnelClosed("gateway closed the connection during the CONNECT handshake")
            buffer += chunk
            split = split_header_block(buffer)
            if split is not None:
                block, remainder = split
                break

        headers = parse_connect_response(block)
        self._config = parse_tunnel_config(headers)

        if self._config.content_encoding:
            # We never advertised Accept-Encoding, so this should be impossible.
            # Failing loudly beats silently mangling every packet.
            raise ProtocolParseError(
                f"gateway enabled {self._config.content_encoding!r} compression "
                f"despite no X-CSTP-Accept-Encoding being offered"
            )

        # The gateway often packs the first frames into the same segment as the
        # response headers; dropping them would desynchronise the stream at once.
        if remainder:
            self._consume(remainder)

        self._tasks = [
            asyncio.create_task(self._read_loop(), name="cstp-reader"),
            asyncio.create_task(self._write_loop(), name="cstp-writer"),
            asyncio.create_task(self._timer_loop(), name="cstp-timers"),
        ]
        return self._config

    async def aclose(self) -> None:
        """Tell the gateway we are going, then tear everything down."""
        self._mark_closed("client disconnect")

        if self._writer is not None and not self._writer.is_closing():
            with contextlib.suppress(OSError, ssl.SSLError):
                self._writer.write(FRAME_DISCONN)
                await asyncio.wait_for(self._writer.drain(), timeout=2.0)

        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []

        if self._writer is not None:
            self._writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._writer.wait_closed(), timeout=2.0)

    async def __aenter__(self) -> CstpSession:
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # --- internals ---------------------------------------------------------

    def _mark_closed(self, reason: str) -> None:
        if not self._closed.is_set():
            self._close_reason = reason
            self._closed.set()
        self._wake.set()  # release a driver waiting for packets

    def _consume(self, data: bytes) -> None:
        """Feed raw stream bytes through the framer and dispatch each frame."""
        for frame in self._decoder.feed(data):
            if frame.type == PacketType.DATA:
                if len(self._inbound) >= MAX_INBOUND_BACKLOG:
                    self.dropped_inbound += 1
                    continue
                self._inbound.append(frame.payload)
                if self._pcap is not None:
                    self._pcap.write(frame.payload)
                self._wake.set()

            elif frame.type == PacketType.DPD_OUT:
                # Jump the queue. A full data backlog must never delay a DPD
                # response -- that is how tunnels die under load.
                self._outbound.appendleft(FRAME_DPD_RESP)
                self._writer_wake.set()

            elif frame.type == PacketType.DPD_RESP:
                self._dpd_outstanding = 0

            elif frame.type == PacketType.KEEPALIVE:
                pass

            elif frame.type == PacketType.DISCONN:
                self._mark_closed("gateway sent DISCONNECT")

            elif frame.type == PacketType.TERM_SERVER:
                self._mark_closed("gateway terminated the session")

            elif frame.type == PacketType.COMPRESSED:
                raise ProtocolParseError(
                    "gateway sent a COMPRESSED frame although compression was never offered"
                )

    async def _read_loop(self) -> None:
        assert self._reader is not None
        try:
            while True:
                chunk = await self._reader.read(READ_SIZE)
                if not chunk:
                    self._mark_closed("gateway closed the tunnel")
                    return
                self._consume(chunk)
        except asyncio.CancelledError:
            raise
        except (OSError, ssl.SSLError) as exc:
            self._mark_closed(f"tunnel read failed: {exc}")
        except ProtocolParseError as exc:
            # The stream has desynchronised and CSTP has no delimiter to
            # resynchronise on, so the tunnel cannot be salvaged.
            self._mark_closed(f"protocol error: {exc}")

    async def _write_loop(self) -> None:
        assert self._writer is not None
        try:
            while True:
                await self._writer_wake.wait()
                self._writer_wake.clear()

                if not self._outbound:
                    continue

                # One TLS record per batch rather than per packet.
                batch = b"".join(self._outbound)
                self._outbound.clear()
                self._writer.write(batch)
                await self._writer.drain()
        except asyncio.CancelledError:
            raise
        except (OSError, ssl.SSLError) as exc:
            self._mark_closed(f"tunnel write failed: {exc}")

    async def _timer_loop(self) -> None:
        """Send keepalives and DPD probes, and notice a dead peer."""
        config = self.config
        dpd = config.dpd or 30
        keepalive = config.keepalive or 20
        interval = max(1, min(dpd, keepalive))
        elapsed_dpd = 0
        elapsed_keepalive = 0

        try:
            while True:
                await asyncio.sleep(interval)
                elapsed_dpd += interval
                elapsed_keepalive += interval

                if elapsed_dpd >= dpd:
                    elapsed_dpd = 0
                    if self._dpd_outstanding >= 2:
                        self._mark_closed(f"no DPD response after {self._dpd_outstanding} probes")
                        return
                    self._dpd_outstanding += 1
                    self._outbound.append(FRAME_DPD_OUT)
                    self._writer_wake.set()

                if elapsed_keepalive >= keepalive:
                    elapsed_keepalive = 0
                    self._outbound.append(FRAME_KEEPALIVE)
                    self._writer_wake.set()
        except asyncio.CancelledError:
            raise
