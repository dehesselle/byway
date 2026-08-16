"""An in-memory :class:`~pyac.cstp.link.IpLink` carrying IP packets to a peer.

Stands in for the CSTP tunnel, so the stack and driver can be exercised with
no TLS, no gateway, and no network -- while still going through exactly the
same interface the real tunnel presents.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Callable

from pyac.cstp.config import TunnelConfig
from pyac.errors import ProtocolParseError
from tests.vnet.peer import TcpPeer


class VirtualLink:
    """Connects a driver to a :class:`TcpPeer`.

    Loss, duplication, and reordering are seeded so a failing run reproduces
    exactly; anything else would make an intermittent bug impossible to chase.
    """

    def __init__(
        self,
        peer: TcpPeer,
        *,
        address: str = "172.29.29.5",
        mtu: int = 1383,
        loss: float = 0.0,
        duplicate: float = 0.0,
        seed: int = 0,
        on_send: Callable[[bytes], None] | None = None,
    ) -> None:
        self.peer = peer
        self._config = TunnelConfig(address=address, netmask="255.255.0.0", mtu=mtu)
        self._inbound: list[bytes] = []
        self._wake = asyncio.Event()
        self._closed = asyncio.Event()
        self._close_reason = ""

        self.loss = loss
        self.duplicate = duplicate
        self._random = random.Random(seed)
        self._on_send = on_send

        self.sent_count = 0
        self.dropped_count = 0

    # --- IpLink ------------------------------------------------------------

    @property
    def config(self) -> TunnelConfig:
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
        self.sent_count += 1
        if self._on_send is not None:
            self._on_send(packet)

        # Loss is applied to the client -> peer direction only. The fixture
        # peer has no retransmission timer, so dropping *its* replies would
        # stall forever -- a limitation of the harness, not of the stack. This
        # still exercises our own retransmission, which is the point.
        if self.loss and self._random.random() < self.loss:
            self.dropped_count += 1
            return

        self._deliver(packet)
        if self.duplicate and self._random.random() < self.duplicate:
            self._deliver(packet)

    def _deliver(self, packet: bytes) -> None:
        try:
            replies = self.peer.handle(packet)
        except ProtocolParseError:
            return  # a corrupt packet is dropped, exactly as a real peer would

        self._inbound.extend(replies)
        if self._inbound:
            self._wake.set()

    def take_inbound(self) -> list[bytes]:
        packets = self._inbound
        self._inbound = []
        self._wake.clear()
        return packets

    async def aclose(self) -> None:
        self.close("closed by test")

    def close(self, reason: str) -> None:
        self._close_reason = reason
        self._closed.set()
        self._wake.set()
