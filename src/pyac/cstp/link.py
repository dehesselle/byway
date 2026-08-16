"""The IP link abstraction.

Everything above this interface deals in whole IP packets and never learns
that the TLS connection underneath was torn down and rebuilt. That is what
makes rekey and reconnect a non-event rather than a rewrite -- and it is why
this indirection exists from the start instead of being retrofitted once
reconnection becomes a problem.

The contract is deliberately batch-shaped. :meth:`take_inbound` drains
everything received since the last call so the driver can feed the stack in
one pass, and queued outbound packets are coalesced into a single TLS write,
which is the largest cheap throughput win available.
"""

from __future__ import annotations

import asyncio
from typing import Protocol, runtime_checkable

from pyac.cstp.config import TunnelConfig


@runtime_checkable
class IpLink(Protocol):
    """A bidirectional channel carrying raw IPv4 packets."""

    @property
    def config(self) -> TunnelConfig:
        """The gateway's tunnel parameters: address, MTU, DNS, routes."""
        ...

    @property
    def wake(self) -> asyncio.Event:
        """Set whenever inbound packets arrive, so the driver can wait on it."""
        ...

    def send(self, packet: bytes) -> None:
        """Queue one IP packet. Non-blocking; the writer task coalesces."""
        ...

    def take_inbound(self) -> list[bytes]:
        """Drain every IP packet received since the last call."""
        ...

    @property
    def closed(self) -> asyncio.Event:
        """Set when the link is finished; :attr:`close_reason` says why."""
        ...

    @property
    def close_reason(self) -> str: ...

    async def aclose(self) -> None:
        """Shut the link down cleanly."""
        ...
