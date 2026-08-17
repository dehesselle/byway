"""Which destinations the tunnel will actually carry.

Lives above ``cstp`` (it reads a :class:`~pyac.cstp.config.TunnelConfig`) and
below the consumers, because the CLI, the SOCKS server, and anything else
opening a connection all need the same answer to the same question.

The reason to check at all: a split-tunnel gateway silently discards packets
for anything outside its include list. The symptom is a connection that hangs
until the timeout with no error, which is indistinguishable from a bug in our
own stack -- so the check exists as much to protect the next debugging session
as the user.
"""

from __future__ import annotations

import ipaddress

from pyac.cstp.config import TunnelConfig


def route_allows(config: TunnelConfig, host: str) -> bool:
    """Whether the gateway's split routes cover ``host``."""
    address = ipaddress.IPv4Address(host)
    if any(address in network for network in config.split_exclude):
        return False
    if not config.split_include:
        return True  # no include list means full tunnel
    if address in ipaddress.IPv4Network(f"{config.address}/{config.netmask}", strict=False):
        return True  # our own subnet is always reachable
    return any(address in network for network in config.split_include)


def describe_routes(config: TunnelConfig) -> str:
    """The route table as one line, for an error message worth reading."""
    if not config.split_include:
        return "full tunnel"
    text = ", ".join(str(network) for network in config.split_include)
    if config.split_exclude:
        text += " except " + ", ".join(str(network) for network in config.split_exclude)
    return text
