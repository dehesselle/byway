"""pyac -- a userspace Cisco AnyConnect (CSTP) client.

Connects to an AnyConnect gateway and terminates the tunnel's IP traffic in an
in-process TCP/IP stack, so no tun device, virtual adapter, routing change, or
administrator privilege is required.

    async with pyac.connect("vpn.corp.example", user, password) as vpn:
        reader, writer = await vpn.open_connection("10.0.0.5", 22)

Importing this package stays free of side effects: the names below are bound
lazily, so ``import pyac`` does not drag in httpx and the whole stack for a
program that only wanted the version.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__all__ = [
    "Credentials",
    "GatewayConfig",
    "TunnelConfig",
    "VpnClient",
    "__version__",
    "connect",
]

if TYPE_CHECKING:
    from pyac.api import VpnClient, connect
    from pyac.config import Credentials, GatewayConfig
    from pyac.cstp.config import TunnelConfig


def __getattr__(name: str) -> Any:
    if name == "__version__":
        # From the installed metadata rather than a literal here. The project
        # takes its version from git tags (hatch-vcs), so a hardcoded string
        # would sooner or later disagree with the package actually installed --
        # and a version that lies is worse than one that is merely unknown.
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("pyac")
        except PackageNotFoundError:
            return "0.0.0+unknown"
    if name in ("VpnClient", "connect"):
        from pyac import api

        return getattr(api, name)
    if name in ("Credentials", "GatewayConfig"):
        from pyac import config

        return getattr(config, name)
    if name == "TunnelConfig":
        from pyac.cstp.config import TunnelConfig

        return TunnelConfig
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
