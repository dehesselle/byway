"""pyac -- a userspace Cisco AnyConnect (CSTP) client.

Connects to an AnyConnect gateway and terminates the tunnel's IP traffic in an
in-process TCP/IP stack, so no tun device, virtual adapter, routing change, or
administrator privilege is required.

``VpnClient`` and ``connect`` are re-exported here once :mod:`pyac.api` lands
(milestone M5). Importing this package must stay free of side effects.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
