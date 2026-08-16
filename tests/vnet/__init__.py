"""Virtual network harness.

Gives the stack a peer to talk to without any real network, and without the
shipping code ever growing a passive-open path. Everything here is test-only.
"""

from tests.vnet.link import VirtualLink
from tests.vnet.peer import TcpPeer

__all__ = ["TcpPeer", "VirtualLink"]
