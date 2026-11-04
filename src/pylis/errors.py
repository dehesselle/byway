"""Exception hierarchy for pylis.

Every error the library raises derives from :class:`PylisError`, which is
:class:`usernet.errors.UsernetError` under another name. An alias rather than a
subclass, and that is the whole point: the stack, the sockets and the SOCKS
server live in ``usernet`` and raise ``usernet`` errors, so a ``PylisError`` that
did not also catch those would quietly stop covering half of what can go wrong.

The ``NetworkError`` branch is re-exported from there for the same reason --
callers import it from here, and where the class object is defined is not their
business. The pylis-specific errors below (authentication, the CSTP tunnel) are
the ones that genuinely have no meaning outside this project.
"""

from __future__ import annotations

from usernet.errors import (
    ConnectionRefused,
    ConnectionReset,
    ConnectionTimeout,
    HostUnreachable,
    NetworkError,
    ProtocolParseError,
    ResolveError,
    RouteNotAllowed,
    UsernetError,
)

__all__ = [
    "AuthChallengeRequired",
    "AuthError",
    "AuthFailed",
    "ConnectionRefused",
    "ConnectionReset",
    "ConnectionTimeout",
    "GroupSelectionRequired",
    "HandshakeRejected",
    "HostUnreachable",
    "NetworkError",
    "PostureCheckRequired",
    "ProtocolParseError",
    "PylisError",
    "RekeyFailed",
    "ResolveError",
    "RouteNotAllowed",
    "TunnelAddressChanged",
    "TunnelClosed",
    "TunnelError",
]

PylisError = UsernetError


# --- authentication --------------------------------------------------------


class AuthError(PylisError):
    """Base for failures during the aggregate-auth XML exchange."""


class AuthFailed(AuthError):
    """The gateway rejected the credentials."""


class AuthChallengeRequired(AuthError):
    """The gateway returned ``<auth id="challenge">`` (MFA).

    Not supported in v1. Carries the gateway's own prompt so the CLI can show
    the user what was actually asked rather than a traceback.
    """

    def __init__(self, prompt: str) -> None:
        super().__init__(f"gateway requires an additional challenge: {prompt}")
        self.prompt = prompt


class GroupSelectionRequired(AuthError):
    """The gateway offers several tunnel groups and none was chosen."""

    def __init__(self, groups: list[str]) -> None:
        super().__init__("gateway requires a group; choose one of: " + ", ".join(groups))
        self.groups = groups


class PostureCheckRequired(AuthError):
    """The gateway demands CSD/HostScan posture assessment, which we cannot do."""


# --- tunnel ----------------------------------------------------------------


class TunnelError(PylisError):
    """Base for CSTP tunnel failures."""


class HandshakeRejected(TunnelError):
    """``CONNECT /CSCOSSLC/tunnel`` did not return 200."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(f"tunnel handshake rejected: {status} {reason}")
        self.status = status
        self.reason = reason


class TunnelClosed(TunnelError):
    """The tunnel went away: TLS EOF, DISCONN, TERM_SERVER, or DPD timeout."""


class RekeyFailed(TunnelError):
    """Proactive rekey could not re-establish the tunnel."""


class TunnelAddressChanged(TunnelError):
    """Reconnect succeeded but the gateway assigned a different address.

    Every open socket must be aborted: their four-tuples are no longer valid.
    """


# The network branch -- NetworkError and everything under it -- is imported at
# the top of this module from usernet.errors, where the stack that raises it
# lives. Defining it again here would produce a second set of classes that look
# identical and never match in an `except`.
