"""Exception hierarchy for pyac.

Every error the library raises derives from :class:`PyacError`. The
``NetworkError`` branch mirrors the errors an ordinary socket would raise, so
the SOCKS5 layer can map them onto reply codes with a single table.
"""

from __future__ import annotations


class PyacError(Exception):
    """Base class for every pyac error."""


class ProtocolParseError(PyacError):
    """Malformed input from the gateway, the network, or a SOCKS client.

    Parsers raise only this. Never let ``IndexError``, ``struct.error``, or
    ``UnicodeDecodeError`` escape a parser -- callers cannot distinguish those
    from genuine bugs.
    """


# --- authentication --------------------------------------------------------


class AuthError(PyacError):
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


class TunnelError(PyacError):
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


# --- network (socket-level, mapped onto SOCKS5 reply codes) ----------------


class NetworkError(PyacError):
    """Base for errors on a connection carried by the tunnel."""


class ConnectionRefused(NetworkError):
    """RST in response to SYN, or an ICMP hard error during connect."""


class ConnectionReset(NetworkError):
    """RST on an established connection."""


class ConnectionTimeout(NetworkError):
    """Connect timed out, or retransmission backoff was exhausted."""


class HostUnreachable(NetworkError):
    """ICMP destination unreachable, or the name did not resolve."""


class RouteNotAllowed(NetworkError):
    """The destination lies outside the gateway's split-tunnel scope.

    Raised eagerly rather than letting the gateway drop the packets silently,
    which would otherwise surface as an unexplained connect timeout.
    """

    def __init__(self, dst: str) -> None:
        super().__init__(
            f"{dst} is outside the tunnel's split-include routes; "
            f"use --route-policy all or --route-add to override"
        )
        self.dst = dst


class ResolveError(NetworkError):
    """In-tunnel DNS resolution failed."""
