"""Configuration shared by the auth, tunnel, and API layers.

Lives outside :mod:`pylis.api` so :mod:`pylis.auth` can use it without importing
the public API and creating a cycle; ``api`` re-exports these names.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass

DEFAULT_USER_AGENT = "AnyConnect Windows 4.10.07061"


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    """How to reach and trust a VPN gateway."""

    host: str
    port: int = 443

    verify: bool | str | ssl.SSLContext = True
    """``True`` for the system trust store, a path to a CA bundle, an explicit
    context, or ``False`` to disable verification entirely."""

    server_cert_pin: str | None = None
    """``"sha256:<hex>"``, interchangeable with openconnect's ``--servercert``.

    Internal CAs are the common case, and pinning the gateway's certificate is
    the right answer to that -- not turning verification off. When set, the
    certificate is fetched and checked before any request is sent.
    """

    user_agent: str = DEFAULT_USER_AGENT
    device_id: str = "win"

    @property
    def base_url(self) -> str:
        if self.port == 443:
            return f"https://{self.host}"
        return f"https://{self.host}:{self.port}"


@dataclass(frozen=True, slots=True)
class Credentials:
    """Credentials for the v1 username/password flow.

    ``__repr__`` is suppressed for the password so it cannot reach a log line
    or a traceback by accident.
    """

    username: str
    password: str = ""
    group: str | None = None

    def __repr__(self) -> str:
        group = f", group={self.group!r}" if self.group else ""
        return f"Credentials(username={self.username!r}, password=<redacted>{group})"
