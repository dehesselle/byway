"""Parsed representations of the gateway's authentication XML.

Gateways differ -- ASA, FTD, ocserv, and Meraki all vary in field names, in
whether group selection needs an extra round trip, and in what they put in
``<opaque>``. So these model whatever the gateway *described*, rather than
assuming a fixed username/password shape, and the reply is built by filling in
the fields the server actually declared.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class FormOption:
    """One ``<option>`` of a ``<select>``, typically a tunnel group."""

    value: str
    label: str
    selected: bool = False


@dataclass(frozen=True, slots=True)
class FormField:
    """One ``<input>`` or ``<select>`` the gateway asked us to fill in."""

    name: str
    type: str  # "text", "password", "hidden", "select", or whatever else appears
    label: str | None = None
    value: str | None = None  # server-supplied default, echoed back if we have nothing
    options: tuple[FormOption, ...] = ()

    @property
    def is_secret(self) -> bool:
        return self.type == "password"


@dataclass(frozen=True, slots=True)
class AuthForm:
    """``<auth id="main">`` or ``<auth id="challenge">`` -- the gateway wants input.

    ``opaque`` is the gateway's own state blob. It must be echoed back
    unmodified in the reply; we carry it as serialized XML rather than parsing
    it, because its contents are none of our business.
    """

    id: str  # "main" or "challenge"
    fields: tuple[FormField, ...] = ()
    title: str | None = None
    message: str | None = None
    banner: str | None = None
    error: str | None = None
    opaque: str | None = None

    @property
    def is_challenge(self) -> bool:
        return self.id == "challenge"

    @property
    def group_field(self) -> FormField | None:
        """The tunnel-group selector, if the gateway offered one."""
        for f in self.fields:
            if f.options:
                return f
        return None

    @property
    def groups(self) -> tuple[str, ...]:
        group = self.group_field
        return tuple(o.value for o in group.options) if group else ()


@dataclass(frozen=True, slots=True)
class AuthSuccess:
    """``<auth id="success">`` -- authentication completed.

    ``session_token`` is what becomes the ``webvpn`` cookie value on the
    tunnel's CONNECT request.
    """

    session_token: str
    session_id: str | None = None
    banner: str | None = None


@dataclass(frozen=True, slots=True)
class GatewayInfo:
    """What ``pyac probe`` learned about a gateway without authenticating."""

    host: str
    port: int
    cert_fingerprint: str  # "sha256:<hex>", comparable with openconnect --servercert
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_after: str | None = None
    cert_verify_error: str | None = None
    """Why system-trust verification failed, if it did -- the internal-CA case.
    Reported alongside the fingerprint so the user knows what to pin."""
    form: AuthForm | None = None
    raw_response: str = ""
    http_status: int = 0
    redirected_to: str | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
