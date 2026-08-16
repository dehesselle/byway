"""Sans-IO builder and parser for the aggregate-auth XML exchange.

The exchange is::

    client  --> <config-auth type="init">
    gateway <-- <config-auth type="auth-request"> with <auth id="main"> and <opaque>
    client  --> <config-auth type="auth-reply"> echoing <opaque>, plus the filled form
    gateway <-- <config-auth type="complete"> with <auth id="success"> and <session-token>

No I/O happens here, so every gateway dialect in ``tests/corpus/`` can be
exercised without a network.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Final

from defusedxml.ElementTree import fromstring as _defused_fromstring

from pyac.auth.models import AuthForm, AuthSuccess, FormField, FormOption
from pyac.errors import AuthFailed, ProtocolParseError

# The gateway is untrusted input. Cap the body before parsing rather than
# after: a decompression or entity bomb is only cheap to refuse up front.
MAX_XML_BYTES: Final = 256 * 1024

DEFAULT_VERSION: Final = "4.10.07061"
DEFAULT_DEVICE_ID: Final = "win"

_XML_DECL: Final = b'<?xml version="1.0" encoding="UTF-8"?>\n'


def _text(element: ET.Element | None) -> str | None:
    """Stripped text of an element, or None if absent or blank."""
    if element is None or element.text is None:
        return None
    stripped = element.text.strip()
    return stripped or None


def _serialize(element: ET.Element) -> str:
    """Serialize a subtree, dropping the tail text that follows it."""
    element.tail = None
    text: str = ET.tostring(element, encoding="unicode")
    return text


def _finish(root: ET.Element) -> bytes:
    """Serialize a request document with our own XML declaration."""
    body: bytes = ET.tostring(root, encoding="utf-8", xml_declaration=False)
    return _XML_DECL + body


# --- building --------------------------------------------------------------


def build_init_request(
    *,
    group_access: str,
    version: str = DEFAULT_VERSION,
    device_id: str = DEFAULT_DEVICE_ID,
    group_select: str | None = None,
) -> bytes:
    """Build the opening ``<config-auth type="init">`` POST body.

    Note what is *not* here: no ``<capabilities>`` advertising
    ``single-sign-on-v2``. A gateway offering both password and SAML will
    choose SAML if the client claims to support it, and we cannot complete
    that flow -- so we do not claim it.
    """
    root = ET.Element(
        "config-auth",
        {"client": "vpn", "type": "init", "aggregate-auth-version": "2"},
    )
    ET.SubElement(root, "version", {"who": "vpn"}).text = version
    ET.SubElement(root, "device-id").text = device_id
    if group_select:
        ET.SubElement(root, "group-select").text = group_select
    ET.SubElement(root, "group-access").text = group_access
    return _finish(root)


def build_auth_reply(
    *,
    group_access: str,
    values: dict[str, str],
    opaque: str | None = None,
    version: str = DEFAULT_VERSION,
    device_id: str = DEFAULT_DEVICE_ID,
    group_select: str | None = None,
) -> bytes:
    """Build the ``<config-auth type="auth-reply">`` POST body.

    ``opaque`` is round-tripped as the exact subtree the gateway sent, not
    rebuilt from a model of what we think it contains -- it is gateway-private
    state and its structure varies.
    """
    root = ET.Element(
        "config-auth",
        {"client": "vpn", "type": "auth-reply", "aggregate-auth-version": "2"},
    )
    ET.SubElement(root, "version", {"who": "vpn"}).text = version
    ET.SubElement(root, "device-id").text = device_id
    ET.SubElement(root, "session-token")
    ET.SubElement(root, "session-id")
    if group_select:
        ET.SubElement(root, "group-select").text = group_select
    ET.SubElement(root, "group-access").text = group_access

    if opaque:
        try:
            root.append(_defused_fromstring(opaque, forbid_dtd=True))
        except ET.ParseError as exc:  # pragma: no cover - only on a malformed round trip
            raise ProtocolParseError(f"cannot round-trip <opaque>: {exc}") from exc

    auth = ET.SubElement(root, "auth")
    for name, value in values.items():
        ET.SubElement(auth, name).text = value

    return _finish(root)


# --- parsing ---------------------------------------------------------------


def parse_auth_response(data: bytes | str) -> AuthForm | AuthSuccess:
    """Parse a gateway response into a form to fill or a completed session.

    Raises :class:`ProtocolParseError` for anything unrecognisable and
    :class:`AuthFailed` when the gateway reports success but withholds a
    session token.
    """
    if len(data) > MAX_XML_BYTES:
        raise ProtocolParseError(
            f"gateway response of {len(data)} bytes exceeds the {MAX_XML_BYTES}-byte limit"
        )

    try:
        root = _defused_fromstring(data, forbid_dtd=True)
    except ET.ParseError as exc:
        raise ProtocolParseError(f"gateway response is not well-formed XML: {exc}") from exc
    except ValueError as exc:
        # defusedxml raises its own subclasses of ValueError for DTDs and
        # entity bombs; surface them as a parse failure like anything else.
        raise ProtocolParseError(f"gateway response rejected: {exc}") from exc

    if root.tag != "config-auth":
        raise ProtocolParseError(f"expected <config-auth>, got <{root.tag}>")

    auth = root.find("auth")
    if auth is None:
        raise ProtocolParseError("gateway response has no <auth> element")

    auth_id = auth.get("id", "")
    if auth_id == "success":
        return _parse_success(root, auth)
    return _parse_form(root, auth, auth_id)


def _parse_success(root: ET.Element, auth: ET.Element) -> AuthSuccess:
    # The token lives under <config-auth> on most gateways but under <auth> on
    # some, so look in both rather than guessing.
    token = _text(root.find("session-token")) or _text(auth.find("session-token"))
    session_id = _text(root.find("session-id")) or _text(auth.find("session-id"))
    if not token:
        raise AuthFailed("gateway reported success but returned no <session-token>")
    return AuthSuccess(
        session_token=token,
        session_id=session_id,
        banner=_text(auth.find("banner")),
    )


def _parse_form(root: ET.Element, auth: ET.Element, auth_id: str) -> AuthForm:
    opaque_element = root.find("opaque")
    form = auth.find("form")

    fields: list[FormField] = []
    if form is not None:
        for child in form:
            if child.tag == "input":
                name = child.get("name")
                if not name:
                    continue
                fields.append(
                    FormField(
                        name=name,
                        type=child.get("type", "text"),
                        label=child.get("label"),
                        value=child.get("value") or _text(child),
                    )
                )
            elif child.tag == "select":
                name = child.get("name")
                if not name:
                    continue
                options = tuple(
                    FormOption(
                        # ASA puts the group in the option's text and, in some
                        # versions, in a value attribute; prefer the attribute.
                        value=option.get("value") or (option.text or "").strip(),
                        label=option.get("label") or (option.text or "").strip(),
                        selected=option.get("selected", "").lower() in ("true", "1"),
                    )
                    for option in child.findall("option")
                )
                fields.append(
                    FormField(
                        name=name,
                        type="select",
                        label=child.get("label"),
                        options=options,
                    )
                )

    return AuthForm(
        id=auth_id or "main",
        fields=tuple(fields),
        title=_text(auth.find("title")),
        message=_text(auth.find("message")),
        banner=_text(auth.find("banner")),
        error=_text(auth.find("error")),
        opaque=_serialize(opaque_element) if opaque_element is not None else None,
    )


# --- filling ---------------------------------------------------------------


def fill_form(
    form: AuthForm,
    *,
    username: str,
    password: str,
    group: str | None = None,
) -> dict[str, str]:
    """Fill the fields the gateway declared, by their declared types.

    Driven off the server's own ``<form>`` rather than hardcoded field names,
    because those vary across ASA, FTD, and ocserv. Anything we cannot fill is
    reported by name instead of being silently omitted, which would otherwise
    surface as an unexplained authentication failure.
    """
    values: dict[str, str] = {}
    unfillable: list[str] = []
    text_used = False
    password_used = False

    for field in form.fields:
        if field.options:
            values[field.name] = _choose_option(field, group)
        elif field.type == "password":
            # A second password field is a token or secondary credential, not
            # a repeat of the first; echo a default if one was given, else say so.
            if password_used:
                if field.value is not None:
                    values[field.name] = field.value
                else:
                    unfillable.append(f"{field.name} (second password field)")
            else:
                values[field.name] = password
                password_used = True
        elif field.type == "hidden":
            values[field.name] = field.value or ""
        elif field.type == "text":
            if text_used:
                if field.value is not None:
                    values[field.name] = field.value
                else:
                    unfillable.append(f"{field.name} (second text field)")
            else:
                values[field.name] = username
                text_used = True
        elif field.value is not None:
            values[field.name] = field.value
        else:
            unfillable.append(f"{field.name} (type={field.type!r})")

    if unfillable:
        raise AuthFailed(
            "gateway asked for fields pyac cannot supply: "
            + ", ".join(unfillable)
            + " -- run `pyac probe` to see the full form"
        )
    return values


def _choose_option(field: FormField, group: str | None) -> str:
    """Pick a ``<select>`` option, preferring the user's choice."""
    if group is not None:
        for option in field.options:
            if group in (option.value, option.label):
                return option.value
        available = ", ".join(o.value for o in field.options)
        raise AuthFailed(f"group {group!r} not offered by the gateway; available: {available}")

    for option in field.options:
        if option.selected:
            return option.value
    return field.options[0].value if field.options else ""
