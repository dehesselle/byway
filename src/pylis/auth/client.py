# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The HTTP side of aggregate-auth.

Certificate handling is the subtle part. Internal CAs are the norm for VPN
gateways, so pinning has to be a first-class option rather than an
afterthought -- and pinning is only meaningful if the check happens *before*
any credential is sent. So the certificate is fetched in a dedicated
handshake, checked, and only then is the HTTP client built.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ssl
from dataclasses import dataclass, field
from typing import Any

import httpx

from pylis.auth.models import AuthForm, AuthSuccess, GatewayInfo
from pylis.auth.xml_forms import (
    MAX_XML_BYTES,
    build_auth_reply,
    build_init_request,
    fill_form,
    parse_auth_response,
)
from pylis.config import Credentials, GatewayConfig
from pylis.errors import (
    AuthChallengeRequired,
    AuthFailed,
    PostureCheckRequired,
    ProtocolParseError,
)

CONNECT_TIMEOUT = 15.0
REQUEST_TIMEOUT = 30.0

# ASA looks for these on the authentication POST.
_AUTH_HEADERS = {
    "Accept": "*/*",
    "Accept-Encoding": "identity",
    "X-Transcend-Version": "1",
    "X-Aggregate-Auth": "1",
    "Content-Type": "application/x-www-form-urlencoded",
}


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    """What a bare TLS handshake told us about the gateway."""

    fingerprint: str  # "sha256:<hex>"
    der: bytes = field(repr=False, default=b"")
    subject: str | None = None
    issuer: str | None = None
    not_after: str | None = None
    verify_error: str | None = None
    """Why system-trust verification failed, if it did. A gateway behind an
    internal CA fails here routinely; the fingerprint is what to pin."""


def sha256_fingerprint(der: bytes) -> str:
    """openconnect-compatible ``--servercert`` fingerprint."""
    return "sha256:" + hashlib.sha256(der).hexdigest()


def _format_name(name: Any) -> str | None:
    """Flatten getpeercert()'s nested RDN tuples into ``CN=x, O=y``."""
    if not name:
        return None
    parts = [f"{key}={value}" for rdn in name for key, value in rdn]
    return ", ".join(parts) or None


def unverified_context() -> ssl.SSLContext:
    """A context that completes a handshake without judging the certificate."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def build_ssl_context(gateway: GatewayConfig) -> ssl.SSLContext:
    """Build the context used for the authentication requests.

    When a pin is configured, CA verification is switched off deliberately:
    the pin *is* the trust decision, and it has already been checked against a
    real handshake by :func:`inspect_certificate`.
    """
    if isinstance(gateway.verify, ssl.SSLContext):
        return gateway.verify

    context = ssl.create_default_context()
    if gateway.server_cert_pin or gateway.verify is False:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    elif isinstance(gateway.verify, str):
        context.load_verify_locations(cafile=gateway.verify)
    return context


async def _handshake(host: str, port: int, context: ssl.SSLContext) -> tuple[bytes, Any]:
    """Complete a TLS handshake and return the peer certificate, then hang up."""
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=context, server_hostname=host),
        timeout=CONNECT_TIMEOUT,
    )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der: bytes = ssl_object.getpeercert(binary_form=True) or b""
        decoded = ssl_object.getpeercert()
        return der, decoded
    finally:
        writer.close()
        # The peer may already be gone; we have what we came for either way.
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()


async def inspect_certificate(gateway: GatewayConfig) -> CertificateInfo:
    """Fetch the gateway certificate, preferring a verified handshake.

    Tries system trust first so a well-configured gateway yields full subject
    and issuer detail, then falls back to an unverified handshake purely to
    recover the fingerprint. That fallback is what makes ``pylis probe`` useful
    against an internal CA: it reports *why* verification failed and what to
    pin, instead of just refusing to connect.
    """
    verify_error: str | None = None

    if not gateway.server_cert_pin and gateway.verify is not False:
        try:
            context = build_ssl_context(gateway)
            der, decoded = await _handshake(gateway.host, gateway.port, context)
            return CertificateInfo(
                fingerprint=sha256_fingerprint(der),
                der=der,
                subject=_format_name((decoded or {}).get("subject")),
                issuer=_format_name((decoded or {}).get("issuer")),
                not_after=(decoded or {}).get("notAfter"),
            )
        except ssl.SSLCertVerificationError as exc:
            verify_error = exc.verify_message or str(exc)

    der, _ = await _handshake(gateway.host, gateway.port, unverified_context())

    return CertificateInfo(
        fingerprint=sha256_fingerprint(der),
        der=der,
        verify_error=verify_error,
    )


def check_pin(gateway: GatewayConfig, certificate: CertificateInfo) -> None:
    """Enforce ``server_cert_pin`` before anything sensitive is transmitted."""
    if not gateway.server_cert_pin:
        return
    expected = gateway.server_cert_pin.strip().lower()
    if not expected.startswith("sha256:"):
        expected = "sha256:" + expected
    if expected != certificate.fingerprint.lower():
        raise AuthFailed(
            f"gateway certificate does not match the pin\n"
            f"  expected: {expected}\n"
            f"  actual:   {certificate.fingerprint}"
        )


def _new_client(gateway: GatewayConfig, context: ssl.SSLContext | None = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=gateway.base_url,
        verify=context if context is not None else build_ssl_context(gateway),
        follow_redirects=True,  # load balancers redirect mid-auth
        timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=CONNECT_TIMEOUT),
        headers={"User-Agent": gateway.user_agent, **_AUTH_HEADERS},
    )


async def _post_xml(client: httpx.AsyncClient, body: bytes) -> tuple[httpx.Response, str]:
    """POST an XML body and return the response with its decoded text.

    Streamed rather than buffered so an oversized or unbounded body is refused
    while it arrives, instead of after we have already held it all in memory.
    A ``Content-Length`` header would not do: it can be absent, or a lie.
    """
    async with client.stream("POST", "/", content=body) as response:
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > MAX_XML_BYTES:
                raise ProtocolParseError(f"gateway response exceeds the {MAX_XML_BYTES}-byte limit")
            chunks.append(chunk)
        raw = b"".join(chunks)

    return response, raw.decode(response.encoding or "utf-8", errors="replace")


def _check_posture_required(text: str) -> None:
    """Detect CSD/HostScan before it turns into a mysterious hang."""
    lowered = text.lower()
    if "<csd" in lowered or "hostscan" in lowered:
        raise PostureCheckRequired(
            "gateway requires CSD/HostScan posture assessment, which pylis cannot perform"
        )


async def logout(gateway: GatewayConfig, session_token: str) -> None:
    """Release the session on the gateway.

    Not optional housekeeping: gateways enforce concurrent-session limits, so
    leaked sessions eventually lock the user out of their own VPN with no
    obvious cause. Best-effort -- a failure here must never mask the real
    reason we are shutting down.
    """
    context = build_ssl_context(gateway)
    with contextlib.suppress(Exception):
        async with _new_client(gateway, context) as client:
            await client.get(
                "/+webvpn+/webvpn_logout.html",
                headers={"Cookie": f"webvpn={session_token}"},
            )


async def probe_gateway(gateway: GatewayConfig) -> GatewayInfo:
    """Ask the gateway what it wants, without sending any credential.

    This is the first thing to run against a new gateway: it reveals the
    dialect, the form fields, the tunnel groups, and the certificate, with no
    risk of a failed-login lockout.
    """
    certificate = await inspect_certificate(gateway)
    check_pin(gateway, certificate)

    # If system trust rejected the certificate, carry on unverified anyway --
    # probe sends no credentials, and refusing here would withhold precisely
    # the form and fingerprint the user needs in order to configure a pin.
    # The report says loudly that verification failed.
    context = unverified_context() if certificate.verify_error else None

    async with _new_client(gateway, context) as client:
        init = build_init_request(group_access=gateway.base_url)
        response, raw = await _post_xml(client, init)

        form: AuthForm | None = None
        with contextlib.suppress(ProtocolParseError, AuthFailed):
            # Report the raw body regardless of whether it parses -- against an
            # unexpected gateway that body is the most useful thing probe shows.
            parsed = parse_auth_response(raw)
            form = parsed if isinstance(parsed, AuthForm) else None

        final_url = str(response.url).rstrip("/")
        redirected = final_url if final_url != gateway.base_url else None

        return GatewayInfo(
            host=gateway.host,
            port=gateway.port,
            cert_fingerprint=certificate.fingerprint,
            cert_subject=certificate.subject,
            cert_issuer=certificate.issuer,
            cert_not_after=certificate.not_after,
            cert_verify_error=certificate.verify_error,
            form=form,
            raw_response=raw,
            http_status=response.status_code,
            redirected_to=redirected,
            response_headers=dict(response.headers),
        )


async def authenticate(gateway: GatewayConfig, credentials: Credentials) -> AuthSuccess:
    """Run the full form exchange and return the session token.

    The token becomes the ``webvpn`` cookie on the tunnel's CONNECT request.
    """
    certificate = await inspect_certificate(gateway)
    check_pin(gateway, certificate)

    # Unlike probe, this request carries a password. An untrusted certificate
    # is therefore fatal: refuse, and point at the two legitimate ways out.
    if certificate.verify_error:
        raise AuthFailed(
            f"cannot verify the certificate of {gateway.host}: {certificate.verify_error}\n"
            f"  fingerprint: {certificate.fingerprint}\n"
            f"  run `pylis probe {gateway.host}` to inspect it, then either pass\n"
            f"  --pin {certificate.fingerprint} or supply your CA bundle"
        )

    async with _new_client(gateway) as client:
        init = build_init_request(group_access=gateway.base_url)
        _response, raw = await _post_xml(client, init)
        _check_posture_required(raw)
        parsed = parse_auth_response(raw)

        if isinstance(parsed, AuthSuccess):
            return parsed  # certificate-only auth: nothing was asked of us

        if parsed.is_challenge:
            raise AuthChallengeRequired(parsed.message or parsed.title or "additional factor")

        values = fill_form(
            parsed,
            username=credentials.username,
            password=credentials.password,
            group=credentials.group,
        )
        reply = build_auth_reply(
            group_access=gateway.base_url,
            values=values,
            opaque=parsed.opaque,
            device_id=gateway.device_id,
        )
        _response, raw = await _post_xml(client, reply)
        result = parse_auth_response(raw)

        if isinstance(result, AuthSuccess):
            return result
        if result.is_challenge:
            raise AuthChallengeRequired(result.message or result.title or "additional factor")
        raise AuthFailed(result.error or result.message or "gateway rejected the credentials")
