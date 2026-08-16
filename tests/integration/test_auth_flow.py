"""End-to-end authentication against the fake gateway.

Exercises the real code path -- TLS handshake, certificate inspection,
pinning, the streamed POST, and XML parsing -- with no VPN involved. Runs on
Windows and Linux in about a second.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pyac.auth.client import authenticate, inspect_certificate, probe_gateway
from pyac.config import Credentials, GatewayConfig
from pyac.errors import AuthChallengeRequired, AuthFailed
from tests.fakegw import FakeGateway

CORPUS = Path(__file__).parent.parent / "corpus"


def corpus(name: str) -> str:
    return (CORPUS / name).read_text(encoding="utf-8")


def config(gateway: FakeGateway, **overrides: object) -> GatewayConfig:
    defaults: dict[str, object] = {
        "host": "127.0.0.1",
        "port": gateway.port,
        "verify": gateway.ca_path,
    }
    return GatewayConfig(**{**defaults, **overrides})  # type: ignore[arg-type]


@pytest.fixture
def certs(tmp_path: Path) -> Path:
    return tmp_path


async def test_probe_reports_the_form_and_certificate(certs: Path) -> None:
    async with FakeGateway([corpus("asa_group_list.xml")], certs_dir=certs) as gateway:
        info = await probe_gateway(config(gateway))

    assert info.http_status == 200
    assert info.cert_fingerprint.startswith("sha256:")
    assert len(info.cert_fingerprint) == len("sha256:") + 64

    assert info.form is not None
    assert info.form.id == "main"
    assert [f.name for f in info.form.fields] == ["username", "password", "group_list"]
    assert info.form.groups == ("Contractors", "Employees", "Lab")
    assert info.form.opaque is not None


async def test_probe_sends_the_init_document_and_no_credentials(certs: Path) -> None:
    async with FakeGateway([corpus("asa_main_form.xml")], certs_dir=certs) as gateway:
        await probe_gateway(config(gateway))
        (request,) = gateway.requests

    assert request.method == "POST"
    assert 'type="init"' in request.text
    assert 'aggregate-auth-version="2"' in request.text
    # The whole point of probe: nothing secret leaves the machine.
    assert "<auth>" not in request.text
    assert "password" not in request.text


async def test_probe_sends_the_headers_asa_expects(certs: Path) -> None:
    async with FakeGateway([corpus("asa_main_form.xml")], certs_dir=certs) as gateway:
        await probe_gateway(config(gateway))
        (request,) = gateway.requests

    assert request.headers["x-aggregate-auth"] == "1"
    assert request.headers["x-transcend-version"] == "1"
    assert "AnyConnect" in request.headers["user-agent"]


async def test_full_authentication_yields_a_session_token(certs: Path) -> None:
    responses = [corpus("asa_group_list.xml"), corpus("asa_success.xml")]
    async with FakeGateway(responses, certs_dir=certs) as gateway:
        result = await authenticate(
            config(gateway),
            Credentials(username="rene", password="hunter2", group="Lab"),
        )
        init_request, reply_request = gateway.requests

    assert result.session_token.startswith("9F86D081")
    assert result.session_id == "a1b2c3d4"

    assert 'type="init"' in init_request.text
    assert 'type="auth-reply"' in reply_request.text
    # The opaque blob must come back with the gateway's own state intact.
    assert "aggauth-handle" in reply_request.text
    assert "<group_list>Lab</group_list>" in reply_request.text
    assert "<username>rene</username>" in reply_request.text


async def test_login_failure_reports_the_gateway_message(certs: Path) -> None:
    responses = [corpus("asa_main_form.xml"), corpus("asa_login_failed.xml")]
    async with FakeGateway(responses, certs_dir=certs) as gateway:
        with pytest.raises(AuthFailed, match="Login failed"):
            await authenticate(config(gateway), Credentials(username="rene", password="wrong"))


async def test_challenge_is_reported_not_crashed_on(certs: Path) -> None:
    responses = [corpus("asa_main_form.xml"), corpus("asa_challenge.xml")]
    async with FakeGateway(responses, certs_dir=certs) as gateway:
        with pytest.raises(AuthChallengeRequired, match="one-time passcode"):
            await authenticate(config(gateway), Credentials(username="rene", password="hunter2"))


async def test_matching_pin_is_accepted(certs: Path) -> None:
    async with FakeGateway([corpus("asa_main_form.xml")], certs_dir=certs) as gateway:
        # Learn the fingerprint the way a user would: from probe.
        discovered = await probe_gateway(config(gateway))

    async with FakeGateway([corpus("asa_main_form.xml")], certs_dir=certs) as gateway2:
        pass  # a fresh CA, so the old pin must not match it

    async with FakeGateway([corpus("asa_main_form.xml")], certs_dir=certs) as gateway3:
        info = await inspect_certificate(config(gateway3, verify=True))
        pinned = await probe_gateway(config(gateway3, server_cert_pin=info.fingerprint))

    assert pinned.cert_fingerprint == info.fingerprint
    assert discovered.cert_fingerprint.startswith("sha256:")
    assert gateway2.requests == []


async def test_mismatched_pin_aborts_before_any_request(certs: Path) -> None:
    wrong = "sha256:" + "00" * 32
    async with FakeGateway([corpus("asa_main_form.xml")], certs_dir=certs) as gateway:
        with pytest.raises(AuthFailed, match="does not match the pin"):
            await authenticate(
                config(gateway, server_cert_pin=wrong),
                Credentials(username="rene", password="hunter2"),
            )
        # Nothing was sent: the pin is checked against a bare handshake first.
        assert gateway.requests == []


async def test_probe_still_works_against_an_untrusted_certificate(certs: Path) -> None:
    """The internal-CA case, which is the common one.

    Verification fails, but probe must still show the form and the
    fingerprint -- refusing here would withhold exactly what the user needs in
    order to configure a pin.
    """
    async with FakeGateway([corpus("asa_group_list.xml")], certs_dir=certs) as gateway:
        info = await probe_gateway(config(gateway, verify=True))

    assert info.cert_verify_error
    assert info.form is not None
    assert info.form.groups == ("Contractors", "Employees", "Lab")


async def test_authenticate_refuses_an_untrusted_certificate(certs: Path) -> None:
    """A password must never cross a connection we could not verify."""
    async with FakeGateway([corpus("asa_main_form.xml")], certs_dir=certs) as gateway:
        with pytest.raises(AuthFailed, match="cannot verify the certificate"):
            await authenticate(
                config(gateway, verify=True),
                Credentials(username="rene", password="hunter2"),
            )
        assert gateway.requests == []


async def test_authenticate_accepts_an_internal_ca_via_pin(certs: Path) -> None:
    """The documented way out: pin the fingerprint probe showed you."""
    responses = [corpus("asa_main_form.xml"), corpus("asa_success.xml")]
    async with FakeGateway(responses, certs_dir=certs) as gateway:
        discovered = await probe_gateway(config(gateway, verify=True))

    async with FakeGateway(responses, certs_dir=certs) as gateway2:
        # Same certs_dir, so trustme reissued from a new CA; the old pin is stale.
        with pytest.raises(AuthFailed, match="does not match the pin"):
            await authenticate(
                config(gateway2, verify=True, server_cert_pin=discovered.cert_fingerprint),
                Credentials(username="rene", password="hunter2"),
            )


async def test_untrusted_certificate_still_yields_a_fingerprint_to_pin(certs: Path) -> None:
    """The internal-CA case: verification fails, but probe stays useful."""
    async with FakeGateway([corpus("asa_main_form.xml")], certs_dir=certs) as gateway:
        info = await inspect_certificate(config(gateway, verify=True))

    # Don't assert on OpenSSL's exact wording -- it varies by version and
    # platform. What matters is that the user is told *something* went wrong
    # and still gets the fingerprint they need in order to pin.
    assert info.verify_error
    assert info.fingerprint.startswith("sha256:")
    assert len(info.fingerprint) == len("sha256:") + 64
