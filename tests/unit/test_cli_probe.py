"""Rendering and argument handling for ``pyac probe``.

The report is the whole product of M1 -- it is what tells us which dialect a
gateway speaks -- so its content is worth pinning down.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pyac.auth.models import AuthForm, GatewayInfo
from pyac.auth.xml_forms import parse_auth_response
from pyac.cli.cmd_probe import _as_dict, _print_report, parse_gateway
from pyac.cli.main import build_parser

CORPUS = Path(__file__).parent.parent / "corpus"


def info_for(corpus_name: str) -> GatewayInfo:
    raw = (CORPUS / corpus_name).read_text(encoding="utf-8")
    form = parse_auth_response(raw)
    assert isinstance(form, AuthForm)
    return GatewayInfo(
        host="vpn.corp.example",
        port=443,
        cert_fingerprint="sha256:" + "ab" * 32,
        cert_subject="CN=vpn.corp.example",
        cert_issuer="CN=Corp Issuing CA",
        cert_not_after="Dec 31 23:59:59 2026 GMT",
        form=form,
        raw_response=raw,
        http_status=200,
    )


# --- argument parsing ------------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "host", "port"),
    [
        ("vpn.corp.example", "vpn.corp.example", 443),
        ("https://vpn.corp.example", "vpn.corp.example", 443),
        ("https://vpn.corp.example/", "vpn.corp.example", 443),
        ("vpn.corp.example:8443", "vpn.corp.example", 8443),
        ("https://vpn.corp.example:8443/", "vpn.corp.example", 8443),
    ],
)
def test_gateway_spec_forms(spec: str, host: str, port: int) -> None:
    gateway = parse_gateway(spec, pin=None, no_verify=False)
    assert (gateway.host, gateway.port) == (host, port)


def test_no_verify_and_pin_are_wired_through() -> None:
    gateway = parse_gateway("vpn.corp.example", pin="sha256:beef", no_verify=True)
    assert gateway.verify is False
    assert gateway.server_cert_pin == "sha256:beef"


def test_probe_is_registered_on_the_top_level_parser() -> None:
    args = build_parser().parse_args(["probe", "vpn.corp.example"])
    assert args.command == "probe"
    assert args.gateway == "vpn.corp.example"
    assert callable(args.handler)


# --- report rendering ------------------------------------------------------


def test_report_shows_fields_groups_and_certificate(capsys: pytest.CaptureFixture[str]) -> None:
    _print_report(info_for("asa_group_list.xml"), show_raw=False)
    out = capsys.readouterr().out

    assert "vpn.corp.example:443" in out
    assert "sha256:" + "ab" * 32 in out
    assert "CN=Corp Issuing CA" in out

    assert "username" in out
    assert "password" in out
    assert "(secret)" in out

    assert "Contractors" in out
    assert "* Employees" in out  # the gateway's default is marked
    assert "Lab" in out
    assert "opaque blob  present" in out


def test_report_flags_an_mfa_challenge(capsys: pytest.CaptureFixture[str]) -> None:
    _print_report(info_for("asa_challenge.xml"), show_raw=False)
    out = capsys.readouterr().out
    assert "MFA" in out
    assert "does not yet support" in out


def test_report_dumps_the_body_when_the_form_is_unrecognised(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An unknown dialect must still show the user (and us) the raw XML."""
    unknown = GatewayInfo(
        host="gw",
        port=443,
        cert_fingerprint="sha256:" + "00" * 32,
        form=None,
        raw_response="<something-else/>",
        http_status=200,
    )
    _print_report(unknown, show_raw=False)
    out = capsys.readouterr().out

    assert "no recognisable <auth> form" in out
    assert "tests/corpus/" in out
    assert "<something-else/>" in out


def test_json_output_is_machine_readable() -> None:
    payload = json.loads(json.dumps(_as_dict(info_for("asa_group_list.xml"))))

    assert payload["host"] == "vpn.corp.example"
    assert payload["certificate"]["issuer"] == "CN=Corp Issuing CA"
    assert payload["auth"]["groups"] == ["Contractors", "Employees", "Lab"]
    assert payload["auth"]["has_opaque"] is True
    assert {f["name"] for f in payload["auth"]["fields"]} == {
        "username",
        "password",
        "group_list",
    }


def test_json_output_handles_an_unparsed_response() -> None:
    unknown = GatewayInfo(host="gw", port=443, cert_fingerprint="sha256:00", form=None)
    assert _as_dict(unknown)["auth"] is None
