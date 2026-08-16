"""Aggregate-auth XML tests, driven off a corpus of gateway responses.

Every real response encountered in the wild belongs in ``tests/corpus/``. That
is the whole defence against gateway dialect drift, since the XML layer is the
only place where ASA, FTD, ocserv, and Meraki differences surface.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from pyac.auth.models import AuthForm, AuthSuccess
from pyac.auth.xml_forms import (
    MAX_XML_BYTES,
    build_auth_reply,
    build_init_request,
    fill_form,
    parse_auth_response,
)
from pyac.errors import AuthFailed, ProtocolParseError

CORPUS = Path(__file__).parent.parent / "corpus"


def load(name: str) -> str:
    return (CORPUS / name).read_text(encoding="utf-8")


def parse(name: str) -> AuthForm | AuthSuccess:
    return parse_auth_response(load(name))


# --- building --------------------------------------------------------------


def test_init_request_shape() -> None:
    body = build_init_request(group_access="https://vpn.corp.example")
    root = ET.fromstring(body)

    assert root.tag == "config-auth"
    assert root.attrib == {
        "client": "vpn",
        "type": "init",
        "aggregate-auth-version": "2",
    }
    assert root.findtext("version") == "4.10.07061"
    assert root.findtext("device-id") == "win"
    assert root.findtext("group-access") == "https://vpn.corp.example"


def test_init_request_does_not_advertise_sso() -> None:
    """Claiming single-sign-on-v2 would invite a SAML flow we cannot complete."""
    body = build_init_request(group_access="https://vpn.corp.example")
    assert b"single-sign-on" not in body
    assert b"capabilities" not in body


def test_auth_reply_echoes_opaque_unchanged() -> None:
    form = parse("asa_main_form.xml")
    assert isinstance(form, AuthForm)

    body = build_auth_reply(
        group_access="https://vpn.corp.example",
        values={"username": "rene", "password": "hunter2"},
        opaque=form.opaque,
    )
    root = ET.fromstring(body)

    opaque = root.find("opaque")
    assert opaque is not None
    assert opaque.get("is-for") == "sg"
    assert opaque.findtext("tunnel-group") == "DefaultWEBVPNGroup"
    assert opaque.findtext("aggauth-handle") == "168430090"
    assert opaque.findtext("config-hash") == "1730388000000"


def test_auth_reply_carries_form_values_under_auth() -> None:
    body = build_auth_reply(
        group_access="https://vpn.corp.example",
        values={"username": "rene", "password": "hunter2", "group_list": "Employees"},
    )
    auth = ET.fromstring(body).find("auth")

    assert auth is not None
    assert auth.findtext("username") == "rene"
    assert auth.findtext("password") == "hunter2"
    assert auth.findtext("group_list") == "Employees"


def test_auth_reply_escapes_special_characters() -> None:
    """A password containing XML metacharacters must survive a round trip."""
    nasty = "p&ss<w>rd\"'"
    body = build_auth_reply(
        group_access="https://vpn.corp.example",
        values={"username": "rene", "password": nasty},
    )
    auth = ET.fromstring(body).find("auth")
    assert auth is not None
    assert auth.findtext("password") == nasty


# --- parsing ---------------------------------------------------------------


def test_parse_main_form() -> None:
    form = parse("asa_main_form.xml")
    assert isinstance(form, AuthForm)

    assert form.id == "main"
    assert form.title == "Login"
    assert form.message == "Please enter your username and password."
    assert form.banner is None  # empty element, not the string ""
    assert form.error is None
    assert [(f.name, f.type) for f in form.fields] == [
        ("username", "text"),
        ("password", "password"),
    ]
    assert form.fields[1].is_secret
    assert form.opaque is not None and "aggauth-handle" in form.opaque


def test_parse_group_list() -> None:
    form = parse("asa_group_list.xml")
    assert isinstance(form, AuthForm)

    assert form.groups == ("Contractors", "Employees", "Lab")
    group_field = form.group_field
    assert group_field is not None
    assert group_field.name == "group_list"
    assert [o.value for o in group_field.options if o.selected] == ["Employees"]


def test_parse_success() -> None:
    result = parse("asa_success.xml")
    assert isinstance(result, AuthSuccess)

    assert result.session_token.startswith("9F86D081")
    assert result.session_id == "a1b2c3d4"
    assert result.banner is not None and result.banner.startswith("Authorised")


def test_parse_challenge() -> None:
    form = parse("asa_challenge.xml")
    assert isinstance(form, AuthForm)

    assert form.is_challenge
    assert form.message == "Enter your one-time passcode."
    assert [f.name for f in form.fields] == ["password"]


def test_parse_login_failure_surfaces_the_gateway_message() -> None:
    form = parse("asa_login_failed.xml")
    assert isinstance(form, AuthForm)
    assert form.error == "Login failed."


def test_success_without_token_is_a_failure() -> None:
    xml = (
        '<config-auth client="vpn" type="complete" aggregate-auth-version="2">'
        '<auth id="success"/></config-auth>'
    )
    with pytest.raises(AuthFailed, match="no <session-token>"):
        parse_auth_response(xml)


def test_token_under_auth_is_also_found() -> None:
    """Some gateways nest the token inside <auth> rather than <config-auth>."""
    xml = (
        '<config-auth client="vpn" type="complete" aggregate-auth-version="2">'
        '<auth id="success"><session-token>TOK</session-token></auth></config-auth>'
    )
    result = parse_auth_response(xml)
    assert isinstance(result, AuthSuccess)
    assert result.session_token == "TOK"


# --- hostile input ---------------------------------------------------------


def test_oversized_body_rejected_before_parsing() -> None:
    with pytest.raises(ProtocolParseError, match="exceeds"):
        parse_auth_response("<config-auth/>" + " " * MAX_XML_BYTES)


def test_malformed_xml() -> None:
    with pytest.raises(ProtocolParseError, match="well-formed"):
        parse_auth_response("<config-auth><auth id='main'>")


def test_wrong_root_element() -> None:
    with pytest.raises(ProtocolParseError, match="expected <config-auth>"):
        parse_auth_response("<html><body>Gateway error</body></html>")


def test_missing_auth_element() -> None:
    with pytest.raises(ProtocolParseError, match="no <auth>"):
        parse_auth_response('<config-auth client="vpn" type="init"/>')


def test_entity_expansion_is_refused() -> None:
    """A billion-laughs bomb must be rejected, not expanded."""
    bomb = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
        "<config-auth>&lol1;</config-auth>"
    )
    with pytest.raises(ProtocolParseError):
        parse_auth_response(bomb)


# --- filling ---------------------------------------------------------------


def test_fill_form_uses_declared_field_names() -> None:
    form = parse("asa_main_form.xml")
    assert isinstance(form, AuthForm)
    assert fill_form(form, username="rene", password="hunter2") == {
        "username": "rene",
        "password": "hunter2",
    }


def test_fill_form_defaults_to_the_selected_group() -> None:
    form = parse("asa_group_list.xml")
    assert isinstance(form, AuthForm)
    values = fill_form(form, username="rene", password="hunter2")
    assert values["group_list"] == "Employees"


def test_fill_form_honours_an_explicit_group() -> None:
    form = parse("asa_group_list.xml")
    assert isinstance(form, AuthForm)
    values = fill_form(form, username="rene", password="hunter2", group="Lab")
    assert values["group_list"] == "Lab"


def test_fill_form_rejects_an_unknown_group_by_listing_the_real_ones() -> None:
    form = parse("asa_group_list.xml")
    assert isinstance(form, AuthForm)
    with pytest.raises(AuthFailed, match="Contractors, Employees, Lab"):
        fill_form(form, username="rene", password="hunter2", group="Nope")


def test_fill_form_echoes_hidden_fields() -> None:
    xml = (
        '<config-auth client="vpn" type="auth-request"><auth id="main"><form>'
        '<input type="text" name="username"/>'
        '<input type="password" name="password"/>'
        '<input type="hidden" name="state" value="xyz"/>'
        "</form></auth></config-auth>"
    )
    form = parse_auth_response(xml)
    assert isinstance(form, AuthForm)
    assert fill_form(form, username="rene", password="pw")["state"] == "xyz"


def test_fill_form_reports_a_field_it_cannot_supply() -> None:
    """A second password field is a token, not a repeat -- say so by name."""
    xml = (
        '<config-auth client="vpn" type="auth-request"><auth id="main"><form>'
        '<input type="text" name="username"/>'
        '<input type="password" name="password"/>'
        '<input type="password" name="secondary_password"/>'
        "</form></auth></config-auth>"
    )
    form = parse_auth_response(xml)
    assert isinstance(form, AuthForm)
    with pytest.raises(AuthFailed, match="secondary_password"):
        fill_form(form, username="rene", password="pw")


def test_roundtrip_form_to_reply() -> None:
    """The end-to-end sans-IO path: parse a form, fill it, build the reply."""
    form = parse("asa_group_list.xml")
    assert isinstance(form, AuthForm)

    body = build_auth_reply(
        group_access="https://vpn.corp.example",
        values=fill_form(form, username="rene", password="hunter2", group="Lab"),
        opaque=form.opaque,
    )
    root = ET.fromstring(body)
    auth = root.find("auth")

    assert root.get("type") == "auth-reply"
    assert auth is not None
    assert auth.findtext("group_list") == "Lab"
    assert root.find("opaque") is not None
