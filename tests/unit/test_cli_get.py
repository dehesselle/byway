"""URL and option handling for ``pyac get``.

The HTTP itself is httpx's since M7, so what is left here is what we decide:
which URLs are acceptable, and which of the *two* trust decisions in this
command a given flag governs.
"""

from __future__ import annotations

import argparse

import pytest

from pyac.cli.cmd_get import parse_header, parse_url, target_verification

# --- URLs ------------------------------------------------------------------


def test_a_plain_url_is_split_into_host_port_and_path() -> None:
    target = parse_url("http://10.221.188.32:8080/v1/things")
    assert (target.host, target.port, target.path) == ("10.221.188.32", 8080, "/v1/things")
    assert target.scheme == "http"


def test_the_defaults_are_port_80_and_root() -> None:
    target = parse_url("http://10.221.188.32")
    assert (target.port, target.path) == (80, "/")


def test_https_defaults_to_port_443() -> None:
    target = parse_url("https://10.221.188.32/api")
    assert (target.scheme, target.port, target.path) == ("https", 443, "/api")


def test_the_scheme_may_be_omitted() -> None:
    assert parse_url("10.221.188.32/health").path == "/health"


def test_a_hostname_is_kept_for_the_host_table_to_resolve() -> None:
    target = parse_url("https://api.orka/v1")
    assert (target.host, target.port) == ("api.orka", 443)
    assert target.url == "https://api.orka/v1"


def test_a_url_without_a_host_is_refused() -> None:
    with pytest.raises(ValueError, match="names no host"):
        parse_url("http:///v1")


def test_an_unknown_scheme_is_refused() -> None:
    with pytest.raises(ValueError, match="unsupported scheme"):
        parse_url("ftp://10.221.188.32/")


def test_the_url_is_rebuilt_for_httpx() -> None:
    for original in (
        "http://10.221.188.32/",
        "https://10.221.188.32/v1/things",
        "http://10.221.188.32:8080/x",
        "https://10.221.188.32:8443/y",
    ):
        assert parse_url(original).url == original


def test_a_default_port_is_left_out_of_the_authority() -> None:
    assert parse_url("http://10.221.188.32:80/").authority == "10.221.188.32"
    assert parse_url("https://10.221.188.32:443/").authority == "10.221.188.32"
    assert parse_url("http://10.221.188.32:8080/").authority == "10.221.188.32:8080"


# --- headers ----------------------------------------------------------------


def test_a_header_is_split_on_the_first_colon() -> None:
    assert parse_header("Accept: application/json") == ("Accept", "application/json")
    assert parse_header("X-Trace: a:b:c") == ("X-Trace", "a:b:c")


def test_a_header_without_a_colon_is_rejected() -> None:
    with pytest.raises(ValueError, match="missing a colon"):
        parse_header("NotAHeader")


# --- the two trust decisions ------------------------------------------------


def options(**overrides: object) -> argparse.Namespace:
    return argparse.Namespace(**{"insecure": False, "cacert": None, **overrides})


def test_the_target_is_verified_by_default() -> None:
    assert target_verification(options()) is True


def test_insecure_applies_to_the_target_not_the_gateway() -> None:
    """Conflating these two would be a security bug, not a usability one:
    ``--no-verify`` is about the VPN gateway, ``--insecure`` about the host
    inside it, and neither should quietly imply the other."""
    assert target_verification(options(insecure=True)) is False


def test_a_ca_bundle_is_passed_through() -> None:
    assert target_verification(options(cacert="/etc/ssl/internal.pem")) == "/etc/ssl/internal.pem"


def test_insecure_wins_over_a_ca_bundle() -> None:
    assert target_verification(options(insecure=True, cacert="ignored.pem")) is False
