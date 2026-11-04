# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""URL and option handling for ``byway http``.

The HTTP itself is httpx's since M7, so what is left here is what we decide:
which URLs are acceptable, and which of the *two* trust decisions in this
command a given flag governs.
"""

from __future__ import annotations

import argparse
import io
from pathlib import Path

import pytest

from byway.cli import cmd_http
from byway.cli.cmd_http import (
    parse_header,
    parse_url,
    read_body,
    request_method,
    target_verification,
)
from byway.cli.main import build_parser

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


# --- the request body -------------------------------------------------------


def test_no_data_means_no_body() -> None:
    assert read_body(None) is None


def test_data_is_sent_as_given() -> None:
    assert read_body('{"name": "ä"}') == '{"name": "ä"}'.encode()


def test_data_from_a_file_is_read_byte_for_byte(tmp_path: Path) -> None:
    payload = b'{"a": 1}\r\n\x00\xff\n'
    (tmp_path / "body.json").write_bytes(payload)
    assert read_body(f"@{tmp_path / 'body.json'}") == payload


def test_data_from_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"piped\n")))
    assert read_body("@-") == b"piped\n"


def test_a_missing_data_file_raises(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        read_body(f"@{tmp_path / 'nope.json'}")


def parse(*argv: str) -> argparse.Namespace:
    """``argv`` ends with the URL; the gateway goes right before it."""
    *flags, url = argv
    return build_parser().parse_args(["http", "-u", "me", *flags, "gw", url])


def test_the_method_defaults_to_get() -> None:
    assert request_method(parse("http://10.0.0.1/")) == "GET"


def test_data_makes_the_default_method_post() -> None:
    assert request_method(parse("-d", "x", "http://10.0.0.1/")) == "POST"


def test_an_explicit_method_wins_over_the_data_default() -> None:
    assert request_method(parse("-X", "put", "-d", "x", "http://10.0.0.1/")) == "PUT"


def test_body_and_password_cannot_both_come_from_stdin(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = parse("-d", "@-", "--password-stdin", "http://10.0.0.1/")
    assert cmd_http.run(args) == 2
    assert "both read stdin" in capsys.readouterr().err


def test_an_unreadable_body_fails_before_authenticating(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = parse("-d", f"@{tmp_path / 'nope.json'}", "http://10.0.0.1/")
    assert cmd_http.run(args) == 2
    assert "cannot read the request body" in capsys.readouterr().err


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
