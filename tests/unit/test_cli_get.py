"""URL, HTTP and routing logic behind ``pyac get``.

All of it is pure, so none of it needs a tunnel. The hand-rolled HTTP reader
exists only until the httpx transport lands, but a wrong Content-Length or a
mishandled chunk would look exactly like a stack bug, which is precisely the
confusion worth spending a few tests to avoid.
"""

from __future__ import annotations

import pytest

from pyac.cli.cmd_get import (
    build_request,
    decode_chunked,
    parse_header,
    parse_response,
    parse_url,
)
from pyac.errors import ProtocolParseError

# --- URLs ------------------------------------------------------------------


def test_a_plain_url_is_split_into_host_port_and_path() -> None:
    target = parse_url("http://10.221.188.32:8080/v1/things")
    assert (target.host, target.port, target.path) == ("10.221.188.32", 8080, "/v1/things")


def test_the_defaults_are_port_80_and_root() -> None:
    target = parse_url("http://10.221.188.32")
    assert (target.port, target.path) == (80, "/")


def test_the_scheme_may_be_omitted() -> None:
    assert parse_url("10.221.188.32/health").path == "/health"


def test_https_is_refused_rather_than_downgraded() -> None:
    """Silently dropping to plaintext would be the worst possible answer."""
    with pytest.raises(ValueError, match="https is not supported yet"):
        parse_url("https://10.221.188.32/")


def test_a_hostname_is_refused_with_the_reason() -> None:
    with pytest.raises(ValueError, match="no in-tunnel DNS resolver"):
        parse_url("http://api.internal/v1")


def test_an_unknown_scheme_is_refused() -> None:
    with pytest.raises(ValueError, match="unsupported scheme"):
        parse_url("ftp://10.221.188.32/")


# --- requests --------------------------------------------------------------


def test_a_request_carries_host_and_connection_close() -> None:
    request = build_request(parse_url("http://10.221.188.32/x"), "GET", [])
    assert request.startswith(b"GET /x HTTP/1.1\r\n")
    assert b"Host: 10.221.188.32\r\n" in request
    assert b"Connection: close\r\n" in request
    assert request.endswith(b"\r\n\r\n")


def test_a_non_default_port_appears_in_the_host_header() -> None:
    request = build_request(parse_url("http://10.221.188.32:8080/"), "GET", [])
    assert b"Host: 10.221.188.32:8080\r\n" in request


def test_supplied_headers_are_not_duplicated() -> None:
    request = build_request(parse_url("http://10.221.188.32/"), "GET", [("Host", "api.internal")])
    assert request.count(b"Host:") == 1
    assert b"Host: api.internal\r\n" in request


def test_the_method_is_upper_cased() -> None:
    assert build_request(parse_url("http://10.221.188.32/"), "post", []).startswith(b"POST ")


def test_a_header_without_a_colon_is_rejected() -> None:
    with pytest.raises(ValueError, match="missing a colon"):
        parse_header("NotAHeader")


# --- responses -------------------------------------------------------------

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello"


def test_a_response_is_split_into_status_headers_and_body() -> None:
    response = parse_response(OK)
    assert (response.version, response.status, response.reason) == ("HTTP/1.1", 200, "OK")
    assert response.header("content-type") == "text/plain"
    assert response.body == b"hello"


def test_header_lookup_is_case_insensitive() -> None:
    assert parse_response(OK).header("CONTENT-LENGTH") == "5"


def test_a_status_line_without_a_reason_is_accepted() -> None:
    response = parse_response(b"HTTP/1.1 204\r\n\r\n")
    assert (response.status, response.reason) == (204, "")


def test_the_body_is_cut_at_content_length() -> None:
    """A server that keeps talking past its own length must not confuse us."""
    response = parse_response(OK + b"trailing junk")
    assert response.body == b"hello"


def test_a_body_without_content_length_runs_to_end_of_stream() -> None:
    response = parse_response(b"HTTP/1.1 200 OK\r\n\r\neverything after the blank line")
    assert response.body == b"everything after the blank line"


def test_a_chunked_body_is_reassembled() -> None:
    raw = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    )
    assert parse_response(raw).body == b"hello world"


def test_a_chunk_extension_is_ignored() -> None:
    assert decode_chunked(b"5;name=value\r\nhello\r\n0\r\n\r\n") == b"hello"


def test_a_truncated_chunked_body_is_reported() -> None:
    with pytest.raises(ProtocolParseError, match="truncated chunk"):
        decode_chunked(b"20\r\ntoo short\r\n")


def test_an_empty_response_says_the_server_sent_nothing() -> None:
    """The likeliest first failure against a real host; say so plainly."""
    with pytest.raises(ProtocolParseError, match="the server sent nothing"):
        parse_response(b"")


def test_something_that_is_not_http_is_reported_as_such() -> None:
    with pytest.raises(ProtocolParseError, match="not an HTTP status line"):
        parse_response(b"SSH-2.0-OpenSSH_9.6\r\n\r\n")
