"""The CONNECT request and response, sans-IO."""

from __future__ import annotations

import pytest

from pyac.cstp.handshake import (
    MAX_HEADER_BYTES,
    build_connect_request,
    parse_connect_response,
    split_header_block,
)
from pyac.errors import HandshakeRejected, ProtocolParseError


def build(**overrides: object) -> bytes:
    defaults: dict[str, object] = {
        "host": "vpn.corp.example",
        "session_token": "TOK",
        "local_hostname": "laptop",
        "user_agent": "AnyConnect Windows 4.10.07061",
    }
    return build_connect_request(**{**defaults, **overrides})  # type: ignore[arg-type]


# --- request ---------------------------------------------------------------


def test_request_line_and_required_headers() -> None:
    lines = build().decode().split("\r\n")

    assert lines[0] == "CONNECT /CSCOSSLC/tunnel HTTP/1.1"
    assert "Host: vpn.corp.example" in lines
    assert "Cookie: webvpn=TOK" in lines
    assert "X-CSTP-Version: 1" in lines
    assert "X-CSTP-Hostname: laptop" in lines
    assert "X-CSTP-Address-Type: IPv4" in lines
    assert build().endswith(b"\r\n\r\n")


def test_non_default_port_appears_in_host() -> None:
    assert b"Host: vpn.corp.example:8443" in build(port=8443)


def test_default_port_is_omitted_from_host() -> None:
    assert b"Host: vpn.corp.example\r\n" in build(port=443)


def test_compression_and_dtls_are_never_advertised() -> None:
    """Load-bearing: see the module docstring in cstp.handshake."""
    request = build().lower()
    assert b"accept-encoding" not in request
    assert b"x-dtls" not in request


# --- splitting the header block --------------------------------------------


def test_split_returns_none_until_the_block_is_complete() -> None:
    assert split_header_block(b"HTTP/1.1 200 OK\r\nX-CSTP-MTU: 1406\r\n") is None


def test_split_separates_headers_from_trailing_frame_bytes() -> None:
    """The gateway often packs the first frames into the same segment."""
    raw = b"HTTP/1.1 200 OK\r\nX-CSTP-MTU: 1406\r\n\r\nSTF\x01\x00\x00\x00\x00"
    result = split_header_block(raw)

    assert result is not None
    block, remainder = result
    assert block == b"HTTP/1.1 200 OK\r\nX-CSTP-MTU: 1406"
    assert remainder == b"STF\x01\x00\x00\x00\x00"


def test_split_with_no_remainder() -> None:
    result = split_header_block(b"HTTP/1.1 200 OK\r\n\r\n")
    assert result is not None
    assert result[1] == b""


def test_endless_headers_are_refused() -> None:
    with pytest.raises(ProtocolParseError, match="exceed"):
        split_header_block(b"X" * (MAX_HEADER_BYTES + 1))


# --- parsing the response --------------------------------------------------


def test_headers_parse_in_order_preserving_duplicates() -> None:
    block = (
        b"HTTP/1.1 200 OK\r\n"
        b"X-CSTP-Address: 10.1.2.3\r\n"
        b"X-CSTP-DNS: 10.0.0.53\r\n"
        b"X-CSTP-DNS: 10.0.0.54\r\n"
    )
    assert parse_connect_response(block) == [
        ("X-CSTP-Address", "10.1.2.3"),
        ("X-CSTP-DNS", "10.0.0.53"),
        ("X-CSTP-DNS", "10.0.0.54"),
    ]


def test_bare_lf_line_endings_are_tolerated() -> None:
    block = b"HTTP/1.1 200 OK\nX-CSTP-Address: 10.1.2.3\n"
    assert parse_connect_response(block) == [("X-CSTP-Address", "10.1.2.3")]


def test_values_containing_colons_survive() -> None:
    block = b"HTTP/1.1 200 OK\r\nX-CSTP-Banner: 09:00 to 17:00\r\n"
    assert parse_connect_response(block) == [("X-CSTP-Banner", "09:00 to 17:00")]


@pytest.mark.parametrize(("status", "hint"), [(401, "token"), (403, "token"), (502, "tunnel")])
def test_rejection_carries_an_actionable_reason(status: int, hint: str) -> None:
    block = f"HTTP/1.1 {status} \r\n".encode()
    with pytest.raises(HandshakeRejected) as caught:
        parse_connect_response(block)

    assert caught.value.status == status
    assert hint in str(caught.value)


def test_gateway_supplied_reason_is_preferred() -> None:
    with pytest.raises(HandshakeRejected, match="Session expired"):
        parse_connect_response(b"HTTP/1.1 401 Session expired\r\n")


@pytest.mark.parametrize(
    "block",
    [b"", b"garbage\r\n", b"NOTHTTP/1.1 200 OK\r\n", b"HTTP/1.1 notanumber OK\r\n"],
)
def test_malformed_status_lines_raise_parse_errors(block: bytes) -> None:
    with pytest.raises(ProtocolParseError):
        parse_connect_response(block)


def test_undecodable_bytes_do_not_crash_the_parser() -> None:
    block = b"HTTP/1.1 200 OK\r\nX-CSTP-Banner: \xff\xfe\r\n"
    headers = parse_connect_response(block)
    assert headers[0][0] == "X-CSTP-Banner"
