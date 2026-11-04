"""The ``CONNECT /CSCOSSLC/tunnel`` handshake.

Sans-IO: builds the request bytes and parses a response header block. The
session layer owns the socket and decides when a complete block has arrived.

Two omissions are deliberate and load-bearing:

* No ``X-CSTP-Accept-Encoding``. Without it the gateway will not compress, so
  LZS, LZ4, and deflate never need implementing. A ``COMPRESSED`` frame
  arriving anyway means this assumption is wrong for that device.
* No ``X-DTLS-*``. Everything rides the TLS connection.
"""

from __future__ import annotations

from typing import Final

from pylis.errors import HandshakeRejected, ProtocolParseError

TUNNEL_PATH: Final = "/CSCOSSLC/tunnel"
HEADER_TERMINATOR: Final = b"\r\n\r\n"

# Guards against a gateway (or something pretending to be one) streaming
# headers forever before we can act on them.
MAX_HEADER_BYTES: Final = 64 * 1024

DEFAULT_MTU: Final = 1406
DEFAULT_BASE_MTU: Final = 1500


def build_connect_request(
    *,
    host: str,
    session_token: str,
    local_hostname: str,
    user_agent: str,
    mtu: int = DEFAULT_MTU,
    base_mtu: int = DEFAULT_BASE_MTU,
    port: int = 443,
) -> bytes:
    """Build the CONNECT request that turns HTTPS into a CSTP tunnel."""
    authority = host if port == 443 else f"{host}:{port}"
    headers = [
        f"CONNECT {TUNNEL_PATH} HTTP/1.1",
        f"Host: {authority}",
        f"User-Agent: {user_agent}",
        f"Cookie: webvpn={session_token}",
        "X-CSTP-Version: 1",
        f"X-CSTP-Hostname: {local_hostname}",
        f"X-CSTP-MTU: {mtu}",
        f"X-CSTP-Base-MTU: {base_mtu}",
        "X-CSTP-Address-Type: IPv4",
        "X-CSTP-Full-IPv6-Capability: false",
    ]
    return ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8")


def split_header_block(data: bytes) -> tuple[bytes, bytes] | None:
    """Split off a complete header block, returning ``(headers, remainder)``.

    Returns None while the block is still incomplete. The remainder matters:
    the gateway may pack the first CSTP frames into the same TCP segment as
    the response, and dropping them would desynchronise the stream
    immediately.
    """
    index = data.find(HEADER_TERMINATOR)
    if index == -1:
        if len(data) > MAX_HEADER_BYTES:
            raise ProtocolParseError(f"CONNECT response headers exceed {MAX_HEADER_BYTES} bytes")
        return None
    return data[:index], data[index + len(HEADER_TERMINATOR) :]


def parse_connect_response(block: bytes) -> list[tuple[str, str]]:
    """Parse the status line and headers, raising unless the status is 200.

    Returns header pairs in order, preserving duplicates -- ``X-CSTP-DNS`` and
    ``X-CSTP-Split-Include`` legitimately repeat.
    """
    try:
        text = block.decode("utf-8")
    except UnicodeDecodeError:
        text = block.decode("latin-1")

    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    if not lines or not lines[0]:
        raise ProtocolParseError("empty CONNECT response")

    status_line = lines[0]
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        raise ProtocolParseError(f"malformed CONNECT status line: {status_line!r}")

    try:
        status = int(parts[1])
    except ValueError as exc:
        raise ProtocolParseError(f"malformed CONNECT status code: {status_line!r}") from exc

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        name, separator, value = line.partition(":")
        if separator:
            headers.append((name.strip(), value.strip()))

    if status != 200:
        reason = parts[2] if len(parts) > 2 else ""
        raise HandshakeRejected(status, reason.strip() or _hint_for(status))

    return headers


def _hint_for(status: int) -> str:
    """Turn the common rejection codes into something actionable."""
    if status in (401, 403):
        return "session token rejected; the cookie may have expired"
    if status == 502:
        return "gateway could not establish the tunnel"
    return "unexpected status"
