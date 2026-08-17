"""``pyac get`` -- fetch one URL from inside the tunnel.

The command that closes the thin slice. Everything the project has built so
far is on the path: aggregate-auth, the CSTP tunnel, framing, the userspace
IPv4 stack, and a real TCP connection carrying a real request to a real
server. If this works against the gateway, the design works.

Two deliberate limits, both temporary:

* **Plain HTTP only.** TLS *inside* the tunnel needs the ``ssl.MemoryBIO``
  wrapper that arrives with the httpx transport, at which point this command
  becomes a thin shell over ``httpx`` and the response reader below goes away.
  An ``https://`` URL is refused rather than silently downgraded.
* **IP addresses only.** There is no in-tunnel resolver yet, and resolving an
  internal name through the *host's* resolver would both leak it and usually
  fail. Refusing with an explanation beats a confusing answer.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
import sys
import time
from dataclasses import dataclass

from pyac._logging import configure as configure_logging
from pyac._pcap import PcapWriter
from pyac.auth.client import authenticate, build_ssl_context, logout
from pyac.cli.cmd_probe import parse_gateway
from pyac.cli.cmd_up import read_password
from pyac.config import Credentials, GatewayConfig
from pyac.cstp.session import CstpSession
from pyac.errors import ProtocolParseError, PyacError, RouteNotAllowed
from pyac.routing import describe_routes, route_allows
from pyac.runtime.driver import Driver

DEFAULT_BODY_LIMIT = 8 * 1024 * 1024


def register(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    shared: argparse.ArgumentParser,
) -> None:
    parser = subparsers.add_parser(
        "get",
        parents=[shared],
        help="fetch one URL through the tunnel",
        description=(
            "Authenticate, bring the tunnel up, and make one HTTP request through "
            "the userspace TCP stack. Plain HTTP to an IP address only, for now."
        ),
    )
    parser.add_argument("gateway", help="gateway hostname, optionally host:port")
    parser.add_argument("url", help="http://<ip>[:port][/path] inside the VPN")
    parser.add_argument("-u", "--user", required=True, help="username")
    parser.add_argument("-g", "--group", help="tunnel group (see `pyac probe`)")
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password from stdin instead of prompting",
    )
    parser.add_argument(
        "--pin",
        metavar="sha256:HEX",
        help="require this certificate fingerprint (openconnect --servercert)",
    )
    parser.add_argument("--no-verify", action="store_true", help="skip verification (prefer --pin)")
    parser.add_argument("--mtu", type=int, help="override the MTU requested of the gateway")
    parser.add_argument("-X", "--method", default="GET", help="HTTP method (default GET)")
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="NAME: VALUE",
        help="extra request header; repeatable",
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE", help="write the body to FILE instead of stdout"
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="seconds to wait for the connection"
    )
    parser.add_argument(
        "--route-policy",
        choices=("auto", "all"),
        default="auto",
        help="auto refuses addresses outside the advertised split routes; all tries anyway",
    )
    parser.set_defaults(handler=run)


# --- URL and HTTP, kept minimal on purpose ---------------------------------


@dataclass(frozen=True, slots=True)
class Target:
    host: str
    port: int
    path: str


def parse_url(url: str) -> Target:
    """Split an ``http://`` URL. Raises :class:`ValueError` with a usable message."""
    scheme, separator, rest = url.partition("://")
    if not separator:
        scheme, rest = "http", url
    elif scheme == "https":
        raise ValueError(
            "https is not supported yet: TLS inside the tunnel needs the MemoryBIO "
            "wrapper that lands with the httpx transport. Use http:// for now."
        )
    elif scheme != "http":
        raise ValueError(f"unsupported scheme {scheme!r}; only http is available")

    authority, slash, path = rest.partition("/")
    host, _, port = authority.partition(":")

    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        raise ValueError(
            f"{host!r} is not an IPv4 address. There is no in-tunnel DNS resolver yet, "
            "and resolving an internal name through the host would leak it and "
            "probably fail. Pass the address directly."
        ) from None

    return Target(host=host, port=int(port) if port else 80, path=(slash + path) or "/")


def parse_header(raw: str) -> tuple[str, str]:
    name, separator, value = raw.partition(":")
    if not separator:
        raise ValueError(f"header {raw!r} is missing a colon")
    return name.strip(), value.strip()


def build_request(target: Target, method: str, headers: list[tuple[str, str]]) -> bytes:
    supplied = {name.lower() for name, _ in headers}
    lines = [f"{method.upper()} {target.path} HTTP/1.1"]
    if "host" not in supplied:
        host = target.host if target.port == 80 else f"{target.host}:{target.port}"
        lines.append(f"Host: {host}")
    if "connection" not in supplied:
        # Closing after one response is what lets the reader below stop at EOF
        # instead of implementing keep-alive framing it will never need.
        lines.append("Connection: close")
    lines += [f"{name}: {value}" for name, value in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


@dataclass(frozen=True, slots=True)
class Response:
    version: str
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        return next((value for key, value in self.headers if key.lower() == wanted), None)


def parse_response(raw: bytes) -> Response:
    """Parse a complete HTTP/1.1 response read to end of stream."""
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise ProtocolParseError(
            f"no header terminator in {len(raw)} bytes of response"
            + (f": {raw[:80]!r}" if raw else " (the server sent nothing)")
        )

    lines = head.decode("latin-1").split("\r\n")
    status_line = lines[0].split(" ", 2)
    if len(status_line) < 2 or not status_line[0].startswith("HTTP/"):
        raise ProtocolParseError(f"not an HTTP status line: {lines[0]!r}")

    headers = [parse_header(line) for line in lines[1:] if line]
    response = Response(
        version=status_line[0],
        status=int(status_line[1]),
        reason=status_line[2] if len(status_line) > 2 else "",
        headers=headers,
        body=body,
    )

    encoding = response.header("transfer-encoding")
    if encoding is not None and "chunked" in encoding.lower():
        return Response(
            version=response.version,
            status=response.status,
            reason=response.reason,
            headers=headers,
            body=decode_chunked(body),
        )

    length = response.header("content-length")
    if length is not None and length.strip().isdigit():
        return Response(
            version=response.version,
            status=response.status,
            reason=response.reason,
            headers=headers,
            body=body[: int(length)],
        )
    return response


def decode_chunked(body: bytes) -> bytes:
    chunks: list[bytes] = []
    rest = body
    while True:
        line, separator, rest = rest.partition(b"\r\n")
        if not separator:
            raise ProtocolParseError("truncated chunked body: no size line")
        try:
            size = int(line.split(b";", 1)[0], 16)
        except ValueError:
            raise ProtocolParseError(f"bad chunk size {line!r}") from None
        if size == 0:
            return b"".join(chunks)
        if len(rest) < size:
            raise ProtocolParseError(f"truncated chunk: wanted {size}, have {len(rest)}")
        chunks.append(rest[:size])
        rest = rest[size:].removeprefix(b"\r\n")


# --- the command -----------------------------------------------------------


def run(args: argparse.Namespace) -> int:
    configure_logging(args.verbose)
    try:
        target = parse_url(args.url)
        headers = [parse_header(raw) for raw in args.header]
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    gateway = parse_gateway(args.gateway, pin=args.pin, no_verify=args.no_verify)
    credentials = Credentials(
        username=args.user,
        password=read_password(args.password_stdin),
        group=args.group,
    )
    try:
        return asyncio.run(_run(args, gateway, credentials, target, headers))
    except KeyboardInterrupt:
        return 130
    except PyacError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


async def _run(
    args: argparse.Namespace,
    gateway: GatewayConfig,
    credentials: Credentials,
    target: Target,
    headers: list[tuple[str, str]],
) -> int:
    print(f"authenticating to {gateway.host}...", file=sys.stderr)
    success = await authenticate(gateway, credentials)

    pcap = PcapWriter(args.pcap) if args.pcap else None
    session = CstpSession(
        host=gateway.host,
        port=gateway.port,
        session_token=success.session_token,
        ssl_context=build_ssl_context(gateway),
        user_agent=gateway.user_agent,
        mtu=args.mtu or 1406,
        pcap=pcap,
    )

    try:
        config = await session.connect()
        print(
            f"tunnel up: {config.address}/{config.netmask} mtu {config.mtu}, "
            f"routes {describe_routes(config)}",
            file=sys.stderr,
        )

        if args.route_policy == "auto" and not route_allows(config, target.host):
            raise RouteNotAllowed(
                f"{target.host} is outside the gateway's split routes "
                f"({describe_routes(config)}). Packets would be discarded with no "
                f"error; pass --route-policy all to try anyway."
            )

        driver = Driver(session)
        driver.start()
        try:
            response, timing = await _fetch(driver, target, args, headers)
        finally:
            await driver.aclose()
    finally:
        await session.aclose()
        if pcap is not None:
            pcap.close()
        await logout(gateway, success.session_token)

    _report(response, timing, args)
    return 0 if response.status < 400 else 1


@dataclass(frozen=True, slots=True)
class Timing:
    connect_ms: float
    total_ms: float


async def _fetch(
    driver: Driver,
    target: Target,
    args: argparse.Namespace,
    headers: list[tuple[str, str]],
) -> tuple[Response, Timing]:
    started = time.monotonic()
    print(f"connecting to {target.host}:{target.port}...", file=sys.stderr)
    stream = await driver.connect(target.host, target.port, timeout=args.timeout)
    connected = time.monotonic()

    await stream.write(build_request(target, args.method, headers))
    # Read to end of stream: we asked for Connection: close, so EOF is the
    # message boundary and no keep-alive framing is needed.
    raw = await stream.read_all(limit=DEFAULT_BODY_LIMIT)
    finished = time.monotonic()

    # Give our own FIN a chance to leave before the driver is torn down, so the
    # server sees a clean close rather than an abandoned half-open connection.
    stream.close()
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stream.wait_closed(), timeout=2.0)

    return parse_response(raw), Timing(
        connect_ms=(connected - started) * 1000,
        total_ms=(finished - started) * 1000,
    )


def _report(response: Response, timing: Timing, args: argparse.Namespace) -> None:
    if args.json:
        print(
            json.dumps(
                {
                    "status": response.status,
                    "reason": response.reason,
                    "version": response.version,
                    "headers": [{"name": n, "value": v} for n, v in response.headers],
                    "body_bytes": len(response.body),
                    "connect_ms": round(timing.connect_ms, 1),
                    "total_ms": round(timing.total_ms, 1),
                },
                indent=2,
            )
        )
    else:
        print(f"{response.version} {response.status} {response.reason}".rstrip(), file=sys.stderr)
        for name, value in response.headers:
            print(f"{name}: {value}", file=sys.stderr)
        print(
            f"\n{len(response.body)} bytes in {timing.total_ms:.0f} ms "
            f"(connect {timing.connect_ms:.0f} ms)",
            file=sys.stderr,
        )

    if args.output:
        with open(args.output, "wb") as handle:
            handle.write(response.body)
        print(f"body written to {args.output}", file=sys.stderr)
    elif not args.json:
        sys.stdout.buffer.write(response.body)
        sys.stdout.buffer.flush()
