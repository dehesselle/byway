"""``pyac get`` -- fetch one URL from inside the tunnel.

Everything the project has built is on this path: aggregate-auth, the CSTP
tunnel, framing, the userspace IPv4 stack, a TCP connection, TLS over that
connection, and httpx driving the lot. If this works against the gateway, the
design works.

The request itself is httpx's, through :mod:`usernet.http`, so
chunked encoding, keep-alive, redirects, and content decoding are all handled
by a library that has seen far more of the web than we have.

One limit remains, and it is not temporary in the same way the others were:
**IP addresses only.** This gateway advertises no DNS servers, so there is
nothing to resolve against, and resolving an internal name through the *host's*
resolver would both leak it and usually fail.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import ssl
import sys
import time
from dataclasses import dataclass

import httpx
from usernet.http import TunnelTransport
from usernet.pcap import PcapWriter
from usernet.routing import describe_routes, route_allows
from usernet.runtime.driver import Driver

from pyac._logging import configure as configure_logging
from pyac.auth.client import authenticate, build_ssl_context, logout
from pyac.cli import apply_profile, buffer_bytes, finalize_route_policy
from pyac.cli.cmd_probe import parse_gateway
from pyac.cli.cmd_up import read_password
from pyac.config import Credentials, GatewayConfig
from pyac.cstp.session import CstpSession
from pyac.errors import PyacError, RouteNotAllowed

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
            "Authenticate, bring the tunnel up, and make one HTTP or HTTPS request "
            "through the userspace TCP stack. The URL must name an IP address: "
            "there is no resolver inside the tunnel."
        ),
    )
    parser.add_argument(
        "gateway",
        nargs="?",
        default=None,
        help="gateway hostname, optionally host:port (or from --profile)",
    )
    parser.add_argument("url", help="http[s]://<ip>[:port][/path] inside the VPN")
    parser.add_argument("-u", "--user", help="username (or from --profile)")
    parser.add_argument("-g", "--group", help="tunnel group (see `pyac probe`)")
    parser.add_argument(
        "--profile",
        metavar="NAME",
        help="fill in unset connect flags from [profiles.NAME] in the config file "
        "(see --config); explicit flags always win",
    )
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
    parser.add_argument(
        "--buffer",
        type=int,
        metavar="KIB",
        help="per-socket send and receive buffer in KiB (default 1024); one "
        "connection cannot exceed buffer/RTT, so raise it for a distant gateway",
    )
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
    parser.add_argument("-L", "--location", action="store_true", help="follow redirects")
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not verify the target's certificate (distinct from --no-verify, "
        "which is about the gateway)",
    )
    parser.add_argument(
        "--cacert", metavar="FILE", help="CA bundle for verifying the target's certificate"
    )
    parser.add_argument(
        "--tls-name",
        metavar="NAME",
        help="name to send as SNI and verify the certificate against; defaults to "
        "the Host header, since a certificate is issued for a name and we can "
        "only dial an address",
    )
    parser.add_argument(
        "--route-policy",
        choices=("auto", "all"),
        default=None,
        help="auto refuses addresses outside the advertised split routes; all tries "
        "anyway (default auto)",
    )
    parser.set_defaults(handler=run)


# --- URL and HTTP, kept minimal on purpose ---------------------------------


@dataclass(frozen=True, slots=True)
class Target:
    host: str
    port: int
    path: str
    scheme: str = "http"

    @property
    def authority(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.authority}{self.path}"


def parse_url(url: str) -> Target:
    """Split a URL. Raises :class:`ValueError` with a usable message."""
    scheme, separator, rest = url.partition("://")
    if not separator:
        scheme, rest = "http", url
    elif scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme {scheme!r}; only http and https are available")

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

    return Target(
        scheme=scheme,
        host=host,
        port=int(port) if port else (443 if scheme == "https" else 80),
        path=(slash + path) or "/",
    )


def parse_header(raw: str) -> tuple[str, str]:
    name, separator, value = raw.partition(":")
    if not separator:
        raise ValueError(f"header {raw!r} is missing a colon")
    return name.strip(), value.strip()


def tls_name(args: argparse.Namespace, headers: list[tuple[str, str]]) -> str | None:
    """Which name the target's certificate should be checked against.

    There is no resolver, so the URL carries an address -- and a certificate is
    never issued for one. Without this every HTTPS call would fail with "IP
    address mismatch" and the only apparent remedy would be ``--insecure``,
    which is precisely the wrong lesson to teach.
    """
    if args.tls_name:
        return str(args.tls_name)
    for name, value in headers:
        if name.lower() == "host":
            return value.partition(":")[0]
    return None


def target_verification(args: argparse.Namespace) -> bool | str | ssl.SSLContext:
    """How to verify the *target's* certificate, which is not the gateway's.

    Two separate trust decisions live in this command, and conflating them
    would be a security bug: ``--no-verify``/``--pin`` govern the TLS to the
    VPN gateway, ``--insecure``/``--cacert`` the TLS to the host inside it.
    """
    if args.insecure:
        return False
    if args.cacert:
        return str(args.cacert)
    return True


# --- the command -----------------------------------------------------------


def run(args: argparse.Namespace) -> int:
    configure_logging(args.verbose)
    try:
        target = parse_url(args.url)
        headers = [parse_header(raw) for raw in args.header]
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        apply_profile(args)
    except KeyboardInterrupt:
        return 130
    except PyacError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finalize_route_policy(args)
    if not args.gateway:
        print("error: gateway is required (pass it directly, or via --profile)", file=sys.stderr)
        return 2
    if not args.user:
        print("error: -u/--user is required (pass it directly, or via --profile)", file=sys.stderr)
        return 2

    gateway = parse_gateway(args.gateway, pin=args.pin, no_verify=args.no_verify)
    try:
        credentials = Credentials(
            username=args.user,
            password=read_password(args.password_stdin, profile=args.profile, username=args.user),
            group=args.group,
        )
    except KeyboardInterrupt:
        return 130
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

        driver = Driver(session, buffer=buffer_bytes(args))
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
    return 0 if response.status_code < 400 else 1


@dataclass(frozen=True, slots=True)
class Timing:
    connect_ms: float
    total_ms: float


async def _fetch(
    driver: Driver,
    target: Target,
    args: argparse.Namespace,
    headers: list[tuple[str, str]],
) -> tuple[httpx.Response, Timing]:
    print(f"connecting to {target.host}:{target.port}...", file=sys.stderr)
    # verify goes on the transport, not the client: httpx only applies its own
    # to the transport it builds, so passing it here would do nothing at all.
    transport = TunnelTransport(
        driver, verify=target_verification(args), connect_timeout=args.timeout
    )

    started = time.monotonic()
    async with httpx.AsyncClient(
        transport=transport,
        follow_redirects=args.location,
        timeout=args.timeout,
    ) as client:
        name = tls_name(args, headers)
        response = await client.request(
            args.method.upper(),
            target.url,
            headers=headers or None,
            extensions={"sni_hostname": name} if name else {},
        )
        await response.aread()
    finished = time.monotonic()

    return response, Timing(
        connect_ms=transport.last_connect_ms,
        total_ms=(finished - started) * 1000,
    )


def _report(response: httpx.Response, timing: Timing, args: argparse.Namespace) -> None:
    body = response.content
    if args.json:
        print(
            json.dumps(
                {
                    "status": response.status_code,
                    "reason": response.reason_phrase,
                    "version": response.http_version,
                    "url": str(response.url),
                    "headers": [{"name": n, "value": v} for n, v in response.headers.items()],
                    "body_bytes": len(body),
                    "connect_ms": round(timing.connect_ms, 1),
                    "total_ms": round(timing.total_ms, 1),
                },
                indent=2,
            )
        )
    else:
        status = f"{response.http_version} {response.status_code} {response.reason_phrase}"
        print(status.rstrip(), file=sys.stderr)
        for name, value in response.headers.items():
            print(f"{name}: {value}", file=sys.stderr)
        print(
            f"\n{len(body)} bytes in {timing.total_ms:.0f} ms (connect {timing.connect_ms:.0f} ms)",
            file=sys.stderr,
        )

    if args.output:
        with open(args.output, "wb") as handle:
            handle.write(body)
        print(f"body written to {args.output}", file=sys.stderr)
    elif not args.json:
        sys.stdout.buffer.write(body)
        sys.stdout.buffer.flush()
