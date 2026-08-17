"""``pyac up`` -- authenticate, bring the tunnel up, and hold it there.

At M2 the only thing above the tunnel is ``--dump-only``, which reports the
IP traffic the gateway sends us. That is deliberately enough to prove framing,
DPD, keepalive, and MTU handling before any TCP exists, and ``--pcap`` turns
the result into something Wireshark can open.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import logging
import os
import struct
import sys
import time

from pyac._logging import configure as configure_logging
from pyac._pcap import PcapWriter
from pyac.auth.client import authenticate, build_ssl_context, logout
from pyac.cli import buffer_bytes
from pyac.cli.cmd_probe import parse_gateway
from pyac.config import Credentials, GatewayConfig
from pyac.cstp.config import TunnelConfig
from pyac.cstp.link import ReconnectingLink
from pyac.cstp.session import CstpSession
from pyac.errors import HandshakeRejected, ProtocolParseError, PyacError
from pyac.net.icmp import build_echo_request, parse_icmp
from pyac.net.ipv4 import PROTO_ICMP, PROTO_TCP, PROTO_UDP, build_ipv4, parse_ipv4
from pyac.runtime.driver import Driver
from pyac.socks import Socks5Server

log = logging.getLogger("pyac.cli")

_PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp"}
_ICMP_TYPES = {0: "echo-reply", 3: "unreachable", 8: "echo-request", 11: "ttl-exceeded"}


def register(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    shared: argparse.ArgumentParser,
) -> None:
    parser = subparsers.add_parser(
        "up",
        parents=[shared],
        help="authenticate and establish the tunnel",
        description="Authenticate against the gateway and hold the CSTP tunnel open.",
    )
    parser.add_argument("gateway", help="gateway hostname, optionally host:port")
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
    parser.add_argument(
        "--buffer",
        type=int,
        metavar="KIB",
        help="per-socket send and receive buffer in KiB (default 1024); one "
        "connection cannot exceed buffer/RTT, so raise it for a distant gateway",
    )
    parser.add_argument(
        "--dump-only",
        action="store_true",
        help="report inbound IP packets instead of running a network stack",
    )
    parser.add_argument(
        "--ping",
        metavar="HOST",
        help="send ICMP echo through the tunnel every few seconds (real traffic)",
    )
    parser.add_argument(
        "--ping-interval", type=float, default=5.0, help="seconds between pings (default 5)"
    )
    parser.add_argument(
        "--socks",
        nargs="?",
        const="127.0.0.1:1080",
        metavar="[HOST:]PORT",
        help="serve SOCKS5 for the tunnel (default 127.0.0.1:1080)",
    )
    parser.add_argument(
        "--socks-auth",
        metavar="USER:PASS",
        help="require these RFC 1929 credentials from SOCKS clients",
    )
    parser.add_argument(
        "--socks-allow-remote",
        action="store_true",
        help="permit binding a non-loopback address (opens the VPN to the network)",
    )
    parser.add_argument(
        "--route-policy",
        choices=("auto", "all"),
        default="auto",
        help="auto refuses addresses outside the advertised split routes; all tries anyway",
    )
    parser.add_argument(
        "--keepalive",
        metavar="HOST",
        help="send an ICMP echo to HOST periodically, so the gateway's idle "
        "timeout never fires (DPD and keepalive frames may not reset it)",
    )
    parser.add_argument(
        "--keepalive-interval",
        type=float,
        default=300.0,
        help="seconds between idle keepalives (default 300)",
    )
    parser.add_argument(
        "--no-reconnect",
        action="store_true",
        help="exit when the tunnel ends instead of rebuilding it",
    )
    parser.add_argument(
        "--no-client-dpd",
        action="store_true",
        help="diagnostic: answer the gateway's DPD but never send our own",
    )
    parser.add_argument(
        "--coalesce",
        action="store_true",
        help="batch frames into one TLS record (known to break Cisco ASA; see docs/protocol.md)",
    )
    parser.set_defaults(handler=run)


def read_password(from_stdin: bool) -> str:
    """Never from argv: that leaks into the process list and shell history."""
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    if (from_env := os.environ.get("PYAC_PASSWORD")) is not None:
        return from_env
    return getpass.getpass("Password: ")


def summarize_ipv4(packet: bytes) -> str:
    """A one-line description of an IP packet, for --dump-only."""
    try:
        header, payload = parse_ipv4(packet)
    except ProtocolParseError as exc:
        return f"unparseable ({len(packet)} bytes): {exc}"

    name = _PROTOCOLS.get(header.protocol, str(header.protocol))
    detail = ""

    if header.protocol == PROTO_ICMP:
        with contextlib.suppress(ProtocolParseError):
            message = parse_icmp(payload)
            kind = _ICMP_TYPES.get(message.type, f"type {message.type}")
            detail = f" {kind} id={message.ident} seq={message.sequence}"
    elif header.protocol in (PROTO_TCP, PROTO_UDP) and len(payload) >= 4:
        source_port, destination_port = struct.unpack_from("!HH", payload)
        detail = f" {source_port}->{destination_port}"

    return f"{name:<4} {header.source} > {header.destination}{detail}  ({len(packet)} bytes)"


def print_tunnel(config: TunnelConfig) -> None:
    print(f"\naddress   {config.address}/{config.netmask}")
    print(f"mtu       {config.mtu}")
    if config.dns:
        print(f"dns       {', '.join(config.dns)}")
    else:
        # Worth calling out: with no DNS servers the gateway is not offering
        # in-tunnel resolution, so names must be resolved by the host.
        print(f"dns       none advertised (tunnel-all-dns={str(config.tunnel_all_dns).lower()})")
    if config.default_domain:
        print(f"domain    {config.default_domain}")
    if config.split_include:
        print("routes    " + ", ".join(str(n) for n in config.split_include))
        for network in config.split_exclude:
            print(f"          except {network}")
    else:
        print("routes    full tunnel (no split-include advertised)")
    print(f"timers    dpd {config.dpd}s  keepalive {config.keepalive}s", end="")
    if config.idle_timeout:
        print(f"  idle {config.idle_timeout}s", end="")
    if config.session_timeout:
        print(f"  session {config.session_timeout}s", end="")
    print()
    if config.rekey_time:
        print(f"rekey     {config.rekey_time}s (method {config.rekey_method})")
    else:
        # Said out loud, because silence here reads as "pyac forgot to print
        # it" rather than "the gateway asked for no rekey", and the two have
        # very different consequences for a long-running session.
        print("rekey     none advertised")
    if config.banner:
        print(f"\nbanner    {config.banner}")
    if config.unknown_headers:
        print("\nunrecognised headers (please report these):")
        for name, value in config.unknown_headers:
            print(f"  {name}: {value}")


def print_liveness(
    config: TunnelConfig, args: argparse.Namespace, rekey_seconds: float | None
) -> None:
    """What is keeping this tunnel alive, and what will end it.

    Printed unconditionally. The two facts that decide whether a long session
    survives -- whether a rekey is scheduled, and whether anything is resetting
    the idle timer -- are exactly the ones a user cannot infer from an absent
    line, so every branch says something.
    """
    print()
    if args.no_reconnect:
        print("reconnect disabled; the tunnel ends when the connection does")
    elif rekey_seconds is not None:
        print(f"reconnect rebuilding the tunnel every {rekey_seconds:.0f}s, and on any drop")
    else:
        print("reconnect on drop only (this gateway schedules no rekey)")

    if args.keepalive:
        print(f"keepalive icmp echo to {args.keepalive} every {args.keepalive_interval:.0f}s")
    elif config.idle_timeout:
        # The failure this averts is silent and slow: the tunnel simply stops
        # half an hour after the last request, with nothing to explain it.
        print(
            f"keepalive none -- the gateway drops an idle tunnel after "
            f"{config.idle_timeout}s; pass --keepalive <ip-inside-the-vpn> to hold it open"
        )


def print_close_advice(
    config: TunnelConfig, args: argparse.Namespace, error: BaseException | None
) -> None:
    """Turn the way this run ended into the flag that would have prevented it.

    A rejected cookie is not a transport failure. The gateway destroyed the
    session -- almost always because the idle timer fired -- and nothing short
    of authenticating again will bring it back, which a background task must
    not do on its own.
    """
    if not isinstance(error, HandshakeRejected) or error.status not in (401, 403):
        return

    print(
        "\nthe gateway rejected the session cookie, so the tunnel could not be\n"
        "rebuilt without authenticating again. run pyac up once more to do that."
    )
    if config.idle_timeout and not args.keepalive:
        print(
            f"an idle tunnel is destroyed after {config.idle_timeout}s on this gateway;\n"
            f"--keepalive <ip-inside-the-vpn> keeps payload flowing so it never happens."
        )


def run(args: argparse.Namespace) -> int:
    configure_logging(args.verbose)
    gateway = parse_gateway(args.gateway, pin=args.pin, no_verify=args.no_verify)
    credentials = Credentials(
        username=args.user,
        password=read_password(args.password_stdin),
        group=args.group,
    )
    try:
        return asyncio.run(_run(args, gateway, credentials))
    except KeyboardInterrupt:
        return 130
    except PyacError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


async def _run(args: argparse.Namespace, gateway: GatewayConfig, credentials: Credentials) -> int:
    print(f"authenticating to {gateway.host}...")
    success = await authenticate(gateway, credentials)
    print("authenticated" + (f"  session {success.session_id}" if success.session_id else ""))
    if success.banner:
        print(f"\n{success.banner}\n")

    pcap = PcapWriter(args.pcap) if args.pcap else None

    async def open_session() -> CstpSession:
        """Build a fresh tunnel on the same ``webvpn`` cookie.

        No re-authentication: the cookie stays valid across a reconnect, which
        is what makes this transparent to the gateway. If it ever stops being
        valid the CONNECT fails loudly -- a background task must never prompt
        for a password.
        """
        session = CstpSession(
            host=gateway.host,
            port=gateway.port,
            session_token=success.session_token,
            ssl_context=build_ssl_context(gateway),
            user_agent=gateway.user_agent,
            mtu=args.mtu or 1406,
            pcap=pcap,
            client_dpd=not args.no_client_dpd,
            coalesce=args.coalesce,
        )
        await session.connect()
        return session

    link = ReconnectingLink(open_session, reconnect=not args.no_reconnect)

    try:
        config = await link.start()
        print_tunnel(config)
        if pcap is not None:
            print(f"\nwriting {args.pcap}")
        print_liveness(config, args, link.rekey_seconds)
        print("\ntunnel is up; press Ctrl-C to disconnect")

        if args.ping:
            pinger = asyncio.create_task(
                _ping_loop(link, args.ping, args.ping_interval), name="pyac-ping"
            )
        else:
            pinger = None

        if args.socks:
            await _serve_socks(link, args)
        elif args.dump_only or args.ping:
            await _dump(link, verbose=args.verbose > 0)
        else:
            print("(nothing to do: pass --socks to serve a proxy, or --dump-only)")
            await link.closed.wait()

        if pinger is not None:
            pinger.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await pinger

        if link.close_reason:
            print(f"\ntunnel closed: {link.close_reason}")
            print_close_advice(config, args, link.close_error)
        if link.reconnects:
            print(
                f"reconnects {link.reconnects}"
                + (f" ({link.address_changes} with a new address)" if link.address_changes else "")
            )
        with contextlib.suppress(PyacError):
            print(link.session.stats())
    finally:
        await link.aclose()
        if pcap is not None:
            pcap.close()
        await logout(gateway, success.session_token)

    return 0


def parse_listen(spec: str) -> tuple[str, int]:
    """``1080``, ``127.0.0.1:1080``, or ``[::1]:1080``."""
    if ":" not in spec:
        return "127.0.0.1", int(spec)
    host, _, port = spec.rpartition(":")
    return host.strip("[]") or "127.0.0.1", int(port)


def parse_socks_auth(spec: str | None) -> tuple[str | None, str | None]:
    if spec is None:
        return None, None
    username, separator, password = spec.partition(":")
    if not separator:
        raise PyacError("--socks-auth expects USER:PASS")
    return username, password


async def _serve_socks(link: ReconnectingLink, args: argparse.Namespace) -> None:
    """Run the proxy until the tunnel closes for good, or Ctrl-C arrives."""
    host, port = parse_listen(args.socks)
    username, password = parse_socks_auth(args.socks_auth)

    driver = Driver(link, buffer=buffer_bytes(args))
    driver.start()
    proxy = Socks5Server(
        driver,
        host=host,
        port=port,
        username=username,
        password=password,
        allow_non_loopback=args.socks_allow_remote,
        route_policy=args.route_policy,
    )
    try:
        await proxy.start()
        print(f"\nsocks5    {proxy.address}" + ("  (authenticated)" if username else ""))
        if username is None:
            # Loopback still means every local process, including a browser
            # tab running someone else's JavaScript.
            print("          no authentication: any local process can use this")
        print(f"\ncurl --socks5 {proxy.address} http://<ip-inside-the-vpn>/")
        print("\npress Ctrl-C to disconnect")

        keeper = None
        if args.keepalive:
            keeper = asyncio.create_task(
                _keepalive_loop(driver, args.keepalive, args.keepalive_interval),
                name="pyac-keepalive",
            )

        while not link.closed.is_set():
            # Short waits: an idle proactor loop on Windows will not notice
            # Ctrl-C until something wakes it.
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(link.closed.wait(), timeout=0.5)

        if keeper is not None:
            keeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await keeper

        print(f"\nsocks: {proxy.connections} connections, {proxy.rejected} rejected")
        if driver.address_changes:
            print(
                f"       {driver.address_changes} address change(s); connections open "
                f"at the time were reset"
            )
    finally:
        await proxy.aclose()
        await driver.aclose()


async def _keepalive_loop(driver: Driver, target: str, interval: float) -> None:
    """Push real traffic through the tunnel so the idle timer keeps resetting.

    DPD and keepalive *frames* do not always count: on several gateways only
    payload resets ``X-CSTP-Idle-Timeout``. One echo request every few minutes
    is the cheapest thing that unambiguously does.
    """
    sequence = 0
    while True:
        await asyncio.sleep(interval)
        sequence += 1
        # Quiet by design: this runs for hours and its whole job is to be
        # unremarkable. A lost reply is not news either -- the point is the
        # bytes we sent, not the ones that came back.
        rtt = await driver.ping(target, sequence, timeout=5.0)
        log.debug(
            "keepalive %d to %s: %s",
            sequence,
            target,
            f"{rtt:.0f} ms" if rtt else "no reply",
        )


async def _ping_loop(link: ReconnectingLink, target: str, interval: float) -> None:
    """Send ICMP echo requests through the tunnel.

    This is real data on the wire, which distinguishes a gateway that drops
    idle tunnels from one that objects to how we send control frames. It is
    also the first half of `pyac ping`.
    """
    ident = os.getpid() & 0xFFFF
    sequence = 0

    while True:
        sequence += 1
        packet = build_ipv4(
            source=link.config.address,
            destination=target,
            protocol=PROTO_ICMP,
            payload=build_echo_request(ident, sequence, b"pyac" * 4),
            identification=sequence,
        )
        link.send(packet)
        print(f"  -> icmp echo request to {target} seq={sequence}")
        await asyncio.sleep(interval)


HEARTBEAT_SECONDS = 30.0


async def _dump(link: ReconnectingLink, *, verbose: bool) -> None:
    """Report inbound packets until the tunnel closes or Ctrl-C arrives."""
    total = 0
    next_heartbeat = time.monotonic() + HEARTBEAT_SECONDS

    while not link.closed.is_set():
        # Short waits rather than one long one: on Windows an idle event loop
        # will not notice Ctrl-C until it wakes up.
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(link.wake.wait(), timeout=0.5)

        for packet in link.take_inbound():
            total += 1
            if verbose or total <= 20:
                print(f"  <- {summarize_ipv4(packet)}")
            elif total == 21:
                print("  ... (further packets suppressed; use -v to see them all)")

        # An idle tunnel is indistinguishable from a wedged one without this;
        # the frame counters show that keepalives and DPD are still flowing.
        if time.monotonic() >= next_heartbeat:
            next_heartbeat = time.monotonic() + HEARTBEAT_SECONDS
            session = link.session
            elapsed = time.monotonic() - session.started_at
            sent = sum(session.frames_out.values())
            received = sum(session.frames_in.values())
            print(
                f"  [{elapsed:5.0f}s] {total} data packets, {received} frames in, {sent} frames out"
            )

    print(f"\n{total} packets received, {link.session.dropped_inbound} dropped")
