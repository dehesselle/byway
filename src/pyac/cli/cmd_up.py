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
import os
import struct
import sys
import time

from pyac._logging import configure as configure_logging
from pyac._pcap import PcapWriter
from pyac.auth.client import authenticate, build_ssl_context, logout
from pyac.cli.cmd_probe import parse_gateway
from pyac.config import Credentials, GatewayConfig
from pyac.cstp.config import TunnelConfig
from pyac.cstp.session import CstpSession
from pyac.errors import ProtocolParseError, PyacError
from pyac.net.icmp import build_echo_request, parse_icmp
from pyac.net.ipv4 import PROTO_ICMP, PROTO_TCP, PROTO_UDP, build_ipv4, parse_ipv4

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
        "--no-client-dpd",
        action="store_true",
        help="diagnostic: answer the gateway's DPD but never send our own",
    )
    parser.add_argument(
        "--no-coalesce",
        action="store_true",
        help="diagnostic: write one frame per TLS record instead of batching",
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
    if config.banner:
        print(f"\nbanner    {config.banner}")
    if config.unknown_headers:
        print("\nunrecognised headers (please report these):")
        for name, value in config.unknown_headers:
            print(f"  {name}: {value}")


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
    session = CstpSession(
        host=gateway.host,
        port=gateway.port,
        session_token=success.session_token,
        ssl_context=build_ssl_context(gateway),
        user_agent=gateway.user_agent,
        mtu=args.mtu or 1406,
        pcap=pcap,
        client_dpd=not args.no_client_dpd,
        coalesce=not args.no_coalesce,
    )

    try:
        config = await session.connect()
        print_tunnel(config)
        if pcap is not None:
            print(f"\nwriting {args.pcap}")
        print("\ntunnel is up; press Ctrl-C to disconnect")

        if args.ping:
            pinger = asyncio.create_task(
                _ping_loop(session, args.ping, args.ping_interval), name="pyac-ping"
            )
        else:
            pinger = None

        if args.dump_only or args.ping:
            await _dump(session, verbose=args.verbose > 0)
        else:
            print("(no network stack yet -- rerun with --dump-only)")
            await session.closed.wait()

        if pinger is not None:
            pinger.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await pinger

        if session.close_reason:
            print(f"\ntunnel closed: {session.close_reason}")
        print(session.stats())
    finally:
        await session.aclose()
        if pcap is not None:
            pcap.close()
        await logout(gateway, success.session_token)

    return 0


async def _ping_loop(session: CstpSession, target: str, interval: float) -> None:
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
            source=session.config.address,
            destination=target,
            protocol=PROTO_ICMP,
            payload=build_echo_request(ident, sequence, b"pyac" * 4),
            identification=sequence,
        )
        session.send(packet)
        print(f"  -> icmp echo request to {target} seq={sequence}")
        await asyncio.sleep(interval)


HEARTBEAT_SECONDS = 30.0


async def _dump(session: CstpSession, *, verbose: bool) -> None:
    """Report inbound packets until the tunnel closes or Ctrl-C arrives."""
    total = 0
    next_heartbeat = time.monotonic() + HEARTBEAT_SECONDS

    while not session.closed.is_set():
        # Short waits rather than one long one: on Windows an idle event loop
        # will not notice Ctrl-C until it wakes up.
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(session.wake.wait(), timeout=0.5)

        for packet in session.take_inbound():
            total += 1
            if verbose or total <= 20:
                print(f"  <- {summarize_ipv4(packet)}")
            elif total == 21:
                print("  ... (further packets suppressed; use -v to see them all)")

        # An idle tunnel is indistinguishable from a wedged one without this;
        # the frame counters show that keepalives and DPD are still flowing.
        if time.monotonic() >= next_heartbeat:
            next_heartbeat = time.monotonic() + HEARTBEAT_SECONDS
            elapsed = time.monotonic() - session.started_at
            sent = sum(session.frames_out.values())
            received = sum(session.frames_in.values())
            print(
                f"  [{elapsed:5.0f}s] {total} data packets, {received} frames in, {sent} frames out"
            )

    print(f"\n{total} packets received, {session.dropped_inbound} dropped")
