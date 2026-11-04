# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""``byway nc`` -- bridge stdin/stdout to one TCP connection inside the VPN.

The point of this command is a single line in an SSH invocation::

    ssh -o ProxyCommand="byway nc --via 1080 %h %p" user@10.0.0.30

``--via`` borrows a tunnel a running ``byway up --socks`` already holds open.
Prefer it: the alternative authenticates afresh for every ssh you start, which
is slow and eats the gateway's concurrent-session limit.

Direct mode (``--gateway``) exists for one-off use where no tunnel is running.
It cannot read a password from stdin, because stdin is the data channel -- set
``BYWAY_PASSWORD`` or answer the console prompt.

**Nothing may be printed to stdout.** Stdout is the connection. Every
diagnostic here goes to stderr, and logging is configured to do the same.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import sys
from typing import Protocol

from usernet.routing import describe_routes, route_allows
from usernet.runtime.driver import Driver, TcpStream
from usernet.runtime.stdio import CHUNK, StdioBridge
from usernet.socks.client import open_via_socks

from byway._logging import configure as configure_logging
from byway.auth.client import authenticate, build_ssl_context, logout
from byway.cli import (
    add_host_argument,
    apply_profile,
    buffer_bytes,
    finalize_route_policy,
    host_resolver,
)
from byway.cli.cmd_probe import parse_gateway
from byway.cli.cmd_up import parse_listen, parse_socks_auth, read_password
from byway.config import Credentials
from byway.cstp.session import CstpSession
from byway.errors import BywayError, RouteNotAllowed


def register(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    shared: argparse.ArgumentParser,
) -> None:
    parser = subparsers.add_parser(
        "nc",
        parents=[shared],
        help="bridge stdio to a TCP connection inside the VPN",
        description=(
            "Connect to one host inside the VPN and relay it to stdin/stdout, for "
            'use as an SSH ProxyCommand: ssh -o ProxyCommand="byway nc --via 1080 %%h %%p"'
        ),
    )
    parser.add_argument(
        "host",
        help="address inside the VPN, or a name from the host table (the proxy's, with --via)",
    )
    parser.add_argument("port", type=int, help="TCP port")

    parser.add_argument(
        "--via",
        metavar="[HOST:]PORT",
        help="reuse a running `byway up --socks` proxy instead of authenticating",
    )
    parser.add_argument("--via-auth", metavar="USER:PASS", help="credentials for that proxy")

    parser.add_argument("--gateway", help="gateway to authenticate against, if not using --via")
    parser.add_argument("-u", "--user", help="username (direct mode)")
    parser.add_argument("-g", "--group", help="tunnel group (direct mode)")
    parser.add_argument(
        "--profile",
        metavar="NAME",
        help="direct mode: fill in unset connect flags from [profiles.NAME] in the "
        "config file (see --config); explicit flags always win",
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
        "--route-policy",
        choices=("auto", "all"),
        default=None,
        help="auto refuses addresses outside the advertised split routes; all tries "
        "anyway (default auto)",
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="seconds to wait for the connection"
    )
    add_host_argument(parser)
    parser.set_defaults(handler=run)


# --- the two kinds of remote -------------------------------------------------


class Remote(Protocol):
    """What the bridge needs, however the bytes are carried.

    ``close_write`` and ``close`` are deliberately separate. Ending our half
    when stdin runs out must not discard what the far side is still sending --
    conflating the two truncates the last reply of every session.
    """

    async def read(self, size: int) -> bytes: ...
    async def write(self, data: bytes) -> None: ...
    def close_write(self) -> None: ...
    def close(self) -> None: ...


class ProxiedRemote:
    """An ``asyncio`` stream pair, presented as a :class:`Remote`."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    async def read(self, size: int) -> bytes:
        return await self._reader.read(size)

    async def write(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    def close_write(self) -> None:
        # Not close(): that would shut both directions and lose the reply.
        with contextlib.suppress(OSError, NotImplementedError, RuntimeError):
            if self._writer.can_write_eof():
                self._writer.write_eof()

    def close(self) -> None:
        self._writer.close()


class TunnelRemote:
    """A :class:`~usernet.runtime.driver.TcpStream`, presented as a :class:`Remote`."""

    def __init__(self, stream: TcpStream) -> None:
        self._stream = stream

    async def read(self, size: int) -> bytes:
        return await self._stream.read(size)

    async def write(self, data: bytes) -> None:
        await self._stream.write(data)

    def close_write(self) -> None:
        self._stream.close()  # sends FIN and keeps receiving

    def close(self) -> None:
        self._stream.close()


# --- the bridge --------------------------------------------------------------


async def bridge(remote: Remote, stdio: StdioBridge) -> None:
    """Relay until the remote end finishes.

    Stdin reaching EOF only *half*-closes: the far side may still have output
    to send, and tearing down there would truncate it. The remote closing is
    what ends the session.
    """
    upstream = asyncio.create_task(_to_remote(remote, stdio), name="byway-nc-upstream")
    downstream = asyncio.create_task(_to_stdout(remote, stdio), name="byway-nc-downstream")
    try:
        await downstream
    finally:
        upstream.cancel()
        with contextlib.suppress(asyncio.CancelledError, OSError, BywayError):
            await upstream


async def _to_remote(remote: Remote, stdio: StdioBridge) -> None:
    while True:
        data = await stdio.read()
        if not data:
            break
        await remote.write(data)
    remote.close_write()


async def _to_stdout(remote: Remote, stdio: StdioBridge) -> None:
    while True:
        data = await remote.read(CHUNK)
        if not data:
            break
        try:
            await stdio.write(data)
        except OSError:
            # ssh has already gone away and closed its end of our stdout --
            # a normal teardown race, not a failure worth reporting.
            break


# --- entry points ------------------------------------------------------------


def run(args: argparse.Namespace) -> int:
    # Logging must never reach stdout here; stdout is the connection.
    configure_logging(args.verbose, stream=sys.stderr)

    if args.via and args.profile:
        print(
            "error: --profile has no effect with --via (nothing to authenticate)", file=sys.stderr
        )
        return 2
    if args.via and args.add_host:
        print(
            "error: --add-host has no effect with --via (the proxy resolves names)",
            file=sys.stderr,
        )
        return 2
    if args.via and args.gateway:
        print("error: pass exactly one of --via or --gateway", file=sys.stderr)
        return 2

    if not args.via:
        try:
            apply_profile(args)
        except KeyboardInterrupt:
            return 130
        except BywayError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        finalize_route_policy(args)
        try:
            args.address = host_resolver(args).resolve(args.host)
        except BywayError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not args.gateway:
            print(
                "error: pass --gateway (directly or via --profile), or use --via", file=sys.stderr
            )
            return 2
        if not args.user:
            print("error: --gateway needs --user (directly or via --profile)", file=sys.stderr)
            return 2

    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        return 130
    except BywayError as exc:
        print(f"byway nc: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"byway nc: {exc}", file=sys.stderr)
        return 1


async def _run(args: argparse.Namespace) -> int:
    if args.via:
        return await _run_via(args)
    return await _run_direct(args)


async def _run_via(args: argparse.Namespace) -> int:
    proxy_host, proxy_port = parse_listen(args.via)
    username, password = parse_socks_auth(args.via_auth)

    reader, writer = await open_via_socks(
        proxy_host,
        proxy_port,
        args.host,
        args.port,
        username=username,
        password=password,
    )
    remote = ProxiedRemote(reader, writer)
    stdio = StdioBridge()
    try:
        await bridge(remote, stdio)
    finally:
        remote.close()
        stdio.close()
    return 0


async def _run_direct(args: argparse.Namespace) -> int:
    gateway = parse_gateway(args.gateway, pin=args.pin, no_verify=args.no_verify)
    credentials = Credentials(
        username=args.user,
        # Never from stdin: stdin is carrying the connection.
        password=read_password(False, profile=args.profile, username=args.user),
        group=args.group,
    )

    success = await authenticate(gateway, credentials)
    session = CstpSession(
        host=gateway.host,
        port=gateway.port,
        session_token=success.session_token,
        ssl_context=build_ssl_context(gateway),
        user_agent=gateway.user_agent,
        mtu=args.mtu or 1406,
    )
    try:
        config = await session.connect()
        if args.route_policy == "auto" and not route_allows(config, args.address):
            raise RouteNotAllowed(
                f"{args.host} is outside the gateway's split routes "
                f"({describe_routes(config)}); packets would be discarded with no error"
            )

        driver = Driver(session, buffer=buffer_bytes(args))
        driver.start()
        stdio = StdioBridge()
        try:
            stream = await driver.connect(args.address, args.port, timeout=args.timeout)
            await bridge(TunnelRemote(stream), stdio)
        finally:
            stdio.close()
            await driver.aclose()
    finally:
        await session.aclose()
        await logout(gateway, success.session_token)
    return 0
