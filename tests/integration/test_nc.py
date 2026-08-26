"""``pyac nc --via``: the SOCKS client and the stdio bridge, end to end.

The full path an SSH ProxyCommand takes -- stdin, a SOCKS5 proxy, the
userspace stack, the CSTP tunnel, a peer -- with real pipes standing in for
the descriptors ``ssh`` would hand us.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from usernet.runtime.driver import Driver
from usernet.runtime.stdio import StdioBridge
from usernet.socks import Socks5Server
from usernet.socks.client import open_via_socks
from usernet.testing.peer import TcpPeer
from usernet.testing.pipes import Pipes

from pyac.cli.cmd_nc import ProxiedRemote, bridge
from pyac.errors import ConnectionRefused, NetworkError, RouteNotAllowed
from tests.fakegw import FakeGateway
from tests.fakegw.server import DEFAULT_TUNNEL_HEADERS
from tests.integration.test_tunnel import session_for

SERVER_IP = "10.11.12.13"
OUTSIDE_IP = "8.8.8.8"
TUNNEL_HEADERS = [(n, v) for n, v in DEFAULT_TUNNEL_HEADERS if n != "X-CSTP-Banner"]


@pytest.fixture
def certs(tmp_path: Path) -> Path:
    return tmp_path


def echo_handler(received: bytes) -> bytes | None:
    """Answer once a line is complete, upper-cased so the reply is distinct."""
    if not received.endswith(b"\n"):
        return None
    return received.upper()


@asynccontextmanager
async def proxy_for(
    certs: Path, handler=echo_handler, **options: object
) -> AsyncIterator[tuple[Socks5Server, TcpPeer]]:
    peer = TcpPeer(ip=SERVER_IP, port=22, handler=handler)
    async with (
        FakeGateway([], certs_dir=certs, peer=peer, tunnel_headers=TUNNEL_HEADERS) as gateway,
        session_for(gateway) as session,
    ):
        driver = Driver(session)
        driver.start()
        server = Socks5Server(driver, port=0, **options)  # type: ignore[arg-type]
        await server.start()
        try:
            yield server, peer
        finally:
            await server.aclose()
            await driver.aclose()


# --- the SOCKS client -------------------------------------------------------


async def test_the_client_connects_through_the_proxy(certs: Path) -> None:
    async with proxy_for(certs) as (server, _peer):
        reader, writer = await open_via_socks("127.0.0.1", server.port, SERVER_IP, 22)
        writer.write(b"hello\n")
        await writer.drain()
        answer = await reader.read(64)
        writer.close()

    assert answer == b"HELLO\n"


async def test_a_refusal_comes_back_as_the_error_it_means(certs: Path) -> None:
    """The reply code is nearly all a client learns, so it must round-trip."""
    async with proxy_for(certs) as (server, _peer):
        with pytest.raises(RouteNotAllowed):
            await open_via_socks("127.0.0.1", server.port, OUTSIDE_IP, 22)


async def test_a_dead_port_is_reported(certs: Path) -> None:
    async with proxy_for(certs, connect_timeout=1.0) as (server, _peer):
        with pytest.raises(NetworkError):
            await open_via_socks("127.0.0.1", server.port, SERVER_IP, 23)


async def test_credentials_are_sent_when_the_proxy_asks(certs: Path) -> None:
    async with proxy_for(certs, username="alice", password="hunter2") as (server, _peer):
        reader, writer = await open_via_socks(
            "127.0.0.1", server.port, SERVER_IP, 22, username="alice", password="hunter2"
        )
        writer.write(b"authed\n")
        await writer.drain()
        answer = await reader.read(64)
        writer.close()

    assert answer == b"AUTHED\n"


async def test_bad_credentials_are_reported(certs: Path) -> None:
    async with proxy_for(certs, username="alice", password="hunter2") as (server, _peer):
        with pytest.raises(NetworkError, match="rejected the credentials"):
            await open_via_socks(
                "127.0.0.1", server.port, SERVER_IP, 22, username="alice", password="wrong"
            )


async def test_a_proxy_needing_auth_says_so_when_none_is_given(certs: Path) -> None:
    async with proxy_for(certs, username="alice", password="hunter2") as (server, _peer):
        with pytest.raises(NetworkError, match="may require credentials"):
            await open_via_socks("127.0.0.1", server.port, SERVER_IP, 22)


async def test_nothing_is_left_open_when_the_connection_is_refused(certs: Path) -> None:
    """A leaked socket per failed ssh would accumulate fast under a retry loop."""
    async with proxy_for(certs) as (server, _peer):
        for _ in range(5):
            with pytest.raises((NetworkError, ConnectionRefused)):
                await open_via_socks("127.0.0.1", server.port, OUTSIDE_IP, 22)
        assert server.active == 0


# --- the bridge -------------------------------------------------------------


@asynccontextmanager
async def bridged(
    server: Socks5Server, port: int = 22
) -> AsyncIterator[tuple[Pipes, asyncio.Task]]:
    """Run the bridge against pipes, the way ssh would drive it."""
    pipes = Pipes()
    reader, writer = await open_via_socks("127.0.0.1", server.port, SERVER_IP, port)
    remote = ProxiedRemote(reader, writer)
    stdio = StdioBridge(pipes.stdin_read, pipes.stdout_write, chunk=4096)
    task = asyncio.create_task(bridge(remote, stdio))
    try:
        yield pipes, task
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        remote.close()  # as ssh exiting would; the proxy is waiting on it
        stdio.close()
        pipes.end_input()
        await asyncio.to_thread(stdio.join, 2.0)
        pipes.close()


async def test_stdin_reaches_the_far_side_and_the_answer_comes_back(certs: Path) -> None:
    """One line in, one line out: the shape of every ProxyCommand session."""
    async with proxy_for(certs) as (server, _peer), bridged(server) as (pipes, _task):
        pipes.send(b"ping\n")
        assert await asyncio.wait_for(pipes.receive(), timeout=5) == b"PING\n"


async def test_the_bridge_ends_when_the_far_side_closes(certs: Path) -> None:
    """ssh has to learn the connection is over, and only our exit tells it."""

    def close_immediately(received: bytes) -> bytes | None:
        return b"bye\n" if received.endswith(b"\n") else None

    async with (
        proxy_for(certs, handler=close_immediately) as (server, _peer),
        bridged(server) as (pipes, task),
    ):
        pipes.send(b"go\n")
        assert await asyncio.wait_for(pipes.receive(), timeout=5) == b"bye\n"
        await asyncio.wait_for(task, timeout=5)
        assert task.done() and task.exception() is None


async def test_a_gone_stdout_reader_ends_the_bridge_quietly(certs: Path) -> None:
    """ssh exiting can close its read end mid-write; that's not a failure.

    This is what produced the stray ``pyac nc: [Errno 22] Invalid argument``
    after every ordinary ssh exit: the far side's reply was still in flight
    when the consumer of our stdout went away.
    """

    async with (
        proxy_for(certs) as (server, _peer),
        bridged(server) as (pipes, task),
    ):
        os.close(pipes.stdout_read)  # as ssh exiting closes its read end
        pipes.send(b"x\n")
        await asyncio.wait_for(task, timeout=5)
        assert task.done() and task.exception() is None


async def test_stdin_eof_half_closes_without_truncating_the_reply(certs: Path) -> None:
    """The far side may still be talking; tearing down on stdin EOF loses it."""

    def handler(received: bytes) -> bytes | None:
        return b"late answer\n" if received.endswith(b"\n") else None

    async with (
        proxy_for(certs, handler=handler) as (server, _peer),
        bridged(server) as (pipes, _task),
    ):
        pipes.send(b"question\n")
        pipes.end_input()  # ssh closes its half straight away
        assert await asyncio.wait_for(pipes.receive(), timeout=5) == b"late answer\n"


async def test_binary_data_crosses_the_bridge_unchanged(certs: Path) -> None:
    """CRLF translation would corrupt exactly this, and look like an SSH bug."""
    payload = bytes(range(256)) + b"\r\n\x1a\r\r\n"

    def echo_binary(received: bytes) -> bytes | None:
        return bytes(received) if received.endswith(b"\r\r\n") else None

    async with (
        proxy_for(certs, handler=echo_binary) as (server, _peer),
        bridged(server) as (pipes, _task),
    ):
        pipes.send(payload)
        received = await asyncio.wait_for(pipes.receive_exactly(len(payload)), timeout=5)
        assert received == payload


async def test_a_large_transfer_crosses_intact(certs: Path) -> None:
    """scp-shaped: many segments each way, so both windows have to hold up."""
    payload = bytes(range(256)) * 120  # 30 KB

    def echo_when_complete(received: bytes) -> bytes | None:
        return bytes(received) if len(received) >= len(payload) else None

    async with (
        proxy_for(certs, handler=echo_when_complete) as (server, _peer),
        bridged(server) as (pipes, _task),
    ):
        # A pipe buffer is smaller than the payload, so this blocks until the
        # bridge drains it -- off the loop thread, or it deadlocks.
        writing = asyncio.create_task(asyncio.to_thread(pipes.send, payload))
        received = await asyncio.wait_for(pipes.receive_exactly(len(payload)), timeout=10)
        await writing
        assert received == payload


async def test_the_bridge_writes_nothing_of_its_own_to_stdout(certs: Path) -> None:
    """Stdout is the connection: one stray byte corrupts the SSH stream."""
    async with proxy_for(certs) as (server, _peer), bridged(server) as (pipes, _task):
        pipes.send(b"x\n")
        assert await asyncio.wait_for(pipes.receive(), timeout=5) == b"X\n"
        # Nothing further may appear. A banner, a log line, or a progress
        # message would surface right here.
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(pipes.receive(), timeout=0.5)
