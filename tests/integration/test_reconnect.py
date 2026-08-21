"""Rekey and reconnection: the tunnel outliving the TLS connection under it.

The top risk in the plan. An ASA advertises ``Rekey-Method: ssl``, meaning
renegotiate in place, which Python cannot do at all -- so the tunnel has to be
rebuilt on the same cookie instead, before the gateway loses patience.

Rebuilding is not the same as being seamless, and these tests hold that line:
when the address survives, connections survive; when it changes, they are
failed with a message that says why.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from pathlib import Path

import pytest
from usernet.runtime.driver import Driver
from usernet.testing.peer import TcpPeer, http_handler

from pyac.cstp.link import ReconnectingLink
from pyac.cstp.session import CstpSession
from pyac.errors import HandshakeRejected, NetworkError
from tests.fakegw import FakeGateway
from tests.fakegw.server import DEFAULT_TUNNEL_HEADERS

SERVER_IP = "10.11.12.13"
BASE_HEADERS = [(n, v) for n, v in DEFAULT_TUNNEL_HEADERS if n != "X-CSTP-Banner"]


@pytest.fixture
def certs(tmp_path: Path) -> Path:
    return tmp_path


def headers_with(**overrides: str) -> list[tuple[str, str]]:
    """The default tunnel headers, with some replaced or added."""
    wanted = {f"x-cstp-{key.replace('_', '-')}": value for key, value in overrides.items()}
    result = [(n, wanted.pop(n.lower(), v)) for n, v in BASE_HEADERS]
    result += [(name, value) for name, value in wanted.items()]
    return result


async def make_session(gateway: FakeGateway) -> CstpSession:
    session = CstpSession(
        host="127.0.0.1",
        port=gateway.port,
        session_token="TESTTOKEN",
        ssl_context=ssl.create_default_context(cafile=gateway.ca_path),
        user_agent="AnyConnect Windows 4.10.07061",
        local_hostname="testhost",
    )
    await session.connect()
    return session


def linking(gateway: FakeGateway, **options: object) -> ReconnectingLink:
    async def open_session() -> CstpSession:
        return await make_session(gateway)

    return ReconnectingLink(open_session, **options)  # type: ignore[arg-type]


async def wait_until(  # type: ignore[no-untyped-def]
    predicate,
    timeout: float = 5.0,  # noqa: ASYNC109 - a bound on the test, not a protocol deadline
) -> None:
    """Poll until ``predicate`` holds.

    Polling rather than awaiting an Event, because what these tests watch are
    counters and addresses that reconnection happens to change -- adding an
    Event per observable would be instrumentation the product does not need.
    """
    async with asyncio.timeout(timeout):
        while not predicate():  # noqa: ASYNC110 - see above
            await asyncio.sleep(0.02)


# --- reconnection -----------------------------------------------------------


async def test_a_disconnect_is_rebuilt(certs: Path) -> None:
    async with FakeGateway([], certs_dir=certs, tunnel_headers=BASE_HEADERS) as gateway:
        link = linking(gateway)
        await link.start()
        try:
            gateway.send_disconnect()
            await wait_until(lambda: link.reconnects >= 1)

            assert not link.closed.is_set(), "the link gave up instead of rebuilding"
            assert gateway.connects == 2
        finally:
            await link.aclose()


async def test_the_cookie_is_reused_rather_than_reauthenticating(certs: Path) -> None:
    """Re-authenticating per reconnect would burn the gateway's session limit,
    and a background task must never prompt for a password."""
    async with FakeGateway([], certs_dir=certs, tunnel_headers=BASE_HEADERS) as gateway:
        link = linking(gateway)
        await link.start()
        try:
            gateway.send_disconnect()
            await wait_until(lambda: link.reconnects >= 1)
        finally:
            await link.aclose()

    assert gateway.requests == [], "a reconnect posted an authentication request"
    assert gateway.connect_headers["cookie"] == "webvpn=TESTTOKEN"


async def test_rekey_happens_early_and_by_itself(certs: Path) -> None:
    """Proactive, at a fraction of the interval: being disconnected mid-request
    costs far more than one spare handshake."""
    async with FakeGateway(
        [], certs_dir=certs, tunnel_headers=headers_with(rekey_time="1")
    ) as gateway:
        link = linking(gateway, rekey_fraction=0.2)  # 200 ms, so the test is quick
        await link.start()
        try:
            await wait_until(lambda: link.reconnects >= 2, timeout=5.0)
            assert not link.closed.is_set()
        finally:
            await link.aclose()


async def test_no_rekey_when_the_gateway_asks_for_none(certs: Path) -> None:
    async with FakeGateway(
        [], certs_dir=certs, tunnel_headers=headers_with(rekey_time="0")
    ) as gateway:
        link = linking(gateway, rekey_fraction=0.01)
        await link.start()
        try:
            await asyncio.sleep(0.5)
            assert link.reconnects == 0
        finally:
            await link.aclose()


async def test_the_effective_rekey_interval_is_reported(certs: Path) -> None:
    """``pyac up`` prints this, so it has to be the interval in force rather
    than the advertised one -- otherwise the output describes something the
    link does not do."""
    async with FakeGateway(
        [], certs_dir=certs, tunnel_headers=headers_with(rekey_time="3600")
    ) as gateway:
        link = linking(gateway, rekey_fraction=0.9)
        await link.start()
        try:
            assert link.rekey_seconds == pytest.approx(3240)
        finally:
            await link.aclose()


async def test_no_rekey_interval_is_reported_when_none_is_scheduled(certs: Path) -> None:
    """Two ways to get here, and both must be distinguishable from a number:
    a gateway that asks for no rekey, and reconnection switched off."""
    async with FakeGateway(
        [], certs_dir=certs, tunnel_headers=headers_with(rekey_time="0")
    ) as gateway:
        link = linking(gateway)
        await link.start()
        try:
            assert link.rekey_seconds is None
        finally:
            await link.aclose()

    async with FakeGateway(
        [], certs_dir=certs, tunnel_headers=headers_with(rekey_time="3600")
    ) as gateway:
        link = linking(gateway, reconnect=False)
        await link.start()
        try:
            assert link.rekey_seconds is None
        finally:
            await link.aclose()


async def test_packets_sent_during_the_gap_are_delivered(certs: Path) -> None:
    """TCP would retransmit them anyway, but an immediate flush saves an RTO."""
    async with FakeGateway([], certs_dir=certs, tunnel_headers=BASE_HEADERS) as gateway:
        link = linking(gateway)
        await link.start()
        try:
            # Close it ourselves, so the packet is written during the gap
            # rather than racing the supervisor for it.
            await link.session.aclose()
            link.send(b"\x45\x00sent while down")

            await wait_until(lambda: link.reconnects >= 1)
            await wait_until(lambda: b"\x45\x00sent while down" in gateway.received_packets)
        finally:
            await link.aclose()


async def test_the_buffer_is_bounded(certs: Path) -> None:
    """A tunnel that stays down must not turn into unbounded memory growth."""
    async with FakeGateway([], certs_dir=certs, tunnel_headers=BASE_HEADERS) as gateway:
        link = linking(gateway, buffer_limit=4)
        await link.start()
        try:
            await link.session.aclose()
            for index in range(20):
                link.send(bytes([0x45, 0x00, index]))
            assert link.dropped_while_down >= 15
        finally:
            await link.aclose()


async def test_giving_up_closes_the_link_with_a_reason(certs: Path) -> None:
    """Retrying forever would hide a gateway that is genuinely gone."""
    async with FakeGateway([], certs_dir=certs, tunnel_headers=BASE_HEADERS) as gateway:
        opened = 0

        async def open_session() -> CstpSession:
            nonlocal opened
            opened += 1
            if opened > 1:
                raise NetworkError("the gateway is not answering")
            return await make_session(gateway)

        link = ReconnectingLink(open_session, backoff_ms=(10, 10), max_attempts=3)
        await link.start()
        try:
            gateway.send_disconnect()
            await wait_until(link.closed.is_set, timeout=5.0)

            assert "could not re-establish" in link.close_reason
            assert opened == 4, "the first open plus exactly three attempts"
        finally:
            await link.aclose()


async def test_a_rejected_cookie_stops_immediately(certs: Path) -> None:
    """Observed against the real gateway: its idle timer does not merely drop
    the connection, it destroys the session, so CONNECT returns 401 and will
    keep doing so. Backing off through five of those wastes half a minute and
    walks an account towards a lockout policy."""
    async with FakeGateway([], certs_dir=certs, tunnel_headers=BASE_HEADERS) as gateway:
        attempts = 0

        async def open_session() -> CstpSession:
            nonlocal attempts
            attempts += 1
            if attempts > 1:
                raise HandshakeRejected(401, "session token rejected")
            return await make_session(gateway)

        link = ReconnectingLink(open_session, backoff_ms=(10,), max_attempts=5)
        await link.start()
        try:
            gateway.send_disconnect()
            await wait_until(link.closed.is_set)

            assert attempts == 2, "a permanently rejected cookie was retried"
            assert "cannot re-establish" in link.close_reason
            assert isinstance(link.close_error, HandshakeRejected)
        finally:
            await link.aclose()


async def test_giving_up_names_the_last_error(certs: Path) -> None:
    """A close reason naming only the trigger -- "after DISCONNECT" -- leaves
    out the part the user needs, which is why the retries failed."""
    async with FakeGateway([], certs_dir=certs, tunnel_headers=BASE_HEADERS) as gateway:
        opened = 0

        async def open_session() -> CstpSession:
            nonlocal opened
            opened += 1
            if opened > 1:
                raise NetworkError("connection refused")
            return await make_session(gateway)

        link = ReconnectingLink(open_session, backoff_ms=(10,), max_attempts=2)
        await link.start()
        try:
            gateway.send_disconnect()
            await wait_until(link.closed.is_set)
            assert "connection refused" in link.close_reason
        finally:
            await link.aclose()


async def test_the_last_attempt_is_not_followed_by_a_backoff(certs: Path) -> None:
    """Sleeping after the final try delays the error and buys nothing."""
    async with FakeGateway([], certs_dir=certs, tunnel_headers=BASE_HEADERS) as gateway:
        opened = 0

        async def open_session() -> CstpSession:
            nonlocal opened
            opened += 1
            if opened > 1:
                raise NetworkError("still down")
            return await make_session(gateway)

        # One retry, then give up; the backoff is long enough that sleeping
        # through it would blow the deadline below.
        link = ReconnectingLink(open_session, backoff_ms=(30_000,), max_attempts=1)
        await link.start()
        try:
            started = time.monotonic()
            gateway.send_disconnect()
            await wait_until(link.closed.is_set, timeout=5.0)
            assert time.monotonic() - started < 2.0
        finally:
            await link.aclose()


async def test_reconnection_can_be_switched_off(certs: Path) -> None:
    async with FakeGateway([], certs_dir=certs, tunnel_headers=BASE_HEADERS) as gateway:
        link = linking(gateway, reconnect=False)
        await link.start()
        try:
            gateway.send_disconnect()
            await wait_until(link.closed.is_set)

            assert link.reconnects == 0
            assert gateway.connects == 1
        finally:
            await link.aclose()


# --- what reconnection costs the layer above --------------------------------


async def test_connections_survive_when_the_address_does(certs: Path) -> None:
    """The payoff of the sans-IO design: the stack never learns it blipped."""
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"still here"))
    async with FakeGateway([], certs_dir=certs, peer=peer, tunnel_headers=BASE_HEADERS) as gateway:
        link = linking(gateway)
        await link.start()
        driver = Driver(link)
        driver.start()
        try:
            before = driver.config.local_ip
            gateway.send_disconnect()
            await wait_until(lambda: link.reconnects >= 1)
            await asyncio.sleep(0.2)

            assert driver.address_changes == 0
            assert driver.config.local_ip == before

            # And the stack still works afterwards.
            stream = await driver.connect(SERVER_IP, 80, timeout=5)
            await stream.write(b"GET / HTTP/1.1\r\n\r\n")
            assert (await stream.read_all()).endswith(b"still here")
        finally:
            await driver.aclose()
            await link.aclose()


async def test_a_new_address_resets_the_stack_and_says_why(certs: Path) -> None:
    """This ASA assigns a fresh address every time, so this is the normal case.
    A socket bound to an address the gateway has taken back cannot work, and
    pretending otherwise would leave it silently dead."""
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=lambda _received: None)
    async with FakeGateway(
        [],
        certs_dir=certs,
        peer=peer,
        tunnel_headers=BASE_HEADERS,
        address_per_connect=True,
    ) as gateway:
        link = linking(gateway)
        await link.start()
        driver = Driver(link)
        driver.start()
        try:
            stream = await driver.connect(SERVER_IP, 80, timeout=5)
            before = driver.config.local_ip

            gateway.send_disconnect()
            await wait_until(lambda: driver.address_changes >= 1)

            assert driver.config.local_ip != before
            assert link.address_changes == 1
            await asyncio.wait_for(stream.wait_closed(), timeout=5)
            assert isinstance(stream.error, NetworkError)
            assert "reassigned our address" in str(stream.error)
        finally:
            await driver.aclose()
            await link.aclose()


async def test_new_connections_work_after_an_address_change(certs: Path) -> None:
    """Losing the old connections is acceptable; losing the tunnel is not."""
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"after the change"))
    async with FakeGateway(
        [],
        certs_dir=certs,
        peer=peer,
        tunnel_headers=BASE_HEADERS,
        address_per_connect=True,
    ) as gateway:
        link = linking(gateway)
        await link.start()
        driver = Driver(link)
        driver.start()
        try:
            gateway.send_disconnect()
            await wait_until(lambda: driver.address_changes >= 1)

            stream = await driver.connect(SERVER_IP, 80, timeout=5)
            await stream.write(b"GET /after HTTP/1.1\r\n\r\n")
            assert (await stream.read_all()).endswith(b"after the change")
        finally:
            await driver.aclose()
            await link.aclose()
