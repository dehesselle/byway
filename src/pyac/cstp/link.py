"""The CSTP implementation of the IP link abstraction.

Everything above this interface deals in whole IP packets and never learns
that the TLS connection underneath was torn down and rebuilt. That is what
makes rekey and reconnect a non-event rather than a rewrite -- and it is why
this indirection exists from the start instead of being retrofitted once
reconnection becomes a problem.

The interface itself is :class:`usernet.link.IpLink`, re-exported here because
this module used to define it and callers still expect to find it. The
contract is deliberately batch-shaped: :meth:`~usernet.link.IpLink.take_inbound`
drains everything received since the last call so the driver can feed the stack
in one pass, and queued outbound packets are coalesced into a single TLS write,
which is the largest cheap throughput win available.

:class:`~pyac.cstp.config.TunnelConfig` carries far more than the stack needs --
DPD timers, rekey method, the banner -- but it satisfies
:class:`usernet.link.LinkConfig` structurally, so it is handed over whole rather
than being split in two.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable, Sequence
from types import TracebackType

from usernet.aio import first_of
from usernet.link import IpLink

from pyac.cstp.config import TunnelConfig
from pyac.cstp.session import CstpSession
from pyac.errors import AuthError, HandshakeRejected, TunnelClosed

__all__ = ["DEFAULT_BACKOFF_MS", "DEFAULT_BUFFER_LIMIT", "IpLink", "ReconnectingLink"]

log = logging.getLogger("pyac.cstp")


# Reconnect backoff. Short enough that a blip is barely noticed, long enough
# that a gateway which is genuinely down is not hammered.
DEFAULT_BACKOFF_MS: tuple[int, ...] = (1000, 2000, 4000, 8000, 16000)

# Packets accepted while there is no session. Roughly five seconds of a busy
# connection; past that the sender is better served by TCP's own retransmission
# than by us hoarding memory on its behalf.
DEFAULT_BUFFER_LIMIT = 512


class ReconnectingLink:
    """An :class:`IpLink` that outlives the TLS connection beneath it.

    Rekey is the project's top risk. An ASA typically advertises
    ``X-CSTP-Rekey-Method: ssl``, meaning renegotiate in place -- which Python
    cannot do, and TLS 1.3 removes entirely. openconnect's own fallback is to
    tear the tunnel down and repeat ``CONNECT`` with the same ``webvpn``
    cookie, which is transparent to the gateway, and that is what happens here.
    Proactively, at a fraction of the advertised interval, rather than waiting
    to be disconnected.

    The same machinery covers every other way a tunnel ends: TLS EOF, a
    ``DISCONN`` frame, a DPD timeout, a laptop changing networks.

    **Reconnecting is not the same as being transparent.** If the gateway
    reassigns the same address, live TCP connections carry on and never learn
    anything happened. If it assigns a different one -- and this ASA assigns a
    fresh address every single time -- their local address has ceased to exist,
    and the honest thing is to fail them with a message that says so. The
    driver watches :attr:`config` for exactly that.
    """

    def __init__(
        self,
        open_session: Callable[[], Awaitable[CstpSession]],
        *,
        rekey_fraction: float = 0.9,
        backoff_ms: Sequence[int] = DEFAULT_BACKOFF_MS,
        max_attempts: int = 5,
        buffer_limit: int = DEFAULT_BUFFER_LIMIT,
        reconnect: bool = True,
    ) -> None:
        self._open_session = open_session
        self._rekey_fraction = rekey_fraction
        self._backoff_ms = tuple(backoff_ms)
        self._max_attempts = max_attempts
        self._buffer_limit = buffer_limit
        self._reconnect = reconnect

        self._session: CstpSession | None = None
        self._config: TunnelConfig | None = None
        """Last known tunnel parameters, kept across the gap.

        Everything above treats these as a property of the link, and reads them
        on every pass -- the driver compares the address to spot a reassignment.
        Letting them vanish for the duration of a reconnect would make that
        read fail rather than simply return the same answer as before.
        """
        self._pending: deque[bytes] = deque()
        self._idle = asyncio.Event()  # never set: stands in for a missing wake
        self._closed = asyncio.Event()
        self._close_reason = ""
        self._close_error: BaseException | None = None
        self._supervisor: asyncio.Task[None] | None = None

        self.reconnects = 0
        self.address_changes = 0
        self.dropped_while_down = 0

    # --- lifecycle ---------------------------------------------------------

    async def start(self) -> TunnelConfig:
        """Open the first session and begin supervising it."""
        self._session = await self._open_session()
        self._config = self._session.config
        if self._reconnect:
            self._supervisor = asyncio.create_task(self._supervise(), name="pyac-reconnect")
            self._supervisor.add_done_callback(self._on_supervisor_done)
        else:
            self._supervisor = asyncio.create_task(self._watch_once(), name="pyac-link-watch")
            self._supervisor.add_done_callback(self._on_supervisor_done)
        return self._session.config

    async def aclose(self) -> None:
        self._closed.set()
        if self._supervisor is not None:
            self._supervisor.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._supervisor
            self._supervisor = None
        if self._session is not None:
            await self._session.aclose()

    async def __aenter__(self) -> ReconnectingLink:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    def _on_supervisor_done(self, task: asyncio.Task[None]) -> None:
        if task.cancelled():
            return
        exception = task.exception()
        if exception is not None:
            log.error("reconnect supervisor failed: %r", exception)
            self._fail(f"reconnect supervisor failed: {exception!r}")

    # --- IpLink ------------------------------------------------------------

    @property
    def session(self) -> CstpSession:
        """The session in force right now, for statistics and diagnostics."""
        if self._session is None:
            raise TunnelClosed("the link has not been started")
        return self._session

    @property
    def config(self) -> TunnelConfig:
        if self._config is None:
            raise TunnelClosed("the link has not been started")
        return self._config

    @property
    def rekey_seconds(self) -> float | None:
        """How long a session is allowed to live before being rebuilt, or None
        if the gateway schedules no rekey at all.

        The interval actually in force, fraction included, so a caller can
        report what will happen rather than re-deriving it and drifting.
        """
        config = self._config
        if config is None or not config.rekey_time or not self._reconnect:
            return None
        return config.rekey_time * self._rekey_fraction

    @property
    def wake(self) -> asyncio.Event:
        # The current session's, re-read by the driver on every pass. During a
        # reconnect there is no session to wait on, so hand back an event that
        # never fires and let the driver's own idle timeout carry it across.
        session = self._session
        return session.wake if session is not None else self._idle

    @property
    def closed(self) -> asyncio.Event:
        return self._closed

    @property
    def close_reason(self) -> str:
        return self._close_reason

    @property
    def close_error(self) -> BaseException | None:
        """What ended the link, as an exception, when there was one.

        The string in :attr:`close_reason` is for the user; this is for code
        that wants to react to *why* rather than match on prose.
        """
        return self._close_error

    def send(self, packet: bytes) -> None:
        session = self._session
        if session is not None and not session.closed.is_set():
            session.send(packet)
            return
        # Buffered across the gap, bounded. TCP will retransmit whatever we
        # drop, so the bound costs a delay rather than data.
        if len(self._pending) < self._buffer_limit:
            self._pending.append(packet)
        else:
            self.dropped_while_down += 1

    def take_inbound(self) -> list[bytes]:
        session = self._session
        return session.take_inbound() if session is not None else []

    # --- supervision -------------------------------------------------------

    async def _watch_once(self) -> None:
        """Without reconnect, a closed session simply closes the link."""
        session = self.session
        await session.closed.wait()
        self._fail(session.close_reason or "tunnel closed")

    async def _supervise(self) -> None:
        while not self._closed.is_set():
            session = self.session
            reason = await self._wait_for_end(session)
            if self._closed.is_set():
                return
            log.info("tunnel ended (%s); reconnecting", reason)
            if not await self._reopen(reason):
                return

    async def _wait_for_end(self, session: CstpSession) -> str:
        """Wait until the session dies, or until it is time to rekey."""
        deadline = self._rekey_deadline(session)
        if deadline is None:
            await session.closed.wait()
            return session.close_reason or "tunnel closed"

        remaining = deadline - time.monotonic()
        if remaining > 0:
            await first_of(session.closed, self._closed, seconds=remaining)
        if session.closed.is_set():
            return session.close_reason or "tunnel closed"
        return "rekey due"

    def _rekey_deadline(self, session: CstpSession) -> float | None:
        rekey_time = session.config.rekey_time
        if not rekey_time:
            return None
        # Early, not on the dot: being disconnected mid-request costs far more
        # than one extra handshake.
        return session.started_at + rekey_time * self._rekey_fraction

    async def _reopen(self, reason: str) -> bool:
        previous = self._session
        previous_address = previous.config.address if previous is not None else None
        self._session = None
        if previous is not None:
            await previous.aclose()

        last_error: BaseException | None = None
        for attempt in range(self._max_attempts):
            if self._closed.is_set():
                return False
            try:
                session = await self._open_session()
            except Exception as exc:
                # Most failures are worth retrying: a refused connection, a TLS
                # failure, a DNS blip on the gateway's own name. A rejected
                # cookie is not -- see _is_permanent.
                last_error = exc
                if _is_permanent(exc):
                    log.error("reconnect is not possible: %s", exc)
                    self._fail(f"cannot re-establish the tunnel: {exc}", exc)
                    return False
                if attempt + 1 >= self._max_attempts:
                    # No backoff before giving up: that last sleep buys nothing
                    # and delays the error the user is waiting for.
                    log.warning("reconnect attempt %d failed (%s); giving up", attempt + 1, exc)
                    break
                delay = self._backoff_ms[min(attempt, len(self._backoff_ms) - 1)] / 1000
                log.warning(
                    "reconnect attempt %d of %d failed (%s); retrying in %.0fs",
                    attempt + 1,
                    self._max_attempts,
                    exc,
                    delay,
                )
                await first_of(self._closed, seconds=delay)
                continue

            self._session = session
            self._config = session.config
            self.reconnects += 1
            if session.config.address != previous_address:
                self.address_changes += 1
                log.warning(
                    "the gateway reassigned our address (%s -> %s); connections open "
                    "across the gap cannot survive that",
                    previous_address,
                    session.config.address,
                )
            log.info("tunnel re-established after %s", reason)
            self._flush_pending(session)
            return True

        detail = f": {last_error}" if last_error is not None else ""
        self._fail(f"could not re-establish the tunnel after {reason}{detail}", last_error)
        return False

    def _flush_pending(self, session: CstpSession) -> None:
        while self._pending:
            session.send(self._pending.popleft())

    def _fail(self, reason: str, error: BaseException | None = None) -> None:
        self._close_reason = reason
        self._close_error = error
        self._closed.set()


def _is_permanent(exc: BaseException) -> bool:
    """Errors that no amount of retrying can fix.

    A rejected cookie is the one that matters in practice. When this gateway's
    idle timeout fires it does not merely drop the connection, it destroys the
    session, so ``CONNECT`` comes back 401 and will keep doing so. Retrying is
    then not just futile but actively unwise: repeated rejected credentials are
    how accounts meet a lockout policy.
    """
    if isinstance(exc, AuthError):
        return True
    return isinstance(exc, HandshakeRejected) and exc.status in (401, 403)
