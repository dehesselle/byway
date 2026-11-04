"""One CSTP frame per TLS record.

This is a regression guard for the hardest bug in the project so far. A real
Cisco ASA closes the connection without warning the moment two CSTP frames
arrive in a single TLS record. The symptom is maximally misleading: the tunnel
establishes cleanly, runs fine for 20-60 seconds, then the gateway hangs up --
and only when two timers happen to coincide, so the time to failure looks
random. See docs/protocol.md for the evidence.

The invariant is asserted here rather than against the fake gateway because
asyncio's SSL transport hands decrypted plaintext to ``StreamReader`` as a
stream, concatenating records -- a server built on it cannot see record
boundaries at all. What we control, and what maps one-to-one onto TLS records,
is the number of ``write()`` calls: asyncio turns each into a single
``SSLObject.write()``.
"""

from __future__ import annotations

import ssl
from typing import Any

from pylis.cstp.framing import FRAME_DPD_OUT, FRAME_KEEPALIVE, HEADER_LEN, PacketType, encode_frame
from pylis.cstp.session import CstpSession


class RecordingWriter:
    """Stands in for asyncio's StreamWriter, recording each write separately."""

    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.drains = 0

    def write(self, data: bytes) -> None:
        self.writes.append(bytes(data))

    async def drain(self) -> None:
        self.drains += 1

    def is_closing(self) -> bool:
        return False


def make_session(**kwargs: Any) -> tuple[CstpSession, RecordingWriter]:
    session = CstpSession(
        host="gw.example",
        port=443,
        session_token="TOK",
        ssl_context=ssl.create_default_context(),
        user_agent="test",
        local_hostname="test",
        **kwargs,
    )
    writer = RecordingWriter()
    session._writer = writer  # type: ignore[assignment]
    return session, writer


async def test_each_frame_gets_its_own_write() -> None:
    session, writer = make_session()
    session.send(b"a" * 40)
    session.send(b"b" * 40)
    session._queue(FRAME_DPD_OUT, "DPD_OUT")
    session._queue(FRAME_KEEPALIVE, "KEEPALIVE")

    await session._flush_outbound()

    assert len(writer.writes) == 4, "frames must not share a TLS record"
    assert writer.writes[0] == encode_frame(PacketType.DATA, b"a" * 40)
    assert writer.writes[1] == encode_frame(PacketType.DATA, b"b" * 40)
    assert writer.writes[2] == FRAME_DPD_OUT
    assert writer.writes[3] == FRAME_KEEPALIVE


async def test_the_coinciding_timer_case_that_killed_the_real_tunnel() -> None:
    """DPD and keepalive firing on the same tick is what triggered it."""
    session, writer = make_session()
    session._queue(FRAME_DPD_OUT, "DPD_OUT")
    session._queue(FRAME_KEEPALIVE, "KEEPALIVE")

    await session._flush_outbound()

    assert writer.writes == [FRAME_DPD_OUT, FRAME_KEEPALIVE]
    # The fatal shape: one write carrying two 8-byte frames.
    assert not any(len(write) > HEADER_LEN for write in writer.writes)


async def test_a_dpd_response_jumps_the_queue_but_stays_separate() -> None:
    session, writer = make_session()
    session.send(b"queued" * 20)
    session._queue(b"URGENT", "DPD_RESP", urgent=True)

    await session._flush_outbound()

    assert writer.writes[0] == b"URGENT"
    assert len(writer.writes) == 2


async def test_every_write_is_drained() -> None:
    session, writer = make_session()
    for index in range(5):
        session.send(bytes([index]))

    await session._flush_outbound()

    assert writer.drains == 5
    assert not session._outbound


async def test_flush_with_nothing_queued_is_a_no_op() -> None:
    session, writer = make_session()
    await session._flush_outbound()
    assert writer.writes == []


async def test_coalescing_is_off_by_default() -> None:
    session, _ = make_session()
    assert session._coalesce is False


async def test_coalescing_remains_available_as_an_opt_in() -> None:
    """Retained for gateways that tolerate it; never the default."""
    session, writer = make_session(coalesce=True)
    session._queue(FRAME_DPD_OUT, "DPD_OUT")
    session._queue(FRAME_KEEPALIVE, "KEEPALIVE")

    await session._flush_outbound()

    assert writer.writes == [FRAME_DPD_OUT + FRAME_KEEPALIVE]
