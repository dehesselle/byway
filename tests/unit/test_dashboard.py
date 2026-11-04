# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The ``byway up`` dashboard: what it draws, and what it draws it from.

The panel is redrawn by moving the cursor up as many rows as it last took, so
a line that wraps would leave a ghost of the previous frame behind. Hence the
recurring check that nothing is ever as wide as the terminal.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field, replace
from types import SimpleNamespace
from typing import Any

import pytest

from byway.cli.dashboard import (
    ASCII,
    PLAIN,
    ConnSample,
    Sample,
    Sampler,
    Sources,
    clip,
    duration,
    render,
    size,
)
from byway.cli.terminal import visible_length

BASE = Sample(
    address="10.1.2.3",
    gateway="vpn.example.com",
    state="up",
    uptime=7980.0,
    last_rx=0.4,
    stale_after=40.0,
    bytes_in=325_000_000,
    bytes_out=23_000_000,
    rate_in=12_288.0,
    rate_out=1_126.0,
    reconnects=1,
    rekey_in=20460.0,
)

WITH_SOCKS = replace(
    BASE,
    keepalive=(23.0, 12.0),
    socks=(2, 41, 2),
    conns=[
        ConnSample("10.20.0.5:443", 4.0, 9_800_000, 812_000.0, 2_000.0),
        ConnSample("git.corp.example:22", 720.0, 1_200_000, 0.0, 0.0),
    ],
)


def text(lines: list[str]) -> str:
    return "\n".join(lines)


# --- formatting ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [(0, "0s"), (59.9, "59s"), (61, "1m01s"), (7980, "2h13m"), (90000, "1d01h")],
)
def test_durations_stay_short(seconds: float, expected: str) -> None:
    assert duration(seconds) == expected


@pytest.mark.parametrize(
    ("n", "expected"),
    [(0, "0 B"), (1023, "1023 B"), (1024, "1.0 KiB"), (325_000_000, "309.9 MiB")],
)
def test_sizes_are_binary(n: int, expected: str) -> None:
    assert size(n) == expected


def test_clipping_keeps_escape_sequences_whole() -> None:
    clipped = clip("\x1b[1mabcdef\x1b[0m", 3, "\x1b[0m")
    assert visible_length(clipped) == 3
    assert clipped.startswith("\x1b[1mabc")
    assert clipped.endswith("\x1b[0m")


# --- layout -------------------------------------------------------------------


@pytest.mark.parametrize("width", [200, 100, 80, 60, 40, 20, 5])
@pytest.mark.parametrize("sample", [BASE, WITH_SOCKS], ids=["tunnel", "socks"])
def test_no_line_reaches_the_last_column(sample: Sample, width: int) -> None:
    for line in render(sample, width, 40):
        assert visible_length(line) <= width - 1, repr(line)


def test_a_wide_terminal_gets_two_columns() -> None:
    lines = render(BASE, 120, 40, style=PLAIN)
    assert "tunnel" in lines[1] and "received" in lines[1]
    assert len(lines) == 5  # top, three rows, bottom


def test_a_narrow_terminal_stacks_them() -> None:
    lines = render(BASE, 50, 40, style=PLAIN)
    assert "received" not in lines[1]
    assert any("received" in line for line in lines)


def test_the_frame_is_closed_and_titled() -> None:
    lines = render(BASE, 100, 40, style=PLAIN)
    assert lines[0].startswith("╭─ byway · 10.1.2.3 via vpn.example.com")
    assert lines[0].endswith("Ctrl+C to stop ─╮")
    assert lines[-1].startswith("╰") and lines[-1].endswith("╯")
    assert {len(line) for line in lines} == {99}


def test_the_final_frame_drops_the_hint() -> None:
    assert "Ctrl+C" not in render(BASE, 100, 40, final=True)[0]


def test_ascii_glyphs_for_a_terminal_that_cannot_encode_box_drawing() -> None:
    lines = render(WITH_SOCKS, 100, 40, glyphs=ASCII, style=PLAIN)
    assert all(line.isascii() for line in lines)


def test_reconnecting_is_flagged_and_has_no_last_rx() -> None:
    sample = replace(BASE, state="reconnecting", last_rx=None)
    body = text(render(sample, 100, 40, style=PLAIN))
    assert "reconnecting" in body
    assert re.search(r"last rx\s+- ", body)


def test_a_quiet_gateway_is_flagged() -> None:
    quiet = render(replace(BASE, last_rx=95.0), 100, 40)
    lively = render(BASE, 100, 40)
    assert "\x1b[1;33m" in text(quiet)
    assert "\x1b[1;33m" not in text(lively)


def test_optional_rows_appear_only_when_there_is_something_behind_them() -> None:
    plain = text(render(BASE, 100, 40, style=PLAIN))
    assert "keepalive" not in plain and "socks" not in plain

    full = text(render(WITH_SOCKS, 120, 40, style=PLAIN))
    assert "keepalive" in full and "23 ms" in full
    assert "2 open" in full and "41 total · 2 rejected" in full


def test_keepalive_states() -> None:
    def row(keepalive: tuple[float | None, float | None]) -> str:
        return text(render(replace(BASE, keepalive=keepalive), 120, 40, style=PLAIN))

    assert "waiting" in row((None, None))
    assert "no reply" in row((None, 3.0))


def test_connections_are_listed_by_the_name_asked_for() -> None:
    body = text(render(WITH_SOCKS, 120, 40, style=PLAIN))
    assert "git.corp.example:22" in body
    assert "793.0 KiB/s" in body


def test_no_connections_says_so() -> None:
    body = text(render(replace(WITH_SOCKS, conns=[]), 120, 40, style=PLAIN))
    assert "no open connections" in body


def test_too_many_connections_are_capped_by_height() -> None:
    conns = [ConnSample(f"10.0.0.{i}:22", 1.0, 0, 0.0, 0.0) for i in range(30)]
    lines = render(replace(WITH_SOCKS, conns=conns), 120, 20, style=PLAIN)
    assert len(lines) < 20
    assert "more" in lines[-2]


def test_a_narrow_terminal_keeps_room_for_the_name() -> None:
    lines = render(WITH_SOCKS, 60, 40, style=PLAIN)
    assert any("git.corp.example:22" in line for line in lines)
    assert not any(" out " in line for line in lines)


def test_a_long_hostname_is_shortened_rather_than_wrapped() -> None:
    long = ConnSample("a-very-long-internal-hostname.corp.example.com:443", 1.0, 0, 0.0, 0.0)
    lines = render(replace(WITH_SOCKS, conns=[long]), 100, 40, style=PLAIN)
    assert all(len(line) <= 99 for line in lines)
    assert any("…" in line for line in lines)


# --- sampling -----------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class FakeLink:
    bytes_in: int = 0
    bytes_out: int = 0
    reconnecting: bool = False
    reconnects: int = 0
    rekey_at: float | None = None
    started_at: float = 900.0
    closed: asyncio.Event = field(default_factory=asyncio.Event)
    config: Any = field(
        default_factory=lambda: SimpleNamespace(address="10.1.2.3", dpd=30, keepalive=20)
    )
    session: Any = field(default_factory=lambda: SimpleNamespace(last_frame_at=999.0))


@dataclass
class FakeStream:
    opened_at: float
    rx: int = 0
    tx: int = 0

    __hash__ = object.__hash__


def sources_for(link: FakeLink, proxy: Any = None) -> Sources:
    return Sources(link, "vpn.example.com", proxy=proxy)  # type: ignore[arg-type]


def test_rates_come_from_the_previous_sample() -> None:
    clock, link = Clock(), FakeLink()
    sampler = Sampler(clock)
    first = sampler.next(sources_for(link))
    assert first.rate_in == 0.0
    assert first.uptime == 100.0
    assert first.last_rx == pytest.approx(1.0)

    clock.now += 2.0
    link.bytes_in, link.bytes_out = 4096, 1024
    second = sampler.next(sources_for(link))
    assert (second.rate_in, second.rate_out) == (2048.0, 512.0)


def test_a_counter_going_backwards_is_not_negative_traffic() -> None:
    clock, link = Clock(), FakeLink(bytes_in=5000)
    sampler = Sampler(clock)
    sampler.next(sources_for(link))
    clock.now += 1.0
    link.bytes_in = 0
    assert sampler.next(sources_for(link)).rate_in == 0.0


def test_the_state_follows_the_link() -> None:
    link = FakeLink(reconnecting=True)
    sample = Sampler(Clock()).next(sources_for(link))
    assert (sample.state, sample.last_rx) == ("reconnecting", None)

    link = FakeLink()
    link.closed.set()
    assert Sampler(Clock()).next(sources_for(link)).state == "closed"


def test_rekey_counts_down() -> None:
    sample = Sampler(Clock()).next(sources_for(FakeLink(rekey_at=1600.0)))
    assert sample.rekey_in == 600.0


def test_the_busiest_connection_comes_first() -> None:
    clock = Clock()
    idle, busy = FakeStream(opened_at=100.0), FakeStream(opened_at=900.0)
    proxy = SimpleNamespace(
        active=2, connections=5, rejected=0, relays={idle: "idle:22", busy: "busy:443"}
    )
    sampler = Sampler(clock)
    sampler.next(sources_for(FakeLink(), proxy))

    clock.now += 1.0
    busy.rx = 10_000
    sample = sampler.next(sources_for(FakeLink(), proxy))
    assert sample.socks == (2, 5, 0)
    assert [c.label for c in sample.conns] == ["busy:443", "idle:22"]
    assert sample.conns[0].rx_rate == 10_000.0
    assert sample.conns[0].total == 10_000


def test_a_finished_relay_is_forgotten() -> None:
    clock = Clock()
    stream = FakeStream(opened_at=900.0)
    proxy = SimpleNamespace(active=1, connections=1, rejected=0, relays={stream: "x:1"})
    sampler = Sampler(clock)
    sampler.next(sources_for(FakeLink(), proxy))
    proxy.relays = {}
    assert sampler.next(sources_for(FakeLink(), proxy)).conns == []
    assert sampler._conns == {}


# --- the whole thing ------------------------------------------------------------


async def test_the_dashboard_takes_over_output_and_gives_it_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import contextlib
    import io
    import logging
    import sys

    from byway import _logging
    from byway.cli import dashboard as module

    console = io.StringIO()
    stdout = io.StringIO()
    restored: list[bool] = []
    monkeypatch.setattr(sys, "stderr", console)
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(module, "enable_vt", lambda _stream: lambda: restored.append(True))
    monkeypatch.setattr(module, "REFRESH_SECONDS", 0.01)
    monkeypatch.setenv("NO_COLOR", "1")
    title = "byway / 10.1.2.3 via vpn.example.com"  # ASCII: a StringIO has no encoding
    _logging.configure(0, stream=console)
    handler = logging.getLogger("byway").handlers[0]
    try:
        async with module.dashboard(sources_for(FakeLink()), enabled=True) as drawing:
            assert drawing
            logging.getLogger("byway.cli").warning("a warning")
            print("a print")
            await asyncio.sleep(0.05)
        print("after")

        assert restored == [True]
        assert getattr(handler, "stream", None) is console
        assert sys.stdout is stdout
        drawn = console.getvalue()
        assert drawn.index("a warning") < drawn.rindex(title)
        assert drawn.index("a print") < drawn.rindex(title)
        assert f"a print\n\n+- {title}" in drawn  # one blank line above the panel
        # The last frame is the final one, and nothing is drawn after it.
        assert "Ctrl+C" not in drawn[drawn.rindex(title) :]
        assert drawn.endswith("+\n")
        assert stdout.getvalue() == "after\n"
    finally:
        with contextlib.suppress(Exception):
            _logging.configure(0)


async def test_no_terminal_means_no_dashboard(monkeypatch: pytest.MonkeyPatch) -> None:
    from byway.cli import dashboard as module

    monkeypatch.setattr(module, "enable_vt", lambda _stream: None)
    async with module.dashboard(sources_for(FakeLink()), enabled=True) as drawing:
        assert not drawing
    async with module.dashboard(sources_for(FakeLink()), enabled=False) as drawing:
        assert not drawing
