# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""A live panel under ``byway up``'s output, when there is a terminal to draw on.

It answers "is the tunnel alive?" rather than "how fast is it?". Throughput
alone cannot tell an idle tunnel from a dead one -- both read 0 B/s -- so the
first things shown are the ones that can: how long ago the gateway last said
anything, and whether the last keepalive came back.

Everything is sampled on the event loop, once a second, from counters the link
and the SOCKS server keep anyway. Drawing happens on :class:`TermWriter`'s
thread, so a terminal that stops accepting output cannot stall the tunnel.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import re
import shutil
import sys
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TextIO

from byway.cli.terminal import TermWriter, enable_vt, visible_length
from byway.cstp.link import ReconnectingLink

if TYPE_CHECKING:
    from usernet.runtime.driver import TcpStream
    from usernet.socks import Socks5Server

REFRESH_SECONDS = 1.0
MAX_CONNECTION_ROWS = 8
FLUSH_TIMEOUT = 3.0

# --- what is shown -----------------------------------------------------------


@dataclass
class Sources:
    """What the panel reads. ``byway up`` fills in the parts it has."""

    link: ReconnectingLink
    gateway: str
    keepalive: bool = False
    proxy: Socks5Server | None = None
    keepalive_rtt: float | None = None
    keepalive_at: float = 0.0  # when the last keepalive was answered, or given up on


@dataclass(frozen=True)
class ConnSample:
    label: str
    age: float
    total: int
    rx_rate: float
    tx_rate: float


@dataclass(frozen=True)
class Sample:
    address: str
    gateway: str
    state: str  # "up", "reconnecting" or "closed"
    uptime: float
    last_rx: float | None  # seconds since the gateway's last frame
    stale_after: float
    bytes_in: int
    bytes_out: int
    rate_in: float
    rate_out: float
    reconnects: int
    rekey_in: float | None
    keepalive: tuple[float | None, float | None] | None = None  # (rtt ms, age); None: off
    socks: tuple[int, int, int] | None = None  # open, total, rejected; None: no proxy
    conns: list[ConnSample] = field(default_factory=list)


class Sampler:
    """Turns counters into a :class:`Sample`, rates from the previous one."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._at = 0.0
        self._in = 0
        self._out = 0
        # Per relay: (rx, tx, last time either moved). Rebuilt every tick, so
        # a finished relay is forgotten rather than kept alive by this dict.
        self._conns: dict[TcpStream, tuple[int, int, float]] = {}

    def next(self, sources: Sources) -> Sample:
        now = self._clock()
        elapsed = now - self._at if self._at else 0.0
        link = sources.link

        def rate(current: int, previous: int) -> float:
            # Never negative: a counter that went backwards is a reset, not traffic.
            return max(0.0, (current - previous) / elapsed) if elapsed > 0 else 0.0

        bytes_in, bytes_out = link.bytes_in, link.bytes_out
        rate_in, rate_out = rate(bytes_in, self._in), rate(bytes_out, self._out)
        self._at, self._in, self._out = now, bytes_in, bytes_out

        if link.closed.is_set():
            state = "closed"
        elif link.reconnecting:
            state = "reconnecting"
        else:
            state = "up"
        last_rx = None if state != "up" else now - link.session.last_frame_at
        config = link.config
        rekey_at = link.rekey_at

        keepalive = None
        if sources.keepalive:
            age = now - sources.keepalive_at if sources.keepalive_at else None
            keepalive = (sources.keepalive_rtt, age)

        socks = None
        conns: list[ConnSample] = []
        proxy = sources.proxy
        if proxy is not None:
            socks = (proxy.active, proxy.connections, proxy.rejected)
            seen: dict[TcpStream, tuple[int, int, float]] = {}
            moving: list[tuple[float, float, ConnSample]] = []
            for stream, label in list(proxy.relays.items()):
                rx, tx, active_at = self._conns.get(stream, (0, 0, stream.opened_at))
                if (stream.rx, stream.tx) != (rx, tx):
                    active_at = now
                seen[stream] = (stream.rx, stream.tx, active_at)
                sample = ConnSample(
                    label=label,
                    age=now - stream.opened_at,
                    total=stream.rx + stream.tx,
                    rx_rate=rate(stream.rx, rx),
                    tx_rate=rate(stream.tx, tx),
                )
                moving.append((active_at, stream.opened_at, sample))
            self._conns = seen
            # What is moving right now first: that is the row worth seeing
            # when there are more connections than room.
            moving.sort(key=lambda entry: (-entry[0], entry[1]))
            conns = [entry[2] for entry in moving]

        return Sample(
            address=config.address,
            gateway=sources.gateway,
            state=state,
            uptime=now - link.started_at if link.started_at else 0.0,
            last_rx=last_rx,
            # DPD or keepalive frames arrive at least this often on a live tunnel.
            stale_after=max(config.dpd, config.keepalive) + 10.0,
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            rate_in=rate_in,
            rate_out=rate_out,
            reconnects=link.reconnects,
            rekey_in=max(0.0, rekey_at - now) if rekey_at is not None else None,
            keepalive=keepalive,
            socks=socks,
            conns=conns,
        )


# --- drawing -----------------------------------------------------------------


@dataclass(frozen=True)
class Glyphs:
    top_left: str
    top_right: str
    bottom_left: str
    bottom_right: str
    horizontal: str
    vertical: str
    tee_left: str
    tee_right: str
    dot: str
    more: str


UNICODE = Glyphs("╭", "╮", "╰", "╯", "─", "│", "├", "┤", "·", "…")
ASCII = Glyphs("+", "+", "+", "+", "-", "|", "+", "+", "/", "...")


@dataclass(frozen=True)
class Style:
    faint: str = "\x1b[2m"
    bold: str = "\x1b[1m"
    warn: str = "\x1b[1;33m"
    reset: str = "\x1b[0m"


COLOR = Style()
PLAIN = Style("", "", "", "")


@dataclass(frozen=True)
class Row:
    label: str
    value: str
    remark: str = ""
    warn: bool = False


def size(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def duration(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h}h{m:02d}m"
    d, h = divmod(h, 24)
    return f"{d}d{h:02d}h"


def ago(seconds: float) -> str:
    return f"{seconds:.1f}s ago" if seconds < 10 else f"{duration(seconds)} ago"


_SGR = re.compile(r"(\x1b\[[0-9;]*[A-Za-z])")


def clip(text: str, width: int, reset: str = "") -> str:
    """At most ``width`` visible characters, escape sequences kept intact."""
    if visible_length(text) <= width:
        return text
    out: list[str] = []
    left = width
    for part in _SGR.split(text):
        if _SGR.fullmatch(part):
            out.append(part)
        elif left > 0:
            out.append(part[:left])
            left -= len(part[:left])
    return "".join(out) + reset


def _group(rows: list[Row], style: Style) -> list[str]:
    """Label, value right-aligned, remark: lined up within the group."""
    if not rows:
        return []
    label_w = max(len(r.label) for r in rows)
    value_w = max(len(r.value) for r in rows)
    remark_w = max(len(r.remark) for r in rows)
    lines = []
    for r in rows:
        value_style = style.warn if r.warn else style.bold
        line = (
            f"{style.faint}{r.label:<{label_w}}{style.reset}  "
            f"{value_style}{r.value:>{value_w}}{style.reset}"
        )
        if remark_w:
            line += f"  {style.faint}{r.remark:<{remark_w}}{style.reset}"
        lines.append(line)
    return lines


def _pad(line: str, width: int, style: Style) -> str:
    line = clip(line, width, style.reset)
    return line + " " * (width - visible_length(line))


def render(
    sample: Sample,
    width: int,
    height: int,
    *,
    final: bool = False,
    glyphs: Glyphs = UNICODE,
    style: Style = COLOR,
) -> list[str]:
    """The panel, one string per terminal row, none wider than ``width - 1``.

    Never the full width: a line that fills the last column wraps on some
    terminals and not others, and the redraw counts on knowing which.
    """
    g, st = glyphs, style
    usable = max(8, width - 1)
    inner = usable - 4

    if sample.state == "up":
        tunnel = Row("tunnel", f"up {duration(sample.uptime)}")
    else:
        tunnel = Row("tunnel", sample.state, warn=True)
    if sample.last_rx is None:
        last_rx = Row("last rx", "-")
    else:
        last_rx = Row("last rx", ago(sample.last_rx), warn=sample.last_rx > sample.stale_after)
    left = [tunnel, last_rx]
    if sample.keepalive is not None:
        rtt, age = sample.keepalive
        if age is None:
            left.append(Row("keepalive", "waiting"))
        elif rtt is None:
            left.append(Row("keepalive", "no reply", ago(age), warn=True))
        else:
            left.append(Row("keepalive", f"{rtt:.0f} ms", ago(age)))
    if sample.socks is not None:
        active, total, rejected = sample.socks
        remark = f"{total} total"
        if rejected:
            remark += f" {g.dot} {rejected} rejected"
        left.append(Row("socks", f"{active} open", remark))

    rekey = f"rekey in {duration(sample.rekey_in)}" if sample.rekey_in is not None else ""
    right = [
        Row("received", f"{size(sample.rate_in)}/s", f"{size(sample.bytes_in):>9}"),
        Row("sent", f"{size(sample.rate_out)}/s", f"{size(sample.bytes_out):>9}"),
        Row("reconnects", str(sample.reconnects), rekey),
    ]

    left_lines, right_lines = _group(left, st), _group(right, st)
    left_w = max(visible_length(line) for line in left_lines)
    right_w = max(visible_length(line) for line in right_lines)
    gap = 4
    if left_w + gap + right_w <= inner:
        body = []
        for i in range(max(len(left_lines), len(right_lines))):
            a = left_lines[i] if i < len(left_lines) else ""
            b = right_lines[i] if i < len(right_lines) else ""
            spacer = " " * (left_w - visible_length(a) + gap)
            body.append(a + spacer + b if b else a)
    else:
        body = left_lines + right_lines  # too narrow for two columns: stack them

    title = f"byway {g.dot} {sample.address} via {sample.gateway}"
    lines = [_top(title, usable, final, g, st)]
    lines += [_framed(line, inner, g, st) for line in body]

    if sample.socks is not None:
        lines.append(f"{st.faint}{g.tee_left}{g.horizontal * (usable - 2)}{g.tee_right}{st.reset}")
        room = max(1, min(MAX_CONNECTION_ROWS, height - len(lines) - 6))
        shown = sample.conns if len(sample.conns) <= room else sample.conns[: room - 1]
        if not sample.conns:
            lines.append(_framed(f"{st.faint}no open connections{st.reset}", inner, g, st))
        for conn in shown:
            lines.append(_framed(_connection(conn, inner, g, st), inner, g, st))
        if len(shown) < len(sample.conns):
            more = f"{g.more} {len(sample.conns) - len(shown)} more"
            lines.append(_framed(f"{st.faint}{more}{st.reset}", inner, g, st))

    bottom = g.bottom_left + g.horizontal * (usable - 2) + g.bottom_right
    lines.append(f"{st.faint}{bottom}{st.reset}")
    return [clip(line, max(1, width - 1), st.reset) for line in lines]


def _top(title: str, usable: int, final: bool, g: Glyphs, st: Style) -> str:
    hint = "" if final else " Ctrl+C to stop "
    head = f"{g.top_left}{g.horizontal} "
    tail = f"{hint}{g.horizontal}{g.top_right}"
    room = usable - len(head) - len(tail) - 1
    if room < len(title) + 2 and hint:
        tail = f"{g.horizontal}{g.top_right}"  # the hint goes before the title does
        room = usable - len(head) - len(tail) - 1
    title = title[: max(0, room)]
    fill = g.horizontal * max(0, usable - len(head) - len(title) - 1 - len(tail))
    return f"{st.faint}{head}{st.reset}{st.bold}{title}{st.reset}{st.faint} {fill}{tail}{st.reset}"


def _framed(content: str, inner: int, g: Glyphs, st: Style) -> str:
    border = f"{st.faint}{g.vertical}{st.reset}"
    return f"{border} {_pad(content, inner, st)} {border}"


MIN_LABEL = 20  # below this, a hostname stops being recognisable


def _connection(conn: ConnSample, inner: int, g: Glyphs, st: Style) -> str:
    figures = (
        f"{duration(conn.age):>7}"
        f"  {st.faint}in{st.reset} {size(conn.rx_rate) + '/s':>12}"
        f"  {st.faint}out{st.reset} {size(conn.tx_rate) + '/s':>12}"
        f"  {size(conn.total):>10}"
    )
    if inner - visible_length(figures) - 2 < MIN_LABEL:
        # Narrow: one combined rate instead of in and out.
        rate = size(conn.rx_rate + conn.tx_rate) + "/s"
        figures = f"{duration(conn.age):>7}  {rate:>12}  {size(conn.total):>10}"
    label_w = max(8, inner - visible_length(figures) - 2)
    label = conn.label
    if len(label) > label_w:
        label = label[: label_w - len(g.more)] + g.more
    return f"{label:<{label_w}}  {figures}"


# --- running it --------------------------------------------------------------


def wanted(args: argparse.Namespace) -> bool:
    """Whether ``byway up`` should draw the panel at all."""
    if getattr(args, "no_dashboard", False) or getattr(args, "json", False):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty() and sys.stderr.isatty()


def _glyphs_for(stream: TextIO) -> Glyphs:
    try:
        "".join(vars(UNICODE).values()).encode(stream.encoding or "ascii")
    except (UnicodeEncodeError, LookupError):
        return ASCII
    return UNICODE


def _terminal_size() -> os.terminal_size:
    try:
        return os.get_terminal_size(sys.stderr.fileno())
    except (AttributeError, OSError, ValueError):
        return shutil.get_terminal_size()


@contextlib.asynccontextmanager
async def dashboard(sources: Sources, *, enabled: bool) -> AsyncIterator[bool]:
    """Draw the panel for as long as the block runs; yields whether it does.

    While it runs, logging and ``print`` both go above the panel. Afterwards
    the last frame stays on screen, and output carries on beneath it.
    """
    restore_console = enable_vt(sys.stderr) if enabled else None
    if restore_console is None:
        yield False
        return

    sys.stdout.flush()
    sink = sys.stderr
    writer = TermWriter(sink)
    glyphs = _glyphs_for(sink)
    style = PLAIN if os.environ.get("NO_COLOR") else COLOR
    sampler = Sampler()

    def frame(*, final: bool = False) -> list[str]:
        columns, lines = _terminal_size()
        sample = sampler.next(sources)
        # The leading empty row keeps the panel clear of the output above it.
        return ["", *render(sample, columns, lines, final=final, glyphs=glyphs, style=style)]

    # The handler usernet.log.configure installed, pointed at the writer.
    handlers = {
        handler
        for name in ("byway", "usernet")
        for handler in logging.getLogger(name).handlers
        if isinstance(handler, logging.StreamHandler) and handler.stream is sink
    }
    for handler in handlers:
        handler.setStream(writer)

    async def tick() -> None:
        while True:
            writer.set_panel(frame())
            await asyncio.sleep(REFRESH_SECONDS)

    ticker = asyncio.create_task(tick(), name="byway-dashboard")
    try:
        with contextlib.redirect_stdout(writer):
            yield True
    finally:
        # Not awaited: a second Ctrl-C would cancel the wait and skip the
        # restore below. A late tick finds the writer closed and does nothing.
        ticker.cancel()
        try:
            writer.close(frame(final=True), timeout=FLUSH_TIMEOUT)
        finally:
            for handler in handlers:
                handler.setStream(sink)
            restore_console()
