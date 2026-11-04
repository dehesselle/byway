# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Terminal output that never stalls the tunnel, and a panel pinned beneath it.

Everything in ``pylis up`` runs on one event loop, and a write to a terminal
can block: a Windows console with text selected (QuickEdit) stops accepting
output until the selection ends, and so does a Unix terminal after Ctrl-S.
Blocked on the loop thread, that freezes the tunnel itself -- no DPD, no
keepalive -- and the gateway drops it. Rare while ``up`` prints next to
nothing; certain once a panel redraws every second.

So :class:`TermWriter` only queues. One thread owns the real stream and is the
only thing that can block on it. A full queue drops output and says so
afterwards, rather than ever making a writer wait.
"""

from __future__ import annotations

import contextlib
import os
import queue
import re
import sys
import threading
from collections.abc import Callable, Iterator, Sequence
from typing import TextIO

QUEUE_SIZE = 1024

# Cursor to the start of the line N lines up, then erase to the end of screen.
_ERASE = "\x1b[{n}F\x1b[J"
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_REDRAW = object()
_STOP = object()


def visible_length(text: str) -> int:
    return len(_ANSI.sub("", text))


class TermWriter:
    """A text stream for logging and ``print``, plus a panel kept beneath it.

    :meth:`write` and :meth:`set_panel` return immediately from any thread.
    Text is shown a complete line at a time, above the panel; the panel is
    always redrawn from the latest lines given, so a skipped redraw costs
    nothing but a second's staleness.
    """

    def __init__(self, sink: TextIO) -> None:
        self._sink = sink
        self._queue: queue.Queue[object] = queue.Queue(QUEUE_SIZE)
        self._panel: Sequence[str] = ()
        self._dropped = 0
        self._lock = threading.Lock()
        self._closed = False
        self._thread = threading.Thread(target=self._drain, name="pylis-terminal", daemon=True)
        self._thread.start()

    # --- the stream interface ------------------------------------------------

    def write(self, text: str) -> int:
        if text and not self._closed:
            try:
                self._queue.put_nowait(text)
            except queue.Full:
                with self._lock:
                    self._dropped += text.count("\n") or 1
        return len(text)

    def flush(self) -> None:
        """Nothing to do: the thread writes as soon as it can, never later."""

    def isatty(self) -> bool:
        return False  # nobody should draw on this stream but the panel

    # --- the panel -----------------------------------------------------------

    def set_panel(self, lines: Sequence[str]) -> None:
        if self._closed:
            return
        self._panel = tuple(lines)
        # A full queue already holds text, and text redraws the panel anyway.
        with contextlib.suppress(queue.Full):
            self._queue.put_nowait(_REDRAW)

    def close(self, final: Sequence[str], timeout: float = 3.0) -> None:
        """Draw ``final`` as the last panel and leave it on screen.

        Waits at most ``timeout`` for queued output: a terminal that is still
        refusing writes must not keep the process from exiting.
        """
        if self._closed:
            return
        self._panel = tuple(final)
        self._closed = True
        try:
            self._queue.put(_STOP, timeout=timeout)
        except queue.Full:
            return
        self._thread.join(timeout)

    # --- the thread ----------------------------------------------------------

    def _drain(self) -> None:
        drawn = 0  # rows the panel occupies on screen right now
        partial = ""
        while True:
            item = self._queue.get()
            items = [item]
            # Everything already waiting goes out under a single redraw.
            while len(items) < QUEUE_SIZE and item is not _STOP:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
                items.append(item)

            stopping = items[-1] is _STOP
            text = partial + "".join(i for i in items if isinstance(i, str))
            # Whole lines only: half a line above the panel would be overdrawn.
            cut = text.rfind("\n") + 1
            complete, partial = text[:cut], text[cut:]
            if stopping and partial:
                complete, partial = complete + partial + "\n", ""
            with self._lock:
                dropped, self._dropped = self._dropped, 0
            if dropped:
                complete += f"({dropped} lines not shown)\n"

            out = [_ERASE.format(n=drawn)] if drawn else []
            out.append(complete)
            panel = self._panel
            out.append("".join(line + "\n" for line in panel))
            width = _columns(self._sink)
            drawn = sum(max(1, -(-visible_length(line) // width)) for line in panel)

            try:
                self._sink.write("".join(out))
                self._sink.flush()
            except (OSError, ValueError):
                return  # the terminal went away; nothing left to draw on
            if stopping:
                return


def _columns(stream: TextIO) -> int:
    try:
        return max(1, os.get_terminal_size(stream.fileno()).columns)
    except (AttributeError, OSError, ValueError):
        return 80


# --- VT mode ----------------------------------------------------------------

ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004


def enable_vt(stream: TextIO) -> Callable[[], None] | None:
    """Make ``stream`` interpret ANSI sequences; None if it cannot.

    Unix terminals always do. A Windows console does when its host says so --
    Windows Terminal and VS Code turn it on, the classic console window does
    not -- and the flag can be set by any program writing to it. None also
    covers "this is no console at all", which ``isatty`` alone cannot tell on
    Windows: it answers True for ``NUL``.

    Returns a function that puts the console back the way it was found.
    """
    try:
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError):
        return None
    if not os.isatty(fd):
        return None
    if sys.platform != "win32":
        return lambda: None

    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = msvcrt.get_osfhandle(fd)
    mode = wintypes.DWORD()
    if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        return None
    original = mode.value
    if not original & ENABLE_VIRTUAL_TERMINAL_PROCESSING and not kernel32.SetConsoleMode(
        handle, original | ENABLE_VIRTUAL_TERMINAL_PROCESSING
    ):
        return None

    def restore() -> None:
        kernel32.SetConsoleMode(handle, original)

    return restore


# --- window title -----------------------------------------------------------

# XTPUSHTITLE and XTPOPTITLE: the terminal's own title is saved on a stack and
# put back afterwards. A terminal without the stack ignores both, and keeps
# our title until something else sets one.
PUSH_TITLE = "\x1b[22;0t"
POP_TITLE = "\x1b[23;0t"

# C0 and C1 controls: a BEL or ESC inside the title would end the sequence
# early and let the rest of it through as output.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def set_title_sequence(title: str) -> str:
    """The OSC 0 sequence that sets the window (and icon) title."""
    return f"\x1b]0;{_CONTROL.sub('', title)}\x07"


@contextlib.contextmanager
def window_title(stream: TextIO, title: str) -> Iterator[None]:
    """Show ``title`` as the terminal's title while the block runs.

    Written straight to ``stream``, not through :class:`TermWriter`: this is
    meant to wrap the event loop, not run on it, so a terminal that refuses
    writes can delay startup or exit but never stall the tunnel.
    """
    restore_console = None if os.environ.get("TERM") == "dumb" else enable_vt(stream)
    if restore_console is None:
        yield
        return

    def send(sequence: str) -> None:
        # Cosmetic: a terminal that has gone away is no reason to fail.
        with contextlib.suppress(OSError, ValueError):
            stream.write(sequence)
            stream.flush()

    send(PUSH_TITLE + set_title_sequence(title))
    try:
        yield
    finally:
        send(POP_TITLE)
        restore_console()
