"""TermWriter: output that cannot stall the event loop, with a panel beneath it.

The point of the class is the case a test is least likely to hit by accident:
a terminal that stops accepting writes. So the sink here can be made to block.
"""

from __future__ import annotations

import io
import threading
import time

import pytest

from pylis.cli import terminal
from pylis.cli.terminal import POP_TITLE, PUSH_TITLE, TermWriter, set_title_sequence, window_title


class Sink(io.StringIO):
    """A terminal stand-in that can be told to stop accepting output."""

    def __init__(self) -> None:
        super().__init__()
        self.open = threading.Event()
        self.open.set()
        self.writes: list[str] = []

    def write(self, text: str) -> int:
        self.open.wait()
        self.writes.append(text)
        return super().write(text)

    def fileno(self) -> int:
        raise io.UnsupportedOperation  # no real terminal: 80 columns is assumed


def settle(writer: TermWriter, sink: Sink, count: int) -> None:
    deadline = time.monotonic() + 5
    while len(sink.writes) < count and time.monotonic() < deadline:
        time.sleep(0.01)


def test_text_goes_above_a_panel_that_is_redrawn_beneath_it() -> None:
    sink = Sink()
    writer = TermWriter(sink)
    writer.set_panel(["one", "two"])
    settle(writer, sink, 1)
    writer.write("log line\n")
    settle(writer, sink, 2)
    writer.close(["one", "two"])

    assert sink.writes[0] == "one\ntwo\n"
    # Up two rows and erase, the text, then the panel again.
    assert sink.writes[1] == "\x1b[2F\x1b[Jlog line\none\ntwo\n"


def test_a_partial_line_waits_for_the_rest() -> None:
    sink = Sink()
    writer = TermWriter(sink)
    writer.write("half ")
    writer.write("and half\n")
    writer.close([])
    assert "half and half\n" in sink.getvalue()


def test_an_empty_line_is_kept() -> None:
    sink = Sink()
    writer = TermWriter(sink)
    writer.write("\n")
    writer.close([])
    assert sink.getvalue() == "\n"


def test_an_unfinished_line_is_written_on_close() -> None:
    sink = Sink()
    writer = TermWriter(sink)
    writer.write("no newline")
    writer.close(["panel"])
    assert sink.getvalue().endswith("no newline\npanel\n")


def test_a_blocked_terminal_never_blocks_the_writer(monkeypatch: object) -> None:
    sink = Sink()
    sink.open.clear()  # QuickEdit selection, Ctrl-S: the terminal stops reading
    writer = TermWriter(sink)

    started = time.monotonic()
    for i in range(terminal.QUEUE_SIZE * 3):
        writer.write(f"line {i}\n")
        writer.set_panel([f"frame {i}"])
    assert time.monotonic() - started < 1.0, "a write waited for the terminal"

    sink.open.set()
    writer.close(["last"])
    output = sink.getvalue()
    assert "lines not shown)" in output
    assert output.endswith("last\n")


def test_close_gives_up_on_a_terminal_that_never_recovers() -> None:
    sink = Sink()
    sink.open.clear()
    writer = TermWriter(sink)
    writer.write("stuck\n")
    started = time.monotonic()
    writer.close([], timeout=0.2)
    assert time.monotonic() - started < 2.0
    sink.open.set()


def test_nothing_is_accepted_after_close() -> None:
    sink = Sink()
    writer = TermWriter(sink)
    writer.close(["final"])
    writer.write("late\n")
    writer.set_panel(["late"])
    time.sleep(0.05)
    assert sink.getvalue() == "final\n"


def test_a_wrapped_panel_line_is_counted_as_the_rows_it_takes() -> None:
    sink = Sink()
    writer = TermWriter(sink)
    writer.set_panel(["x" * 100])  # 80 columns assumed: two rows on screen
    settle(writer, sink, 1)
    writer.write("after\n")
    writer.close([])
    assert "\x1b[2F\x1b[Jafter\n" in sink.getvalue()


# --- window title -------------------------------------------------------------


def test_controls_cannot_end_the_title_sequence_early() -> None:
    assert set_title_sequence("py\x07l\x1bi\x9bs") == "\x1b]0;pylis\x07"


def test_the_title_is_set_and_given_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TERM", raising=False)
    restored: list[bool] = []
    monkeypatch.setattr(terminal, "enable_vt", lambda _stream: lambda: restored.append(True))
    sink = io.StringIO()

    with pytest.raises(RuntimeError), window_title(sink, "pylis"):
        assert sink.getvalue() == PUSH_TITLE + "\x1b]0;pylis\x07"
        raise RuntimeError

    assert sink.getvalue().endswith(POP_TITLE)
    assert restored == [True]


@pytest.mark.parametrize("dumb", [False, True])
def test_no_title_without_a_terminal(monkeypatch: pytest.MonkeyPatch, dumb: bool) -> None:
    if dumb:
        monkeypatch.setenv("TERM", "dumb")
        monkeypatch.setattr(terminal, "enable_vt", lambda _stream: lambda: None)
    else:
        monkeypatch.delenv("TERM", raising=False)
        monkeypatch.setattr(terminal, "enable_vt", lambda _stream: None)
    sink = io.StringIO()
    with window_title(sink, "pylis"):
        pass
    assert sink.getvalue() == ""
