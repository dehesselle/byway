"""Command-line interface.

Shared helpers live here rather than in ``main.py``: ``main`` imports the
command modules, so anything they import back would be circular.

``main.py`` is a thin dispatcher; each command lives in its own ``cmd_*``
module exposing ``register(subparsers)``. argparse is deliberate: a handful of
commands does not justify pulling in click (and, in practice, rich) for
``--help`` formatting. Revisit past roughly a dozen commands.
"""

from __future__ import annotations

import argparse

MIN_BUFFER_KIB = 8


def buffer_bytes(args: argparse.Namespace) -> int | None:
    """``--buffer`` in bytes, or None to keep the stack's own default.

    Refuses a buffer too small to hold a couple of segments: that does not
    produce a slow connection, it produces a stalled one, and the symptom
    would look nothing like the cause.
    """
    kib = getattr(args, "buffer", None)
    if kib is None:
        return None
    if kib < MIN_BUFFER_KIB:
        raise SystemExit(f"--buffer must be at least {MIN_BUFFER_KIB} KiB (got {kib})")
    return int(kib) * 1024
