# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Logging setup, with redaction that does not rely on remembering.

Session tokens and passwords are stripped by a filter on the handler rather
than at each call site. Redaction that depends on every future ``log.debug``
being careful is redaction that will eventually fail.

The mechanism lives in :mod:`usernet.log`; what belongs here is the part only
this project knows -- what an AnyConnect secret looks like on the wire.

:func:`configure` deliberately names two loggers. ``usernet`` carries the
stack's own diagnostics (retransmits, window stalls, dropped packets), and
those are wanted precisely when something has gone wrong; attaching only to
``byway`` would send them nowhere.
"""

from __future__ import annotations

import re
from typing import TextIO

from usernet.log import DEFAULT_PATTERNS
from usernet.log import RedactingFilter as _RedactingFilter
from usernet.log import configure as _configure
from usernet.log import redact as _redact

__all__ = ["PATTERNS", "RedactingFilter", "configure", "redact"]

# webvpn cookies and session tokens are long opaque strings; ASA's own tokens
# look like "35B466@-123@A96E@AE5E...". Match generously and redact the tail.
PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(webvpn=)([^\s;,]+)", re.IGNORECASE),
    re.compile(r"(<session-token>)(.*?)(</session-token>)", re.IGNORECASE | re.DOTALL),
    re.compile(r"(<password>)(.*?)(</password>)", re.IGNORECASE | re.DOTALL),
    *DEFAULT_PATTERNS,
)


class RedactingFilter(_RedactingFilter):
    """Removes credentials from formatted log records."""

    def __init__(self) -> None:
        super().__init__(PATTERNS)


def redact(text: str) -> str:
    return _redact(text, PATTERNS)


def configure(verbosity: int, stream: TextIO | None = None) -> None:
    """Set up logging. 0 = warnings, 1 = debug, 2 = debug with timestamps.

    ``stream`` defaults to stderr, which is also what it must be: ``byway nc``
    relays a connection over stdout, so a single log line landing there would
    corrupt the stream it is trying to describe. Callers that care pass it
    explicitly rather than trusting the default to stay put.
    """
    _configure(verbosity, loggers=("byway", "usernet"), patterns=PATTERNS, stream=stream)
