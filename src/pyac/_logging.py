"""Logging setup, with redaction that does not rely on remembering.

Session tokens and passwords are stripped by a filter on the handler rather
than at each call site. Redaction that depends on every future ``log.debug``
being careful is redaction that will eventually fail.
"""

from __future__ import annotations

import logging
import re

# webvpn cookies and session tokens are long opaque strings; ASA's own tokens
# look like "35B466@-123@A96E@AE5E...". Match generously and redact the tail.
_PATTERNS = [
    re.compile(r"(webvpn=)([^\s;,]+)", re.IGNORECASE),
    re.compile(r"(<session-token>)(.*?)(</session-token>)", re.IGNORECASE | re.DOTALL),
    re.compile(r"(<password>)(.*?)(</password>)", re.IGNORECASE | re.DOTALL),
    re.compile(r"(password[\"']?\s*[:=]\s*)(\S+)", re.IGNORECASE),
]


class RedactingFilter(logging.Filter):
    """Removes credentials from formatted log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def redact(text: str) -> str:
    for pattern in _PATTERNS:
        if pattern.groups == 3:
            text = pattern.sub(r"\1<redacted>\3", text)
        else:
            text = pattern.sub(r"\1<redacted>", text)
    return text


def configure(verbosity: int) -> None:
    """Set up logging. 0 = warnings, 1 = debug, 2 = debug with timestamps."""
    level = logging.WARNING if verbosity == 0 else logging.DEBUG
    fmt = "%(message)s" if verbosity < 2 else "%(asctime)s %(name)s %(message)s"

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    handler.addFilter(RedactingFilter())

    root = logging.getLogger("pyac")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False
