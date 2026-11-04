# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

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
from pathlib import Path

from usernet.resolve import StaticResolver

from byway.errors import BywayError
from byway.profile import load_profile

MIN_BUFFER_KIB = 8

# up, http, and direct-mode nc all use these exact attribute names.
CONNECT_PROFILE_FIELDS: tuple[str, ...] = (
    "gateway",
    "user",
    "group",
    "pin",
    "mtu",
    "buffer",
    "route_policy",
)


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


def apply_profile(
    args: argparse.Namespace, *, fields: tuple[str, ...] = CONNECT_PROFILE_FIELDS
) -> None:
    """Fill in unset connect flags from ``--profile``, in place.

    No-op if ``args.profile`` is None. Precedence: an explicit CLI value
    always wins; the profile only fills an attribute that is still None.
    Call this once, right after argparse, before any of ``fields`` (or
    ``--no-verify``) is read for real work.

    ``--no-verify`` is ``store_true`` and so cannot represent "unset" the way
    the other flags can. The merge is therefore intentionally asymmetric:
    the effective "skip verification" is ``args.no_verify or not
    profile.verify`` -- passing ``--no-verify`` on the CLI always forces
    verification off, regardless of the profile; a profile with ``verify =
    false`` forces it off too, when ``--no-verify`` was not passed. There is
    no CLI flag to force verification back *on* when the profile disables
    it -- accepted, and documented in the README rather than solved with a
    second flag.
    """
    name = getattr(args, "profile", None)
    if name is None:
        return
    config_path = Path(args.config) if getattr(args, "config", None) else None
    profile = load_profile(name, path=config_path)
    for field in fields:
        if getattr(args, field, None) is None:
            setattr(args, field, getattr(profile, field))
    args.no_verify = bool(args.no_verify) or not profile.verify
    args.profile_hosts = profile.hosts


def finalize_route_policy(args: argparse.Namespace) -> None:
    """``--route-policy``'s real default, applied only after apply_profile ran."""
    if getattr(args, "route_policy", None) is None:
        args.route_policy = "auto"


def add_host_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--add-host",
        action="append",
        default=[],
        metavar="NAME=ADDR",
        help="resolve NAME to ADDR inside the tunnel; repeatable, adds to (and "
        "overrides) the profile's [hosts] table",
    )


def host_resolver(args: argparse.Namespace) -> StaticResolver:
    """The tunnel's name table: the profile's ``hosts``, then ``--add-host``.

    Always a resolver, even an empty one, so that a name it does not know is
    refused with a message saying where names come from -- never sent to the
    host's DNS.
    """
    hosts = dict(getattr(args, "profile_hosts", {}))
    for entry in getattr(args, "add_host", []):
        name, separator, address = entry.partition("=")
        if not separator:
            raise BywayError(f"--add-host expects NAME=ADDR, got {entry!r}")
        try:
            StaticResolver({name: address}, source=f"--add-host {entry}")
        except ValueError as exc:
            raise BywayError(str(exc)) from None
        hosts[name] = address
    profile = getattr(args, "profile", None)
    if profile:
        source = f"the host table ([profiles.{profile}.hosts] or --add-host)"
    else:
        source = "the host table (add entries with --add-host NAME=ADDR or a profile)"
    return StaticResolver(hosts, source=source)
