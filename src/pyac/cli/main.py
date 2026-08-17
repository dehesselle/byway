"""Argument parsing and dispatch."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from pyac import __version__

# Commands register themselves here as they land; see cli/__init__.py.
# Still to come: ping, resolve, info, diag.
_COMMAND_MODULES: tuple[str, ...] = ("cmd_probe", "cmd_up", "cmd_get", "cmd_nc")


def add_global_flags(parser: argparse.ArgumentParser, *, suppress: bool = False) -> None:
    """Add the flags that apply to every command.

    They are attached twice: once to the top level, and once to each
    subcommand, so ``pyac --pcap f up ...`` and ``pyac up ... --pcap f`` both
    work. Users reasonably expect the latter, and argparse would otherwise
    reject it.

    The subcommand copies use ``SUPPRESS`` defaults. Without that, argparse
    parses the subcommand into a fresh namespace and copies every attribute
    back over the top-level one -- so a subcommand default of ``None`` would
    silently erase a value given before the subcommand.
    """

    def default(value: object) -> object:
        return argparse.SUPPRESS if suppress else value

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=default(0),
        help="-v for debug logging, -vv to add per-packet tracing",
    )
    parser.add_argument(
        "--pcap",
        metavar="FILE",
        default=default(None),
        help="write tunnel IP traffic to a pcap file for Wireshark",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=default(False),
        help="machine-readable output",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyac",
        description="Userspace Cisco AnyConnect client -- no tun device, no admin rights.",
    )
    parser.add_argument("--version", action="version", version=f"pyac {__version__}")
    add_global_flags(parser)

    shared = argparse.ArgumentParser(add_help=False)
    add_global_flags(shared, suppress=True)

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    for module_name in _COMMAND_MODULES:
        module = __import__(f"pyac.cli.{module_name}", fromlist=["register"])
        module.register(subparsers, shared)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help(sys.stderr)
        return 2
    result: int = handler(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
