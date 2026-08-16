"""Argument parsing and dispatch."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from pyac import __version__

# Commands register themselves here as they land; see cli/__init__.py.
# M2: up.  M3: ping, resolve.  M5: nc.  M7: get.
_COMMAND_MODULES: tuple[str, ...] = ("cmd_probe",)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyac",
        description="Userspace Cisco AnyConnect client -- no tun device, no admin rights.",
    )
    parser.add_argument("--version", action="version", version=f"pyac {__version__}")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="-v for debug logging, -vv to add per-packet tracing",
    )
    parser.add_argument(
        "--pcap",
        metavar="FILE",
        help="write tunnel IP traffic to a pcap file for Wireshark",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    for module_name in _COMMAND_MODULES:
        module = __import__(f"pyac.cli.{module_name}", fromlist=["register"])
        module.register(subparsers)
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
