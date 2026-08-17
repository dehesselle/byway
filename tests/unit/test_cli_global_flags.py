"""Global flags must work on either side of the subcommand.

``pyac up 1.2.3.4 -u me --pcap f.pcap`` is what a user naturally types, and
argparse rejects it unless the flags are attached to the subparser too. The
subtle half is that adding them to the subparser can silently *erase* a value
given before the subcommand, because argparse parses the subcommand into a
fresh namespace and copies every attribute back over the outer one.
"""

from __future__ import annotations

import pytest

from pyac.cli.main import build_parser


def parse(*argv: str):  # type: ignore[no-untyped-def]
    return build_parser().parse_args(list(argv))


@pytest.mark.parametrize(
    "argv",
    [
        ("--pcap", "t.pcap", "up", "gw", "-u", "me"),
        ("up", "gw", "-u", "me", "--pcap", "t.pcap"),
        ("up", "--pcap", "t.pcap", "gw", "-u", "me"),
    ],
)
def test_pcap_is_accepted_on_either_side(argv: tuple[str, ...]) -> None:
    args = parse(*argv)
    assert args.pcap == "t.pcap"
    assert args.gateway == "gw"


def test_subcommand_default_does_not_erase_an_earlier_value() -> None:
    """The argparse trap this design exists to avoid."""
    assert parse("--pcap", "before.pcap", "up", "gw", "-u", "me").pcap == "before.pcap"
    assert parse("--json", "probe", "gw").json is True
    assert parse("-vv", "probe", "gw").verbose == 2


def test_flags_default_sensibly_when_absent() -> None:
    args = parse("probe", "gw")
    assert args.pcap is None
    assert args.json is False
    assert args.verbose == 0


@pytest.mark.parametrize(
    "argv",
    [("-vv", "probe", "gw"), ("probe", "gw", "-vv"), ("probe", "-vv", "gw")],
)
def test_verbosity_counts_on_either_side(argv: tuple[str, ...]) -> None:
    assert parse(*argv).verbose == 2


def test_verbosity_does_not_accumulate_across_the_subcommand() -> None:
    """Documented wart, not a bug worth machinery.

    argparse parses the subcommand into a fresh namespace, so a ``-v`` after
    the subcommand restarts the count rather than continuing the outer one.
    Splitting a repeated flag across the boundary is pathological input; every
    ordinary spelling above gives the expected answer.
    """
    assert parse("-v", "probe", "gw", "-v").verbose == 1


def test_probe_accepts_the_global_flags_too() -> None:
    args = parse("probe", "gw", "--json", "-v")
    assert (args.json, args.verbose) == (True, 1)


def test_up_does_not_require_a_user_at_parse_time() -> None:
    """-u is optional in argparse now: a --profile can supply it instead.

    cmd_up.run() enforces its presence at runtime; see
    tests/unit/test_cli_profile_merge.py.
    """
    assert parse("up", "gw").user is None
