"""Merging --profile into parsed args: precedence, and the --no-verify asymmetry.

A wrong precedence here means a "saved" setting silently overrides something a
user just typed on the command line -- or the reverse, an explicit override is
silently ignored. Either way the connection ends up somewhere the user did not
intend, so every merge rule is pinned down against real argparse output rather
than a hand-built Namespace.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pyac.cli import apply_profile, finalize_route_policy, host_resolver
from pyac.cli.main import build_parser
from pyac.errors import PyacError


def parse(*argv: str):  # type: ignore[no-untyped-def]
    return build_parser().parse_args(list(argv))


def write_profile(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(body, encoding="utf-8")
    return path


# --- precedence ---------------------------------------------------------------


def test_no_profile_flag_is_a_total_no_op(tmp_path: Path) -> None:
    """Must not even touch the filesystem when --profile is absent."""
    args = parse("--config", str(tmp_path / "nope.toml"), "up", "gw", "-u", "me")
    apply_profile(args)
    assert (args.gateway, args.user) == ("gw", "me")


def test_profile_fills_in_only_unset_fields(tmp_path: Path) -> None:
    path = write_profile(
        tmp_path,
        """
        [profiles.work]
        gateway = "vpn.example.com"
        user = "jdoe"
        group = "employees"
        mtu = 1400
        """,
    )
    args = parse("--config", str(path), "up", "-u", "override", "--profile", "work")
    apply_profile(args)
    assert args.user == "override"  # CLI wins
    assert args.gateway == "vpn.example.com"  # from the profile
    assert args.group == "employees"
    assert args.mtu == 1400


def test_explicit_flags_always_win_over_the_profile(tmp_path: Path) -> None:
    path = write_profile(
        tmp_path,
        """
        [profiles.work]
        gateway = "profile.example.com"
        user = "profileuser"
        group = "profilegroup"
        pin = "sha256:aaaa"
        mtu = 1000
        buffer = 512
        route_policy = "all"
        """,
    )
    args = parse(
        "--config",
        str(path),
        "up",
        "cli.example.com",
        "-u",
        "cliuser",
        "-g",
        "cligroup",
        "--pin",
        "sha256:bbbb",
        "--mtu",
        "2000",
        "--buffer",
        "1024",
        "--route-policy",
        "auto",
        "--profile",
        "work",
    )
    apply_profile(args)
    assert args.gateway == "cli.example.com"
    assert args.user == "cliuser"
    assert args.group == "cligroup"
    assert args.pin == "sha256:bbbb"
    assert args.mtu == 2000
    assert args.buffer == 1024
    assert args.route_policy == "auto"


def test_unknown_profile_name_is_a_pyac_error(tmp_path: Path) -> None:
    path = write_profile(tmp_path, '[profiles.home]\ngateway = "home.example.com"\n')
    args = parse("--config", str(path), "up", "-u", "me", "--profile", "work")
    with pytest.raises(PyacError, match="available profiles: home"):
        apply_profile(args)


def test_profile_works_the_same_for_get_and_direct_mode_nc(tmp_path: Path) -> None:
    path = write_profile(tmp_path, '[profiles.work]\ngateway = "vpn.example.com"\nuser = "jdoe"\n')

    get_args = parse("--config", str(path), "get", "--profile", "work", "http://10.0.0.1/")
    apply_profile(get_args)
    assert (get_args.gateway, get_args.user) == ("vpn.example.com", "jdoe")

    nc_args = parse("--config", str(path), "nc", "--profile", "work", "10.0.0.1", "22")
    apply_profile(nc_args)
    assert (nc_args.gateway, nc_args.user) == ("vpn.example.com", "jdoe")


# --- the --no-verify asymmetry -------------------------------------------------


def test_profile_verify_false_is_the_baseline(tmp_path: Path) -> None:
    path = write_profile(tmp_path, '[profiles.work]\ngateway = "g"\nverify = false\n')
    args = parse("--config", str(path), "up", "-u", "me", "--profile", "work")
    apply_profile(args)
    assert args.no_verify is True


def test_cli_no_verify_wins_even_when_profile_verifies(tmp_path: Path) -> None:
    path = write_profile(tmp_path, '[profiles.work]\ngateway = "g"\n')  # verify defaults True
    args = parse("--config", str(path), "up", "-u", "me", "--no-verify", "--profile", "work")
    apply_profile(args)
    assert args.no_verify is True


def test_there_is_no_way_to_force_verification_back_on(tmp_path: Path) -> None:
    """Documented asymmetry, not a bug: no flag re-enables verification a
    profile turned off. Pinned down here as a passing test, per the plan."""
    path = write_profile(tmp_path, '[profiles.work]\ngateway = "g"\nverify = false\n')
    args = parse("--config", str(path), "up", "-u", "me", "--profile", "work")
    apply_profile(args)
    assert args.no_verify is True


# --- finalize_route_policy -----------------------------------------------------


def test_route_policy_defaults_to_auto_only_after_finalize() -> None:
    args = parse("up", "gw", "-u", "me")
    assert args.route_policy is None
    finalize_route_policy(args)
    assert args.route_policy == "auto"


def test_profile_route_policy_survives_finalize(tmp_path: Path) -> None:
    path = write_profile(tmp_path, '[profiles.work]\ngateway = "g"\nroute_policy = "all"\n')
    args = parse("--config", str(path), "up", "-u", "me", "--profile", "work")
    apply_profile(args)
    finalize_route_policy(args)
    assert args.route_policy == "all"


# --- the host table -------------------------------------------------------------


HOSTS_PROFILE = """
[profiles.orka]
gateway = "vpn.example.com"

[profiles.orka.hosts]
"node-1.orka" = "10.0.0.11"
"api.orka" = "10.0.0.20"
"""


def test_add_host_adds_to_and_overrides_the_profile_table(tmp_path: Path) -> None:
    path = write_profile(tmp_path, HOSTS_PROFILE)
    args = parse(
        "--config",
        str(path),
        "up",
        "--profile",
        "orka",
        "--add-host",
        "API.orka=10.0.0.21",
        "--add-host",
        "node-2.orka=10.0.0.12",
    )
    apply_profile(args)
    resolver = host_resolver(args)
    assert resolver.lookup("node-1.orka") == "10.0.0.11"
    assert resolver.lookup("node-2.orka") == "10.0.0.12"
    assert resolver.lookup("api.orka") == "10.0.0.21"


def test_add_host_works_without_a_profile() -> None:
    args = parse("get", "gw", "http://web/", "--add-host", "web=10.0.0.5")
    assert host_resolver(args).resolve("web") == "10.0.0.5"


def test_an_unknown_name_says_where_names_come_from(tmp_path: Path) -> None:
    path = write_profile(tmp_path, HOSTS_PROFILE)
    args = parse("--config", str(path), "get", "--profile", "orka", "http://other/")
    apply_profile(args)
    with pytest.raises(PyacError, match=r"\[profiles\.orka\.hosts\] or --add-host"):
        host_resolver(args).resolve("other")


@pytest.mark.parametrize(
    ("entry", "message"),
    [("web", "expects NAME=ADDR"), ("web=nowhere", "not an IPv4 address")],
)
def test_a_malformed_add_host_is_refused(entry: str, message: str) -> None:
    args = parse("up", "gw", "--add-host", entry)
    with pytest.raises(PyacError, match=message):
        host_resolver(args)
