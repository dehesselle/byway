"""Parsing of the ``--socks`` flags.

Small functions, but a listener bound to the wrong interface is the difference
between a local convenience and an open door into the corporate network, so
the address parsing is worth pinning down.
"""

from __future__ import annotations

import pytest

from pyac.cli.cmd_up import parse_listen, parse_socks_auth
from pyac.cli.main import build_parser
from pyac.errors import PyacError


def parse(*argv: str):  # type: ignore[no-untyped-def]
    return build_parser().parse_args(list(argv))


# --- listen addresses -------------------------------------------------------


def test_a_bare_port_binds_loopback() -> None:
    """Never 0.0.0.0 by accident: the default has to be the safe one."""
    assert parse_listen("1080") == ("127.0.0.1", 1080)


def test_a_host_and_port_are_split() -> None:
    assert parse_listen("127.0.0.1:9050") == ("127.0.0.1", 9050)
    assert parse_listen("0.0.0.0:1080") == ("0.0.0.0", 1080)


def test_a_bracketed_ipv6_host_is_unwrapped() -> None:
    assert parse_listen("[::1]:1080") == ("::1", 1080)


def test_a_bad_port_is_an_error() -> None:
    with pytest.raises(ValueError):
        parse_listen("1080x")


# --- credentials ------------------------------------------------------------


def test_credentials_are_split_on_the_first_colon() -> None:
    assert parse_socks_auth("alice:hunter2") == ("alice", "hunter2")
    assert parse_socks_auth("alice:pass:with:colons") == ("alice", "pass:with:colons")


def test_no_credentials_means_no_authentication() -> None:
    assert parse_socks_auth(None) == (None, None)


def test_credentials_without_a_colon_are_rejected() -> None:
    with pytest.raises(PyacError, match="expects USER:PASS"):
        parse_socks_auth("alice")


# --- the flags themselves ---------------------------------------------------


def test_socks_defaults_to_loopback_1080() -> None:
    args = parse("up", "gw", "-u", "me", "--socks")
    assert parse_listen(args.socks) == ("127.0.0.1", 1080)


def test_socks_takes_an_optional_address() -> None:
    args = parse("up", "gw", "-u", "me", "--socks", "127.0.0.1:9050")
    assert parse_listen(args.socks) == ("127.0.0.1", 9050)


def test_socks_is_off_unless_asked_for() -> None:
    assert parse("up", "gw", "-u", "me").socks is None


def test_remote_binding_needs_its_own_flag() -> None:
    assert parse("up", "gw", "-u", "me", "--socks").socks_allow_remote is False
    assert parse("up", "gw", "-u", "me", "--socks", "--socks-allow-remote").socks_allow_remote


def test_the_route_policy_is_unset_until_finalized() -> None:
    """None at parse time now: --profile may still supply it.

    finalize_route_policy() (see pyac.cli) is what actually applies the
    "auto" default, after any --profile merge; see
    tests/unit/test_cli_profile_merge.py.
    """
    assert parse("up", "gw", "-u", "me").route_policy is None
    assert parse("up", "gw", "-u", "me", "--route-policy", "all").route_policy == "all"
