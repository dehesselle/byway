"""Runtime validation of gateway/user presence, now that argparse can't enforce it.

Making ``gateway``/``-u`` optional at the argparse level (so --profile can
supply them) moved their "is this actually present" check into run(). That
check is easy to get backwards -- e.g. accepting a connect with no user set
at all -- so it is worth exercising run() directly rather than trusting the
argparse change alone.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pyac.cli import cmd_get, cmd_nc, cmd_up
from pyac.cli.main import build_parser


def parse(*argv: str):  # type: ignore[no-untyped-def]
    return build_parser().parse_args(list(argv))


def test_up_without_a_gateway_or_user_fails_fast(capsys: pytest.CaptureFixture[str]) -> None:
    assert cmd_up.run(parse("up")) == 2
    assert "gateway is required" in capsys.readouterr().err


def test_up_without_a_user_fails_fast(capsys: pytest.CaptureFixture[str]) -> None:
    assert cmd_up.run(parse("up", "gw")) == 2
    assert "-u/--user is required" in capsys.readouterr().err


def test_get_without_a_gateway_or_user_fails_fast(capsys: pytest.CaptureFixture[str]) -> None:
    assert cmd_get.run(parse("get", "http://10.0.0.1/")) == 2
    assert "gateway is required" in capsys.readouterr().err


def test_nc_without_via_or_gateway_fails_fast(capsys: pytest.CaptureFixture[str]) -> None:
    assert cmd_nc.run(parse("nc", "10.0.0.1", "22")) == 2
    assert "pass --gateway" in capsys.readouterr().err


def test_nc_gateway_without_user_fails_fast(capsys: pytest.CaptureFixture[str]) -> None:
    assert cmd_nc.run(parse("nc", "10.0.0.1", "22", "--gateway", "gw")) == 2
    assert "needs --user" in capsys.readouterr().err


def test_nc_profile_with_via_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    args = parse("nc", "10.0.0.1", "22", "--via", "1080", "--profile", "work")
    assert cmd_nc.run(args) == 2
    assert "--profile has no effect with --via" in capsys.readouterr().err


def test_unknown_profile_surfaces_as_an_error_from_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = parse("--config", str(tmp_path / "nope.toml"), "up", "-u", "me", "--profile", "work")
    assert cmd_up.run(args) == 1
    assert "no config file" in capsys.readouterr().err
