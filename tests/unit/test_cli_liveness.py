# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""What ``byway up`` reports about staying alive.

These lines used to be printed only when the gateway advertised a rekey time.
Against a gateway that advertises none -- as the one this was developed
against does -- the output said nothing at all, which reads as a missing
feature rather than as an absent header. Every branch now prints something,
and that is what these tests hold.
"""

from __future__ import annotations

import argparse

import pytest

from byway.cli.cmd_up import print_close_advice, print_liveness, print_tunnel
from byway.cli.main import build_parser
from byway.cstp.config import TunnelConfig
from byway.errors import HandshakeRejected


def config(**overrides: object) -> TunnelConfig:
    defaults: dict[str, object] = {
        "address": "172.29.29.3",
        "netmask": "255.255.0.0",
        "mtu": 1383,
        "idle_timeout": 1800,
    }
    return TunnelConfig(**{**defaults, **overrides})  # type: ignore[arg-type]


def args_for(*argv: str) -> argparse.Namespace:
    return build_parser().parse_args(["up", "gw.example", "-u", "someone", *argv])


# --- the tunnel summary ------------------------------------------------------


def test_an_absent_rekey_time_is_stated_rather_than_omitted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    print_tunnel(config())
    assert "rekey     none advertised" in capsys.readouterr().out


def test_an_advertised_rekey_time_is_shown_with_its_method(
    capsys: pytest.CaptureFixture[str],
) -> None:
    print_tunnel(config(rekey_time=3600, rekey_method="ssl"))
    assert "rekey     3600s (method ssl)" in capsys.readouterr().out


# --- what keeps the tunnel up ------------------------------------------------


def test_without_a_rekey_reconnection_is_reactive_only(
    capsys: pytest.CaptureFixture[str],
) -> None:
    print_liveness(config(), args_for(), None)
    assert "reconnect on drop only" in capsys.readouterr().out


def test_a_scheduled_rekey_reports_the_interval_actually_used(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """0.9 x 3600, not 3600: reporting the advertised figure would describe
    something the link does not do."""
    print_liveness(config(rekey_time=3600), args_for(), 3240.0)
    assert "every 3240s" in capsys.readouterr().out


def test_disabling_reconnection_says_what_that_costs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    print_liveness(config(), args_for("--no-reconnect"), None)
    assert "reconnect disabled" in capsys.readouterr().out


def test_an_idle_timeout_with_no_keepalive_is_a_warning(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The failure it averts is silent: the tunnel simply stops half an hour
    after the last request, with nothing to explain it."""
    print_liveness(config(idle_timeout=1800), args_for(), None)
    text = capsys.readouterr().out
    assert "keepalive none" in text
    assert "1800s" in text
    assert "--keepalive" in text


def test_a_configured_keepalive_reports_its_target_and_interval(
    capsys: pytest.CaptureFixture[str],
) -> None:
    print_liveness(config(), args_for("--keepalive", "10.221.188.20"), None)
    text = capsys.readouterr().out
    assert "keepalive icmp echo to 10.221.188.20 every 300s" in text


def test_no_idle_timeout_and_no_keepalive_says_nothing_about_either(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Nothing to warn about, so no warning -- the point is accuracy, not noise."""
    print_liveness(config(idle_timeout=0), args_for(), None)
    assert "keepalive" not in capsys.readouterr().out


# --- how the run ended -------------------------------------------------------


def test_a_rejected_cookie_is_explained_and_answered(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The exact failure a real 30-minute idle session produces, turned into
    the flag that prevents it."""
    print_close_advice(config(), args_for(), HandshakeRejected(401, "session token rejected"))
    text = capsys.readouterr().out
    assert "rejected the session cookie" in text
    assert "--keepalive" in text


def test_the_keepalive_advice_is_dropped_once_it_is_in_use(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Recommending a flag the user already passed reads as a bug."""
    print_close_advice(
        config(), args_for("--keepalive", "10.221.188.20"), HandshakeRejected(401, "rejected")
    )
    text = capsys.readouterr().out
    assert "rejected the session cookie" in text
    assert "--keepalive" not in text


def test_an_ordinary_close_gets_no_advice(capsys: pytest.CaptureFixture[str]) -> None:
    print_close_advice(config(), args_for(), None)
    print_close_advice(config(), args_for(), HandshakeRejected(502, "gateway error"))
    assert capsys.readouterr().out == ""
