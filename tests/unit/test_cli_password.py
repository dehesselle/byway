# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""``pylis password``: what ends up in the credential store, and what does not.

A wrong entry is expensive: a mistyped password is retried on every connect
until the gateway locks the account, and an entry under the wrong name is never
found at all. So the tests look at the store itself, and at what
``read_password`` then gets out of it.
"""

from __future__ import annotations

import getpass
import io
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from pylis.cli.cmd_up import read_password
from pylis.cli.main import main


class _FakeKeyringError(Exception):
    pass


class _FakeErrorsModule:
    KeyringError = _FakeKeyringError


class _FakeKeyring:
    """Dict-backed, and as unhelpful about a missing entry as the real backends."""

    errors = _FakeErrorsModule

    def __init__(self) -> None:
        self.stored: dict[tuple[str, str], str] = {}

    def get_password(self, target: str, username: str) -> str | None:
        return self.stored.get((target, username))

    def set_password(self, target: str, username: str, password: str) -> None:
        self.stored[(target, username)] = password

    def delete_password(self, target: str, username: str) -> None:
        if (target, username) not in self.stored:
            raise _FakeKeyringError("Password not found")
        del self.stored[(target, username)]


@pytest.fixture
def fake_keyring(monkeypatch: pytest.MonkeyPatch) -> _FakeKeyring:
    fake = _FakeKeyring()
    monkeypatch.setitem(sys.modules, "keyring", fake)
    monkeypatch.setitem(sys.modules, "keyring.errors", _FakeErrorsModule)
    return fake


@pytest.fixture
def config(tmp_path: Path) -> str:
    path = tmp_path / "config.toml"
    path.write_text(
        """
        [profiles.work]
        gateway = "vpn.example.com"
        user = "jdoe"

        [profiles.nouser]
        gateway = "vpn.example.com"
        """,
        encoding="utf-8",
    )
    return str(path)


@pytest.fixture
def prompts(monkeypatch: pytest.MonkeyPatch) -> Callable[..., list[str]]:
    """Answer the getpass prompts in order; returns the prompts that were shown."""

    def install(*answers: str) -> list[str]:
        remaining = iter(answers)
        shown: list[str] = []

        def fake_getpass(prompt: str = "") -> str:
            shown.append(prompt)
            return next(remaining)

        monkeypatch.setattr(getpass, "getpass", fake_getpass)
        return shown

    return install


def test_the_password_is_asked_twice_and_stored_under_profile_and_user(
    fake_keyring: _FakeKeyring, config: str, prompts: Callable[..., list[str]]
) -> None:
    shown = prompts("hunter2", "hunter2")
    assert main(["password", "--config", config, "--profile", "work"]) == 0
    assert len(shown) == 2
    assert fake_keyring.stored == {("pylis:work", "jdoe"): "hunter2"}


def test_a_stored_password_is_what_a_connect_then_reads(
    fake_keyring: _FakeKeyring,
    config: str,
    prompts: Callable[..., list[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PYLIS_PASSWORD", raising=False)
    prompts("hunter2", "hunter2")
    assert main(["password", "--config", config, "--profile", "work"]) == 0
    assert read_password(False, profile="work", username="jdoe") == "hunter2"


def test_another_applications_entry_is_not_sent_to_the_gateway(
    fake_keyring: _FakeKeyring,
    prompts: Callable[..., list[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The store is shared, and "work" is a name other programs use too."""
    monkeypatch.delenv("PYLIS_PASSWORD", raising=False)
    fake_keyring.stored[("work", "jdoe")] = "another application's secret"
    prompts("typed")
    assert read_password(False, profile="work", username="jdoe") == "typed"


def test_running_it_again_replaces_the_password(
    fake_keyring: _FakeKeyring, config: str, prompts: Callable[..., list[str]]
) -> None:
    fake_keyring.stored[("pylis:work", "jdoe")] = "old"
    prompts("new", "new")
    assert main(["password", "--config", config, "--profile", "work"]) == 0
    assert fake_keyring.stored == {("pylis:work", "jdoe"): "new"}


def test_a_mismatch_stores_nothing(
    fake_keyring: _FakeKeyring,
    config: str,
    prompts: Callable[..., list[str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    prompts("hunter2", "hunter3")
    assert main(["password", "--config", config, "--profile", "work"]) == 1
    assert fake_keyring.stored == {}
    assert "do not match" in capsys.readouterr().err


def test_output_never_contains_the_password(
    fake_keyring: _FakeKeyring,
    config: str,
    prompts: Callable[..., list[str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    prompts("hunter2", "hunter2")
    assert main(["password", "--config", config, "--profile", "work"]) == 0
    captured = capsys.readouterr()
    assert "jdoe" in captured.out
    assert "work" in captured.out
    assert "hunter2" not in captured.out + captured.err


@pytest.mark.parametrize("stdin", ["hunter2\nignored\n", "hunter2\r\nignored\n", "hunter2"])
def test_password_stdin_reads_one_line_without_prompting(
    fake_keyring: _FakeKeyring,
    config: str,
    prompts: Callable[..., list[str]],
    monkeypatch: pytest.MonkeyPatch,
    stdin: str,
) -> None:
    shown = prompts()
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    assert main(["password", "--config", config, "--profile", "work", "--password-stdin"]) == 0
    assert shown == []
    assert fake_keyring.stored == {("pylis:work", "jdoe"): "hunter2"}


def test_an_empty_password_is_refused(
    fake_keyring: _FakeKeyring,
    config: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n"))
    assert main(["password", "--config", config, "--profile", "work", "--password-stdin"]) == 1
    assert fake_keyring.stored == {}
    assert "empty" in capsys.readouterr().err


def test_an_explicit_user_wins_over_the_profile(
    fake_keyring: _FakeKeyring, config: str, prompts: Callable[..., list[str]]
) -> None:
    prompts("hunter2", "hunter2")
    assert main(["password", "--config", config, "--profile", "work", "-u", "other"]) == 0
    assert fake_keyring.stored == {("pylis:work", "other"): "hunter2"}


def test_no_username_anywhere_is_a_usage_error(
    fake_keyring: _FakeKeyring, config: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["password", "--config", config, "--profile", "nouser"]) == 2
    assert "-u/--user is required" in capsys.readouterr().err


@pytest.mark.parametrize("extra", [(), ("-u", "jdoe")])
def test_an_unknown_profile_stores_nothing(
    fake_keyring: _FakeKeyring,
    config: str,
    capsys: pytest.CaptureFixture[str],
    extra: tuple[str, ...],
) -> None:
    """Otherwise a typo would store an entry that no connect ever finds."""
    assert main(["password", "--config", config, "--profile", "wrok", *extra]) == 1
    assert fake_keyring.stored == {}
    assert "no profile 'wrok'" in capsys.readouterr().err


def test_a_missing_config_file_stores_nothing(
    fake_keyring: _FakeKeyring, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = str(tmp_path / "nope.toml")
    assert main(["password", "--config", missing, "--profile", "work", "-u", "jdoe"]) == 1
    assert fake_keyring.stored == {}
    assert "no config file" in capsys.readouterr().err


def test_a_profile_is_required() -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["password"])
    assert exit_info.value.code == 2


def test_delete_and_password_stdin_are_mutually_exclusive(config: str) -> None:
    with pytest.raises(SystemExit) as exit_info:
        argv = ["password", "--config", config, "--profile", "work", "--delete", "--password-stdin"]
        main(argv)
    assert exit_info.value.code == 2


def test_delete_removes_the_entry_without_asking_for_a_password(
    fake_keyring: _FakeKeyring, config: str, prompts: Callable[..., list[str]]
) -> None:
    fake_keyring.stored[("pylis:work", "jdoe")] = "hunter2"
    shown = prompts()
    assert main(["password", "--config", config, "--profile", "work", "--delete"]) == 0
    assert shown == []
    assert fake_keyring.stored == {}


def test_deleting_what_is_not_stored_is_an_error(
    fake_keyring: _FakeKeyring, config: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["password", "--config", config, "--profile", "work", "--delete"]) == 1
    assert "no password is stored for 'work'/'jdoe'" in capsys.readouterr().err


def test_a_missing_keyring_package_gives_the_hint_before_prompting(
    config: str,
    prompts: Callable[..., list[str]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setitem(sys.modules, "keyring", None)
    shown = prompts()
    assert main(["password", "--config", config, "--profile", "work"]) == 1
    assert shown == []
    assert 'uv tool install "pylis[keyring]"' in capsys.readouterr().err


def test_ctrl_c_at_the_prompt_stores_nothing(
    fake_keyring: _FakeKeyring, config: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(prompt: str = "") -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(getpass, "getpass", interrupted)
    assert main(["password", "--config", config, "--profile", "work"]) == 130
    assert fake_keyring.stored == {}
