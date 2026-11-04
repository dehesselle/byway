# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Profile loading and the keyring password lookup.

A profile is meant to replace typing the same connect flags every time, so a
parsing mistake here either silently drops a setting a user thought they
saved, or -- worse -- connects somewhere they did not intend to. Every field
and every error path is worth pinning down directly.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from byway.errors import BywayError
from byway.profile import (
    Profile,
    config_file_path,
    delete_password_from_keyring,
    load_profile,
    load_profiles,
    password_from_keyring,
    store_password_in_keyring,
)

# --- config_file_path --------------------------------------------------------


def test_config_file_path_is_under_a_byway_directory() -> None:
    path = config_file_path()
    assert path.name == "config.toml"
    assert path.parent.name == "byway"


# --- parsing, valid ----------------------------------------------------------


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_a_minimal_profile_needs_only_gateway(tmp_path: Path) -> None:
    path = write(tmp_path, '[profiles.work]\ngateway = "vpn.example.com"\n')
    assert load_profile("work", path=path) == Profile(gateway="vpn.example.com")


def test_a_full_profile_round_trips_every_field(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        """
        [profiles.work]
        gateway = "vpn.example.com:8443"
        user = "jdoe"
        group = "employees"
        pin = "sha256:deadbeef"
        verify = false
        mtu = 1400
        buffer = 2048
        route_policy = "all"
        """,
    )
    assert load_profile("work", path=path) == Profile(
        gateway="vpn.example.com:8443",
        user="jdoe",
        group="employees",
        pin="sha256:deadbeef",
        verify=False,
        mtu=1400,
        buffer=2048,
        route_policy="all",
    )


def test_two_profiles_in_one_file(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        """
        [profiles.work]
        gateway = "work.example.com"
        [profiles.home]
        gateway = "home.example.com"
        """,
    )
    profiles = load_profiles(path)
    assert set(profiles) == {"work", "home"}
    assert profiles["work"].gateway == "work.example.com"
    assert profiles["home"].gateway == "home.example.com"


# --- parsing, invalid ---------------------------------------------------------


def test_invalid_toml_is_a_byway_error(tmp_path: Path) -> None:
    path = write(tmp_path, "this is not [ toml")
    with pytest.raises(BywayError, match="invalid TOML"):
        load_profiles(path)


def test_a_profile_without_gateway_is_rejected(tmp_path: Path) -> None:
    path = write(tmp_path, '[profiles.work]\nuser = "jdoe"\n')
    with pytest.raises(BywayError, match="missing required key 'gateway'"):
        load_profiles(path)


def test_an_unknown_key_is_rejected(tmp_path: Path) -> None:
    path = write(tmp_path, '[profiles.work]\ngateway = "x"\nbogus = 1\n')
    with pytest.raises(BywayError, match="unknown key"):
        load_profiles(path)


def test_a_bad_route_policy_is_rejected(tmp_path: Path) -> None:
    path = write(tmp_path, '[profiles.work]\ngateway = "x"\nroute_policy = "sometimes"\n')
    with pytest.raises(BywayError, match="route_policy must be one of"):
        load_profiles(path)


def test_profiles_must_be_a_table(tmp_path: Path) -> None:
    path = write(tmp_path, 'profiles = "not a table"\n')
    with pytest.raises(BywayError, match=r"\[profiles\] must be a table"):
        load_profiles(path)


# --- missing file / missing profile -------------------------------------------


def test_missing_file_has_no_profiles(tmp_path: Path) -> None:
    assert load_profiles(tmp_path / "nope.toml") == {}


def test_load_profile_on_a_missing_file_explains_that(tmp_path: Path) -> None:
    with pytest.raises(BywayError, match="no config file"):
        load_profile("work", path=tmp_path / "nope.toml")


def test_load_profile_lists_available_names(tmp_path: Path) -> None:
    path = write(tmp_path, '[profiles.home]\ngateway = "home.example.com"\n')
    with pytest.raises(BywayError, match="available profiles: home"):
        load_profile("work", path=path)


# --- keyring lookup ------------------------------------------------------------


class _FakeKeyringError(Exception):
    pass


class _FakeErrorsModule:
    KeyringError = _FakeKeyringError


def install_fake_keyring(monkeypatch: pytest.MonkeyPatch, get_password: object) -> list[object]:
    calls: list[object] = []

    class _FakeKeyring:
        errors = _FakeErrorsModule

        @staticmethod
        def get_password(target: str, username: str) -> str | None:
            calls.append((target, username))
            if callable(get_password):
                return get_password(target, username)  # type: ignore[no-any-return]
            return get_password  # type: ignore[return-value]

    monkeypatch.setitem(sys.modules, "keyring", _FakeKeyring)
    monkeypatch.setitem(sys.modules, "keyring.errors", _FakeErrorsModule)
    return calls


def test_keyring_lookup_returns_the_stored_password(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = install_fake_keyring(monkeypatch, "hunter2")
    assert password_from_keyring("work", "jdoe") == "hunter2"
    assert calls == [("byway:work", "jdoe")]


def test_keyring_lookup_returns_none_when_nothing_is_stored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_fake_keyring(monkeypatch, None)
    assert password_from_keyring("work", "jdoe") is None


def test_keyring_lookup_returns_none_when_keyring_is_not_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "keyring", None)
    assert password_from_keyring("work", "jdoe") is None


def test_keyring_backend_errors_are_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    def raising(target: str, username: str) -> str | None:
        raise _FakeKeyringError("locked")

    install_fake_keyring(monkeypatch, raising)
    with pytest.raises(BywayError, match="keyring lookup"):
        password_from_keyring("work", "jdoe")


# --- keyring store and delete ---------------------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        lambda: store_password_in_keyring("work", "jdoe", "hunter2"),
        lambda: delete_password_from_keyring("work", "jdoe"),
    ],
)
def test_changing_the_keyring_without_the_package_gives_the_install_hint(
    monkeypatch: pytest.MonkeyPatch, call: Callable[[], None]
) -> None:
    """Unlike a lookup, nothing can fall back to a prompt here."""
    monkeypatch.setitem(sys.modules, "keyring", None)
    with pytest.raises(BywayError, match=r'uv tool install "byway\[keyring\]"'):
        call()


def test_keyring_store_and_delete_errors_are_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    class _BrokenKeyring:
        errors = _FakeErrorsModule

        @staticmethod
        def get_password(target: str, username: str) -> str | None:
            return "stored"

        @staticmethod
        def set_password(target: str, username: str, password: str) -> None:
            raise _FakeKeyringError("locked")

        @staticmethod
        def delete_password(target: str, username: str) -> None:
            raise _FakeKeyringError("locked")

    monkeypatch.setitem(sys.modules, "keyring", _BrokenKeyring)
    monkeypatch.setitem(sys.modules, "keyring.errors", _FakeErrorsModule)
    with pytest.raises(BywayError, match="keyring store"):
        store_password_in_keyring("work", "jdoe", "hunter2")
    with pytest.raises(BywayError, match="keyring delete"):
        delete_password_from_keyring("work", "jdoe")


# --- the hosts table -----------------------------------------------------------


def test_a_hosts_table_is_read(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        """
        [profiles.work]
        gateway = "vpn.example.com"

        [profiles.work.hosts]
        "node-1.internal" = "10.221.188.11"
        api = "10.221.188.20"
        """,
    )
    profile = load_profile("work", path=path)
    assert profile.hosts == {"node-1.internal": "10.221.188.11", "api": "10.221.188.20"}


def test_no_hosts_table_means_an_empty_one(tmp_path: Path) -> None:
    path = write(tmp_path, '[profiles.work]\ngateway = "vpn.example.com"\n')
    assert load_profile("work", path=path).hosts == {}


def test_an_unquoted_dotted_name_is_explained(tmp_path: Path) -> None:
    """TOML reads ``node-1.internal = ...`` as nested tables, which is never what
    anyone writing a hosts table meant."""
    path = write(
        tmp_path,
        '[profiles.work]\ngateway = "gw"\n[profiles.work.hosts]\nnode-1.internal = "10.0.0.1"\n',
    )
    with pytest.raises(BywayError, match=r"\[profiles\.work\.hosts\].*quote names"):
        load_profile("work", path=path)


def test_a_hosts_entry_that_is_not_an_address_is_refused(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        '[profiles.work]\ngateway = "gw"\n[profiles.work.hosts]\napi = "api.example"\n',
    )
    with pytest.raises(BywayError, match=r"config\.toml: \[profiles\.work\.hosts\].*not an IPv4"):
        load_profile("work", path=path)


def test_hosts_must_be_a_table(tmp_path: Path) -> None:
    path = write(tmp_path, '[profiles.work]\ngateway = "gw"\nhosts = "10.0.0.1"\n')
    with pytest.raises(BywayError, match="must be a table"):
        load_profile("work", path=path)
