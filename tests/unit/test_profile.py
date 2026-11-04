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
from pathlib import Path

import pytest

from pylis.errors import PylisError
from pylis.profile import (
    Profile,
    config_file_path,
    load_profile,
    load_profiles,
    password_from_keyring,
)

# --- config_file_path --------------------------------------------------------


def test_config_file_path_is_under_a_pylis_directory() -> None:
    path = config_file_path()
    assert path.name == "config.toml"
    assert path.parent.name == "pylis"


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


def test_invalid_toml_is_a_pylis_error(tmp_path: Path) -> None:
    path = write(tmp_path, "this is not [ toml")
    with pytest.raises(PylisError, match="invalid TOML"):
        load_profiles(path)


def test_a_profile_without_gateway_is_rejected(tmp_path: Path) -> None:
    path = write(tmp_path, '[profiles.work]\nuser = "jdoe"\n')
    with pytest.raises(PylisError, match="missing required key 'gateway'"):
        load_profiles(path)


def test_an_unknown_key_is_rejected(tmp_path: Path) -> None:
    path = write(tmp_path, '[profiles.work]\ngateway = "x"\nbogus = 1\n')
    with pytest.raises(PylisError, match="unknown key"):
        load_profiles(path)


def test_a_bad_route_policy_is_rejected(tmp_path: Path) -> None:
    path = write(tmp_path, '[profiles.work]\ngateway = "x"\nroute_policy = "sometimes"\n')
    with pytest.raises(PylisError, match="route_policy must be one of"):
        load_profiles(path)


def test_profiles_must_be_a_table(tmp_path: Path) -> None:
    path = write(tmp_path, 'profiles = "not a table"\n')
    with pytest.raises(PylisError, match=r"\[profiles\] must be a table"):
        load_profiles(path)


# --- missing file / missing profile -------------------------------------------


def test_missing_file_has_no_profiles(tmp_path: Path) -> None:
    assert load_profiles(tmp_path / "nope.toml") == {}


def test_load_profile_on_a_missing_file_explains_that(tmp_path: Path) -> None:
    with pytest.raises(PylisError, match="no config file"):
        load_profile("work", path=tmp_path / "nope.toml")


def test_load_profile_lists_available_names(tmp_path: Path) -> None:
    path = write(tmp_path, '[profiles.home]\ngateway = "home.example.com"\n')
    with pytest.raises(PylisError, match="available profiles: home"):
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
    assert calls == [("work", "jdoe")]


def test_keyring_lookup_returns_none_when_nothing_is_stored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_fake_keyring(monkeypatch, None)
    assert password_from_keyring("work", "jdoe") is None


def test_keyring_not_installed_raises_a_pylis_error_with_the_install_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "keyring", None)
    with pytest.raises(PylisError, match=r"pip install pylis\[keyring\]"):
        password_from_keyring("work", "jdoe")


def test_keyring_backend_errors_are_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    def raising(target: str, username: str) -> str | None:
        raise _FakeKeyringError("locked")

    install_fake_keyring(monkeypatch, raising)
    with pytest.raises(PylisError, match="keyring lookup"):
        password_from_keyring("work", "jdoe")


# --- the hosts table -----------------------------------------------------------


def test_a_hosts_table_is_read(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        """
        [profiles.orka]
        gateway = "vpn.example.com"

        [profiles.orka.hosts]
        "node-1.orka" = "10.221.188.11"
        api = "10.221.188.20"
        """,
    )
    profile = load_profile("orka", path=path)
    assert profile.hosts == {"node-1.orka": "10.221.188.11", "api": "10.221.188.20"}


def test_no_hosts_table_means_an_empty_one(tmp_path: Path) -> None:
    path = write(tmp_path, '[profiles.work]\ngateway = "vpn.example.com"\n')
    assert load_profile("work", path=path).hosts == {}


def test_an_unquoted_dotted_name_is_explained(tmp_path: Path) -> None:
    """TOML reads ``node-1.orka = ...`` as nested tables, which is never what
    anyone writing a hosts table meant."""
    path = write(
        tmp_path,
        '[profiles.orka]\ngateway = "gw"\n[profiles.orka.hosts]\nnode-1.orka = "10.0.0.1"\n',
    )
    with pytest.raises(PylisError, match=r"\[profiles\.orka\.hosts\].*quote names"):
        load_profile("orka", path=path)


def test_a_hosts_entry_that_is_not_an_address_is_refused(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        '[profiles.orka]\ngateway = "gw"\n[profiles.orka.hosts]\napi = "api.example"\n',
    )
    with pytest.raises(PylisError, match=r"config\.toml: \[profiles\.orka\.hosts\].*not an IPv4"):
        load_profile("orka", path=path)


def test_hosts_must_be_a_table(tmp_path: Path) -> None:
    path = write(tmp_path, '[profiles.orka]\ngateway = "gw"\nhosts = "10.0.0.1"\n')
    with pytest.raises(PylisError, match="must be a table"):
        load_profile("orka", path=path)
