"""Profiles: named, reusable connection settings, loaded from a TOML config file.

Sibling to config.py, not a submodule of cli/: this module owns no argparse
dependency, so pyac.api can use it too. It only imports pyac.errors, so it
introduces no import cycle.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, fields
from pathlib import Path

import platformdirs

from pyac.errors import PyacError

_ROUTE_POLICIES = ("auto", "all")


@dataclass(frozen=True, slots=True)
class Profile:
    """One ``[profiles.<name>]`` table. Keys map 1:1 onto these field names."""

    gateway: str
    user: str | None = None
    group: str | None = None
    pin: str | None = None
    verify: bool = True
    mtu: int | None = None
    buffer: int | None = None
    route_policy: str | None = None


_FIELD_NAMES = {f.name for f in fields(Profile)}


def config_file_path() -> Path:
    return Path(platformdirs.user_config_dir("pyac", appauthor=False)) / "config.toml"


def load_profiles(path: Path | None = None) -> dict[str, Profile]:
    """Parse every ``[profiles.<name>]`` table.

    Returns ``{}`` if the file does not exist -- that is "no profiles
    configured", not an error; :func:`load_profile` turns an empty result
    into an error message naming the profile that was actually requested.
    """
    resolved = path or config_file_path()
    try:
        with resolved.open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        return {}
    except tomllib.TOMLDecodeError as exc:
        raise PyacError(f"{resolved}: invalid TOML: {exc}") from exc

    raw = data.get("profiles", {})
    if not isinstance(raw, dict):
        raise PyacError(f"{resolved}: [profiles] must be a table of tables")

    return {name: _parse_profile(resolved, name, table) for name, table in raw.items()}


def load_profile(name: str, path: Path | None = None) -> Profile:
    resolved = path or config_file_path()
    profiles = load_profiles(resolved)
    if name in profiles:
        return profiles[name]
    if not profiles:
        raise PyacError(
            f"no config file at {resolved} (or it defines no profiles); "
            f"add a [profiles.{name}] section, or pass --config to point elsewhere"
        )
    available = ", ".join(sorted(profiles))
    raise PyacError(f"no profile {name!r} in {resolved}; available profiles: {available}")


def _parse_profile(path: Path, name: str, table: object) -> Profile:
    if not isinstance(table, dict):
        raise PyacError(f"{path}: [profiles.{name}] must be a table")
    if "gateway" not in table:
        raise PyacError(f"{path}: [profiles.{name}] is missing required key 'gateway'")
    unknown = set(table) - _FIELD_NAMES
    if unknown:
        keys = ", ".join(sorted(unknown))
        raise PyacError(f"{path}: [profiles.{name}] has unknown key(s): {keys}")
    if "route_policy" in table and table["route_policy"] not in _ROUTE_POLICIES:
        raise PyacError(f"{path}: [profiles.{name}].route_policy must be one of {_ROUTE_POLICIES}")
    try:
        return Profile(**table)
    except TypeError as exc:
        raise PyacError(f"{path}: [profiles.{name}]: {exc}") from exc


def password_from_keyring(target: str, username: str) -> str | None:
    """Look up a password stored via the standalone ``keyring`` CLI.

    ``target`` is the profile name; the password is expected to have been
    stored with ``keyring set <profile-name> <username>``. Returns ``None``
    if nothing is stored there -- the caller falls through to the
    interactive prompt, that is not an error. Imports keyring lazily so the
    hard dependency list stays untouched; raises PyacError with an install
    hint if it is missing.
    """
    try:
        import keyring
        import keyring.errors
    except ImportError as exc:
        raise PyacError(
            "no password from --password-stdin or PYAC_PASSWORD, and keyring lookup "
            "needs the optional dependency: pip install pyac[keyring]"
        ) from exc
    try:
        return keyring.get_password(target, username)
    except keyring.errors.KeyringError as exc:
        raise PyacError(f"keyring lookup for {target!r}/{username!r} failed: {exc}") from exc
