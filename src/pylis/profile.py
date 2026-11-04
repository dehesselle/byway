"""Profiles: named, reusable connection settings, loaded from a TOML config file.

Sibling to config.py, not a submodule of cli/: this module owns no argparse
dependency, so pylis.api can use it too. It only imports pylis.errors, so it
introduces no import cycle.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

import platformdirs
from usernet.resolve import StaticResolver

from pylis.errors import PylisError

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
    hosts: dict[str, str] = field(default_factory=dict)
    """``[profiles.<name>.hosts]``: names resolved inside the tunnel, ``name = "ip"``."""


_FIELD_NAMES = {f.name for f in fields(Profile)}


def config_file_path() -> Path:
    return Path(platformdirs.user_config_dir("pylis", appauthor=False)) / "config.toml"


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
        raise PylisError(f"{resolved}: invalid TOML: {exc}") from exc

    raw = data.get("profiles", {})
    if not isinstance(raw, dict):
        raise PylisError(f"{resolved}: [profiles] must be a table of tables")

    return {name: _parse_profile(resolved, name, table) for name, table in raw.items()}


def load_profile(name: str, path: Path | None = None) -> Profile:
    resolved = path or config_file_path()
    profiles = load_profiles(resolved)
    if name in profiles:
        return profiles[name]
    if not profiles:
        raise PylisError(
            f"no config file at {resolved} (or it defines no profiles); "
            f"add a [profiles.{name}] section, or pass --config to point elsewhere"
        )
    available = ", ".join(sorted(profiles))
    raise PylisError(f"no profile {name!r} in {resolved}; available profiles: {available}")


def _parse_profile(path: Path, name: str, table: object) -> Profile:
    if not isinstance(table, dict):
        raise PylisError(f"{path}: [profiles.{name}] must be a table")
    if "gateway" not in table:
        raise PylisError(f"{path}: [profiles.{name}] is missing required key 'gateway'")
    unknown = set(table) - _FIELD_NAMES
    if unknown:
        keys = ", ".join(sorted(unknown))
        raise PylisError(f"{path}: [profiles.{name}] has unknown key(s): {keys}")
    if "route_policy" in table and table["route_policy"] not in _ROUTE_POLICIES:
        raise PylisError(f"{path}: [profiles.{name}].route_policy must be one of {_ROUTE_POLICIES}")
    if "hosts" in table:
        _check_hosts(path, name, table["hosts"])
    try:
        return Profile(**table)
    except TypeError as exc:
        raise PylisError(f"{path}: [profiles.{name}]: {exc}") from exc


def _check_hosts(path: Path, name: str, hosts: object) -> None:
    section = f"[profiles.{name}.hosts]"
    if not isinstance(hosts, dict):
        raise PylisError(f'{path}: {section} must be a table of name = "address"')
    for host, address in hosts.items():
        if not isinstance(address, str):
            # The usual cause: an unquoted dotted key, which TOML reads as
            # nested tables rather than as one name.
            raise PylisError(
                f"{path}: {section}: {host!r} must map to an address string; "
                f'quote names that contain dots, e.g. "node-1.orka" = "10.0.0.11"'
            )
    try:
        StaticResolver(hosts, source=f"{path}: {section}")
    except ValueError as exc:
        raise PylisError(str(exc)) from None


def password_from_keyring(target: str, username: str) -> str | None:
    """Look up a password stored via the standalone ``keyring`` CLI.

    ``target`` is the profile name; the password is expected to have been
    stored with ``keyring set <profile-name> <username>``. Returns ``None``
    if nothing is stored there -- the caller falls through to the
    interactive prompt, that is not an error. Imports keyring lazily so the
    hard dependency list stays untouched; raises PylisError with an install
    hint if it is missing.
    """
    try:
        import keyring
        import keyring.errors
    except ImportError as exc:
        raise PylisError(
            "no password from --password-stdin or PYLIS_PASSWORD, and keyring lookup "
            "needs the optional dependency: pip install pylis[keyring]"
        ) from exc
    try:
        return keyring.get_password(target, username)
    except keyring.errors.KeyringError as exc:
        raise PylisError(f"keyring lookup for {target!r}/{username!r} failed: {exc}") from exc
