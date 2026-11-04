# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""``byway password`` -- keep a profile's password in the system's credential store.

Writes the entry that ``read_password`` looks up, so that nobody has to run the
keyring package's own CLI, which uv would not put on the PATH anyway and which
may collide with a keyring the user installed themselves.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from byway.errors import BywayError
from byway.profile import (
    delete_password_from_keyring,
    load_profile,
    require_keyring,
    store_password_in_keyring,
)


def register(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    shared: argparse.ArgumentParser,
) -> None:
    parser = subparsers.add_parser(
        "password",
        parents=[shared],
        help="store a profile's password in the system's credential store",
        description=(
            "Store the password for a profile in the system's credential store, where "
            "`up`, `http` and `nc` look it up when given the same --profile. Run it again "
            "to replace the password. Needs the keyring extra."
        ),
    )
    parser.add_argument(
        "--profile",
        metavar="NAME",
        required=True,
        help="the profile the password belongs to, from [profiles.NAME] in the config "
        "file (see --config)",
    )
    parser.add_argument("-u", "--user", help="username (or from --profile)")
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password from stdin instead of prompting",
    )
    action.add_argument("--delete", action="store_true", help="remove the stored password")
    parser.set_defaults(handler=run)


def read_new_password(from_stdin: bool) -> str:
    """Prompt twice: a mistyped password would be retried on every connect,
    which is how an account gets locked out."""
    if from_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("Password: ")
        if getpass.getpass("Repeat password: ") != password:
            raise BywayError("the passwords do not match; nothing was stored")
    if not password:
        raise BywayError("the password is empty; nothing was stored")
    return password


def run(args: argparse.Namespace) -> int:
    config_path = Path(args.config) if args.config else None
    try:
        # Load it even with -u: a typo must not store an entry that no connect finds.
        profile = load_profile(args.profile, path=config_path)
        username = args.user or profile.user
        if not username:
            print(
                "error: -u/--user is required (pass it directly, or via --profile)",
                file=sys.stderr,
            )
            return 2
        require_keyring()  # before the prompt, not after typing the password twice
        if args.delete:
            delete_password_from_keyring(args.profile, username)
            print(f"removed the password of {username} for profile {args.profile}")
        else:
            password = read_new_password(args.password_stdin)
            store_password_in_keyring(args.profile, username, password)
            print(f"stored the password of {username} for profile {args.profile}")
    except KeyboardInterrupt:
        return 130
    except BywayError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0
