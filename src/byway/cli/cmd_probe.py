# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""``byway probe`` -- ask a gateway what it wants, without authenticating.

The first thing to run against a new gateway. Gateway dialect is the largest
unknown in this project, and probe resolves it with no credential sent and so
no chance of tripping a lockout policy.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import sys
from typing import Any

import httpx

from byway.auth.client import probe_gateway
from byway.auth.models import GatewayInfo
from byway.config import GatewayConfig
from byway.errors import BywayError


def register(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    shared: argparse.ArgumentParser,
) -> None:
    parser = subparsers.add_parser(
        "probe",
        parents=[shared],
        help="show a gateway's authentication form and certificate",
        description=(
            "POST the initial aggregate-auth XML and report what came back: the "
            "form fields, tunnel groups, and TLS certificate. Sends no credentials."
        ),
    )
    parser.add_argument("gateway", help="gateway hostname, optionally host:port")
    parser.add_argument(
        "--pin",
        metavar="sha256:HEX",
        help="require this certificate fingerprint (openconnect --servercert)",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="skip certificate verification (prefer --pin)",
    )
    parser.add_argument("--raw", action="store_true", help="print the raw XML response")
    parser.set_defaults(handler=run)


def parse_gateway(spec: str, *, pin: str | None, no_verify: bool) -> GatewayConfig:
    spec = spec.removeprefix("https://").removeprefix("http://").rstrip("/")
    host, _, port = spec.partition(":")
    return GatewayConfig(
        host=host,
        port=int(port) if port else 443,
        verify=not no_verify,
        server_cert_pin=pin,
    )


def run(args: argparse.Namespace) -> int:
    gateway = parse_gateway(args.gateway, pin=args.pin, no_verify=args.no_verify)
    try:
        info = asyncio.run(probe_gateway(gateway))
    except BywayError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ssl.SSLError as exc:
        print(f"error: TLS failure talking to {gateway.host}: {exc}", file=sys.stderr)
        print("hint: use --pin sha256:<hex> for an internal CA", file=sys.stderr)
        return 1
    except httpx.HTTPError as exc:
        print(f"error: cannot reach {gateway.host}: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(_as_dict(info), indent=2))
    else:
        _print_report(info, show_raw=args.raw)
    return 0


def _as_dict(info: GatewayInfo) -> dict[str, Any]:
    form = info.form
    return {
        "host": info.host,
        "port": info.port,
        "http_status": info.http_status,
        "redirected_to": info.redirected_to,
        "certificate": {
            "fingerprint": info.cert_fingerprint,
            "subject": info.cert_subject,
            "issuer": info.cert_issuer,
            "not_after": info.cert_not_after,
            "verify_error": info.cert_verify_error,
        },
        "auth": None
        if form is None
        else {
            "id": form.id,
            "title": form.title,
            "message": form.message,
            "banner": form.banner,
            "error": form.error,
            "groups": list(form.groups),
            "fields": [
                {"name": f.name, "type": f.type, "label": f.label, "value": f.value}
                for f in form.fields
            ],
            "has_opaque": form.opaque is not None,
        },
    }


def _print_report(info: GatewayInfo, *, show_raw: bool) -> None:
    print(f"gateway   {info.host}:{info.port}   HTTP {info.http_status}")
    if info.redirected_to:
        print(f"redirect  {info.redirected_to}")

    print("\ncertificate")
    print(f"  fingerprint  {info.cert_fingerprint}")
    if info.cert_subject:
        print(f"  subject      {info.cert_subject}")
    if info.cert_issuer:
        print(f"  issuer       {info.cert_issuer}")
    if info.cert_not_after:
        print(f"  expires      {info.cert_not_after}")
    if info.cert_verify_error:
        print(f"  NOT TRUSTED  {info.cert_verify_error}")
        print("               an internal CA is the usual cause; to connect, pass")
        print(f"               --pin {info.cert_fingerprint}")

    form = info.form
    if form is None:
        print("\nno recognisable <auth> form in the response")
        print("the raw body follows; please add it to tests/corpus/\n")
        print(info.raw_response)
        return

    print(f"\nauth id={form.id}")
    for label, value in (
        ("title", form.title),
        ("message", form.message),
        ("banner", form.banner),
        ("error", form.error),
    ):
        if value:
            print(f"  {label:<8} {value}")

    if form.is_challenge:
        print("\n  NOTE: this gateway asks for an additional factor (MFA),")
        print("        which byway does not yet support.")

    print("\nform fields")
    for field in form.fields:
        marker = "(secret)" if field.is_secret else ""
        line = f"  {field.name:<20} {field.type:<10} {marker:<9}"
        if field.label:
            line += f" {field.label!r}"
        print(line.rstrip())

    group_field = form.group_field
    if group_field is not None:
        print("\ntunnel groups")
        for option in group_field.options:
            mark = "*" if option.selected else " "
            print(f"  {mark} {option.value}")
        print("\n  * marks the gateway's default; override it with --group")

    print(f"\nopaque blob  {'present' if form.opaque else 'absent'}")

    if show_raw:
        print("\nraw response\n")
        print(info.raw_response)
