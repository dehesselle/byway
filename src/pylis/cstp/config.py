# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Everything the gateway tells us about the tunnel, parsed and typed.

The ``X-CSTP-*`` response headers to ``CONNECT /CSCOSSLC/tunnel`` carry the
address assignment, MTU, DNS servers, split routes, and timers. Several of
them can repeat (DNS, Split-Include), so parsing works from a list of header
pairs rather than a mapping.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import unquote

# What ASA advertises when it says nothing; also our fallback if the header is
# missing or unparseable. Getting this wrong is the classic silent-hang bug.
DEFAULT_MTU = 1406

# Headers a real ASA always sends that carry nothing we act on. They are
# recognised explicitly so that ``unknown_headers`` means "genuinely new
# behaviour worth reporting" rather than a wall of routine noise.
KNOWN_UNUSED_HEADERS = frozenset(
    {
        "x-cstp-version",
        "x-cstp-protocol",
        "x-cstp-lease-duration",
        "x-cstp-session-timeout-alert-interval",
        "x-cstp-msie-proxy-lockdown",
        "x-cstp-msie-proxy-pac-url",
        "x-cstp-msie-proxy-auto-detect",
        "x-cstp-smartcard-removal-disconnect",
        "x-cstp-routing-filtering-ignore",
        "x-cstp-quarantine",
        "x-cstp-disable-always-on-vpn",
        "x-cstp-tcp-keepalive",
        "x-cstp-license",
        "x-cstp-dyndns",
        "x-cstp-client-bypass-protocol",
        "x-cstp-address-ip6",
        "x-cstp-netmask-ip6",
    }
)


@dataclass(frozen=True, slots=True)
class TunnelConfig:
    """The gateway's description of the tunnel."""

    address: str
    netmask: str = "255.255.255.255"
    mtu: int = DEFAULT_MTU
    base_mtu: int | None = None

    dns: tuple[str, ...] = ()
    nbns: tuple[str, ...] = ()
    default_domain: str | None = None
    split_dns: tuple[str, ...] = ()

    split_include: tuple[ipaddress.IPv4Network, ...] = ()
    split_exclude: tuple[ipaddress.IPv4Network, ...] = ()

    dpd: int = 30
    keepalive: int = 20
    idle_timeout: int = 0
    session_timeout: int = 0
    disconnected_timeout: int = 0

    rekey_time: int = 0
    rekey_method: str | None = None

    banner: str | None = None
    content_encoding: str | None = None
    """Must be absent: we never advertise ``X-CSTP-Accept-Encoding``, so a
    value here means the gateway compressed anyway and our assumptions are
    wrong for this device."""

    tunnel_all_dns: bool = False
    """Whether the gateway wants *all* DNS sent through the tunnel. When false
    and no DNS servers are advertised, in-tunnel resolution is not on offer
    and names must be resolved by the host instead."""

    keep_address: bool = False
    """``X-CSTP-Keep`` -- the gateway intends to reassign the same address on
    reconnect, which is what lets established connections survive a rekey."""

    post_auth_xml: str | None = field(default=None, repr=False)
    """``X-CSTP-Post-Auth-XML``: a multi-kilobyte client-provisioning document
    describing MSI packages and profiles. Nothing in it applies to us, so it
    is captured rather than printed."""

    unknown_headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    """Anything we did not recognise, kept so ``pylis info`` can show it and new
    gateway behaviour is discoverable rather than silently dropped."""

    @property
    def is_split_tunnel(self) -> bool:
        return bool(self.split_include)

    @property
    def local_network(self) -> ipaddress.IPv4Network:
        """The assigned address's own subnet, always in scope."""
        return ipaddress.IPv4Network(f"{self.address}/{self.netmask}", strict=False)

    def summary(self) -> str:
        parts = [f"address {self.address}/{self.netmask}", f"mtu {self.mtu}"]
        if self.dns:
            parts.append("dns " + ",".join(self.dns))
        if self.default_domain:
            parts.append(f"domain {self.default_domain}")
        parts.append(f"dpd {self.dpd}s keepalive {self.keepalive}s")
        return "  ".join(parts)


def _int(value: str, default: int = 0) -> int:
    try:
        return int(value.strip())
    except ValueError:
        return default


def _network(value: str) -> ipaddress.IPv4Network | None:
    """Parse a split route.

    ASA writes ``10.0.0.0/255.0.0.0``; some gateways use CIDR. Accept both and
    drop anything else rather than failing the whole handshake over one route.
    """
    value = value.strip()
    if not value:
        return None
    try:
        return ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        pass
    address, _, mask = value.partition("/")
    try:
        return ipaddress.IPv4Network((address.strip(), mask.strip()), strict=False)
    except ValueError:
        return None


def parse_tunnel_config(headers: list[tuple[str, str]]) -> TunnelConfig:
    """Build a :class:`TunnelConfig` from the CONNECT response headers."""
    address = ""
    netmask = "255.255.255.255"
    mtu = DEFAULT_MTU
    base_mtu: int | None = None
    dns: list[str] = []
    nbns: list[str] = []
    default_domain: str | None = None
    split_dns: list[str] = []
    include: list[ipaddress.IPv4Network] = []
    exclude: list[ipaddress.IPv4Network] = []
    dpd = 30
    keepalive = 20
    idle_timeout = 0
    session_timeout = 0
    disconnected_timeout = 0
    rekey_time = 0
    rekey_method: str | None = None
    banner: str | None = None
    content_encoding: str | None = None
    tunnel_all_dns = False
    keep_address = False
    post_auth_xml: str | None = None
    unknown: list[tuple[str, str]] = []

    for raw_name, raw_value in headers:
        name = raw_name.strip().lower()
        value = raw_value.strip()

        if name == "x-cstp-address":
            address = value
        elif name == "x-cstp-netmask":
            netmask = value
        elif name == "x-cstp-mtu":
            mtu = _int(value, DEFAULT_MTU)
        elif name == "x-cstp-base-mtu":
            base_mtu = _int(value) or None
        elif name == "x-cstp-dns":
            dns.append(value)
        elif name == "x-cstp-nbns":
            nbns.append(value)
        elif name == "x-cstp-default-domain":
            default_domain = value
        elif name == "x-cstp-split-dns":
            split_dns.append(value)
        elif name == "x-cstp-split-include":
            if (network := _network(value)) is not None:
                include.append(network)
        elif name == "x-cstp-split-exclude":
            if (network := _network(value)) is not None:
                exclude.append(network)
        elif name == "x-cstp-dpd":
            dpd = _int(value, 30)
        elif name == "x-cstp-keepalive":
            keepalive = _int(value, 20)
        elif name == "x-cstp-idle-timeout":
            idle_timeout = _int(value)
        elif name in ("x-cstp-session-timeout", "x-cstp-session-timeout-remaining"):
            # Several timeout headers may appear; the lowest non-zero wins,
            # because any one of them can end the session.
            candidate = _int(value)
            if candidate and (not session_timeout or candidate < session_timeout):
                session_timeout = candidate
        elif name == "x-cstp-disconnected-timeout":
            disconnected_timeout = _int(value)
        elif name == "x-cstp-rekey-time":
            rekey_time = _int(value)
        elif name == "x-cstp-rekey-method":
            rekey_method = value
        elif name == "x-cstp-banner":
            banner = unquote(value)  # gateways percent-encode the banner
        elif name == "x-cstp-content-encoding":
            content_encoding = value
        elif name == "x-cstp-tunnel-all-dns":
            tunnel_all_dns = value.lower() == "true"
        elif name == "x-cstp-keep":
            keep_address = value.lower() == "true"
        elif name == "x-cstp-post-auth-xml":
            post_auth_xml = value
        elif name in KNOWN_UNUSED_HEADERS:
            pass
        elif name.startswith(("x-cstp-", "x-dtls")):
            unknown.append((raw_name.strip(), value))

    return TunnelConfig(
        address=address,
        netmask=netmask,
        mtu=mtu,
        base_mtu=base_mtu,
        dns=tuple(dns),
        nbns=tuple(nbns),
        default_domain=default_domain,
        split_dns=tuple(split_dns),
        split_include=tuple(include),
        split_exclude=tuple(exclude),
        dpd=dpd,
        keepalive=keepalive,
        idle_timeout=idle_timeout,
        session_timeout=session_timeout,
        disconnected_timeout=disconnected_timeout,
        rekey_time=rekey_time,
        rekey_method=rekey_method,
        banner=banner,
        content_encoding=content_encoding,
        tunnel_all_dns=tunnel_all_dns,
        keep_address=keep_address,
        post_auth_xml=post_auth_xml,
        unknown_headers=tuple(unknown),
    )
