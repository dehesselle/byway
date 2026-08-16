"""Parsing of the X-CSTP-* response headers.

This is where gateway variation shows up, so the edge cases matter more than
the happy path (which the integration tests already cover).
"""

from __future__ import annotations

import ipaddress

from pyac.cstp.config import DEFAULT_MTU, parse_tunnel_config


def parse(*headers: tuple[str, str]):  # type: ignore[no-untyped-def]
    return parse_tunnel_config(list(headers))


def test_minimal_response_uses_sane_defaults() -> None:
    config = parse(("X-CSTP-Address", "10.1.2.3"))

    assert config.address == "10.1.2.3"
    assert config.mtu == DEFAULT_MTU
    assert config.dpd == 30
    assert config.keepalive == 20
    assert config.dns == ()
    assert not config.is_split_tunnel


def test_header_names_are_case_insensitive() -> None:
    config = parse(("x-cstp-address", "10.1.2.3"), ("X-CSTP-MTU", "1300"))
    assert (config.address, config.mtu) == ("10.1.2.3", 1300)


def test_repeated_headers_accumulate_in_order() -> None:
    config = parse(
        ("X-CSTP-Address", "10.1.2.3"),
        ("X-CSTP-DNS", "10.0.0.53"),
        ("X-CSTP-DNS", "10.0.0.54"),
        ("X-CSTP-DNS", "10.0.0.55"),
    )
    assert config.dns == ("10.0.0.53", "10.0.0.54", "10.0.0.55")


def test_split_routes_accept_both_notations() -> None:
    """ASA writes a dotted mask; some gateways use CIDR. Accept both."""
    config = parse(
        ("X-CSTP-Address", "10.1.2.3"),
        ("X-CSTP-Split-Include", "10.0.0.0/255.0.0.0"),
        ("X-CSTP-Split-Include", "192.168.5.0/24"),
        ("X-CSTP-Split-Exclude", "10.99.0.0/255.255.0.0"),
    )
    assert config.split_include == (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("192.168.5.0/24"),
    )
    assert config.split_exclude == (ipaddress.IPv4Network("10.99.0.0/16"),)


def test_an_unparseable_route_is_dropped_not_fatal() -> None:
    """One bad route must not cost us the whole tunnel."""
    config = parse(
        ("X-CSTP-Address", "10.1.2.3"),
        ("X-CSTP-Split-Include", "not-a-network"),
        ("X-CSTP-Split-Include", "10.0.0.0/255.0.0.0"),
    )
    assert config.split_include == (ipaddress.IPv4Network("10.0.0.0/8"),)


def test_lowest_non_zero_session_timeout_wins() -> None:
    """Any of these can end the session, so the soonest is the real deadline."""
    config = parse(
        ("X-CSTP-Address", "10.1.2.3"),
        ("X-CSTP-Session-Timeout", "86400"),
        ("X-CSTP-Session-Timeout-Remaining", "3600"),
    )
    assert config.session_timeout == 3600


def test_zero_session_timeout_means_unlimited() -> None:
    config = parse(("X-CSTP-Address", "10.1.2.3"), ("X-CSTP-Session-Timeout", "0"))
    assert config.session_timeout == 0


def test_non_numeric_values_fall_back_to_defaults() -> None:
    config = parse(("X-CSTP-Address", "10.1.2.3"), ("X-CSTP-MTU", "banana"))
    assert config.mtu == DEFAULT_MTU


def test_banner_is_percent_decoded() -> None:
    config = parse(
        ("X-CSTP-Address", "10.1.2.3"),
        ("X-CSTP-Banner", "Authorised%20users%20only.%0AMonitored."),
    )
    assert config.banner == "Authorised users only.\nMonitored."


def test_unknown_cstp_headers_are_kept_for_reporting() -> None:
    """New gateway behaviour should be discoverable, not silently dropped."""
    config = parse(
        ("X-CSTP-Address", "10.1.2.3"),
        ("X-CSTP-Something-New", "42"),
        ("Content-Length", "0"),  # not a CSTP header, so not recorded
    )
    assert config.unknown_headers == (("X-CSTP-Something-New", "42"),)


def test_routine_asa_headers_are_not_reported_as_unknown() -> None:
    """Observed on a real ASA 5.1.5 gateway; all noise, none actionable.

    If these counted as unknown, the genuinely new header that matters would
    be buried in a wall of routine output.
    """
    config = parse(
        ("X-CSTP-Address", "10.1.2.3"),
        ("X-CSTP-Version", "1"),
        ("X-CSTP-Protocol", "Copyright (c) 2004 Cisco Systems, Inc."),
        ("X-CSTP-Lease-Duration", "1209600"),
        ("X-CSTP-Session-Timeout-Alert-Interval", "60"),
        ("X-CSTP-MSIE-Proxy-Lockdown", "true"),
        ("X-CSTP-Smartcard-Removal-Disconnect", "true"),
        ("X-CSTP-Routing-Filtering-Ignore", "false"),
        ("X-CSTP-Quarantine", "false"),
        ("X-CSTP-Disable-Always-On-VPN", "false"),
        ("X-CSTP-TCP-Keepalive", "true"),
    )
    assert config.unknown_headers == ()


def test_post_auth_xml_is_captured_but_kept_out_of_the_report() -> None:
    """It is kilobytes of MSI provisioning detail that never applies to us."""
    blob = "<?xml version='1.0'?><config-auth>" + "x" * 5000 + "</config-auth>"
    config = parse(("X-CSTP-Address", "10.1.2.3"), ("X-CSTP-Post-Auth-XML", blob))

    assert config.post_auth_xml == blob
    assert config.unknown_headers == ()
    assert blob not in repr(config)


def test_dns_policy_flags() -> None:
    config = parse(
        ("X-CSTP-Address", "10.1.2.3"),
        ("X-CSTP-Tunnel-All-DNS", "false"),
        ("X-CSTP-Keep", "true"),
    )
    assert config.tunnel_all_dns is False
    assert config.keep_address is True
    # No X-CSTP-DNS at all: this gateway is not offering in-tunnel resolution.
    assert config.dns == ()


def test_local_network_derives_from_address_and_netmask() -> None:
    config = parse(("X-CSTP-Address", "10.20.30.40"), ("X-CSTP-Netmask", "255.255.255.0"))
    assert config.local_network == ipaddress.IPv4Network("10.20.30.0/24")
    assert ipaddress.IPv4Address("10.20.30.99") in config.local_network


def test_content_encoding_is_surfaced_so_the_session_can_refuse() -> None:
    config = parse(("X-CSTP-Address", "10.1.2.3"), ("X-CSTP-Content-Encoding", "deflate"))
    assert config.content_encoding == "deflate"
