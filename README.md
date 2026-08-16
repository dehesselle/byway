# pyac

A userspace Cisco AnyConnect (CSTP) VPN client. No tun device, no virtual adapter, no
routing changes, no administrator rights — the tunnel and everything carried over it lives
inside the Python process.

openconnect solves the same problem by handing decapsulated IP packets to a tun device and
letting the kernel do TCP. pyac refuses that, so it terminates IP itself: the gateway hands
us raw IP packets and an in-process TCP/IP stack turns them back into streams.

Access is through a local SOCKS5 proxy (so `ssh` and `curl` work unchanged) and an
in-process async API.

> **Status: in development.** See `docs/` for the milestone the code has reached.

## Why you might want this

- You need to reach a REST API or SSH into a host inside a corporate VPN.
- You cannot or would rather not install a VPN client, change routing, or use admin rights.
- You want VPN access scoped to one process rather than the whole machine.

## Intended usage

```console
$ pyac probe vpn.corp.example          # what does this gateway ask for?
$ pyac up --gateway vpn.corp.example --user rene
assigned 10.20.30.40/255.255.255.0  mtu 1406  dns 10.0.0.53
SOCKS5 listening on 127.0.0.1:1080
```

```console
$ curl --socks5-hostname 127.0.0.1:1080 https://api.internal/v1/things
$ ssh -o ProxyCommand="pyac nc %h %p" rene@box.internal
```

```python
async with pyac.connect("vpn.corp.example", user, password) as vpn:
    async with httpx.AsyncClient(transport=vpn.httpx_transport()) as http:
        r = await http.get("https://api.internal/v1/things")
```

Names are resolved *inside* the tunnel using the gateway's own DNS servers, which is why no
OS-level DNS configuration is needed. Use `socks5h://` (or `--socks5-hostname`) so the
hostname reaches pyac rather than being resolved locally.

## Scope and limits

- **IPv4 and TLS only.** No DTLS, no compression — pyac deliberately does not advertise
  `X-CSTP-Accept-Encoding`, so the gateway will not compress.
- **Authentication is username and password.** SAML/SSO, client certificates, and MFA
  challenges are detected and reported clearly, but not yet supported.
- **Outbound TCP only.** No listening sockets inside the VPN.
- **Throughput is roughly 5–20 MB/s.** Per-packet processing happens in Python. That is
  ample for REST calls and interactive SSH; it is not a bulk transfer tool. The
  `NetworkBackend` protocol exists so a native stack could be dropped in later.

## Development

```console
$ uv sync --dev
$ uv run pytest
$ uv run ruff check . && uv run ruff format --check . && uv run mypy src
```

`pyac.net` is sans-IO: it never opens a socket, sleeps, or reads a clock — time enters as an
`int` parameter and randomness as an injected callable. That is what makes the TCP state
machine testable deterministically, and it is enforced by a ruff banned-import rule plus a
runtime guard in `tests/unit/test_sans_io_guard.py`.

Conformance tests against a real kernel TCP stack need a Linux tun device. They are marked
`linux_only` and run in CI; locally they run under WSL2.

## A note on policy

Many organisations' security policies require a sanctioned VPN client, and pyac bypasses
posture assessment (CSD/HostScan) entirely. Check that you are allowed to use this before
you point it at a corporate gateway.
