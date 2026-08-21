# pyac

A userspace Cisco AnyConnect (CSTP) VPN client. No tun device, no virtual adapter, no
routing changes, no administrator rights — the tunnel and everything carried over it lives
inside the Python process.

openconnect solves the same problem by handing decapsulated IP packets to a tun device and
letting the kernel do TCP. pyac refuses that, so it has to terminate IP itself: the gateway
hands us raw IP packets, and an in-process TCP/IP stack turns them back into streams.

Access is through a local SOCKS5 proxy — so `ssh` and `curl` work unchanged — and an
in-process async API.

> **Status: 1.0.** Authentication, the tunnel, the TCP stack, SOCKS5, the CLI and the
> in-process API all work against a real gateway, and the TCP implementation is checked
> against a real Linux kernel under packet loss.

## Why you might want this

- You need to reach a REST API or SSH into a host inside a corporate VPN.
- You cannot, or would rather not, install a VPN client, change routing, or use admin rights.
- You want VPN access scoped to one process rather than to the whole machine.

## Using it

```console
$ pyac probe vpn.corp.example          # what does this gateway ask for?
$ pyac up vpn.corp.example -u rene --socks
address   172.29.29.3/255.255.0.0
mtu       1383
routes    10.221.188.0/23
socks5    127.0.0.1:1080
```

```console
$ curl --socks5 127.0.0.1:1080 http://10.221.188.20/
$ ssh -o ProxyCommand="pyac nc --via 127.0.0.1:1080 %h %p" rene@10.221.188.32
$ pyac get http://10.221.188.20/v1/things
```

Credentials never go in `argv`: use `PYAC_PASSWORD`, `--password-stdin`, or the interactive
prompt. Certificate pinning is `--pin sha256:<hex>`, compatible with openconnect's
`--servercert`, and is the right answer for an internal CA — not `--no-verify`.

## Profiles

Retyping the same gateway, user, group, and pin for every invocation gets old fast. Save them
once as a named profile and pass `--profile <name>` to `up`, `get`, or `nc` (direct mode)
instead — `probe` and `nc --via` take no credentials, so they have no use for one.

The config file lives where [platformdirs](https://pypi.org/project/platformdirs/) puts
per-user config for `pyac` — `~/.config/pyac/config.toml` on Linux, `~/Library/Application
Support/pyac/config.toml` on macOS, `%APPDATA%\pyac\config.toml` on Windows — or wherever
`--config PATH` points instead. Each VPN gets a `[profiles.<name>]` table:

```toml
[profiles.work]
gateway = "vpn.corp.example"
user = "rene"
group = "employees"
pin = "sha256:deadbeef..."
# verify = false
# mtu = 1400
# buffer = 2048
# route_policy = "all"
```

Only `gateway` is required. `pyac up --profile work` then behaves exactly like `pyac up
vpn.corp.example -u rene -g employees --pin sha256:deadbeef...`.

**Any flag given on the command line overrides the same setting in the profile** — the
profile only fills in what you didn't pass. This has one asymmetric case worth knowing:
`verify = false` in a profile disables gateway certificate verification, same as passing
`--no-verify` directly; there is currently no flag to force verification back *on* for a
profile that disables it, so pin the certificate instead if you need that (`--pin` always
works regardless of `verify`).

No password ever goes in the TOML file. Passwords are resolved, in order: `--password-stdin`,
`PYAC_PASSWORD`, a `keyring` lookup (only when `--profile` was used, keyed on the profile name
and the resolved username), then the interactive prompt. To use the keyring step, install the
extra and store the password with the standalone `keyring` CLI it ships:

```console
$ pip install pyac[keyring]
$ keyring set work rene
```

## In your own program

```python
import pyac

async with pyac.connect("vpn.corp.example", user, password) as vpn:
    # A genuine (StreamReader, StreamWriter): asyncssh, asyncpg and anything
    # written against asyncio.open_connection work unchanged.
    reader, writer = await vpn.open_connection("10.221.188.32", 22)

    async with vpn.httpx_client() as http:
        response = await http.get("http://10.221.188.20/v1/things")

    await vpn.serve_socks5(port=1080)  # also expose it to other processes
```

Leaving the block closes the tunnel *and* posts the logout. That second part is not
housekeeping: gateways enforce concurrent-session limits, and leaked sessions eventually lock
you out of your own VPN with nothing to point at.

Flow control composes with the stdlib for free. `StreamReader`'s high-water mark calls
`pause_reading()`, which stops us draining the stack, which shrinks the advertised window,
which stops the far end sending — backpressure reaches the peer without a queue anywhere in
between.

## Limits worth knowing before you start

**There is no in-tunnel DNS resolver, so you need IP addresses.** `--socks5-hostname` and
`socks5h://` cannot work; SOCKS5 rejects names rather than resolving them through the *host's*
resolver, which would leak internal hostnames to whatever DNS your laptop is using. The
gateway this was developed against advertises no DNS servers at all, so there is nothing to
resolve against; on a gateway that does advertise them, this becomes implementable.

**Your address can change underneath you.** Some gateways assign a fresh address on every
connection, and the one used here does. When the tunnel is rebuilt, sockets bound to the old
address cannot survive, so they are failed with an error saying exactly that. The tunnel and
the SOCKS listener stay up; individual connections do not.

**An idle tunnel may be destroyed, not merely dropped.** `X-CSTP-Idle-Timeout` is commonly
30 minutes, and on the gateway used here the session is invalidated when it fires — every
reconnect then returns 401 and only a fresh login helps. `--keepalive <ip-inside-the-vpn>`
sends periodic traffic so the timer never fires. DPD and keepalive *frames* do not always
count; payload does.

Also: IPv4 only. TLS only, no DTLS. No compression — pyac deliberately does not advertise
`X-CSTP-Accept-Encoding`. Username and password only; SAML/SSO, client certificates and MFA
challenges are detected and reported clearly, but not supported. Outbound TCP only.

## Throughput

Measured, not estimated. Single connection, receive direction.

| Path | Throughput |
|---|---|
| CSTP framing over real TLS, loopback | ~300 MB/s |
| Stack alone, over a Linux tun device, no latency | ~50 MB/s |
| Same stack at 150 ms RTT, 256 KiB buffer | 1.4 MB/s |
| Same stack at 150 ms RTT, 1 MiB buffer | 3.8 MB/s |
| A real ASA at 31 ms, 1.3 GB, SHA-256 verified | 1.1 MB/s |

**Latency, not Python, is what you will hit first.** The two 150 ms rows are the same code on
the same machine: one connection cannot exceed `buffer ÷ RTT` whatever the code does. The
default buffer is therefore 1 MiB, and `--buffer KIB` raises it. Bigger is not automatically
better — past about 1 MiB the sender's bursts start overrunning queues below us and the
returns go negative.

**The real-gateway row is a limit of that gateway, not of this code.** At 31 ms even a
256 KiB buffer allowed 8.5 MB/s, the client CPU was idle throughout, and a second transfer
took bandwidth from the first rather than adding to it — a shared ceiling, which is what a
per-user bandwidth policy looks like from inside. 10 Mbit/s of policy works out to roughly
1.15 MB/s of goodput once tunnel and TLS overhead come off. Measure your own before assuming
either explanation applies.

If you need more than this can give, `usernet`'s `NetworkBackend` protocol exists so a native
stack could be dropped in — but on a high-latency or policed link that would change nothing,
because the limit is not the CPU.

## Where the stack lives

The TCP/IP stack, the driver, the SOCKS5 server and the transport bridge are not in this
repository. They are [`usernet`](https://github.com/dehesselle/usernet), because none of that
code knows what AnyConnect is and a second client — a Tailscale one — needed exactly the same
half. What is left here is CSTP: authentication, the tunnel handshake, frame transport, and
reconnection.

The seam is `usernet.link.IpLink`: anything that can carry raw IPv4 packets and say what
address it was assigned. `ReconnectingLink` is this project's implementation of it.

## How it is tested

CSTP is what this repository is responsible for, and the ways a gateway can surprise you are
what it tests:

- **Codecs** — CSTP framing and the tunnel headers, auth XML against a corpus of real gateway
  responses, plus property-based tests feeding arbitrary bytes into every parser and asserting
  that only declared parse errors escape.
- **A fake CSTP gateway** that serves the auth exchange, speaks framing, injects faults, and
  terminates IP into a test peer — so `pyac up` → SOCKS5 → a real HTTP GET runs in CI with no
  VPN anywhere.
- **Reconnection and rekey**, including the case that matters most: a gateway that assigns a
  different address on reconnect, where every open socket has to fail with a reason rather
  than hang.

The stack's own five test layers — the frozen-clock state machine, the virtual network, and
conformance against a real Linux kernel over a tun device degraded with `netem` — moved to
`usernet` along with the code they cover.

## Development

```console
$ git clone https://github.com/dehesselle/usernet ../usernet
$ uv sync --dev
$ uv run pytest
$ uv run ruff check . && uv run ruff format --check . && uv run mypy src
```

`usernet` is consumed from `../usernet` as an editable path dependency, so it has to be
checked out beside this repository. Nothing is published to an index yet.

## A note on policy

Many organisations' security policies require a sanctioned VPN client, and pyac bypasses
posture assessment (CSD/HostScan) entirely. Check that you are allowed to use this before you
point it at a corporate gateway.
