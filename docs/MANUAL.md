# Manual

Everything pyac's command line and library offer. The [README](../README.md) has the short
version; how pyac behaves while running is in [OPERATIONS.md](OPERATIONS.md).

## Commands

| Command | Purpose |
| --- | --- |
| `pyac probe GATEWAY` | Show the gateway's authentication form, tunnel groups and TLS certificate. Sends no credentials. |
| `pyac up [GATEWAY]` | Authenticate and hold the tunnel open, optionally serving SOCKS5. |
| `pyac nc HOST PORT` | Bridge stdin/stdout to one TCP connection inside the VPN, e.g. as an SSH `ProxyCommand`. |
| `pyac http [GATEWAY] URL` | Authenticate, make one HTTP request through the tunnel, and exit. |

Options valid for every command, placed before or after it:

| Option | Effect |
| --- | --- |
| `-v`, `-vv` | Debug logging; `-vv` adds per-packet tracing. |
| `--pcap FILE` | Write the tunnel's IP traffic to a pcap file for Wireshark. |
| `--json` | Machine-readable output. |
| `--config PATH` | Config file for `--profile` (see [Profiles](#profiles)). |

`pyac COMMAND --help` lists every option of a command.

### Connection options

`up`, `http` and `nc` (in direct mode) share these:

| Option | Effect |
| --- | --- |
| `-u USER`, `-g GROUP` | Username and tunnel group. `pyac probe` lists the groups. |
| `--profile NAME` | Fill in unset options from a saved [profile](#profiles). |
| `--password-stdin` | Read the password from stdin (`up` and `http`). |
| `--pin sha256:HEX` | Require this gateway certificate fingerprint. |
| `--no-verify` | Skip gateway certificate verification. Prefer `--pin`. |
| `--mtu MTU` | Override the MTU requested of the gateway. |
| `--buffer KIB` | Per-socket send and receive buffer, default 1024. See [OPERATIONS.md](OPERATIONS.md#throughput). |
| `--route-policy auto\|all` | `auto` refuses addresses outside the routes the gateway advertised; `all` tries anyway. |
| `--add-host NAME=ADDR` | Resolve NAME to ADDR inside the tunnel; repeatable. See [Host names](#host-names). |

## Bringing the tunnel up

```console
$ pyac up vpn.corp.example -u rene --socks
address   172.29.29.3/255.255.0.0
mtu       1383
routes    10.221.188.0/23
socks5    127.0.0.1:1080
```

On a terminal, `pyac up` keeps a small live panel beneath its output: how long ago the
gateway last sent anything, the last keepalive's round trip, tunnel traffic, and each open
SOCKS connection. Output that is piped or redirected stays plain, and so does
`--no-dashboard`.

| Option | Effect |
| --- | --- |
| `--socks [[HOST:]PORT]` | Serve SOCKS5, default `127.0.0.1:1080`. |
| `--socks-auth USER:PASS` | Require RFC 1929 credentials from SOCKS clients. |
| `--socks-allow-remote` | Permit a non-loopback SOCKS address. This opens the VPN to the network. |
| `--keepalive HOST` | Ping HOST (an address or a name from the [host table](#host-names)) inside the VPN so the gateway's idle timeout never fires. See [OPERATIONS.md](OPERATIONS.md#idle-timeout). |
| `--keepalive-interval SECONDS` | Default 300. |
| `--no-reconnect` | Exit when the tunnel ends instead of rebuilding it. |
| `--no-dashboard` | Plain output even on a terminal. |

Diagnostics only:

| Option | Effect |
| --- | --- |
| `--dump-only` | Report inbound IP packets instead of running a network stack. |
| `--ping HOST`, `--ping-interval SECONDS` | Send ICMP echo through the tunnel, default every 5 s. |
| `--no-client-dpd` | Answer the gateway's DPD but never send our own. |
| `--coalesce` | Batch frames into one TLS record. Known to break Cisco ASA; see [protocol.md](protocol.md#one-frame-per-tls-record--mandatory). |

SOCKS5 resolves names only from the [host table](#host-names); any other name sent with
`--socks5-hostname` or `socks5h://` is rejected.

## Reaching hosts

Through a running `pyac up --socks`:

```sh
curl --socks5 127.0.0.1:1080 http://10.221.188.20/
ssh -o ProxyCommand="pyac nc --via 127.0.0.1:1080 %h %p" rene@10.221.188.32
```

`pyac nc --via [HOST:]PORT` reuses the proxy, with `--via-auth USER:PASS` if it requires
credentials. Without `--via`, `nc` authenticates itself: `--gateway GATEWAY -u USER` or
`--profile NAME`.

`pyac http` brings up its own tunnel for one request:

```sh
pyac http --profile work http://10.221.188.20/v1/things
pyac http --profile work -H "Content-Type: application/json" -d '{"name": "x"}' https://10.221.188.20/v1/things
pyac http --profile work -X PUT -H "Content-Type: application/json" -d @thing.json https://10.221.188.20/v1/things/42
pyac http --profile work -X DELETE https://10.221.188.20/v1/things/42
```

It takes `-X METHOD`, `-H "NAME: VALUE"` (repeatable), `-o FILE`, `-L` to follow redirects
and `--timeout SECONDS`. `-d DATA` sends a request body: the text itself, `@FILE` for a
file's contents, or `@-` for stdin, byte for byte. With `-d` the method defaults to `POST`.
No `Content-Type` is implied, so set one with `-H`. `-d @-` cannot be combined with
`--password-stdin`. For HTTPS targets, `--cacert FILE` sets the CA bundle, `-k`
skips verification of the *target* (unlike `--no-verify`, which is about the gateway), and
`--tls-name NAME` sets the name for SNI and certificate verification when the URL names
an address. It defaults to the `Host` header. A URL with a name from the
[host table](#host-names) needs neither: the name is the one the certificate is checked
against.

## Host names

There is no DNS inside the tunnel, so pyac resolves names from a fixed table you keep in the
profile, like `/etc/hosts` for this one VPN:

```toml
[profiles.orka]
gateway = "vpn.example.com"
user = "rene"

[profiles.orka.hosts]
"node-1.orka" = "10.221.188.11"
"api.orka" = "10.221.188.20"
```

Quote names that contain dots: TOML reads `node-1.orka = ...` as nested tables, and pyac
refuses that with a hint. `--add-host NAME=ADDR` (repeatable) adds entries on the command line
and overrides the profile's for the same name.

With the table in place, names work wherever an address does:

```sh
pyac up --profile orka --socks
curl --socks5-hostname 127.0.0.1:1080 http://api.orka/
ssh -o ProxyCommand="pyac nc --via 1080 %h %p" admin@node-1.orka
pyac http --profile orka https://api.orka/v1/status
```

Use `--socks5-hostname` (curl) or `socks5h://`, so the name reaches pyac. With plain
`--socks5`, the client asks the machine's DNS, which leaks the name and usually fails.
`nc --via` sends the name to the proxy, so the table that counts is the one `pyac up` loaded.

Matching is exact and ignores case and a trailing dot. There are no wildcards and no search
domain. A name missing from the table is refused with a message saying where names come
from. It is never sent to the machine's DNS. `http` and direct-mode `nc` refuse it before
authenticating. The split-route check applies to the address a name maps to.

The table is static. A wrong entry connects to the wrong machine, which TLS verification or
SSH host keys will catch and plain HTTP will not.

## Gateway certificates

The gateway's certificate is verified against the system's CA store. For an internal CA, pin
the certificate with `--pin sha256:<hex>` rather than turning verification off with
`--no-verify`. The format is compatible with openconnect's `--servercert`, and `pyac probe`
shows the certificate.

## Credentials

Credentials never go in `argv`. The password is resolved, in this order:

1. `--password-stdin`
2. `PYAC_PASSWORD`
3. a `keyring` lookup, only when `--profile` was used, keyed on the profile name and the
   resolved username
4. the interactive prompt

To use the keyring step, install the extra and store the password with the standalone
`keyring` CLI it ships:

```sh
pip install pyac[keyring]
keyring set work rene
```

## Profiles

Retyping the same gateway, user, group, and pin for every invocation gets old fast. Save them
once as a named profile and pass `--profile <name>` to `up`, `http`, or `nc` (direct mode)
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

# [profiles.work.hosts]           # see Host names
# "intranet.corp" = "10.221.188.20"
```

Only `gateway` is required; unknown keys are an error. `pyac up --profile work` then behaves
exactly like `pyac up vpn.corp.example -u rene -g employees --pin sha256:deadbeef...`.

**Any flag given on the command line overrides the same setting in the profile** — the
profile only fills in what you didn't pass. This has one asymmetric case worth knowing:
`verify = false` in a profile disables gateway certificate verification, same as passing
`--no-verify` directly; there is currently no flag to force verification back *on* for a
profile that disables it, so pin the certificate instead if you need that (`--pin` always
works regardless of `verify`).

No password ever goes in the TOML file; see [Credentials](#credentials).

## Library

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

`pyac.connect()` takes the same settings as the command line as keyword arguments (`group`,
`verify`, `server_cert_pin`, `mtu`, `buffer`, `reconnect`, …). Leaving the block closes the
tunnel *and* posts the logout; see [DESIGN.md](DESIGN.md#core-principles) for why that
matters.

`hosts={"api.orka": "10.221.188.20"}` is the [host table](#host-names): every method that
takes a host, `httpx_client()`, `serve_socks5()` and `vpn.resolve()` use it, and refuse any
other name.

- `open_connection()` and `open_tls_connection()` return stdlib streams. Flow control
  composes with them; see [DESIGN.md](DESIGN.md#core-principles).
- `httpx_client()` and `httpx_transport()` plug the tunnel into `httpx`; see
  [http-async.md](http-async.md).
- `serve_socks5()` binds loopback unless `allow_non_loopback=True`.
- `pyac.connect_sync()` and `SyncVpnClient` are the blocking HTTP-only equivalent; see
  [http-sync.md](http-sync.md).
