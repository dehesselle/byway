# pyac

A userspace Cisco AnyConnect (CSTP) VPN client. No tun device, no virtual adapter, no
routing changes, no administrator rights — the tunnel and everything carried over it lives
inside the Python process. Access is through a local SOCKS5 proxy — so `ssh` and `curl` work
unchanged — and an in-process API.

Use it when you need to reach a REST API or SSH into a host inside a corporate VPN, but
cannot, or would rather not, install a VPN client, change routing, or use admin rights. VPN
access is scoped to one process rather than to the whole machine.

Nothing is published to a package index yet; see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
for working from a checkout.

## Using it

```console
$ pyac probe vpn.corp.example          # what does this gateway ask for?
$ pyac up vpn.corp.example -u rene --socks
address   172.29.29.3/255.255.0.0
mtu       1383
routes    10.221.188.0/23
socks5    127.0.0.1:1080
```

```sh
curl --socks5 127.0.0.1:1080 http://10.221.188.20/
ssh -o ProxyCommand="pyac nc --via 127.0.0.1:1080 %h %p" rene@10.221.188.32
```

`pyac up` prompts for the password. Saved profiles, other ways to pass the password, and
certificate pinning are in the [manual](docs/MANUAL.md).

From your own program:

```python
import pyac

async with pyac.connect("vpn.corp.example", user, password) as vpn:
    reader, writer = await vpn.open_connection("10.221.188.32", 22)

    async with vpn.httpx_client() as http:
        response = await http.get("http://10.221.188.20/v1/things")
```

**Hosts are IP addresses, or names from a fixed table** in the profile: there is no
in-tunnel DNS. IPv4, TLS, outbound TCP and username/password authentication only.

**Check your policy first.** Many organisations require a sanctioned VPN client, and pyac
bypasses posture assessment (CSD/HostScan) entirely. Check that you are allowed to use it
before you point it at a corporate gateway.

## Documentation

- [docs/MANUAL.md](docs/MANUAL.md): all commands, profiles, credentials, certificate pinning
  and the library API
- [docs/http-async.md](docs/http-async.md): calling REST APIs from async code
- [docs/http-sync.md](docs/http-sync.md): calling REST APIs from sync code
- [docs/OPERATIONS.md](docs/OPERATIONS.md): runtime behavior: idle timeouts, reconnects,
  sessions, throughput, diagnostics
- [docs/DESIGN.md](docs/DESIGN.md): architecture, core principles and deliberate omissions
- [docs/protocol.md](docs/protocol.md): CSTP protocol notes and gateway observations
- [docs/throughput.md](docs/throughput.md): throughput measurements
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md): building and testing
