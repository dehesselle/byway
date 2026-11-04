# pylis

> __Pylis__ · _Greek noun_
>
> “Little gate”, a diminutive of _pyle_, “gate”.

pylis is a userspace client that speaks the Cisco AnyConnect VPN protocol. No tun device, no
virtual adapter, no routing changes, no administrator rights: the tunnel and everything carried
over it live inside the Python process. Access is through a local SOCKS5 proxy, so `ssh` and
`curl` work unchanged, and an in-process API.

Use it when you need to reach a REST API or SSH into a host inside a corporate VPN, but
cannot, or would rather not, install a VPN client, change routing, or use admin rights. VPN
access is scoped to one process rather than to the whole machine.

## Install and run

```console
$ uv tool install pylis
$ pylis probe vpn.corp.example          # what does this gateway ask for?
$ pylis up vpn.corp.example -u rene --socks
address   172.29.29.3/255.255.0.0
mtu       1383
routes    10.221.188.0/23
socks5    127.0.0.1:1080
```

`pylis up` prompts for the password and holds the tunnel open. From another terminal:

```sh
curl --socks5 127.0.0.1:1080 http://10.221.188.20/
ssh -o ProxyCommand="pylis nc --via 127.0.0.1:1080 %h %p" rene@10.221.188.32
```

Saved profiles, other ways to pass the password, and certificate pinning are in the
[manual](https://github.com/dehesselle/pylis/blob/master/docs/MANUAL.md).

## Use it from your own program

```sh
uv add pylis
```

```python
import pylis

async with pylis.connect("vpn.corp.example", user, password) as vpn:
    reader, writer = await vpn.open_connection("10.221.188.32", 22)

    async with vpn.httpx_client() as http:
        response = await http.get("http://10.221.188.20/v1/things")
```

## Caveats

- Hosts are IP addresses, or names from a fixed table in the profile: there is no in-tunnel
  DNS.
- pylis supports IPv4, TLS, outbound TCP and username/password authentication only.
- Many organisations require a sanctioned VPN client, and pylis bypasses posture assessment
  (CSD/HostScan) entirely. Check that you are allowed to use it before you point it at a
  corporate gateway.

## Documentation

- [docs/MANUAL.md](https://github.com/dehesselle/pylis/blob/master/docs/MANUAL.md) — all commands, profiles, credentials, certificate pinning and the library API.
- [docs/http-async.md](https://github.com/dehesselle/pylis/blob/master/docs/http-async.md) — calling REST APIs from async code.
- [docs/http-sync.md](https://github.com/dehesselle/pylis/blob/master/docs/http-sync.md) — calling REST APIs from sync code.
- [docs/OPERATIONS.md](https://github.com/dehesselle/pylis/blob/master/docs/OPERATIONS.md) — runtime behavior: idle timeouts, reconnects, sessions, throughput, diagnostics.
- [docs/DESIGN.md](https://github.com/dehesselle/pylis/blob/master/docs/DESIGN.md) — architecture, core principles and deliberate omissions.
- [docs/protocol.md](https://github.com/dehesselle/pylis/blob/master/docs/protocol.md) — protocol notes and gateway observations.
- [docs/throughput.md](https://github.com/dehesselle/pylis/blob/master/docs/throughput.md) — throughput measurements.
- [docs/DEVELOPMENT.md](https://github.com/dehesselle/pylis/blob/master/docs/DEVELOPMENT.md) — building and testing.

## AI disclosure

Substantial parts of this code were generated with Sonnet 5.x/Opus 5.x. Generated code was tested, but not every line was reviewed in detail.

## License

[0BSD](https://github.com/dehesselle/pylis/blob/master/LICENSES/0BSD.txt)
