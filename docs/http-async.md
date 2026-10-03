# Calling REST APIs from async code

The default answer for a Python project that already runs an event loop:
`vpn.httpx_client()` gives you an `httpx.AsyncClient` wired straight into the
tunnel. No proxy port, no SOCKS handshake, no extra dependency — `httpx` is
already what `pyac.connect()` uses internally.

```python
import pyac


async def fetch_things(gateway: str, user: str, password: str) -> dict:
    async with pyac.connect(gateway, user, password) as vpn:
        async with vpn.httpx_client() as http:
            response = await http.get(f"http://10.221.188.20/v1/things", timeout=10)
            response.raise_for_status()
            return response.json()
```

`httpx.AsyncClient`'s API mirrors `requests` closely — `.get()`, `.post()`,
headers, `response.json()`, `response.raise_for_status()` — so if you already
know `requests`, there is nothing new to learn here beyond `await`.

## Why this instead of a proxy

- One process, one hop: requests go client → driver → tunnel directly, with
  no local server or port in between to bind, leak, or clean up.
- No extra runtime dependency, and no background thread. `httpx` is already
  required by `pyac`; the sync path (see [http-sync.md](http-sync.md)) needs
  a dedicated thread to bridge blocking calls onto an event loop.
- Flow control composes for free — the same backpressure guarantee the rest
  of the API gives (see [DESIGN.md](DESIGN.md#core-principles)).

Use `vpn.httpx_transport()` instead if you need to plug the tunnel into your
own `httpx.Client`/`AsyncClient` construction (custom headers, auth, base
URL, etc.) rather than taking the one `httpx_client()` hands back.

## The one caveat

pyac has no in-tunnel DNS, so **hosts are IP addresses or names from the
`hosts` table** passed to `pyac.connect()`. Nothing is ever asked of the
machine's own DNS:

```python
async with pyac.connect(gateway, user, password, hosts={"api.internal": "10.221.188.20"}) as vpn:
    async with vpn.httpx_client() as http:
        response = await http.get("https://api.internal/v1/things")
```

With the name in the URL, TLS checks the certificate against it, as usual.
Any name not in the table raises `ResolveError`. See
[MANUAL.md](MANUAL.md#host-names).

## If your code isn't async

`httpx_client()` requires an event loop. For plain synchronous Python code,
use `pyac.connect_sync()` instead — see [http-sync.md](http-sync.md). For a
non-Python process, use the local SOCKS5 proxy (`vpn.serve_socks5()`,
documented in the same file).
