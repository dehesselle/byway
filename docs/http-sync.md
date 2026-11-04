# Calling REST APIs from sync code

`byway.connect_sync()` is a blocking equivalent of `byway.connect()`, scoped to
HTTP: no `async`, no `await`, no event loop for the calling code to manage.

```python
import byway


def fetch_things(gateway: str, user: str, password: str) -> dict:
    with byway.connect_sync(gateway, user, password) as vpn:
        response = vpn.get(f"http://10.0.0.20/v1/things", timeout=10)
        response.raise_for_status()
        return response.json()
```

`SyncVpnClient` mirrors `requests`' method names — `.get()`, `.post()`,
`.put()`, `.patch()`, `.delete()`, `.head()`, and the general `.request()` —
and every call returns a normal `httpx.Response` (`.status_code`, `.json()`,
`.text`, `.raise_for_status()`, same as `requests`).

## How this works, briefly

byway's core is `asyncio` throughout, so `connect_sync()` runs the real
`byway.connect()` on a dedicated background thread with its own event loop,
and blocks the calling thread for each call until it completes. You don't
need to know this to use it — it behaves like an ordinary blocking client —
but it's why the first call has to actually authenticate and bring up the
tunnel before returning, same as the async path.

Leaving the `with` block tears the tunnel down and posts the logout, even if
the block raises — the same guarantee `byway.connect()` makes, for the same
reason: a leaked session eventually locks you out of your own VPN.

## When the VPN outlives one block

`connect_sync()` scopes the tunnel to a single `with` block. If instead your
code calls VPN-internal APIs from many different places — request handlers,
background jobs, whatever — connect once and hold onto the client instead:

```python
import byway

vpn = byway.SyncVpnClient.connect(gateway, user, password)
...
response = vpn.get("http://10.0.0.20/v1/things")  # from wherever
...
vpn.close()  # once, when the program is done with the VPN
```

Whatever holds `vpn` owns calling `close()` exactly once — nothing does it
for you, including garbage collection. Skipping it leaves the same leaked
session `connect_sync()` guards against, just without a `with` block to make
the lifetime obvious. `close()` is safe to call more than once, and calling
`get()`/`post()`/etc. after `close()` raises a clear `BywayError` rather than
hanging or failing confusingly.

## The one caveat

Same as the async path: hosts are IP addresses, or names from the `hosts`
table passed to `connect_sync()` / `SyncVpnClient.connect()`. Any other name
is refused rather than resolved by the machine's DNS. See
[MANUAL.md](MANUAL.md#host-names).

## Non-Python processes

`connect_sync()` is for synchronous *Python* code. To reach the tunnel from
`curl`, a browser, or another language, use the CLI's SOCKS5 proxy instead —
no Python or asyncio involved on the calling side at all:

```console
$ byway up vpn.corp.example -u user --socks
$ curl --socks5 127.0.0.1:1080 http://10.0.0.20/v1/things
```

This is `vpn.serve_socks5()` under the hood (see [MANUAL.md](MANUAL.md#library)); it stays
async-only as a library call, since every existing caller of it either is
already async or reaches it through the CLI.

## If your code is already async

Skip the thread bridge entirely and call `vpn.httpx_client()` directly — see
[http-async.md](http-async.md).
