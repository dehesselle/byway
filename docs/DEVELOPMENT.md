# Development

Building and testing pyac. The design is described in [DESIGN.md](DESIGN.md).

pyac uses Python 3.12 and [uv](https://docs.astral.sh/uv/):

```sh
uv sync --dev
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy src
```

## usernet

[`usernet`](https://github.com/dehesselle/usernet) is an ordinary dependency from PyPI. To
try pyac against a local checkout of it, install that into the venv with
`uv pip install -e ../usernet`; the next `uv sync` puts the released version back.

## How it is tested

CSTP is what this repository is responsible for, and the ways a gateway can surprise you are
what it tests:

- **Codecs** (`tests/unit`): CSTP framing and the tunnel headers, auth XML against a corpus
  of real gateway responses (`tests/corpus`), plus property-based tests feeding arbitrary
  bytes into every parser and asserting that only declared parse errors escape.
- **A fake CSTP gateway** (`tests/fakegw`) that serves the auth exchange, speaks framing,
  injects faults, and terminates IP into a test peer — so `pyac up` → SOCKS5 → a real HTTP
  GET runs in CI with no VPN anywhere (`tests/integration`).
- **Reconnection and rekey**, including the case that matters most: a gateway that assigns a
  different address on reconnect, where every open socket has to fail with a reason rather
  than hang.

The stack's own test layers — the frozen-clock state machine, the virtual network, and
conformance against a real Linux kernel over a tun device degraded with `netem` — live in
`usernet` along with the code they cover.
