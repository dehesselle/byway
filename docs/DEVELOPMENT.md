# Development

Building and testing pylis. The design is described in [DESIGN.md](DESIGN.md).

pylis uses Python 3.12 and [uv](https://docs.astral.sh/uv/):

```sh
uv sync --dev
```

The version comes from git tags via hatch-vcs, so clone with full history.

## Checks

CI runs ruff and the REUSE check once on Ubuntu, mypy on Ubuntu and Windows, and pytest on
Ubuntu and Windows with Python 3.12, 3.13 and 3.14. Run these before committing:

```sh
uvx --from 'ruff~=0.16.0' ruff check .
uvx --from 'ruff~=0.16.0' ruff format --check .
uvx reuse lint
uv run mypy src
uv run pytest -q -m "not needs_gateway"
```

- Ruff isn't a project dependency. `required-version` in `pyproject.toml` and the pin in
  `.github/workflows/build.yml` are bumped together, once a new minor release's findings have
  been reviewed.
- CI tests the built wheel rather than the checkout, against the test dependency versions
  pinned in `.github/workflows/build.yml`. Update those pins when `uv.lock` moves them.
- The project is REUSE-compliant. New files start with the SPDX header that `reuse annotate`
  writes; files that can't carry a comment get covered in `REUSE.toml`.

## Releasing

Pushing a tag `vX.Y.Z` runs the full workflow and, if every job passes, attaches the built
sdist and wheel to a draft GitHub release and publishes them to PyPI. The build job checks that
the wheel's `__version__` matches the tag. PyPI accepts the upload through trusted publishing,
which requires a publisher on pypi.org for this repository, the workflow `build.yml` and the
GitHub environment `pypi`. The draft release is published by hand.

## usernet

[`usernet`](https://github.com/dehesselle/usernet) is an ordinary dependency from PyPI. To
try pylis against a local checkout of it, install that into the venv with
`uv pip install -e ../usernet`; the next `uv sync` puts the released version back.

## How it is tested

CSTP is what this repository is responsible for, and the ways a gateway can surprise you are
what it tests:

- **Codecs** (`tests/unit`): CSTP framing and the tunnel headers, auth XML against a corpus
  of real gateway responses (`tests/corpus`), plus property-based tests feeding arbitrary
  bytes into every parser and asserting that only declared parse errors escape.
- **A fake CSTP gateway** (`tests/fakegw`) that serves the auth exchange, speaks framing,
  injects faults, and terminates IP into a test peer — so `pylis up` → SOCKS5 → a real HTTP
  GET runs in CI with no VPN anywhere (`tests/integration`).
- **Reconnection and rekey**, including the case that matters most: a gateway that assigns a
  different address on reconnect, where every open socket has to fail with a reason rather
  than hang.

The stack's own test layers — the frozen-clock state machine, the virtual network, and
conformance against a real Linux kernel over a tun device degraded with `netem` — live in
`usernet` along with the code they cover.
