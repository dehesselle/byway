# CLAUDE.md

pyac is a userspace Cisco AnyConnect (CSTP) client: the tunnel terminates in an in-process
TCP/IP stack (from `usernet`), exposed through SOCKS5 and a Python API.

- Read [docs/DESIGN.md](docs/DESIGN.md) before architectural changes and respect its core
  principles.
- CLI options, profiles and the library API: [docs/MANUAL.md](docs/MANUAL.md).
- Runtime behavior (idle timeout, reconnects, throughput): [docs/OPERATIONS.md](docs/OPERATIONS.md).
- Gateway quirks and CSTP facts: [docs/protocol.md](docs/protocol.md). Add anything learned
  the hard way there.
- Anything that does not know about AnyConnect belongs in `../usernet`, not here.

@docs/DEVELOPMENT.md

## Documentation rules

- Keep the README short: what pyac is and a working usage example. Everything else goes
  into `docs/`.
- A change that affects design, usage or behavior updates the matching document in the same
  change.
- DESIGN.md is kept current and carries no project history.
