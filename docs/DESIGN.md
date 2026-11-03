# pyac design

How pyac is built and why. This is the standing design reference: keep it current when the
design changes.

## Architecture

openconnect solves the same problem as pyac by handing decapsulated IP packets to a tun
device and letting the kernel do TCP. pyac refuses that, so it has to terminate IP itself:
the gateway hands us raw IP packets, and an in-process TCP/IP stack turns them back into
streams.

```text
curl, ssh ──SOCKS5──┐
                    ├─▶ usernet: TCP/IP stack, driver ──IpLink──▶ ReconnectingLink ──CSTP/TLS──▶ gateway
your code ──API─────┘   (SOCKS5 server, stream bridge)            (this repository)
```

The TCP/IP stack, the driver, the SOCKS5 server and the transport bridge are not in this
repository. They are [`usernet`](https://github.com/dehesselle/usernet), because none of
that code knows what AnyConnect is and a second client — a Tailscale one — needed exactly the
same half. What is left here is CSTP: authentication, the tunnel handshake, frame transport,
and reconnection.

The seam is `usernet.link.IpLink`: anything that can carry raw IPv4 packets and say what
address it was assigned. `ReconnectingLink` is this project's implementation of it.

## Core principles

1. **No tun device, no routing changes, no administrator rights.** Everything carried over
   the tunnel lives inside the Python process, so VPN access is scoped to that process.
2. **Only the VPN protocol lives here.** Anything not specific to it belongs in `usernet`,
   behind `IpLink`.
3. **Every session ends with a logout.** Leaving `pyac.connect()` closes the tunnel *and*
   posts the logout, whatever went wrong. That is not housekeeping: gateways enforce
   concurrent-session limits, and leaked sessions eventually lock you out of your own VPN
   with nothing to point at.
4. **Credentials never go in `argv` or in the config file.** Passwords come from stdin, the
   environment, the keyring or a prompt ([MANUAL.md](MANUAL.md#credentials)).
5. **One CSTP frame per TLS record.** A Cisco ASA hangs up on anything else; see
   [protocol.md](protocol.md#one-frame-per-tls-record--mandatory). `--coalesce` exists for
   experiments only and must never be the default.
6. **Names come from the tunnel's host table or nowhere.** Falling back to the host's
   resolver would send internal hostnames to whatever DNS the machine uses. A name is
   resolved from a static table (the profile's `hosts`, `--add-host`, or `hosts=` in the
   API) and refused otherwise, everywhere: SOCKS5, `http`, `nc` and the library. The table
   is a `usernet.resolve.StaticResolver` on the driver, so every consumer gets the same
   answer, and routing is checked against the address, not the name.
7. **Streams are real stdlib streams, and backpressure reaches the peer.**
   `StreamReader`'s high-water mark calls `pause_reading()`, which stops us draining the
   stack, which shrinks the advertised window, which stops the far end sending — without a
   queue anywhere in between.
8. **SOCKS5 binds loopback unless told otherwise.** An unauthenticated proxy on a routable
   address is an open door into the corporate network for anything that can reach the
   machine.

## Deliberate omissions

- **No DNS client, a static host table only.** The gateway this was developed against
  advertises no DNS servers at all, so there is nothing to ask, and the machines behind it
  have fixed addresses. The table matches names exactly: no wildcards, no search domain, no
  reverse lookups. Querying a DNS server would also need UDP, which pyac does not carry. On
  a gateway that does advertise DNS servers, a resolver using them could take the table's
  place on the driver.
- **No compression.** pyac does not advertise `X-CSTP-Accept-Encoding`, so LZS, LZ4 and
  deflate never need implementing. A compressed frame arriving anyway is a loud error.
- **TLS only, no DTLS.** Everything rides the TLS connection.
- **IPv4 only, outbound TCP only.**
- **Username and password only.** SAML/SSO, client certificates and MFA challenges are
  detected and reported clearly, but not supported.
- **No posture assessment.** CSD/HostScan is bypassed entirely.

## Reconnection

`ReconnectingLink` rebuilds the tunnel when it ends, unless `reconnect=False`
(`--no-reconnect`). Some gateways assign a fresh address on every connection. Sockets bound
to the old address cannot survive that, so they are failed with an error saying exactly
that, rather than left to hang. The tunnel and the SOCKS listener stay up.

A gateway's `X-CSTP-Rekey-Method: ssl` is treated as `new-tunnel`, because Python's `ssl`
cannot renegotiate ([protocol.md](protocol.md#cisco-asa--secure-client-515)).

## Buffer size

One connection cannot exceed `buffer ÷ RTT`, whatever the code does, so the default
per-socket buffer is 1 MiB, raised with `--buffer KIB`. Bigger is not automatically better:
past about 1 MiB the
sender's bursts start overrunning queues below us and the returns go negative. The
measurements are in [throughput.md](throughput.md).

If a link ever needs more than this can give, `usernet`'s `NetworkBackend` protocol exists
so a native stack could be dropped in. On a high-latency or policed link that would change
nothing, because the limit is not the CPU.
