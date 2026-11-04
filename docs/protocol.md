# CSTP protocol notes

Facts verified against openconnect's source and against a real Cisco ASA
(Secure Client 5.1.5, `X-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.`).
Anything learned the hard way belongs here so it is not re-learned.

## Frame format

Eight-byte header, then the payload:

```
0       1       2       3       4       5       6       7
+-------+-------+-------+-------+-------+-------+-------+-------+
|  'S'  |  'T'  |  'F'  | 0x01  |  length (be16)|  type | pad   |
+-------+-------+-------+-------+-------+-------+-------+-------+
```

`length` counts the payload only. Types: `DATA=0`, `DPD_OUT=3`, `DPD_RESP=4`,
`DISCONN=5`, `KEEPALIVE=7`, `COMPRESSED=8`, `TERM_SERVER=9`.

## One frame per TLS record — mandatory

**Never write two CSTP frames in a single TLS record.** A real ASA closes the
connection immediately and without warning when it receives one.

This was expensive to find, because the symptom looks like anything but the
cause: the tunnel establishes cleanly, survives for 20–60 seconds, and then
the gateway simply hangs up. It only happens when two timers coincide, so the
time-to-failure varies with the DPD and keepalive periods and looks random.

Evidence, from three runs against the same gateway:

| Run | Behaviour at the first coinciding tick | Outcome |
|---|---|---|
| Coalesced | `DPD_OUT`+`KEEPALIVE` in one record at t=60 | no `DPD_RESP`, closed at t=60 |
| Coalesced, with pings | `DATA`+`KEEPALIVE` in one record at t=20 | closed at t=20 |
| One frame per record | same frames, separate records | `DPD_RESP` received, ran past 2 min |

The gateway answered DPD normally in the third case at exactly the ticks where
the coalesced runs died, so the frames themselves are well-formed. openconnect
issues one `SSL_write` per packet, so no real client has ever sent batched
frames and gateway readers evidently assume one frame per record.

Consequence: coalescing outbound packets into one TLS write — an obvious
throughput optimisation, and one this project originally planned on — is off
the table. `byway up --coalesce` still enables it for experimenting against
other gateways (ocserv may well tolerate it), but it must never be the default.

## Deliberate omissions in the CONNECT request

* No `X-CSTP-Accept-Encoding`, so the gateway will not compress and LZS, LZ4,
  and deflate never need implementing. A `COMPRESSED` frame arriving anyway
  means the assumption is wrong for that device, so it is a loud error.
* No `X-DTLS-*`. Everything rides the TLS connection.

## Gateway observations

### Cisco ASA / Secure Client 5.1.5

* Answers client `DPD_OUT` with `DPD_RESP`, but **never initiates DPD or
  keepalive of its own**. A client that only responds and never probes will
  never learn that the tunnel has died.
* Sends `X-CSTP-Post-Auth-XML`: several kilobytes of MSI package and profile
  provisioning in a single header. Nothing in it applies to a userspace
  client. Capture it, never print it.
* May advertise **no `X-CSTP-DNS` at all**, together with
  `X-CSTP-Tunnel-All-DNS: false`. In-tunnel DNS resolution is then simply not
  on offer, and names must be resolved by the host.
* `X-CSTP-Rekey-Method: ssl` requests in-place TLS renegotiation. Python's
  `ssl` cannot initiate renegotiation and TLS 1.3 removes it entirely, so this
  is unavailable to us; treat it as `new-tunnel` and redo `CONNECT` with the
  same `webvpn` cookie.
* Assigns a fresh address on each connection (`172.29.29.3`, `.4`, `.5`, …),
  so sessions leak if `/+webvpn+/webvpn_logout.html` is not called on exit.

## First real fetch through the stack

`byway http 207.254.103.218 http://10.221.188.20/` — nginx 1.29.1, 908 bytes of
HTML, 78 ms total with a 47 ms connect. Tunnel `172.29.29.3/255.255.0.0`,
MTU 1383 (so MSS 1343), split route `10.221.188.0/23`.

Five inbound frames, and nothing else:

| # | Bytes | Segment |
|---|---|---|
| 1 | 48 | SYN-ACK, 8 bytes of TCP options |
| 2 | 40 | bare ACK of the request |
| 3 | 1181 | the entire response, one segment (1141 payload) |
| 4 | 40 | server FIN |
| 5 | 40 | ACK of our FIN |

No retransmission, no duplicate ACK, a clean four-way close, and connect
completing in exactly one round trip. Worth keeping as the reference for what
a healthy exchange looks like: a run that produces materially more frames than
this for a single small request has something wrong with it.

The 8 option bytes are MSS plus either window-scale or SACK-permitted — both
are 8 bytes once padded, and the summary output cannot tell them apart. Check a
pcap before concluding which.

### Routine headers carrying nothing actionable

`X-CSTP-Version`, `-Protocol`, `-Lease-Duration`,
`-Session-Timeout-Alert-Interval`, `-MSIE-Proxy-Lockdown`,
`-Smartcard-Removal-Disconnect`, `-Routing-Filtering-Ignore`, `-Quarantine`,
`-Disable-Always-On-VPN`, `-TCP-Keepalive`, `-License`, `-DynDNS`,
`-Client-Bypass-Protocol`.

Recognised explicitly so that an unknown header means genuinely new behaviour
rather than noise.
