# Operations

How byway behaves while the tunnel is up, and what to do about it. Commands and options are
in [MANUAL.md](MANUAL.md).

## Idle timeout

An idle tunnel may be destroyed, not merely dropped. `X-CSTP-Idle-Timeout` is commonly
30 minutes, and on the gateway used during development the session is invalidated when it
fires — every reconnect then returns 401 and only a fresh login helps.

`byway up --keepalive <ip-inside-the-vpn>` sends an ICMP echo every 300 seconds
(`--keepalive-interval`), so the timer never fires. DPD and keepalive *frames* do not always
count; payload does.

## Reconnects and address changes

When the tunnel ends, `byway up` rebuilds it (unless `--no-reconnect`). Some gateways assign
a fresh address on every connection, and the one used during development does. Sockets bound
to the old address cannot survive that, so they are failed with an error saying exactly
that. The tunnel and the SOCKS listener stay up; individual connections do not. Traffic
totals in the live panel carry across reconnects.

## Sessions

Every exit posts the logout to the gateway, including Ctrl-C and errors. Gateways limit
concurrent sessions per user, so a process that is killed hard (`kill -9`, a crashed host)
leaves a session behind until the gateway expires it.

## Throughput

**Latency, not Python, is what you will hit first.** One connection cannot exceed
`buffer ÷ RTT`: at 150 ms the default 1 MiB buffer allows about 3.8 MB/s, 256 KiB only
1.4 MB/s. For a distant gateway, raise it with `--buffer KIB` (or `buffer` in a profile),
but bigger is not automatically better: past about 1 MiB returns go negative.

A gateway may also police bandwidth per user. On the gateway used during development a
single transfer reached about 1.1 MB/s with the client CPU idle, and a second transfer took
bandwidth from the first rather than adding to it. Measure your own before assuming either
explanation applies. Figures and method: [throughput.md](throughput.md).

## Diagnostics

| Need | How |
| --- | --- |
| Debug log, per-packet trace | `-v`, `-vv` |
| Capture tunnel traffic for Wireshark | `--pcap FILE` |
| Check whether the gateway sees the tunnel as alive | the live panel's last-received time and keepalive round trip |
| Is the connection carrying the tunnel losing packets? (Windows) | `powershell -ExecutionPolicy Bypass -File tools\tcp-retransmits.ps1` during a transfer |
| What a healthy single request looks like | [protocol.md](protocol.md#first-real-fetch-through-the-stack) |
