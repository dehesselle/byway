# Throughput measurements

Measured, not estimated. Single connection, receive direction. What to do with these numbers
is in [OPERATIONS.md](OPERATIONS.md#throughput).

| Path | Throughput |
| --- | --- |
| CSTP framing over real TLS, loopback | ~300 MB/s |
| Stack alone, over a Linux tun device, no latency | ~50 MB/s |
| Same stack at 150 ms RTT, 256 KiB buffer | 1.4 MB/s |
| Same stack at 150 ms RTT, 1 MiB buffer | 3.8 MB/s |
| A real ASA at 31 ms, 1.3 GB, SHA-256 verified | 1.1 MB/s |

## Latency, not Python, is the first limit

The two 150 ms rows are the same code on the same machine: one connection cannot exceed
`buffer ÷ RTT` whatever the code does. The default buffer is therefore 1 MiB, and
`--buffer KIB` raises it. Bigger is not automatically better — past about 1 MiB the sender's
bursts start overrunning queues below us and the returns go negative.

## The real-gateway row is a limit of that gateway

At 31 ms even a 256 KiB buffer allowed 8.5 MB/s, the client CPU was idle throughout, and a
second transfer took bandwidth from the first rather than adding to it — a shared ceiling,
which is what a per-user bandwidth policy looks like from inside. 10 Mbit/s of policy works
out to roughly 1.15 MB/s of goodput once tunnel and TLS overhead come off. Measure your own
before assuming either explanation applies; `tools/tcp-retransmits.ps1` tells packet loss
apart from a policer on Windows.
