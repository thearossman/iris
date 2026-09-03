# noisy_subnets

Per-subnet traffic statistics for a fixed set of monitored networks. Only traffic touching
one of these seven supernets is counted at all:

```
171.64.0.0/14     192.168.0.0/16
172.16.0.0/12     128.12.0.0/16
10.0.0.0/8        204.63.224.0/21
                  68.65.160.0/20
```

An `ipv4.addr` filter prefilters in the runtime, so a connection with neither endpoint in a
monitored supernet is never tracked. One callback then fires once per surviving TCP/UDP
connection at `L4Terminated`, reading the 5-tuple (`FiveTuple`), the L4 payload byte count
(`ByteCount`) and the packet count (`PktCount`).

Each **monitored** endpoint of the connection is masked to a subnet of `--prefix` bits
(default `/24`) and the connection is credited to that subnet. Flow direction is not
tracked: a connection between two monitored subnets counts toward both, and one between a
monitored subnet and an unmonitored address counts only toward the monitored side. A
connection whose endpoints fall in the same subnet is credited once.

## Output

One row per subnet, ranked by total bytes descending:

| Column | Meaning |
|---|---|
| `conns` | connections this subnet was an endpoint of |
| `packets` | total packets across those connections |
| `bytes` | total L4 payload bytes across those connections |
| `mean`, `p10`, `p25`, `median`, `p75`, `p90`, `p99` | distribution of **bytes per connection** |

The top `--top` rows go to stdout; `--out <FILE>` writes every subnet as JSON with the raw
(non-human-formatted) numbers.

## Usage

```
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error \
  ./target/release/noisy_subnets --config configs/offline.toml
```

| Flag | Default | Meaning |
|---|---|---|
| `--config <FILE>` | `./configs/offline.toml` | Iris config (offline pcap or online NIC) |
| `--top <N>` | `20` | rows to print |
| `--prefix <BITS>` | `24` | prefix length addresses are grouped into subnets by |
| `--out <FILE>` | — | also write the complete table (every subnet) as JSON |

## Notes

- Byte counts are L4 payload bytes (packet headers excluded), matching the `ByteCount`
  built-in datatype.
- `--prefix` is clamped per address to be no coarser than the supernet containing it, so a
  reported subnet never spans addresses outside the monitored ranges. With `--prefix 8`,
  `171.64.1.2` is reported under `171.64.0.0/14`, not `171.0.0.0/8`.
- Percentiles are linearly interpolated over the connections credited to a subnet (`p50` is
  the true median). This keeps one `u64` per credited connection in memory until the run
  ends, so peak memory grows with connection count.
- The monitored ranges are IPv4-only, so IPv6 traffic is never counted.
- UDP "connections" are Iris's UDP flow abstraction.
