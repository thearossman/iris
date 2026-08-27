# noisy_subnets

Ranks the noisiest subnets by byte volume, counting a subnet's traffic whether it was the
**source** or the **destination** of a flow.

One callback fires once per TCP/UDP connection at `L4Terminated`, reads the 5-tuple
(`FiveTuple`) and the L4 payload byte count (`ByteCount`), masks each endpoint IP to a
subnet prefix, and adds the connection's total bytes to *each* endpoint subnet's running
total. Flow direction is not tracked.

Each subnet row tracks total `bytes`, the number of `conns` it was an endpoint of, and
`% traffic` — its bytes over the sum of all connections' bytes. Because a flow's bytes
count toward both of its endpoints, `% traffic` does not sum to 100%. Rows are ranked by
`bytes` descending.

After the table, it prints the 5 noisiest individual **public** addresses (routable on the
open internet — private, loopback, link-local, multicast, etc. excluded), then the 5
noisiest **TCP ports** and 5 noisiest **UDP ports**, each with the share of total traffic
it carries. As with the subnet rows, a flow's bytes count toward both of its endpoints
(both addresses, and both the source and destination port).

Finally it prints the share of all connection bytes that belonged to a flow with at least
one endpoint in private IP space (RFC 1918 `10/8`, `172.16/12`, `192.168/16` for IPv4;
`fc00::/7` unique-local for IPv6).

## Usage

```
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error \
  ./target/release/noisy_subnets --config configs/offline.toml
```

| Flag | Default | Meaning |
|---|---|---|
| `--config <FILE>` | `./configs/offline.toml` | Iris config (offline pcap or online NIC) |
| `--top <N>` | `20` | rows to print |
| `--v4-prefix <BITS>` | `24` | IPv4 subnet grouping prefix |
| `--v6-prefix <BITS>` | `64` | IPv6 subnet grouping prefix |
| `--out <FILE>` | — | also write the complete ranking (every subnet) as JSON |

## Notes

- Byte counts are L4 payload bytes (packet headers excluded), matching the `ByteCount`
  built-in datatype.
- A connection whose two endpoints fall in the same subnet is credited to that subnet once.
- UDP "connections" are Iris's UDP flow abstraction.
