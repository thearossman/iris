# noisy_subnets

Ranks the noisiest subnets by byte volume, separately for subnets acting as the
connection **source** (originator) and as the connection **destination** (responder).

One callback fires once per TCP/UDP connection at `L4Terminated`, reads the 5-tuple
(`FiveTuple`) and per-direction L4 payload byte counts (`ByteCount`), masks each endpoint
IP to a subnet prefix, and accumulates bytes into two global tables:

- **by source subnet** — keyed by the originator's subnet
- **by destination subnet** — keyed by the responder's subnet

Each subnet row tracks bytes `sent`, bytes `recv`, the number of `conns` it took part in,
and its share of the table's total observed bytes (`% traffic`); rows are ranked by
`sent + recv` descending.

## Usage

```
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error \
  ./target/release/noisy_subnets --config configs/offline.toml
```

| Flag | Default | Meaning |
|---|---|---|
| `--config <FILE>` | `./configs/offline.toml` | Iris config (offline pcap or online NIC) |
| `--top <N>` | `20` | rows of each table to print |
| `--v4-prefix <BITS>` | `24` | IPv4 subnet grouping prefix |
| `--v6-prefix <BITS>` | `64` | IPv6 subnet grouping prefix |
| `--out <FILE>` | — | also write the complete ranking (all subnets, both tables) as JSON |

## Notes

- Byte counts are L4 payload bytes (packet headers excluded), matching the `ByteCount`
  built-in datatype.
- A single connection contributes its bytes once to the source table and once to the
  destination table, so the two rankings are independent views of the same traffic.
- UDP "connections" are Iris's UDP flow abstraction.
