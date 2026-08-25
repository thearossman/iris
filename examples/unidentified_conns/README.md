# Unidentified Connections

An Iris application that writes a **raw packet capture of a sample of connections** — specifically,
the connections whose application-layer protocol Iris's stateful parsers could *not* identify.

All seven of Iris's session parsers (TLS, DNS, HTTP, QUIC, SSH, WireGuard, IKE) are registered and
run against every TCP/UDP connection. Connections that any parser identifies are dropped; whatever
is left — protocol discovery failed outright, or never concluded — has its raw packets written out.

The app's own reporting stops at *identified* connections: the run summary breaks those down by
protocol (TLS, DNS, HTTP, ...), a free byproduct of the identified/unidentified check it already
runs in `finalize`. Everything about the *unidentified* connections — which is the traffic this
app exists to surface — comes from the companion [`identify_protocols.sh`](./identify_protocols.sh)
script, which post-processes the written captures with `tshark`. Its independent dissectors take a
second pass at the leftover traffic and print the most common protocols found there — again by
parsing, not by assuming that a port number implies a protocol.

## Running at line rate

Recording every packet of every connection will not survive a real link, so the app is built
around two decisions:

**Sampling happens once, in `StreamingCallback::new`.** Each connection's fate is decided on its
first packet from the five-tuple alone. Connections that lose the draw return `false` from their
first `InL4Conn` call, which unsubscribes them entirely — no frames are ever buffered, and Iris
stops tracking *and* parsing them. Only the sampled minority costs anything.

The draw is a hash (the SplitMix64 finalizer) rather than a counter, so no shared state sits on
the new-connection path across cores, and the same connection is sampled consistently across
runs. Measured against a synthetic client/server/port mix, `--sample-rate 100` keeps 1.02% of
connections and shows no lockstep on sequential ephemeral ports.

**Output is sharded per core.** Each core writes its own `<prefix>_core<N>.pcap` through its own
1 MiB `BufWriter`, so cores never contend on a writer or interleave frames into one file. Iris
pins a connection to a single core for its lifetime, so no connection is split across files, and
the writer is touched once per *written connection* rather than once per packet.

**Unanswered SYNs are excluded.** A TCP connection whose responder never sends a single packet
is a scan, backscatter, or a failed connect. It has no payload to identify by definition, so
recording it says nothing about parser coverage while burying the genuinely unknown traffic —
on a real link this class can be three quarters of everything unidentified. These are dropped at
teardown, which is the earliest point at which "no response ever arrived" is knowable.

The rule is deliberately narrow: it drops connections with *no responder packet at all*, not all
zero-payload connections. A refused connect (SYN → RST) and a connection that completes its
handshake but exchanges no data were both answered, so both are kept and still appear as
`tcp-no-payload`. Verified on `small_flows.pcap`: of 29 unanswered TCP streams, none carried any
payload, and excluding them left the count of every other protocol bucket exactly unchanged.

**A frame cap bounds each connection.** Sampled connections buffer frames until teardown, so a
single long-lived connection could otherwise grow without limit. `--max-frames` (default 128)
caps what is kept; a connection that hits it stays subscribed and simply stops buffering, since
unsubscribing would skip `finalize` and drop the connection from the capture entirely — and
whether it is even wanted is not known until teardown.

The frames kept are the *first* ones, which is what downstream dissection needs: protocols are
identified from the start of a connection. Measured on `small_flows.pcap`, capping at 128 frames
drops 13% of frames and produces a byte-identical protocol ranking; even an aggressive cap of 8
frames drops 74% of frames and moves just one connection out of 632.

## IP anonymization

Pass `--anon-key` to rewrite every frame's source and destination IP with
[Crypto-PAn](https://en.wikipedia.org/wiki/Crypto-PAn) (Xu, Fan, Ammar & Moore, 2002) before it's
written, so a capture meant to leave a trusted network doesn't carry real addresses:

```
openssl rand -out anon.key 32
./target/release/unidentified_conns --config configs/offline.toml --anon-key anon.key
```

Anonymization is **prefix-preserving** — two hosts sharing a real `/24` still share an anonymized
one, so subnet-level structure survives even though individual addresses don't. It runs once per
*written* connection, in `finalize`, right before the frames hit disk, so identified and unsampled
connections never pay for it. It applies to IPv4 and IPv6; MAC addresses and everything above the
IP layer (ports, payload) are untouched.

`--anon-bits-v4`/`--anon-bits-v6` (default: full address, 32/128) restrict anonymization to the
trailing N bits, leaving the leading bits — and therefore coarse subnet/geo/ASN information — in
plaintext. `--anon-bits-v4 8` anonymizes only the last octet of every IPv4 address, for example.

The same key always produces the same mapping, so running the app twice against the same traffic
with the same keyfile yields comparable output — useful for correlating captures taken on
different days. Anyone with the keyfile can reverse the mapping for a *known* address (Crypto-PAn
is prefix-preserving, not one-way), so treat it like any other secret and don't ship it alongside
the capture.

Only the IPv4 header checksum is recomputed after rewriting. TCP/UDP checksums, which also cover
the addresses via the pseudo-header, are left stale — this matches most captures already, since
checksum offload means on-the-wire transport checksums are frequently invalid before anonymization
even runs, and `tshark` does not validate them by default. IPv6 has no header checksum to fix.

## Skipping capture entirely

Pass `--no-pcap` to run the app for its connection-level counts alone — identified/unanswered/
per-protocol — without buffering a single packet or writing a `.pcap` file:

```
./target/release/unidentified_conns --config configs/offline.toml --no-pcap
```

The `finalize` classification (identified vs. unidentified, unanswered SYN, per-protocol) is
unchanged, since it comes from `SessionProto` and the five-tuple/`dir` bit, not from the buffered
frames. `update` never makes the copy that normally fills `self.frames`, and no per-core `.pcap`
files are created at all. `--min-bytes` still works as a size-threshold statistic, since the byte
count is tracked from packet lengths regardless. `--outfile-prefix`, `--max-frames`, and
`--anon-key`/`--anon-bits-*` are accepted but have nothing to act on.

## Usage

Build from the repo root:

```
cargo build --release
```

Run against a packet capture in offline mode. Edit [`configs/offline.toml`](../../configs/offline.toml)
to point at a different `.pcap` (the samples in [`traces/`](../../traces/) are a good start). When
analyzing a capture file offline, `--sample-rate 1` records everything:

```
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/unidentified_conns --config configs/offline.toml --sample-rate 1
```

This writes one `unidentified_core<N>.pcap` per core and reports what it kept:

```
Sampled 1 in 1 connections. Of those, identified 349 (55.2%) by parsing and wrote 283 (44.8%) unidentified ones to unidentified_core*.pcap
Skipped 29 (4.4%) unanswered SYNs (TCP connections the responder never answered).

Identified connections by protocol (these were dropped, not written):
  TLS        210 (33.2%)
  DNS        84 (13.3%)
  HTTP       31 (4.9%)
  QUIC       17 (2.7%)
  SSH        7 (1.1%)
IP addresses in the capture were anonymized with Crypto-PAn.
```

Both counts cover sampled connections only — unsampled ones unsubscribe on their first packet and
are never classified at all, which is precisely the work being skipped.

Every percentage answers "what share of the connections that were actually candidates for
identification?" — not "what share of everything sampled?" On a real capture, unanswered SYNs
(scans, backscatter) and connections below `--min-bytes` can dwarf everything else, and folding
them into the denominator would make "identified" and each protocol's share look artificially
tiny. So "identified", "wrote"/unidentified, and the per-protocol breakdown are all measured
against `real_sampled = identified + written` — the connections that cleared both the unanswered-
SYN and `--min-bytes` filters — and always sum to exactly 100% of it: "identified" and "wrote" are
its only two components, and the protocol rows sum back to exactly the "identified" percentage.

The two "Skipped" lines are the exception, by necessity: they're reporting how much of *everything
sampled* got excluded, so they're measured against the full sampled population (identified +
written + unanswered + below-threshold) instead — the one denominator that includes them. A later
"truncated" line, when present, uses a third denominator, *written connections*, since truncation
is only ever recorded for a connection that made it to disk.

The protocol breakdown is a byproduct of the identified/unidentified check `finalize` already
runs, not a separate pass — it counts every connection that *was* identified, so it's the mirror
image of what `identify_protocols.sh` reports on the ones that weren't. Only protocols actually
seen are listed; an `other` bucket exists for any `SessionProto` value outside the seven parsers
this app registers, as a safety net, and should always read zero in practice.

Then post-process the whole set — with no arguments the script picks up every
`unidentified_core*.pcap` in the current directory:

```
./examples/unidentified_conns/identify_protocols.sh
```

```
Most common protocols across 2 capture file(s) (283 connections, identified by parsing)

  data-unparsed             113    39.93%
  tcp-no-payload            110    38.87%
  ssdp                        6     2.12%
  dhcp                        3     1.06%
  ...
```

Three labels come from the script rather than from a protocol name:

| Label | Meaning |
|-------|---------|
| `<transport>-no-payload` | The connection carried no payload (e.g. a refused connect, or a handshake with no data). Unanswered SYNs are excluded upstream and never appear |
| `data-unparsed` | Payload was present but opaque to every dissector `tshark` tried |
| anything else | The protocol `tshark` dissected directly above the transport layer |

## Options

### Application

| Option | Default | Description |
|--------|---------|-------------|
| `--config` | `./configs/offline.toml` | Iris runtime config (selects the input capture in offline mode) |
| `--outfile-prefix` | `unidentified` | Per-core captures are written as `<prefix>_core<N>.pcap` |
| `--sample-rate` | `100` | Record one in every N connections; `1` records all of them |
| `--max-frames` | `128` | Keep at most N frames per sampled connection; `0` for no limit |
| `--min-bytes` | `0` | Only write a connection if its captured frames total at least N bytes; `0` for no threshold |
| `--anon-key` | (none) | Path to a 32-byte key file; if given, IPs are anonymized with Crypto-PAn |
| `--anon-bits-v4` | `32` | Trailing IPv4 bits to anonymize (only meaningful with `--anon-key`) |
| `--anon-bits-v6` | `128` | Trailing IPv6 bits to anonymize (only meaningful with `--anon-key`) |
| `--no-pcap` | off | Skip capturing entirely: no frames buffered, no `.pcap` files written, counts only |

### Script

| Option | Description |
|--------|-------------|
| `-n N` | Only show the top N protocols |
| `-H` | Also print `tshark`'s full per-frame protocol hierarchy |

Positional arguments are capture files; the default is `unidentified_core*.pcap` in the current
directory. The script requires `tshark` (`sudo apt install tshark`).

## Notes

- **Memory is bounded by `--sample-rate` × `--max-frames`**, not by connection lifetime. Raising
  either raises the ceiling; `--max-frames 0` removes the per-connection half of it.
- **Truncated connections are marked in the run summary** but not in the capture itself, so a
  truncated connection is indistinguishable from a short one when reading the pcap alone.
- **Timestamps in the output captures are zeroed.** Iris does not surface original capture
  timestamps to subscribers, so written frames all carry a zero timestamp. Protocol dissection
  does not depend on them, but anything timing-related in the output is meaningless.
- **`tshark` still consults well-known ports** for some dissectors before falling back to its
  heuristic content-sniffing ones, so a few of its labels can be port-derived. Iris's own
  identification, which decides what lands in these captures, is parser-based throughout.
- The `parsers=` key on the callback filter is what registers all seven Iris parsers. Iris only
  compiles in the parsers some filter or datatype actually needs, so without it no parsing would
  happen and *every* connection would look unidentified.
- **Without `--anon-key`, captures carry real IP addresses.** The run summary states which mode
  was used on every run, so it's visible rather than silent.
- **`--no-pcap` changes what the run summary reports, not just whether files are written.** The
  "wrote N unidentified ones to ..." and anonymization-status lines are replaced with a note that
  capture was skipped, and the final `identify_protocols.sh` suggestion is omitted, since there
  is nothing for it to read.
