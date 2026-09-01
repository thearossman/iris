#!/usr/bin/env python3

"""Build a high-traffic stress trace for bytes_over_time out of a small real one.

`traces/small_flows.pcap` is 14k packets of real traffic with real TLS handshakes, but it is
nothing like a busy uplink: a few dozen concurrent connections, all short, 9MB over five
minutes. The bucketing in `bytes_over_time` (sparse per-connection histograms, adaptive
coarsening, flush-at-teardown) only gets interesting at the other end of that scale, so this
script replicates a base trace into one that has the properties a real high-traffic capture
does, while keeping every packet a genuine packet the parsers will still identify:

  * `--replicas N`   -- N copies of the base trace, each on its own IP block, so connection
                        concurrency and the connection-table population scale up
  * `--stagger S`    -- start each copy S seconds after the last, so copies overlap partially
                        instead of all sharing one time origin
  * `--stretch F`    -- scale each copy's internal timeline by F, turning short connections
                        into long-lived ones without changing their byte counts (F > 1) or
                        compressing them into bursts (F < 1)
  * `--truncate T`   -- cut the trace at T seconds, leaving connections open at the end the
                        way stopping a live capture does
  * `--skip S`       -- drop the first S seconds, so connections that were already in
                        progress have no SYN in the trace -- what a tap on a live link
                        always looks like, and the case Iris drops outright
  * `--drop-rate P`  -- delete a fraction P of TCP packets, punching sequence holes into
                        flows the way RX-ring drops on a saturated link do. Reassembly then
                        buffers behind each hole, and once `max_out_of_order` segments pile
                        up it abandons the connection -- taking everything the application
                        had accumulated for it. Deterministic given `--seed`.

Every copy carries the same bytes as the base trace, so ground truth is exact and the result
is still checkable with `check_bytes.py`. Only IPv4/IPv6 addresses and capture timestamps are
rewritten; ports, sequence numbers, and payloads are untouched, so TLS/QUIC/SSH handshakes
still parse. IPv4 header checksums are recomputed (Iris does not verify L4 checksums, so
those are left alone).

Run the result with `replay_clock = true` in the `[offline]` config block, or the whole thing
collapses into a single time slice.
"""

import argparse
import random
import struct
from pathlib import Path

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D

ETH_HDR_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
VLAN_HDR_LEN = 4


def read_pcap(path):
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) < 24:
            raise ValueError("truncated pcap file header")
        (magic,) = struct.unpack("<I", header[:4])
        endian = "<"
        if magic not in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            (magic,) = struct.unpack(">I", header[:4])
            endian = ">"
            if magic not in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
                raise ValueError("not a classic pcap file (pcapng is not supported)")
        divisor = 1e9 if magic == PCAP_MAGIC_NS else 1e6
        link_type = struct.unpack(endian + "I", header[20:24])[0]
        snaplen = struct.unpack(endian + "I", header[16:20])[0]

        records = []
        while True:
            record = handle.read(16)
            if len(record) < 16:
                break
            ts_sec, ts_frac, caplen, origlen = struct.unpack(endian + "IIII", record)
            data = handle.read(caplen)
            if len(data) < caplen:
                break
            records.append((ts_sec + ts_frac / divisor, data, origlen))
        return link_type, snaplen, records


def write_pcap(path, link_type, snaplen, records):
    with path.open("wb") as handle:
        handle.write(
            struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, snaplen, link_type)
        )
        for ts, data, origlen in records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            if usec >= 1_000_000:
                sec += 1
                usec -= 1_000_000
            handle.write(struct.pack("<IIII", sec, usec, len(data), origlen))
            handle.write(data)


def ip_offset(frame):
    """Byte offset of the IP header and its ethertype, or (None, None)."""
    if len(frame) < ETH_HDR_LEN:
        return None, None
    (ethertype,) = struct.unpack("!H", frame[12:14])
    offset = ETH_HDR_LEN
    while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
        if len(frame) < offset + VLAN_HDR_LEN:
            return None, None
        (ethertype,) = struct.unpack("!H", frame[offset + 2 : offset + 4])
        offset += VLAN_HDR_LEN
    if ethertype in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
        return offset, ethertype
    return None, None


def ipv4_checksum(header):
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def remap_v4(addr, replica):
    """Move an address into replica `replica`'s own /16, preserving the host part.

    Keeping the low 16 bits means two endpoints that differed in the base trace still differ
    here, so each replica's connection five-tuples stay distinct from every other replica's.
    """
    host = (addr[2] << 8) | addr[3]
    return bytes((10, (replica >> 8) & 0xFF, replica & 0xFF, 0))[:2] + struct.pack(
        "!H", host
    )


def rewrite(frame, replica):
    """Return `frame` with its IP addresses moved into replica `replica`'s address space."""
    if replica == 0:
        return frame
    offset, ethertype = ip_offset(frame)
    if offset is None:
        return frame
    frame = bytearray(frame)

    if ethertype == ETHERTYPE_IPV4:
        if len(frame) < offset + 20:
            return bytes(frame)
        ihl = (frame[offset] & 0x0F) * 4
        if ihl < 20 or len(frame) < offset + ihl:
            return bytes(frame)
        frame[offset + 12 : offset + 16] = remap_v4(frame[offset + 12 : offset + 16], replica)
        frame[offset + 16 : offset + 20] = remap_v4(frame[offset + 16 : offset + 20], replica)
        frame[offset + 10 : offset + 12] = b"\x00\x00"
        checksum = ipv4_checksum(frame[offset : offset + ihl])
        frame[offset + 10 : offset + 12] = struct.pack("!H", checksum)
    else:
        if len(frame) < offset + 40:
            return bytes(frame)
        # IPv6 has no header checksum; rewrite the low 16 bits of each address only, which
        # is enough to separate replicas without disturbing the prefix.
        for base in (offset + 8, offset + 24):
            host = struct.unpack("!H", frame[base + 14 : base + 16])[0]
            frame[base + 12 : base + 14] = struct.pack("!H", replica)
            frame[base + 14 : base + 16] = struct.pack("!H", host)
    return bytes(frame)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Replicate a pcap into a high-traffic stress trace."
    )
    parser.add_argument("base", type=Path, help="base pcap to replicate")
    parser.add_argument("output", type=Path, help="stress trace to write")
    parser.add_argument(
        "--replicas",
        type=int,
        default=64,
        help="number of copies of the base trace (default: 64, max 65536)",
    )
    parser.add_argument(
        "--stagger",
        type=float,
        default=1.0,
        help="seconds between the start of consecutive copies (default: 1.0)",
    )
    parser.add_argument(
        "--stretch",
        type=float,
        default=1.0,
        help=(
            "scale each copy's internal timeline by this factor -- >1 makes connections "
            "long-lived, <1 compresses them into bursts (default: 1.0)"
        ),
    )
    parser.add_argument(
        "--truncate",
        type=float,
        help="drop everything after this many seconds, leaving connections open at the end",
    )
    parser.add_argument(
        "--skip",
        type=float,
        default=0.0,
        help=(
            "drop everything before this many seconds, so connections already in progress "
            "have no SYN -- mimics attaching to a live link (default: 0)"
        ),
    )
    parser.add_argument(
        "--drop-rate",
        type=float,
        default=0.0,
        help=(
            "fraction of TCP packets to delete, punching sequence holes the way RX-ring "
            "drops do (default: 0)"
        ),
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help="PRNG seed for --drop-rate, so a lossy trace is reproducible (default: 1)",
    )
    return parser


def is_tcp(frame):
    offset, ethertype = ip_offset(frame)
    if offset is None:
        return False
    if ethertype == ETHERTYPE_IPV4:
        if len(frame) < offset + 20:
            return False
        return frame[offset + 9] == 6
    if len(frame) < offset + 40:
        return False
    return frame[offset + 6] == 6


def main():
    args = build_parser().parse_args()
    if not 1 <= args.replicas <= 65536:
        raise SystemExit("error: --replicas must be between 1 and 65536")
    if args.stretch <= 0:
        raise SystemExit("error: --stretch must be positive")
    if not 0.0 <= args.drop_rate < 1.0:
        raise SystemExit("error: --drop-rate must be in [0, 1)")

    link_type, snaplen, records = read_pcap(args.base)
    if not records:
        raise SystemExit(f"error: {args.base} has no packets")

    rng = random.Random(args.seed)
    origin = records[0][0]
    out = []
    dropped = 0
    for replica in range(args.replicas):
        shift = replica * args.stagger
        for ts, data, origlen in records:
            when = (ts - origin) * args.stretch + shift
            if args.truncate is not None and when > args.truncate:
                continue
            if when < args.skip:
                continue
            frame = rewrite(data, replica)
            if args.drop_rate and is_tcp(frame) and rng.random() < args.drop_rate:
                dropped += 1
                continue
            out.append((when - args.skip, frame, origlen))

    out.sort(key=lambda item: item[0])
    write_pcap(args.output, link_type, snaplen, out)

    span = out[-1][0] - out[0][0] if out else 0.0
    total = sum(len(data) for _, data, _ in out)
    print(f"Wrote {args.output}")
    print(f"  packets  : {len(out):,}")
    print(f"  bytes    : {total:,}")
    print(f"  span     : {span:,.3f}s")
    if dropped:
        print(f"  TCP packets deleted: {dropped:,}")
    if span > 0:
        print(f"  mean rate: {total * 8 / span / 1e9:.3f} Gb/s")


if __name__ == "__main__":
    main()
