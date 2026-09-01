#!/usr/bin/env python3

"""Differential check of bytes_over_time's CSV against ground truth read from the pcap.

Only meaningful for a run made with `replay_clock = true` in the `[offline]` config block
(see `OfflineConfig::replay_clock`). Without it every packet in a trace is stamped with the
same processing-time instant, so the app produces one slice and there is nothing per-window
to check.

Ground truth here is deliberately dumb: walk the pcap, decode just enough of each frame to
tell TCP from UDP, and bucket its full on-wire length (the same `mbuf.data_len()` unit the
app counts -- see bytes_over_time's "Byte unit" module docs) into the slice its capture
timestamp falls in, relative to the first frame. That is what the app's `tcp_bytes`/
`udp_bytes` columns would report if the connection tracker delivered every frame.

The app's numbers are legitimately a subset of that: Iris only creates a TCP connection on a
bare SYN, so a flow already in progress at the start of the trace is dropped outright, and
frames the runtime never got to the tracker (oversized vs. `mtu`, unparseable L3/L4) are
missing too. So this reports the gap rather than asserting equality, and separately checks
the invariants that must hold regardless of which connections were tracked:

  * conservation -- per-slice columns sum to the run's reported total
  * containment  -- no slice reports more transport bytes than the wire actually carried
  * placement    -- reported bytes appear in the slices the traffic was actually in

`--mid-stream-ok` recomputes the wire-side truth over only those TCP flows whose SYN is
present in the trace, which is the like-for-like comparison when a trace was cut from the
middle of live traffic.
"""

import argparse
import csv
import struct
import sys
from pathlib import Path

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D

ETH_HDR_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
VLAN_HDR_LEN = 4

IPPROTO_TCP = 6
IPPROTO_UDP = 17

TCP_SYN = 0x02
TCP_ACK = 0x10


def read_pcap(path):
    """Yield (capture_ts_seconds, frame_bytes) for each record in a classic pcap file."""
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) < 24:
            raise ValueError("truncated pcap file header")
        (magic,) = struct.unpack("<I", header[:4])
        if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            endian = "<"
        else:
            (magic,) = struct.unpack(">I", header[:4])
            if magic not in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
                raise ValueError(
                    "not a classic pcap file (pcapng is not supported; "
                    "convert with `editcap -F pcap`)"
                )
            endian = ">"
        divisor = 1e9 if magic == PCAP_MAGIC_NS else 1e6

        while True:
            record = handle.read(16)
            if len(record) < 16:
                return
            ts_sec, ts_frac, caplen, _origlen = struct.unpack(endian + "IIII", record)
            data = handle.read(caplen)
            if len(data) < caplen:
                return
            yield ts_sec + ts_frac / divisor, data


def decode(frame):
    """Return (l4_proto, flow_key, tcp_flags), or None if this is not a TCP/UDP frame.

    `flow_key` is direction-insensitive so both halves of a connection share one key, as
    Iris's `ConnId` does.
    """
    if len(frame) < ETH_HDR_LEN:
        return None
    (ethertype,) = struct.unpack("!H", frame[12:14])
    offset = ETH_HDR_LEN
    # Live taps hand up tagged frames; Iris's ethernet parser walks these too.
    while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
        if len(frame) < offset + VLAN_HDR_LEN:
            return None
        (ethertype,) = struct.unpack("!H", frame[offset + 2 : offset + 4])
        offset += VLAN_HDR_LEN

    if ethertype == ETHERTYPE_IPV4:
        if len(frame) < offset + 20:
            return None
        ihl = (frame[offset] & 0x0F) * 4
        if ihl < 20:
            return None
        proto = frame[offset + 9]
        src = frame[offset + 12 : offset + 16]
        dst = frame[offset + 16 : offset + 20]
        # A non-first fragment carries no L4 header to read ports out of.
        (frag,) = struct.unpack("!H", frame[offset + 6 : offset + 8])
        if frag & 0x1FFF:
            return None
        l4 = offset + ihl
    elif ethertype == ETHERTYPE_IPV6:
        if len(frame) < offset + 40:
            return None
        proto = frame[offset + 6]
        src = frame[offset + 8 : offset + 24]
        dst = frame[offset + 24 : offset + 40]
        l4 = offset + 40
    else:
        return None

    if proto not in (IPPROTO_TCP, IPPROTO_UDP):
        return None
    if len(frame) < l4 + 4:
        return None
    sport, dport = struct.unpack("!HH", frame[l4 : l4 + 4])

    flags = 0
    if proto == IPPROTO_TCP:
        if len(frame) < l4 + 14:
            return None
        flags = frame[l4 + 13]

    ends = sorted(((src, sport), (dst, dport)))
    return proto, (proto, ends[0], ends[1]), flags


def wire_truth(pcap_path, slice_s, syn_only):
    """Per-slice on-wire TCP/UDP byte totals straight from the pcap."""
    frames = []
    syn_flows = set()
    for ts, frame in read_pcap(pcap_path):
        decoded = decode(frame)
        if decoded is None:
            continue
        proto, flow, flags = decoded
        # A bare SYN (SYN set, ACK clear) is exactly what Iris requires to open a TCP conn.
        if proto == IPPROTO_TCP and flags & TCP_SYN and not flags & TCP_ACK:
            syn_flows.add(flow)
        frames.append((ts, proto, flow, len(frame)))

    if not frames:
        return [], [], 0

    origin = min(ts for ts, _, _, _ in frames)
    tcp, udp = {}, {}
    skipped_mid_stream = 0
    for ts, proto, flow, length in frames:
        if syn_only and proto == IPPROTO_TCP and flow not in syn_flows:
            skipped_mid_stream += length
            continue
        index = int((ts - origin) / slice_s)
        bucket = tcp if proto == IPPROTO_TCP else udp
        bucket[index] = bucket.get(index, 0) + length

    last = max(max(tcp, default=0), max(udp, default=0))
    return (
        [tcp.get(i, 0) for i in range(last + 1)],
        [udp.get(i, 0) for i in range(last + 1)],
        skipped_mid_stream,
    )


def read_app_csv(path):
    """Per-slice totals from the app's CSV, keyed by column prefix, plus tcp/udp."""
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError("CSV has no data rows")

    prefixes = sorted(
        name[: -len("_handshake")]
        for name in rows[0]
        if name.endswith("_handshake")
    )
    protos = {
        prefix: [
            int(row[f"{prefix}_handshake"]) + int(row[f"{prefix}_payload"])
            for row in rows
        ]
        for prefix in prefixes
    }
    tcp = [int(row["tcp_bytes"]) for row in rows]
    udp = [int(row["udp_bytes"]) for row in rows]
    offsets = [float(row["slice_start_s"]) for row in rows]
    return offsets, protos, tcp, udp


def pad(values, length):
    return values + [0] * (length - len(values))


def compare(label, got, truth, tolerance_slices):
    """Report totals, peaks, and where reported bytes exceed what the wire carried."""
    length = max(len(got), len(truth))
    got, truth = pad(got, length), pad(truth, length)
    got_sum, truth_sum = sum(got), sum(truth)
    got_peak, truth_peak = max(got, default=0), max(truth, default=0)

    print(f"  {label}")
    print(f"    total     wire={truth_sum:>16,}  app={got_sum:>16,}  "
          f"({100.0 * got_sum / truth_sum if truth_sum else 0:.2f}% of wire)")
    print(f"    peak/slot wire={truth_peak:>16,}  app={got_peak:>16,}  "
          f"({100.0 * got_peak / truth_peak if truth_peak else 0:.2f}% of wire)")

    # Reporting *more* than the wire carried in a slice means bytes were moved into it --
    # smearing or misattribution -- which per-run totals alone would hide.
    overs = [(i, got[i], truth[i]) for i in range(length) if got[i] > truth[i]]
    if overs:
        worst = max(overs, key=lambda item: item[1] - item[2])
        print(f"    OVER-REPORTED in {len(overs)} slice(s); worst slice {worst[0]}: "
              f"app={worst[1]:,} > wire={worst[2]:,}")
    else:
        print("    no slice reports more than the wire carried")

    # Bytes landing far from any real activity is the signature of a bucketing bug.
    active = [i for i in range(length) if truth[i] > 0]
    if active and tolerance_slices is not None:
        first, last = active[0], active[-1]
        stray = sum(
            got[i]
            for i in range(length)
            if got[i] > 0 and not (first - tolerance_slices <= i <= last + tolerance_slices)
        )
        if stray:
            print(f"    STRAY {stray:,} byte(s) outside the trace's active window "
                  f"[{first}, {last}] (+/-{tolerance_slices})")
    return got_sum, truth_sum


def build_parser():
    parser = argparse.ArgumentParser(
        description="Check bytes_over_time's per-slice CSV against the source pcap."
    )
    parser.add_argument("pcap", type=Path, help="the trace the app was run on")
    parser.add_argument(
        "csv_path",
        nargs="?",
        type=Path,
        default=Path("bytes.csv"),
        help="CSV written by bytes_over_time (default: bytes.csv)",
    )
    parser.add_argument(
        "--slice-ms",
        type=int,
        default=1000,
        help="the --slice-ms the app was run with (default: 1000)",
    )
    parser.add_argument(
        "--mid-stream-ok",
        action="store_true",
        help=(
            "count only TCP flows whose SYN is in the trace, matching what Iris can "
            "actually track -- use this on traces cut from mid-stream traffic"
        ),
    )
    parser.add_argument(
        "--stray-tolerance",
        type=int,
        default=2,
        help=(
            "slices of slack either side of the trace's active window before reported "
            "bytes count as stray (default: 2)"
        ),
    )
    return parser


def main():
    args = build_parser().parse_args()
    slice_s = args.slice_ms / 1000.0

    try:
        tcp_truth, udp_truth, skipped = wire_truth(
            args.pcap, slice_s, args.mid_stream_ok
        )
        offsets, protos, tcp_app, udp_app = read_app_csv(args.csv_path)
    except (OSError, ValueError, struct.error) as error:
        raise SystemExit(f"error: {error}") from error

    if len(offsets) > 1:
        observed = round((offsets[1] - offsets[0]) * 1000)
        if observed != args.slice_ms:
            print(
                f"warning: CSV slice width looks like {observed}ms but --slice-ms "
                f"is {args.slice_ms}; the comparison will be misaligned",
                file=sys.stderr,
            )

    print(f"pcap : {args.pcap}")
    print(f"csv  : {args.csv_path}")
    print(f"slice: {args.slice_ms}ms   wire slices={len(tcp_truth)}  "
          f"csv rows={len(offsets)}")
    if args.mid_stream_ok and skipped:
        print(f"       excluded {skipped:,} byte(s) on TCP flows with no SYN in the trace")
    print()

    print("Transport series (independent ground truth from the pcap):")
    tcp_got, tcp_wire = compare("TCP", tcp_app, tcp_truth, args.stray_tolerance)
    udp_got, udp_wire = compare("UDP", udp_app, udp_truth, args.stray_tolerance)
    print()

    # The protocol series are subsets of transport, so the wire has no independent number
    # for them -- but they must still fit inside the transport bytes reported per slice.
    print("Protocol series (checked against the app's own transport columns):")
    transport = [a + b for a, b in zip(pad(tcp_app, len(udp_app)), pad(udp_app, len(tcp_app)))]
    for prefix, values in protos.items():
        total = sum(values)
        if not total:
            continue
        length = max(len(values), len(transport))
        vals, trans = pad(values, length), pad(transport, length)
        exceeds = [i for i in range(length) if vals[i] > trans[i]]
        note = (
            f"exceeds tcp+udp in {len(exceeds)} slice(s), first at {exceeds[0]}"
            if exceeds
            else "within tcp+udp every slice"
        )
        print(f"  {prefix:<14} total={total:>16,}  peak={max(vals):>14,}  {note}")
    print()

    wire_total = tcp_wire + udp_wire
    app_total = tcp_got + udp_got
    missing = wire_total - app_total
    print(f"Transport bytes on the wire but not reported: {missing:,} "
          f"({100.0 * missing / wire_total if wire_total else 0:.2f}%)")


if __name__ == "__main__":
    main()
