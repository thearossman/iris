#!/usr/bin/env python3

"""Plot bytes_over_time's CSV output as a stacked area chart.

The encrypted protocol series are stacked because they are disjoint protocol buckets. TCP
and UDP are intentionally not included: those transport totals overlap the protocol series
(for example, TLS bytes are also TCP bytes), so stacking them would double-count traffic.
"""

import argparse
import csv
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter


PROTOCOLS = [
    ("tls", "TLS"),
    ("ssh", "SSH"),
    ("quic", "QUIC"),
    ("wireguard", "WireGuard"),
    ("ike", "IKE"),
    ("maybe_quic", "MaybeQUIC"),
    ("maybe_zoom", "MaybeZoom"),
]

MINUTES_THRESHOLD_S = 10 * 60
HOURS_THRESHOLD_S = 3 * 60 * 60
Y_HEADROOM = 1.04


def parse_figsize(text):
    try:
        width, height = (float(value) for value in text.split(","))
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(
            "expected WIDTH,HEIGHT in inches, e.g. 7.5,3.5"
        ) from None
    if width <= 0 or height <= 0:
        raise argparse.ArgumentTypeError("WIDTH and HEIGHT must be positive")
    return width, height


def read_bytes(path, component):
    offsets = []
    series = {name: [] for name, _ in PROTOCOLS}
    required = {"slice_start_s"}
    for name, _ in PROTOCOLS:
        required.update((f"{name}_handshake", f"{name}_payload"))

    with path.open(newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        missing = required.difference(reader.fieldnames or [])
        if missing:
            missing_text = ", ".join(sorted(missing))
            raise ValueError(f"missing CSV column(s): {missing_text}")

        for line_number, row in enumerate(reader, start=2):
            try:
                offset = float(row["slice_start_s"])
                values = {}
                for name, _ in PROTOCOLS:
                    handshake = int(row[f"{name}_handshake"])
                    payload = int(row[f"{name}_payload"])
                    if handshake < 0 or payload < 0:
                        raise ValueError("byte counts cannot be negative")
                    if component == "handshake":
                        values[name] = handshake
                    elif component == "payload":
                        values[name] = payload
                    else:
                        values[name] = handshake + payload
            except (TypeError, ValueError) as error:
                raise ValueError(f"invalid data on CSV line {line_number}: {error}") from error

            if offsets and offset <= offsets[-1]:
                raise ValueError(
                    f"slice_start_s must increase on CSV line {line_number}"
                )
            offsets.append(offset)
            for name, _ in PROTOCOLS:
                series[name].append(values[name])

    return offsets, series


def detect_slice_width(offsets):
    if len(offsets) < 2:
        return None
    gaps = sorted(right - left for left, right in zip(offsets, offsets[1:]))
    return gaps[len(gaps) // 2]


def pick_time_unit(duration_s):
    if duration_s > HOURS_THRESHOLD_S:
        return "hours", 3600.0
    if duration_s > MINUTES_THRESHOLD_S:
        return "minutes", 60.0
    return "seconds", 1.0


def pick_byte_unit(max_bytes):
    units = [(1024**3, "GiB"), (1024**2, "MiB"), (1024, "KiB")]
    for divisor, name in units:
        if max_bytes >= divisor:
            return divisor, name
    return 1, "bytes"


def format_slice_width(seconds):
    if seconds is None:
        return "slice"
    if seconds >= 60 and seconds % 60 == 0:
        return f"{seconds / 60:g} min slice"
    return f"{seconds:g} s slice"


def build_parser():
    parser = argparse.ArgumentParser(
        description="Plot bytes_over_time's per-slice CSV as a stacked area chart."
    )
    parser.add_argument(
        "csv_path",
        nargs="?",
        type=Path,
        default=Path("bytes.csv"),
        help="CSV written by bytes_over_time (default: bytes.csv)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Save the plot here instead of opening a window (for example, bytes.png)",
    )
    parser.add_argument(
        "--component",
        choices=("total", "handshake", "payload"),
        default="total",
        help="Byte component to stack (default: total)",
    )
    parser.add_argument(
        "--figsize",
        type=parse_figsize,
        default=(7.5, 3.5),
        help="Figure size as WIDTH,HEIGHT in inches (default: 7.5,3.5)",
    )
    parser.add_argument(
        "--font-size",
        type=float,
        default=12.0,
        help="Base font size in points (default: 12)",
    )
    return parser


def main():
    args = build_parser().parse_args()
    try:
        offsets, series = read_bytes(args.csv_path, args.component)
    except (OSError, ValueError) as error:
        raise SystemExit(f"error: could not read {args.csv_path}: {error}") from error

    if not offsets:
        raise SystemExit(f"error: {args.csv_path} has no data rows")

    # Empty protocol buckets add no information and make the legend needlessly crowded.
    plotted = [
        (name, label, series[name])
        for name, label in PROTOCOLS
        if any(series[name])
    ]
    if not plotted:
        raise SystemExit(
            f"error: {args.csv_path} contains no encrypted {args.component} bytes"
        )

    slice_width_s = detect_slice_width(offsets)
    # A step series needs a right-hand boundary or its last sample has zero visible width.
    # One-row CSVs do not expose their configured slice width, so give that lone slice a
    # one-second display width while keeping the axis label honest ("per slice").
    display_slice_width_s = slice_width_s if slice_width_s is not None else 1.0
    duration_s = offsets[-1] - offsets[0] + display_slice_width_s
    time_unit, time_divisor = pick_time_unit(duration_s)
    x_values = [(offset - offsets[0]) / time_divisor for offset in offsets]
    x_values.append(duration_s / time_divisor)
    totals = [sum(values) for values in zip(*(values for _, _, values in plotted))]
    y_divisor, byte_unit = pick_byte_unit(max(totals))
    slice_label = format_slice_width(slice_width_s)

    plt.rcParams.update(
        {
            "font.size": args.font_size,
            "axes.labelsize": args.font_size,
            "xtick.labelsize": args.font_size - 1,
            "ytick.labelsize": args.font_size - 1,
            "legend.fontsize": args.font_size - 1,
        }
    )
    fig, ax = plt.subplots(figsize=args.figsize)
    ax.stackplot(
        x_values,
        *(values + [values[-1]] for _, _, values in plotted),
        labels=[label for _, label, _ in plotted],
        step="post",
        alpha=0.9,
    )

    component_label = "" if args.component == "total" else f" {args.component}"
    ax.set_xlabel(f"Time ({time_unit})")
    ax.set_ylabel(f"Encrypted{component_label} bytes\nper {slice_label} ({byte_unit})")
    ax.yaxis.set_major_formatter(
        FuncFormatter(lambda value, _: f"{value / y_divisor:,.4g}")
    )
    ax.set_ylim(0, max(totals) * Y_HEADROOM)
    ax.set_xlim(x_values[0], x_values[-1])
    ax.legend(loc="upper left", frameon=False, ncol=min(4, len(plotted)))
    fig.tight_layout()

    if args.output:
        fig.savefig(args.output, dpi=200)
        print(f"Wrote plot to {args.output}")
    else:
        plt.show()


if __name__ == "__main__":
    main()
