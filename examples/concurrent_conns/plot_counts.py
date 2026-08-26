#!/usr/bin/env python3

"""
Plots the per-slice active-connection CSV written by the concurrent_conns Iris app
(examples/concurrent_conns/src/main.rs, --outfile, default counts.csv).

Each connection count is doubled before plotting: concurrent_conns counts bidirectional
connections, and each one is two unidirectional flows (one per five-tuple direction).

The figure is laid out for a paper: short and wide by default, since a roughly steady series
carries its meaning in its level rather than its vertical structure, and zero-based so the
magnitude claim is honest. The raw per-slice series is drawn faintly underneath a rolling
mean, which is what stays legible at print size; a dashed line marks the mean level. Large
counts are rescaled into thousands or millions, named in the axis label, so gridlines aren't
labelled with seven-digit numbers.

`--warmup-mins`/`--cooldown-mins` drop the ends of the run and re-base the remainder to t=0.
Both ends are measurement artifacts rather than network behavior: conntrack only counts a
TCP connection it saw open, so early slices undercount until flows already in flight when
capture started have aged out, and the final slices lose flows still open when it stopped.
Defaults are a starting point -- widen them until the curve is flat at both ends.

The x-axis unit (seconds/minutes/hours) is chosen from the run's full untrimmed duration, so
it doesn't flip units depending on how much warmup/cooldown ate into a borderline-length run.
"""

import argparse
import csv

import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

MINUTES_THRESHOLD_S = 10 * 60
HOURS_THRESHOLD_S = 3 * 60 * 60

# Y-axis tick scaling, largest unit first: a series in the millions reads better as ticks of
# "1,150" against a "(thousands)" axis label than as "1,150,000" repeated up the gridlines.
Y_UNITS = [
    (10_000_000, 1_000_000, "millions"),
    (10_000, 1_000, "thousands"),
]

# Headroom above the tallest sample, so the mean annotation has somewhere to sit.
Y_HEADROOM = 1.15


def read_counts(path):
    offsets = []
    counts = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            offsets.append(float(row["slice_start_s"]))
            counts.append(int(row["active_connections"]))
    return offsets, counts


def trim_warmup_cooldown(offsets, counts, warmup_s, cooldown_s):
    """Drops rows in the first `warmup_s` or last `cooldown_s` seconds of the run, then
    re-bases the remaining offsets so the first kept row is t=0."""
    if not offsets:
        return offsets, counts
    run_end = offsets[-1]
    kept = [
        (t, c) for t, c in zip(offsets, counts) if warmup_s <= t <= run_end - cooldown_s
    ]
    if not kept:
        return [], []
    base = kept[0][0]
    return [t - base for t, _ in kept], [c for _, c in kept]


def detect_slice_width(offsets):
    """The run's slice width in seconds, taken as the median gap between consecutive rows.
    Returns None for a series too short to have a gap."""
    if len(offsets) < 2:
        return None
    diffs = sorted(b - a for a, b in zip(offsets, offsets[1:]))
    return diffs[len(diffs) // 2]


def rolling_mean(values, window):
    """Centered rolling mean. Windows shrink at the two ends rather than going undefined, so
    the smoothed line spans the same x range as the raw series instead of stopping short."""
    if window <= 1:
        return list(values)
    half = window // 2
    cumsum = [0.0]
    for v in values:
        cumsum.append(cumsum[-1] + v)
    out = []
    for i in range(len(values)):
        lo = max(0, i - half)
        hi = min(len(values), i + half + 1)
        out.append((cumsum[hi] - cumsum[lo]) / (hi - lo))
    return out


def pick_time_unit(duration_s):
    if duration_s > HOURS_THRESHOLD_S:
        return "hours", 3600.0
    if duration_s > MINUTES_THRESHOLD_S:
        return "minutes", 60.0
    return "seconds", 1.0


def pick_y_unit(max_value):
    """Divisor and unit name for the y-axis, or (1, None) to plot raw counts."""
    for threshold, divisor, name in Y_UNITS:
        if max_value >= threshold:
            return divisor, name
    return 1, None


def fmt_scaled(value, divisor):
    """Formats one y-value in the axis's own unit, so legend numbers and tick labels are
    directly comparable."""
    decimals = 0 if divisor == 1 else 1
    return f"{value / divisor:,.{decimals}f}"


def fmt_window(seconds):
    """Human-readable smoothing window, for the legend entry."""
    if seconds >= 3600 and seconds % 3600 == 0:
        return f"{seconds / 3600:g}-hr"
    if seconds >= 60 and seconds % 60 == 0:
        return f"{seconds / 60:g}-min"
    return f"{seconds:g}-s"


def parse_figsize(text):
    parts = text.split(",")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("expected WIDTH,HEIGHT in inches, e.g. 6.5,2")
    try:
        width, height = (float(p) for p in parts)
    except ValueError:
        raise argparse.ArgumentTypeError("WIDTH and HEIGHT must be numbers, e.g. 6.5,2")
    if width <= 0 or height <= 0:
        raise argparse.ArgumentTypeError("WIDTH and HEIGHT must be positive")
    return width, height


def main():
    parser = argparse.ArgumentParser(
        description="Plot concurrent_conns' per-slice active-connection CSV output."
    )
    parser.add_argument(
        "csv_path",
        nargs="?",
        default="counts.csv",
        help="Path to the CSV written by concurrent_conns (default: counts.csv)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Save the plot to this file instead of opening a window (e.g. counts.png)",
    )
    parser.add_argument(
        "--warmup-mins",
        type=float,
        default=10.0,
        help="Minutes to drop from the start of the run (default: 10)",
    )
    parser.add_argument(
        "--cooldown-mins",
        type=float,
        default=2.0,
        help="Minutes to drop from the end of the run (default: 2)",
    )
    parser.add_argument(
        "--smooth-secs",
        type=float,
        default=60.0,
        help="Width of the rolling-mean window, in seconds; 0 plots the raw series alone "
        "(default: 60)",
    )
    parser.add_argument(
        "--figsize",
        type=parse_figsize,
        default=(6.5, 2.0),
        help="Figure size as WIDTH,HEIGHT in inches (default: 6.5,2)",
    )
    args = parser.parse_args()

    offsets, counts = read_counts(args.csv_path)
    if not offsets:
        print(f"{args.csv_path} has no data rows (no encrypted connections were observed).")
        return

    unit, divisor = pick_time_unit(offsets[-1])
    slice_width_s = detect_slice_width(offsets)

    offsets, counts = trim_warmup_cooldown(
        offsets, counts, args.warmup_mins * 60, args.cooldown_mins * 60
    )
    if not offsets:
        print(
            f"{args.csv_path}'s run is too short to trim a {args.warmup_mins:g}-minute warmup "
            f"and {args.cooldown_mins:g}-minute cooldown; nothing left to plot."
        )
        return

    flows = [count * 2 for count in counts]
    scaled_offsets = [t / divisor for t in offsets]
    mean_flows = sum(flows) / len(flows)

    window = 1
    if args.smooth_secs > 0 and slice_width_s:
        window = max(1, round(args.smooth_secs / slice_width_s))

    fig, ax = plt.subplots(figsize=args.figsize)
    # One hue for the data, so the faint raw series reads as the same series as the mean
    # line drawn over it rather than as a second quantity.
    color = plt.rcParams["axes.prop_cycle"].by_key()["color"][0]
    if window > 1:
        # Raw samples stay visible underneath so the smoothing isn't hiding real variance.
        ax.step(
            scaled_offsets,
            flows,
            where="post",
            linewidth=0.5,
            alpha=0.3,
            color=color,
            label="per-slice",
        )
        ax.plot(
            scaled_offsets,
            rolling_mean(flows, window),
            linewidth=1.2,
            color=color,
            label=f"{fmt_window(args.smooth_secs)} rolling mean",
        )
    else:
        ax.step(
            scaled_offsets,
            flows,
            where="post",
            linewidth=0.8,
            color=color,
            label="per-slice",
        )
    y_divisor, y_unit = pick_y_unit(max(flows))
    ax.axhline(
        mean_flows,
        linestyle="--",
        linewidth=0.8,
        color="0.35",
        label=f"mean {fmt_scaled(mean_flows, y_divisor)}",
    )

    # Wrapped, and the unit kept on its own line: rotated upright, the label's longest line
    # has to fit the figure's *height*, which is deliberately small here.
    ylabel = "Active encrypted\nunidirectional flows"
    if y_unit:
        ylabel += f"\n({y_unit})"
    ax.set_xlabel(f"Time ({unit})")
    ax.set_ylabel(ylabel)
    ax.set_xlim(scaled_offsets[0], scaled_offsets[-1])
    ax.set_ylim(0, max(flows) * Y_HEADROOM)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v / y_divisor:,.10g}"))
    # The series sits near the top of a zero-based axis, so the lower half is free space.
    ax.legend(loc="lower right", frameon=False, fontsize="small", ncol=3)
    fig.tight_layout()

    if args.output:
        fig.savefig(args.output, dpi=200)
        print(f"Wrote plot to {args.output}")
    else:
        plt.show()


if __name__ == "__main__":
    main()
