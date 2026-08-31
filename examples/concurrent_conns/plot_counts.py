#!/usr/bin/env python3

"""
Plots the per-slice active-connection CSV written by the concurrent_conns Iris app
(examples/concurrent_conns/src/main.rs, --outfile, default counts.csv).

Each connection count is doubled before plotting: concurrent_conns counts bidirectional
connections, and each one is two unidirectional flows (one per five-tuple direction).

The figure is laid out for a paper: short and wide by default, since a roughly steady series
carries its meaning in its level rather than its vertical structure, and zero-based so the
magnitude claim is honest. A dashed line marks the mean level, labelled with the exact figure.
Large counts carry their unit in the tick label itself ("1K", "2.5M"), so gridlines aren't
labelled with seven-digit numbers and a reader can name one without consulting the axis label.

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

# Y-axis tick suffixes, largest unit first: a series in the millions reads better as ticks of
# "1.15M" than as "1,150,000" repeated up the gridlines.
Y_SUFFIXES = [
    (1_000_000_000_000, "T"),
    (1_000_000_000, "B"),
    (1_000_000, "M"),
    (1_000, "K"),
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


def pick_time_unit(duration_s):
    if duration_s > HOURS_THRESHOLD_S:
        return "hours", 3600.0
    if duration_s > MINUTES_THRESHOLD_S:
        return "minutes", 60.0
    return "seconds", 1.0


def fmt_y_tick(value):
    """A y-axis tick label with its unit built in: 100 -> "100", 1_000 -> "1K",
    2_500_000 -> "2.5M". The scaled value keeps whatever precision it needs rather than being
    rounded to a fixed width, so a tick is never labelled with a number it isn't."""
    magnitude = abs(value)
    for divisor, suffix in Y_SUFFIXES:
        if magnitude >= divisor:
            return f"{value / divisor:,.10g}{suffix}"
    return f"{value:,.10g}"


def fmt_sample_label(slice_width_s):
    """Legend label for the raw series. Named after the run's actual slice width, since
    concurrent_conns' --slice-ms is configurable and a hardcoded "per-second" would quietly
    mislabel a run recorded at any other width."""
    if slice_width_s is None:
        return "per-slice"
    if abs(slice_width_s - 1) < 1e-6:
        return "per-second"
    if abs(slice_width_s - 60) < 1e-6:
        return "per-minute"
    return f"per {slice_width_s:g}s"


def place_legend(fig, ax):
    """Adds the legend in the widest column layout that actually fits inside the axes.

    A fixed column count can't work across the range of figure sizes and font sizes this
    script accepts: one wide row is right at default settings, but at a narrower --figsize or
    a larger --font-size the same row runs past the axes and collides with the y-label. So
    try widest-first and measure each candidate's rendered width rather than guessing from
    character counts."""
    legend = None
    for ncol in (3, 2, 1):
        if legend is not None:
            legend.remove()
        legend = ax.legend(loc="lower right", frameon=False, ncol=ncol)
        fig.canvas.draw()
        if legend.get_window_extent().width <= ax.get_window_extent().width:
            break
    return legend


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
        "--font-size",
        type=float,
        default=14.0,
        help="Base point size for axis labels; tick labels sit one point below it "
        "(default: 14)",
    )
    parser.add_argument(
        "--legend-font-size",
        type=float,
        help="Point size for the in-plot legend text (default: matches --font-size)",
    )
    parser.add_argument(
        "--figsize",
        type=parse_figsize,
        default=(6.5, 2.6),
        help="Figure size as WIDTH,HEIGHT in inches (default: 6.5,2.6)",
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

    # Set before the figure is built, so tight_layout below measures the real text extents.
    # Legend text matches the axis text by default, but stays separately settable so either
    # can be nudged without dragging the other along.
    legend_font_size = args.legend_font_size
    if legend_font_size is None:
        legend_font_size = args.font_size
    plt.rcParams.update(
        {
            "font.size": args.font_size,
            "axes.labelsize": args.font_size,
            "xtick.labelsize": args.font_size - 1,
            "ytick.labelsize": args.font_size - 1,
            "legend.fontsize": legend_font_size,
        }
    )

    fig, ax = plt.subplots(figsize=args.figsize)
    # The default cycle's first hue, so the series reads as the figure's one quantity and the
    # grey dashed mean line reads as annotation rather than as a second series.
    color = plt.rcParams["axes.prop_cycle"].by_key()["color"][0]
    ax.step(
        scaled_offsets,
        flows,
        where="post",
        linewidth=0.8,
        color=color,
        label=fmt_sample_label(slice_width_s),
    )
    ax.axhline(
        mean_flows,
        linestyle="--",
        linewidth=0.8,
        color="0.35",
        # Spelled out in full rather than in the axis's unit: the ticks are for reading the
        # shape of the series, but this is the number a reader quotes, and it should be
        # unambiguous on its own.
        label=f"mean {mean_flows:,.0f}",
    )

    # Wrapped: rotated upright, the label's longest line has to fit the figure's *height*,
    # which is deliberately small here.
    ax.set_xlabel(f"Time ({unit})")
    ax.set_ylabel("Active encrypted\nunidirectional flows")
    ax.set_xlim(scaled_offsets[0], scaled_offsets[-1])
    ax.set_ylim(0, max(flows) * Y_HEADROOM)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: fmt_y_tick(v)))
    fig.tight_layout()
    # The series sits near the top of a zero-based axis, so the lower half is free space.
    place_legend(fig, ax)

    if args.output:
        fig.savefig(args.output, dpi=200)
        print(f"Wrote plot to {args.output}")
    else:
        plt.show()


if __name__ == "__main__":
    main()
