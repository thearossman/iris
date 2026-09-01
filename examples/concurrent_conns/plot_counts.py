#!/usr/bin/env python3

"""
Plots the per-slice active-connection CSVs written by the concurrent_conns Iris app
(examples/concurrent_conns/src/main.rs, --outfile, default counts.csv).

Takes one CSV per run. Given several, the figure shows the mean series across runs with error
bars for the spread, so a claim about the level rests on repeated measurement rather than on
whichever run happened to be recorded. Runs are aligned by time offset -- each is trimmed and
re-based to t=0 first, then matched slice-for-slice on a common grid -- and only offsets present
in every run are plotted, since a mean over a varying number of runs would change meaning
partway along the axis. A single CSV plots that run alone, with no error bars.

Each connection count is doubled before plotting: concurrent_conns counts bidirectional
connections, and each one is two unidirectional flows (one per five-tuple direction).

The figure is laid out for a paper: short and wide by default, since a roughly steady series
carries its meaning in its level rather than its vertical structure, and zero-based so the
magnitude claim is honest. A dashed line marks the mean level, labelled with the exact figure
and, across runs, with the spread of the per-run means. Large counts carry their unit in the
tick label itself ("1K", "2.5M"), so gridlines aren't labelled with seven-digit numbers and a
reader can name one without consulting the axis label.

`--warmup-mins`/`--cooldown-mins` drop the ends of each run and re-base the remainder to t=0.
Both ends are measurement artifacts rather than network behavior: conntrack only counts a
TCP connection it saw open, so early slices undercount until flows already in flight when
capture started have aged out, and the final slices lose flows still open when it stopped.
Defaults are a starting point -- widen them until the curve is flat at both ends.

The x-axis unit (seconds/minutes/hours) is chosen from the longest run's full untrimmed
duration, so it doesn't flip units depending on how much warmup/cooldown ate into a
borderline-length run.
"""

import argparse
import csv
import statistics

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

# Fractional disagreement between two runs' slice widths that's worth a warning: below this,
# the gap is float noise in the recorded offsets rather than a genuinely different --slice-ms.
SLICE_WIDTH_TOLERANCE = 0.01


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


def report_trim(path, raw_offsets, kept_offsets, warmup_mins, cooldown_mins):
    """Prints what the warmup/cooldown trim actually did, counting each end separately.

    A trim that silently drops nothing is indistinguishable from one that worked, because the
    kept offsets are re-based to t=0 either way: the axis starts at 0 regardless, so the only
    visible difference is a shorter run. Saying it outright turns "the flags did nothing" into
    numbers that can be checked against the run as recorded, and catches the case the trim
    can't detect on its own -- a slice_start_s column that isn't seconds elapsed since the
    start of the run, against which both bounds are silently meaningless."""
    if not warmup_mins and not cooldown_mins:
        return
    run_end = raw_offsets[-1]
    dropped_head = sum(1 for t in raw_offsets if t < warmup_mins * 60)
    dropped_tail = sum(1 for t in raw_offsets if t > run_end - cooldown_mins * 60)
    for mins, flag, dropped in (
        (warmup_mins, "--warmup-mins", dropped_head),
        (cooldown_mins, "--cooldown-mins", dropped_tail),
    ):
        if mins and not dropped:
            print(
                f"warning: {flag} {mins:g} dropped no rows. {path}'s slice_start_s column runs "
                f"{raw_offsets[0]:,.10g}..{run_end:,.10g}, and the trim reads it as seconds "
                "elapsed since the start of the run."
            )
    raw_span = run_end - raw_offsets[0]
    kept_span = kept_offsets[-1] - kept_offsets[0]
    print(
        f"{path}: trimmed a {warmup_mins:g}-minute warmup and a {cooldown_mins:g}-minute "
        f"cooldown, dropping {dropped_head} rows from the start and {dropped_tail} from the "
        f"end, keeping {kept_span / 60:.1f} of {raw_span / 60:.1f} minutes."
    )


def detect_slice_width(offsets):
    """The run's slice width in seconds, taken as the median gap between consecutive rows.
    Returns None for a series too short to have a gap."""
    if len(offsets) < 2:
        return None
    diffs = sorted(b - a for a, b in zip(offsets, offsets[1:]))
    return diffs[len(diffs) // 2]


def common_slice_width(runs):
    """One slice width for the whole figure, taken as the median of the runs' own widths.

    Runs recorded at different --slice-ms can still be averaged -- the offsets are seconds
    either way -- but only the slices that happen to land on the same grid will line up, so
    the mismatch is worth saying out loud rather than letting it show up as an unexplained
    handful of shared offsets."""
    widths = [(path, detect_slice_width(offsets)) for path, offsets, _ in runs]
    known = [(path, w) for path, w in widths if w is not None]
    if not known:
        return None
    width = statistics.median(w for _, w in known)
    odd = [
        (path, w) for path, w in known if abs(w - width) > SLICE_WIDTH_TOLERANCE * width
    ]
    for path, w in odd:
        print(
            f"warning: {path} was recorded at {w:g}s slices, but the other runs use "
            f"{width:g}s. Only slices that land on the {width:g}s grid will be averaged."
        )
    return width


def align_runs(runs, slice_width_s):
    """Puts every run's flow counts on one grid of `slice_width_s`-spaced offsets.

    Returns (offsets, per_run_series, dropped), where per_run_series[i] is run i's counts at
    each of `offsets` and `dropped` is the number of grid offsets that appeared in some run
    but not all of them, and so aren't plotted."""
    indexed = []
    for _, offsets, flows in runs:
        indexed.append({round(t / slice_width_s): v for t, v in zip(offsets, flows)})
    shared = set(indexed[0])
    seen = set(indexed[0])
    for run in indexed[1:]:
        shared &= run.keys()
        seen |= run.keys()
    grid = sorted(shared)
    offsets = [i * slice_width_s for i in grid]
    per_run_series = [[run[i] for i in grid] for run in indexed]
    return offsets, per_run_series, len(seen) - len(grid)


def summarize(per_run_series, spread):
    """Collapses the aligned runs to a mean series plus asymmetric error bar magnitudes.

    Returns (means, lower, upper) with `lower`/`upper` as distances from the mean rather than
    absolute bounds, which is the form matplotlib's `yerr` wants. Both are zero throughout
    for a single run, which has no spread to show."""
    samples = list(zip(*per_run_series))
    means = [statistics.fmean(s) for s in samples]
    if len(per_run_series) < 2:
        return means, [0.0] * len(means), [0.0] * len(means)
    if spread == "minmax":
        lower = [m - min(s) for m, s in zip(means, samples)]
        upper = [max(s) - m for m, s in zip(means, samples)]
        return means, lower, upper
    errors = [statistics.stdev(s) for s in samples]
    if spread == "sem":
        errors = [e / len(per_run_series) ** 0.5 for e in errors]
    return means, errors, list(errors)


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


def fmt_sample_label(slice_width_s, n_runs, carries_run_count):
    """Legend label for the plotted series. Named after the runs' actual slice width, since
    concurrent_conns' --slice-ms is configurable and a hardcoded "per-second" would quietly
    mislabel a run recorded at any other width.

    Kept terse: the legend sits inside the axes, and at a narrow --figsize a long label is
    what pushes it back out. So the run count rides on the error bars' entry, and only lands
    here when there is no such entry to carry it."""
    if slice_width_s is None:
        width = "per-slice"
    elif abs(slice_width_s - 1) < 1e-6:
        width = "per-second"
    elif abs(slice_width_s - 60) < 1e-6:
        width = "per-minute"
    else:
        width = f"per {slice_width_s:g}s"
    if n_runs < 2:
        return width
    if carries_run_count:
        return f"{width} mean (n={n_runs})"
    return f"{width} mean"


def fmt_spread_label(spread, n_runs):
    if spread == "minmax":
        return f"min-max (n={n_runs})"
    if spread == "sem":
        return f"±1 s.e.m. (n={n_runs})"
    return f"±1 s.d. (n={n_runs})"


def error_bar_positions(n_points, n_bars):
    """Indices for `n_bars` roughly evenly spaced error bars along an `n_points` series.

    A bar per slice is unreadable on a run of any length -- the caps merge into a band -- so
    the spread is sampled instead. Positions sit at the centre of each of `n_bars` equal
    stretches, which keeps the first and last bar off the axes spines where their caps would
    be half-clipped."""
    if n_bars <= 0 or n_points == 0:
        return []
    if n_bars >= n_points:
        return list(range(n_points))
    return sorted(
        {min(n_points - 1, int((i + 0.5) * n_points / n_bars)) for i in range(n_bars)}
    )


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


def load_runs(paths, warmup_mins, cooldown_mins):
    """Reads, trims and re-bases each run's CSV, dropping any that has nothing left to plot.

    Returns (runs, longest_raw_duration_s) with runs as (path, offsets, flows) triples, flows
    already doubled from bidirectional connections to unidirectional flows."""
    runs = []
    longest_raw_s = 0.0
    for path in paths:
        raw_offsets, counts = read_counts(path)
        if not raw_offsets:
            print(f"{path} has no data rows (no encrypted connections were observed).")
            continue
        longest_raw_s = max(longest_raw_s, raw_offsets[-1])
        offsets, counts = trim_warmup_cooldown(
            raw_offsets, counts, warmup_mins * 60, cooldown_mins * 60
        )
        if not offsets:
            print(
                f"{path}'s run is too short to trim a {warmup_mins:g}-minute warmup and "
                f"{cooldown_mins:g}-minute cooldown; skipping it."
            )
            continue
        report_trim(path, raw_offsets, offsets, warmup_mins, cooldown_mins)
        runs.append((path, offsets, [count * 2 for count in counts]))
    return runs, longest_raw_s


def main():
    parser = argparse.ArgumentParser(
        description="Plot concurrent_conns' per-slice active-connection CSV output, "
        "averaging over one CSV per run with error bars for the spread."
    )
    parser.add_argument(
        "csv_paths",
        nargs="*",
        default=["counts.csv"],
        metavar="CSV",
        help="One CSV written by concurrent_conns per run (default: counts.csv)",
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
        help="Minutes to drop from the start of each run (default: 10)",
    )
    parser.add_argument(
        "--cooldown-mins",
        type=float,
        default=2.0,
        help="Minutes to drop from the end of each run (default: 2)",
    )
    parser.add_argument(
        "--spread",
        choices=("std", "sem", "minmax"),
        default="std",
        help="What the error bars show across runs: sample standard deviation, standard "
        "error of the mean, or the full min-max range (default: std)",
    )
    parser.add_argument(
        "--error-bars",
        type=int,
        default=12,
        help="How many error bars to draw along the series; the spread is sampled at evenly "
        "spaced slices rather than drawn at every one (default: 12)",
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

    runs, longest_raw_s = load_runs(
        args.csv_paths, args.warmup_mins, args.cooldown_mins
    )
    if not runs:
        print("No run had any plottable data.")
        return

    unit, divisor = pick_time_unit(longest_raw_s)
    slice_width_s = common_slice_width(runs)
    if slice_width_s is None:
        print("Every run has a single slice, which is too short a series to plot.")
        return

    offsets, per_run_series, dropped = align_runs(runs, slice_width_s)
    if not offsets:
        print(
            f"The {len(runs)} runs share no time offsets once trimmed, so there is nothing "
            "to average. Check that they were recorded at the same --slice-ms."
        )
        return
    if dropped:
        print(
            f"Plotting the {len(offsets)} slices common to all {len(runs)} runs; dropped "
            f"{dropped} that only some runs reached."
        )

    means, lower, upper = summarize(per_run_series, args.spread)
    scaled_offsets = [t / divisor for t in offsets]
    # The level a reader quotes, with the spread of the runs' own means beside it -- that
    # spread answers "would another run have landed here?", which the per-slice bars don't:
    # they mix run-to-run offset with the series' own wobble over time.
    run_means = [statistics.fmean(series) for series in per_run_series]
    grand_mean = statistics.fmean(run_means)

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
    show_error_bars = len(runs) > 1 and args.error_bars > 0
    ax.step(
        scaled_offsets,
        means,
        where="post",
        linewidth=0.8,
        color=color,
        label=fmt_sample_label(slice_width_s, len(runs), not show_error_bars),
    )
    if show_error_bars:
        positions = error_bar_positions(len(scaled_offsets), args.error_bars)
        ax.errorbar(
            [scaled_offsets[i] for i in positions],
            [means[i] for i in positions],
            yerr=[
                [lower[i] for i in positions],
                [upper[i] for i in positions],
            ],
            fmt="none",
            ecolor=color,
            elinewidth=0.8,
            capsize=2.5,
            capthick=0.8,
            label=fmt_spread_label(args.spread, len(runs)),
        )
    mean_label = f"mean {grand_mean:,.0f}"
    if len(runs) > 1:
        mean_label += f" ± {statistics.stdev(run_means):,.0f}"
    ax.axhline(
        grand_mean,
        linestyle="--",
        linewidth=0.8,
        color="0.35",
        # Spelled out in full rather than in the axis's unit: the ticks are for reading the
        # shape of the series, but this is the number a reader quotes, and it should be
        # unambiguous on its own.
        label=mean_label,
    )

    # Wrapped: rotated upright, the label's longest line has to fit the figure's *height*,
    # which is deliberately small here.
    ax.set_xlabel(f"Time ({unit})")
    ax.set_ylabel("Active encrypted\nunidirectional flows")
    ax.set_xlim(scaled_offsets[0], scaled_offsets[-1])
    # Headroom measured from the top of the error bars, not the mean series, so a tall bar
    # isn't clipped by the axes.
    ax.set_ylim(0, max(m + u for m, u in zip(means, upper)) * Y_HEADROOM)
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
