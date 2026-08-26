#!/usr/bin/env python3

"""
Plots the per-slice active-connection CSV written by the concurrent_conns Iris app
(examples/concurrent_conns/src/main.rs, --outfile, default counts.csv).

Drawn as a step plot rather than a straight-line interpolation: each CSV row is one time
slice's count, held flat across that slice's width, since it isn't a sample of a continuously
varying quantity at slice_start_s.

Each connection count is doubled before plotting: concurrent_conns counts bidirectional
connections, and each one is two unidirectional flows. The first WARMUP_S seconds and last
COOLDOWN_S seconds of the run are dropped as ramp-up/ramp-down noise, and the remaining window
is re-based to start at t=0. The x-axis unit (seconds/minutes/hours) is chosen from the run's
full untrimmed duration, so it doesn't flip units depending on how much warmup/cooldown ate
into a borderline-length run.
"""

import argparse
import csv

import matplotlib.pyplot as plt
from matplotlib.ticker import StrMethodFormatter

WARMUP_S = 10 * 60
COOLDOWN_S = 2 * 60

MINUTES_THRESHOLD_S = 10 * 60
HOURS_THRESHOLD_S = 3 * 60 * 60


def read_counts(path):
    offsets = []
    counts = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            offsets.append(float(row["slice_start_s"]))
            counts.append(int(row["active_connections"]))
    return offsets, counts


def trim_warmup_cooldown(offsets, counts):
    """Drops rows in the first WARMUP_S seconds or last COOLDOWN_S seconds of the run, then
    re-bases the remaining offsets so the first kept row is t=0."""
    if not offsets:
        return offsets, counts
    run_end = offsets[-1]
    kept = [
        (t, c) for t, c in zip(offsets, counts) if WARMUP_S <= t <= run_end - COOLDOWN_S
    ]
    if not kept:
        return [], []
    base = kept[0][0]
    return [t - base for t, _ in kept], [c for _, c in kept]


def pick_time_unit(duration_s):
    if duration_s > HOURS_THRESHOLD_S:
        return "hours", 3600.0
    if duration_s > MINUTES_THRESHOLD_S:
        return "minutes", 60.0
    return "seconds", 1.0


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
    args = parser.parse_args()

    offsets, counts = read_counts(args.csv_path)
    if not offsets:
        print(f"{args.csv_path} has no data rows (no encrypted connections were observed).")
        return

    unit, divisor = pick_time_unit(offsets[-1])

    offsets, counts = trim_warmup_cooldown(offsets, counts)
    if not offsets:
        print(
            f"{args.csv_path}'s run is too short to trim a {WARMUP_S // 60}-minute warmup "
            f"and {COOLDOWN_S // 60}-minute cooldown; nothing left to plot."
        )
        return

    flows = [count * 2 for count in counts]
    scaled_offsets = [t / divisor for t in offsets]

    fig, ax = plt.subplots()
    ax.step(scaled_offsets, flows, where="post")
    ax.set_xlabel(f"Time ({unit})")
    ax.set_ylabel("Active encrypted unidirectional flows")
    ax.set_ylim(bottom=0)
    ax.yaxis.set_major_formatter(StrMethodFormatter("{x:,.0f}"))
    fig.tight_layout()

    if args.output:
        fig.savefig(args.output)
        print(f"Wrote plot to {args.output}")
    else:
        plt.show()


if __name__ == "__main__":
    main()
