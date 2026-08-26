#!/usr/bin/env python3

"""
Plots the per-slice active-connection CSV written by the concurrent_conns Iris app
(examples/concurrent_conns/src/main.rs, --outfile, default counts.csv).

Drawn as a step plot rather than a straight-line interpolation: each CSV row is one time
slice's count, held flat across that slice's width, since it isn't a sample of a continuously
varying quantity at slice_start_s.
"""

import argparse
import csv

import matplotlib.pyplot as plt


def read_counts(path):
    offsets = []
    counts = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            offsets.append(float(row["slice_start_s"]))
            counts.append(int(row["active_connections"]))
    return offsets, counts


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

    fig, ax = plt.subplots()
    ax.step(offsets, counts, where="post")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Active encrypted connections")
    ax.set_title("Concurrent encrypted connections over time")
    ax.set_ylim(bottom=0)
    fig.tight_layout()

    if args.output:
        fig.savefig(args.output)
        print(f"Wrote plot to {args.output}")
    else:
        plt.show()


if __name__ == "__main__":
    main()
