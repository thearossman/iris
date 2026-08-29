#!/usr/bin/env python3
"""Plot the `encrypted_bytes` example's output as a stacked column chart.

Reads the text printed by `cargo run --example encrypted_bytes` (or a file/pipe
carrying that output) and draws one column per protocol, split into "Payload"
and "Handshake" segments, each sized as a % of *total transport traffic*
(TCP + UDP) -- the same figure the Rust app itself prints as "of total
traffic" (see `print_proto` in examples/encrypted_bytes/src/main.rs).

"QUIC" and "MaybeQUIC" (the real parser's rows vs. the heuristic mid-stream
detector's row) are merged into a single "QUIC" column, since they're two
detection paths for the same protocol.

Requires: matplotlib (`pip install matplotlib`)

Usage:
    cargo run --example encrypted_bytes -- -c configs/offline.toml > out.txt
    python3 examples/encrypted_bytes/plot_encrypted_bytes.py out.txt

    # or pipe directly:
    cargo run --example encrypted_bytes -- -c configs/offline.toml \\
        | python3 examples/encrypted_bytes/plot_encrypted_bytes.py
"""
import argparse
import re
import sys
from collections import OrderedDict

import matplotlib.pyplot as plt

# One line of `print_proto`'s output, e.g.:
#   "TLS        handshake:  12.34%   payload:  87.66%   of total traffic:   5.02%"
#   "MaybeZoom  handshake:    n/a    payload: 100.00%   of total traffic:   0.01%"
LINE_RE = re.compile(
    r"^(?P<name>\S+)\s+handshake:\s*(?P<handshake>\S+)"
    r"\s+payload:\s*(?P<payload>\S+)"
    r"\s+of total traffic:\s*(?P<total>\S+)"
)

# Rows merged into a single "QUIC" column -- see module docstring.
QUIC_ALIASES = ("QUIC", "MaybeQUIC")
QUIC_MERGED_NAME = "QUIC"

# Fixed categorical order (palette slots 1 and 2 -- a validated adjacent pair,
# never reordered/cycled): Payload first (bottom of the stack), Handshake second.
PAYLOAD_COLOR = "#2a78d6"  # slot 1, blue
HANDSHAKE_COLOR = "#eb6834"  # slot 2, orange
SURFACE_COLOR = "#fcfcfb"
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE_COLOR = "#e1e0d9"
BASELINE_COLOR = "#c3c2b7"


def _pct(raw):
    """Parse one `fmt_pct()` field ("12.34%" or "n/a") to a float, "n/a" -> 0.0.

    "n/a" only appears for a protocol's own handshake/payload split when that
    protocol carried zero bytes -- its share of total traffic is then always
    0.0% too, so treating "n/a" as 0 here is exact, not an approximation.
    """
    raw = raw.strip()
    if raw == "n/a":
        return 0.0
    return float(raw.rstrip("%"))


def parse(text):
    """Extract each protocol's handshake/payload % of *total transport traffic*.

    Returns an OrderedDict of name -> (handshake_pct_of_total, payload_pct_of_total),
    in the order the rows first appeared in the input, with "QUIC" and
    "MaybeQUIC" merged into one "QUIC" entry.
    """
    rows = OrderedDict()
    for line in text.splitlines():
        m = LINE_RE.match(line.strip())
        if not m:
            continue
        name = m.group("name")
        handshake_frac = _pct(m.group("handshake")) / 100.0
        payload_frac = _pct(m.group("payload")) / 100.0
        of_total = _pct(m.group("total"))

        # `handshake`/`payload` are each protocol's *own* split (they sum to
        # 100% of that protocol's bytes); scale by its share of transport
        # traffic so every protocol stacks correctly on one shared
        # "% of total transport traffic" axis.
        handshake_of_total = of_total * handshake_frac
        payload_of_total = of_total * payload_frac

        key = QUIC_MERGED_NAME if name in QUIC_ALIASES else name
        if key in rows:
            prev_handshake, prev_payload = rows[key]
            rows[key] = (
                prev_handshake + handshake_of_total,
                prev_payload + payload_of_total,
            )
        else:
            rows[key] = (handshake_of_total, payload_of_total)
    return rows


def plot(rows, title, out_path):
    if not rows:
        raise SystemExit(
            "No protocol rows found -- is this really `encrypted_bytes`'s output? "
            "Expected lines like "
            "'TLS   handshake: ...  payload: ...  of total traffic: ...'."
        )

    # Columns sorted by total % of transport traffic, largest first.
    names = sorted(rows.keys(), key=lambda n: sum(rows[n]), reverse=True)
    handshake_vals = [rows[n][0] for n in names]
    payload_vals = [rows[n][1] for n in names]
    totals = [h + p for h, p in zip(handshake_vals, payload_vals)]

    fig, ax = plt.subplots(figsize=(max(6, 1.1 * len(names)), 6), dpi=150)
    fig.patch.set_facecolor(SURFACE_COLOR)
    ax.set_facecolor(SURFACE_COLOR)

    x = range(len(names))
    bar_width = 0.6
    gap_lw = 1.5  # ~2px surface-color gap separating the two stacked segments

    ax.bar(
        x,
        payload_vals,
        width=bar_width,
        color=PAYLOAD_COLOR,
        edgecolor=SURFACE_COLOR,
        linewidth=gap_lw,
        label="Payload",
    )
    ax.bar(
        x,
        handshake_vals,
        width=bar_width,
        bottom=payload_vals,
        color=HANDSHAKE_COLOR,
        edgecolor=SURFACE_COLOR,
        linewidth=gap_lw,
        label="Handshake",
    )

    # Direct label: each column's total % of transport traffic, on its cap.
    label_pad = max(totals) * 0.015 if any(totals) else 0.02
    for xi, total in zip(x, totals):
        if total > 0:
            ax.text(
                xi,
                total + label_pad,
                f"{total:.2f}%",
                ha="center",
                va="bottom",
                fontsize=9,
                color=INK_SECONDARY,
            )

    ax.set_xticks(list(x))
    ax.set_xticklabels(names, color=INK_PRIMARY)
    ax.set_ylabel("% of total transport traffic", color=INK_PRIMARY)
    ax.set_title(title, color=INK_PRIMARY, fontsize=13, loc="left")

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.spines["bottom"].set_color(BASELINE_COLOR)
    ax.tick_params(axis="x", colors=INK_MUTED, length=0)
    ax.tick_params(axis="y", colors=INK_MUTED)
    ax.yaxis.grid(True, color=GRIDLINE_COLOR, linewidth=1)
    ax.set_axisbelow(True)

    top = max(totals) if any(totals) else 1.0
    ax.set_ylim(0, top * 1.15)

    # Legend: always present with >=2 series -- the dependable identity
    # channel, so the reader never has to color-match unaided.
    ax.legend(loc="upper right", frameon=False, labelcolor=INK_SECONDARY)

    fig.tight_layout()
    fig.savefig(out_path, facecolor=SURFACE_COLOR)
    print(f"Wrote {out_path}")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Path to a file holding `encrypted_bytes`'s stdout, "
        "or '-' (default) to read stdin",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="encrypted_bytes_chart.png",
        help="Output image path (default: %(default)s)",
    )
    parser.add_argument(
        "--title",
        default="Encrypted protocol traffic: payload vs. handshake",
        help="Chart title",
    )
    args = parser.parse_args()

    if args.input == "-":
        text = sys.stdin.read()
    else:
        with open(args.input) as f:
            text = f.read()

    rows = parse(text)
    plot(rows, args.title, args.output)


if __name__ == "__main__":
    main()
