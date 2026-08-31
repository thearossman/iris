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

Any protocol whose own % of total transport traffic is below 1% (configurable
with `--other-threshold`) is folded into a single "Other" column instead of
getting its own sliver of a bar.

A protocol's handshake share is often a small fraction of its own bytes, and
that share is then scaled again by the protocol's share of total traffic --
in practice this routinely produces handshake segments a few hundredths to a
few tenths of a percentage point tall, too thin to render as visible area at
all. To keep a real, nonzero handshake share from silently disappearing, any
such segment is floored to a minimum rendered height and paired with a small
text label giving its true (unfloored) percentage -- see `MIN_VISIBLE_HANDSHAKE_FRAC`
in `plot()`.

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

# Rows below this % of total transport traffic are folded into "Other".
OTHER_THRESHOLD_PCT = 1.0
OTHER_NAME = "Other"

# Any nonzero handshake segment is floored to at least this fraction of the
# chart's tallest column, so a real-but-tiny handshake share always renders
# as a visible sliver instead of vanishing under the payload/handshake gap
# edge. Purely a rendering floor -- the cap label and axis scaling still use
# the true value; only the drawn bar geometry is exaggerated.
MIN_VISIBLE_HANDSHAKE_FRAC = 0.008

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


def group_small(rows, threshold=OTHER_THRESHOLD_PCT):
    """Fold every row whose total % of transport traffic is below `threshold`
    into a single combined "Other" row, so a long tail of near-zero protocols
    doesn't clutter the chart with unreadable slivers.

    Rows are compared and combined on their *total* (handshake + payload);
    the combined row's handshake/payload split is just the sum of the folded
    rows' own splits, same as the QUIC/MaybeQUIC merge in `parse`.
    """
    kept = OrderedDict()
    other_handshake = 0.0
    other_payload = 0.0
    for name, (handshake, payload) in rows.items():
        if handshake + payload < threshold:
            other_handshake += handshake
            other_payload += payload
        else:
            kept[name] = (handshake, payload)
    if other_handshake or other_payload:
        kept[OTHER_NAME] = (other_handshake, other_payload)
    return kept


def plot(rows, out_path):
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

    # Floor nonzero handshake segments to a minimum rendered height (see
    # MIN_VISIBLE_HANDSHAKE_FRAC) so a real handshake share is never drawn as
    # literally invisible. `rendered_handshake_vals` is for bar geometry only
    # -- `handshake_vals`/`totals` (the true values) still drive every label.
    max_total = max(totals) if any(totals) else 1.0
    min_visible_handshake = max_total * MIN_VISIBLE_HANDSHAKE_FRAC
    rendered_handshake_vals = [
        max(h, min_visible_handshake) if h > 0 else 0.0 for h in handshake_vals
    ]
    render_tops = [p + rh for p, rh in zip(payload_vals, rendered_handshake_vals)]

    # Figure size tracks the column count directly (rather than a wide fixed
    # minimum) so a trace with only a couple of protocols doesn't end up
    # dwarfed by empty canvas on both axes.
    n = len(names)
    fig, ax = plt.subplots(figsize=(max(3.5, 1.3 * n), 3.0), dpi=150)
    fig.patch.set_facecolor(SURFACE_COLOR)
    ax.set_facecolor(SURFACE_COLOR)

    x = range(n)
    bar_width = 0.6
    gap_lw = 1.5  # ~2px surface-color gap separating the two stacked segments
    # Hug the columns instead of matplotlib's default 5% autoscale margin --
    # with few columns that default margin reads as dead space on both sides.
    ax.set_xlim(-0.5, n - 0.5)

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
        rendered_handshake_vals,
        width=bar_width,
        bottom=payload_vals,
        color=HANDSHAKE_COLOR,
        edgecolor=SURFACE_COLOR,
        linewidth=gap_lw,
        label="Handshake",
    )

    # Two stacked labels per column, offset in points (not data units) so
    # their gap stays constant regardless of figure size or the data's
    # scale -- a fixed fraction of `max_total` would compress right along
    # with a shorter figure and start overlapping.
    #
    # Bottom line, right above the cap: the handshake segment's own true %
    # of total traffic -- since a real handshake sliver is often floored to
    # a visible minimum (see MIN_VISIBLE_HANDSHAKE_FRAC), its rendered area
    # can be exaggerated relative to its real value, so the reader needs
    # the number, not just the area, to read it accurately.
    #
    # Top line: the payload segment's % of total traffic. Pushed up an
    # extra LABEL_LINE_GAP_PT above the handshake line only when a
    # handshake line is actually drawn beneath it; otherwise it sits right
    # above the cap like the handshake line would have.
    HANDSHAKE_LABEL_OFFSET_PT = 4
    LABEL_LINE_GAP_PT = 13
    for xi, payload, handshake, render_top in zip(
        x, payload_vals, handshake_vals, render_tops
    ):
        if handshake > 0:
            # ".2f" rounds anything under 0.01% down to a bare "0.00%",
            # which reads as "no handshake" -- exactly the misleading
            # impression this label exists to correct. Say "<0.01%" instead.
            label = "<0.01%" if handshake < 0.005 else f"{handshake:.2f}%"
            ax.annotate(
                label,
                xy=(xi, render_top),
                xytext=(0, HANDSHAKE_LABEL_OFFSET_PT),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=7,
                color=HANDSHAKE_COLOR,
            )
        payload_offset = HANDSHAKE_LABEL_OFFSET_PT + (
            LABEL_LINE_GAP_PT if handshake > 0 else 0
        )
        if payload > 0:
            ax.annotate(
                f"{payload:.2f}%",
                xy=(xi, render_top),
                xytext=(0, payload_offset),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=9,
                color=PAYLOAD_COLOR,
            )

    # The labels above are placed in fixed *point* offsets, not data units,
    # so the axes' data-to-point scale (which depends on figure size) has to
    # be known before we can size the headroom above the tallest column --
    # draw once, then grow the y-limit to fit whatever the renderer actually
    # produced, rather than guessing a fraction of max_total up front.
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    label_tops = [
        ax.transData.inverted().transform((0, txt.get_window_extent(renderer).ymax))[
            1
        ]
        for txt in ax.texts
    ]
    top = max(label_tops, default=max_total)

    ax.set_xticks(list(x))
    ax.set_xticklabels(names, color=INK_PRIMARY)
    ax.set_ylabel("% of total transport bytes", color=INK_PRIMARY)

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.spines["bottom"].set_color(BASELINE_COLOR)
    ax.tick_params(axis="x", colors=INK_MUTED, length=0)
    ax.tick_params(axis="y", colors=INK_MUTED)
    ax.yaxis.grid(True, color=GRIDLINE_COLOR, linewidth=1)
    ax.set_axisbelow(True)

    # A little extra breathing room above the tallest label so its top
    # doesn't sit flush against the figure edge.
    ax.set_ylim(0, top * 1.05)

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
        default="encrypted_bytes_chart.pdf",
        help="Output image path (default: %(default)s)",
    )
    parser.add_argument(
        "--other-threshold",
        type=float,
        default=OTHER_THRESHOLD_PCT,
        metavar="PCT",
        help="Fold protocols below this %% of total transport traffic into a "
        "single 'Other' column (default: %(default)s). Use 0 to disable.",
    )
    args = parser.parse_args()

    if args.input == "-":
        text = sys.stdin.read()
    else:
        with open(args.input) as f:
            text = f.read()

    rows = parse(text)
    rows = group_small(rows, args.other_threshold)
    plot(rows, args.output)


if __name__ == "__main__":
    main()
