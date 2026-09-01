#!/usr/bin/env python3
"""Plot the `encrypted_bytes` example's output as a stacked column chart.

Reads the text printed by `cargo run --example encrypted_bytes` (or a file/pipe
carrying that output) and draws one column per protocol, split into "Payload",
"Headers", and "Handshake" segments, each sized as a % of *total transport
traffic* (TCP + UDP) -- the same figure the Rust app itself prints as "of total
traffic" (see `print_proto` in examples/encrypted_bytes/src/main.rs).

The three segments are the app's own three buckets and partition a protocol's
on-wire bytes: whole frames up to the end of its L7 handshake ("Handshake"),
then, for every frame after that, the L4 payload ("Payload") and the
Ethernet/IP/TCP/UDP header bytes carrying it ("Headers"). Payload and Headers
sit adjacent at the bottom of the stack because they are two halves of the same
post-handshake traffic; the header segment is what the bulk transfer costs
beyond the bulk itself.

"QUIC" and "MaybeQUIC" (the real parser's rows vs. the heuristic mid-stream
detector's row) are merged into a single "QUIC" column, since they're two
detection paths for the same protocol.

Any protocol whose own % of total transport traffic is below 1% (configurable
with `--other-threshold`) is folded into a single "Other" column instead of
getting its own sliver of a bar.

A protocol's handshake or header share is often a small fraction of its own
bytes, and that share is then scaled again by the protocol's share of total
traffic -- in practice this routinely produces segments a few hundredths to a
few tenths of a percentage point tall, too thin to render as visible area at
all. To keep a real, nonzero share from silently disappearing, any such segment
is floored to a minimum rendered height and paired with a small text label
giving its true (unfloored) percentage -- see `MIN_VISIBLE_SEGMENT_FRAC` in
`plot()`.

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
#   "TLS      handshake:  2.34%  payload: 90.00%  headers:  7.66%  of total traffic: 5.02%"
#   "MaybeZoom  handshake:  n/a   payload: 94.10%  headers:  5.90%  of total traffic: 0.01%"
LINE_RE = re.compile(
    r"^(?P<name>\S+)\s+handshake:\s*(?P<handshake>\S+)"
    r"\s+payload:\s*(?P<payload>\S+)"
    r"\s+headers:\s*(?P<headers>\S+)"
    r"\s+of total traffic:\s*(?P<total>\S+)"
)

# Rows merged into a single "QUIC" column -- see module docstring.
QUIC_ALIASES = ("QUIC", "MaybeQUIC")
QUIC_MERGED_NAME = "QUIC"

# Rows below this % of total transport traffic are folded into "Other".
OTHER_THRESHOLD_PCT = 1.0
OTHER_NAME = "Other"

# Any nonzero segment is floored to at least this fraction of the chart's
# tallest column, so a real-but-tiny share always renders as a visible sliver
# instead of vanishing under the gap edges between stacked segments. Purely a
# rendering floor -- the cap labels and axis scaling still use the true values;
# only the drawn bar geometry is exaggerated.
MIN_VISIBLE_SEGMENT_FRAC = 0.008

# Fixed categorical slots 1-3, never reordered/cycled. These three validate on
# every pair in both light and dark modes, so the stack can order them by
# meaning (Payload and Headers adjacent at the bottom, Handshake on top) rather
# than by slot index.
PAYLOAD_COLOR = "#2a78d6"  # slot 1, blue
HANDSHAKE_COLOR = "#eb6834"  # slot 2, orange
HEADERS_COLOR = "#1baf7a"  # slot 3, aqua
# Slot 3 sits just under 3:1 contrast on the light surface, which is fine for a
# bar (the relief rule is satisfied by the direct labels below) but thin for
# 7pt text. The labels use the palette's documented dark step for the same slot.
HEADERS_LABEL_COLOR = "#199e70"
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
    """Extract each protocol's handshake/payload/header % of *total transport traffic*.

    Returns an OrderedDict of
    name -> (handshake_pct_of_total, payload_pct_of_total, header_pct_of_total),
    in the order the rows first appeared in the input, with "QUIC" and
    "MaybeQUIC" merged into one "QUIC" entry.
    """
    rows = OrderedDict()
    for line in text.splitlines():
        m = LINE_RE.match(line.strip())
        if not m:
            continue
        name = m.group("name")
        of_total = _pct(m.group("total"))

        # `handshake`/`payload`/`headers` are each protocol's *own* split (they
        # sum to 100% of that protocol's bytes); scale by its share of
        # transport traffic so every protocol stacks correctly on one shared
        # "% of total transport traffic" axis.
        split = tuple(
            of_total * _pct(m.group(field)) / 100.0
            for field in ("handshake", "payload", "headers")
        )

        key = QUIC_MERGED_NAME if name in QUIC_ALIASES else name
        if key in rows:
            rows[key] = tuple(prev + cur for prev, cur in zip(rows[key], split))
        else:
            rows[key] = split
    return rows


def group_small(rows, threshold=OTHER_THRESHOLD_PCT):
    """Fold every row whose total % of transport traffic is below `threshold`
    into a single combined "Other" row, so a long tail of near-zero protocols
    doesn't clutter the chart with unreadable slivers.

    Rows are compared and combined on their *total* (handshake + payload +
    headers); the combined row's three-way split is just the sum of the folded
    rows' own splits, same as the QUIC/MaybeQUIC merge in `parse`.
    """
    kept = OrderedDict()
    other = None
    for name, split in rows.items():
        if sum(split) < threshold:
            other = split if other is None else tuple(a + b for a, b in zip(other, split))
        else:
            kept[name] = split
    if other is not None and any(other):
        kept[OTHER_NAME] = other
    return kept


def plot(rows, out_path):
    if not rows:
        raise SystemExit(
            "No protocol rows found -- is this really `encrypted_bytes`'s output? "
            "Expected lines like "
            "'TLS   handshake: ...  payload: ...  headers: ...  of total traffic: ...'."
        )

    # Columns sorted by total % of transport traffic, largest first.
    names = sorted(rows.keys(), key=lambda n: sum(rows[n]), reverse=True)
    handshake_vals = [rows[n][0] for n in names]
    payload_vals = [rows[n][1] for n in names]
    header_vals = [rows[n][2] for n in names]
    totals = [sum(rows[n]) for n in names]

    # Floor nonzero segments to a minimum rendered height (see
    # MIN_VISIBLE_SEGMENT_FRAC) so a real share is never drawn as literally
    # invisible. The rendered values are for bar geometry only -- the true
    # values still drive every label and the axis scale.
    max_total = max(totals) if any(totals) else 1.0
    min_visible = max_total * MIN_VISIBLE_SEGMENT_FRAC

    def rendered(vals):
        return [max(v, min_visible) if v > 0 else 0.0 for v in vals]

    render_payload = rendered(payload_vals)
    render_headers = rendered(header_vals)
    render_handshake = rendered(handshake_vals)
    # Bottoms of the second and third stacked segments.
    headers_bottoms = render_payload
    handshake_bottoms = [p + h for p, h in zip(render_payload, render_headers)]
    render_tops = [b + hs for b, hs in zip(handshake_bottoms, render_handshake)]

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

    for values, bottoms, color, label in (
        (render_payload, None, PAYLOAD_COLOR, "Payload"),
        (render_headers, headers_bottoms, HEADERS_COLOR, "Headers"),
        (render_handshake, handshake_bottoms, HANDSHAKE_COLOR, "Handshake"),
    ):
        ax.bar(
            x,
            values,
            width=bar_width,
            bottom=bottoms,
            color=color,
            edgecolor=SURFACE_COLOR,
            linewidth=gap_lw,
            label=label,
        )

    # One label line per nonzero segment, stacked above the column in the
    # stack's own bottom-to-top order (handshake, headers, payload -- reading
    # up from the cap mirrors reading down the bar). Offsets are in points, not
    # data units, so the gap between lines stays constant regardless of figure
    # size or the data's scale -- a fixed fraction of `max_total` would
    # compress right along with a shorter figure and start overlapping.
    #
    # These numbers aren't decoration: a real-but-tiny segment is often floored
    # to a visible minimum (see MIN_VISIBLE_SEGMENT_FRAC), so its rendered area
    # can be exaggerated relative to its true value, and the reader needs the
    # number rather than the area to read it accurately. Lines for segments a
    # protocol doesn't have are skipped rather than printed as 0.00%, so the
    # remaining lines close up against the cap.
    FIRST_LABEL_OFFSET_PT = 4
    LABEL_LINE_GAP_PT = 13
    for xi, handshake, headers, payload, render_top in zip(
        x, handshake_vals, header_vals, payload_vals, render_tops
    ):
        offset = FIRST_LABEL_OFFSET_PT
        for value, color, fontsize in (
            (handshake, HANDSHAKE_COLOR, 7),
            (headers, HEADERS_LABEL_COLOR, 7),
            (payload, PAYLOAD_COLOR, 9),
        ):
            if value <= 0:
                continue
            # ".2f" rounds anything under 0.01% down to a bare "0.00%", which
            # reads as "this segment isn't there" -- exactly the misleading
            # impression these labels exist to correct. Say "<0.01%" instead.
            label = "<0.01%" if value < 0.005 else f"{value:.2f}%"
            ax.annotate(
                label,
                xy=(xi, render_top),
                xytext=(0, offset),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=fontsize,
                color=color,
            )
            offset += LABEL_LINE_GAP_PT

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
