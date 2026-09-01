#!/usr/bin/env python3
"""Plot the `encrypted_bytes` example's output as a stacked column chart.

Reads the text printed by `cargo run --example encrypted_bytes` (or a file/pipe
carrying that output) and draws one column per protocol, split into "Payload",
"Headers", and "Handshake" segments, each sized as a % of *total transport
traffic* (TCP + UDP) -- the same figure the Rust app itself prints as "of total
traffic" (see `print_proto` in examples/encrypted_bytes/src/main.rs).

Accepts one input per run. Given several, every column is the mean across runs,
the error bar on each column caps the spread of that column's total, and each
segment's cap label carries its own spread beside its mean -- so a protocol's
share rests on repeated measurement rather than on whichever run happened to be
captured. A single input plots that run alone, with no error bars.

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
getting its own sliver of a bar. Across runs the fold is decided on a
protocol's *mean* share and then applied identically to every run, so the
columns are the same set in each and their error bars stay comparable.

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

    # one file per run, mean with error bars:
    python3 examples/encrypted_bytes/plot_encrypted_bytes.py run*.txt
"""
import argparse
import re
import statistics
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

# A protocol absent from a run's output, used in place of its three-way split.
# Not a guess: `encrypted_bytes` prints a row per protocol it tracks, so a
# missing row means that run saw no such traffic at all.
ZERO_SPLIT = (0.0, 0.0, 0.0)

# Any nonzero segment is floored to at least this fraction of the chart's
# tallest column, so a real-but-tiny share always renders as a visible sliver
# instead of vanishing under the gap edges between stacked segments. Purely a
# rendering floor -- the cap labels and axis scaling still use the true values;
# only the drawn bar geometry is exaggerated.
MIN_VISIBLE_SEGMENT_FRAC = 0.008

# Per-column figure width, and the padding kept between a cap label and its
# neighbour's. Columns get wider than the default only when a label demands it.
DEFAULT_COLUMN_WIDTH_IN = 1.3
LABEL_PAD_IN = 0.15
# Rough advance width of one cap-label character, as a fraction of the font
# size. These labels are almost entirely digits and punctuation, which are
# narrower than the alphabetic average, so charging a full em each would
# overshoot the needed width badly.
LABEL_CHAR_WIDTH_EM = 0.62

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


def align_runs(run_rows, labels):
    """Put every run on the same set of protocol columns.

    Returns (names, per_run) with `names` every protocol seen in any run, in
    first-seen order, and per_run[i] mapping all of them to run i's split.
    A protocol missing from a run is zero-filled and reported: the column is
    still the mean over every run, so quietly averaging it over only the runs
    that happened to see the protocol would overstate its share.
    """
    names = []
    for rows in run_rows:
        for name in rows:
            if name not in names:
                names.append(name)
    for name in names:
        absent = [label for label, rows in zip(labels, run_rows) if name not in rows]
        if absent and len(run_rows) > 1:
            print(
                f"note: {name} has no row in {len(absent)} of {len(run_rows)} runs "
                f"({', '.join(absent)}); counted as 0% there.",
                file=sys.stderr,
            )
    per_run = [{name: rows.get(name, ZERO_SPLIT) for name in names} for rows in run_rows]
    return names, per_run


def group_small(names, per_run, threshold=OTHER_THRESHOLD_PCT):
    """Fold every protocol whose total % of transport traffic is below
    `threshold` into a single combined "Other" column, so a long tail of
    near-zero protocols doesn't clutter the chart with unreadable slivers.

    Columns are compared and combined on their *total* (handshake + payload +
    headers); the combined column's three-way split is just the sum of the
    folded ones' own splits, same as the QUIC/MaybeQUIC merge in `parse`.

    Across runs the comparison uses a protocol's mean total, and the resulting
    fold is applied to each run unchanged. Deciding it per run instead would
    let a protocol be its own column in one run and part of "Other" in the
    next, which leaves no consistent set of columns to take a spread over.
    """
    kept_names = []
    folded_names = []
    for name in names:
        mean_total = statistics.fmean(sum(run[name]) for run in per_run)
        (kept_names if mean_total >= threshold else folded_names).append(name)

    kept_per_run = []
    for run in per_run:
        kept = OrderedDict((name, run[name]) for name in kept_names)
        other = ZERO_SPLIT
        for name in folded_names:
            other = tuple(a + b for a, b in zip(other, run[name]))
        if folded_names:
            kept[OTHER_NAME] = other
        kept_per_run.append(kept)

    out_names = list(kept_names)
    # An "Other" that is all zeros in every run carries no information, so it
    # is dropped rather than drawn as an empty column.
    if folded_names and any(any(run[OTHER_NAME]) for run in kept_per_run):
        out_names.append(OTHER_NAME)
    else:
        for run in kept_per_run:
            run.pop(OTHER_NAME, None)
    return out_names, kept_per_run


def spread(values, kind):
    """Spread of one quantity across runs, as (below, above) distances from the
    mean -- the form both matplotlib's `yerr` and the cap labels want. Zero for
    a single run, which has no spread to show."""
    if len(values) < 2:
        return 0.0, 0.0
    mean = statistics.fmean(values)
    if kind == "minmax":
        return mean - min(values), max(values) - mean
    sd = statistics.stdev(values)
    if kind == "sem":
        sd /= len(values) ** 0.5
    return sd, sd


def fmt_spread_label(kind, n_runs):
    if kind == "minmax":
        return f"min-max (n={n_runs})"
    if kind == "sem":
        return f"±1 s.e.m. (n={n_runs})"
    return f"±1 s.d. (n={n_runs})"


def fmt_segment_label(mean, below, above, kind, n_runs):
    """One segment's cap label: its mean share, and across runs its spread.

    The number matters more here than the drawn area does -- a real-but-tiny
    segment is often floored to a visible minimum (see
    MIN_VISIBLE_SEGMENT_FRAC), so its rendered height can be exaggerated
    relative to its true value.
    """
    # ".2f" rounds anything under 0.01% down to a bare "0.00%", which reads as
    # "this segment isn't there" -- exactly the misleading impression these
    # labels exist to correct. Say "<0.01%" instead, and skip the spread: a ±
    # on a number that is itself below the printed precision says nothing.
    if mean < 0.005:
        return "<0.01%"
    if n_runs < 2:
        return f"{mean:.2f}%"
    # A spread that rounds to "0.00" reads as "the runs agreed exactly", which
    # is a stronger claim than the data supports. Borrow the same "<0.01"
    # convention used above for a value below the printed precision.
    if max(below, above) < 0.005:
        return f"{mean:.2f} ±<0.01%"
    if kind == "minmax":
        return f"{mean:.2f} +{above:.2f}/-{below:.2f}%"
    return f"{mean:.2f} ± {above:.2f}%"


def plot(names, per_run, out_path, spread_kind="std"):
    if not names:
        raise SystemExit(
            "No protocol rows found -- is this really `encrypted_bytes`'s output? "
            "Expected lines like "
            "'TLS   handshake: ...  payload: ...  headers: ...  of total traffic: ...'."
        )

    n_runs = len(per_run)
    # Columns sorted by mean % of transport traffic, largest first.
    def mean_total(name):
        return statistics.fmean(sum(run[name]) for run in per_run)

    names = sorted(names, key=mean_total, reverse=True)

    def segment_means(index):
        return [
            statistics.fmean(run[name][index] for run in per_run) for name in names
        ]

    handshake_vals, payload_vals, header_vals = (segment_means(i) for i in range(3))
    totals = [mean_total(name) for name in names]

    # Spreads, all taken over the same runs as the means above: one per segment
    # for the cap labels, plus one per column total for the error bar.
    segment_spreads = [
        [spread([run[name][i] for run in per_run], spread_kind) for name in names]
        for i in range(3)
    ]
    total_spreads = [
        spread([sum(run[name]) for run in per_run], spread_kind) for name in names
    ]

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

    n = len(names)

    # Cap label text is settled before the figure is sized, because the widest
    # label is what actually decides whether a column has room for it: the
    # spread appended across runs can more than double a label's length, and
    # centred over an edge column a too-long one spills past the axes.
    column_labels = []
    for i in range(n):
        entries = []
        for index, color, fontsize in (
            (0, HANDSHAKE_COLOR, 7),
            (2, HEADERS_LABEL_COLOR, 7),
            (1, PAYLOAD_COLOR, 9),
        ):
            value = (handshake_vals, payload_vals, header_vals)[index][i]
            # Segments a protocol doesn't have are skipped rather than printed
            # as 0.00%, so the remaining lines close up against the cap.
            if value <= 0:
                continue
            below, above = segment_spreads[index][i]
            text = fmt_segment_label(value, below, above, spread_kind, n_runs)
            entries.append((text, fontsize, color))
        column_labels.append(entries)

    # Figure size tracks the column count directly (rather than a wide fixed
    # minimum) so a trace with only a couple of protocols doesn't end up
    # dwarfed by empty canvas on both axes, and widens past the default column
    # if the labels need it.
    widest_label_in = max(
        (
            len(text) * fontsize * LABEL_CHAR_WIDTH_EM / 72.0
            for entries in column_labels
            for text, fontsize, _ in entries
        ),
        default=0.0,
    )
    column_width_in = max(DEFAULT_COLUMN_WIDTH_IN, widest_label_in + LABEL_PAD_IN)
    fig, ax = plt.subplots(figsize=(max(3.5, column_width_in * n), 3.0), dpi=150)
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

    # One error bar per column, on the column *total*: a stacked bar has no
    # unambiguous place to hang three separate ones, and the boundaries between
    # segments would move under each other's spread. The per-segment spreads go
    # in the cap labels instead, where they can't be misread as area.
    #
    # Centred on the drawn top of the stack rather than on the true total,
    # which the rendering floor can leave slightly below it -- an error bar
    # floating off the end of its own bar reads as a bug, and the labels
    # already carry the exact numbers.
    label_anchors = list(render_tops)
    if n_runs > 1:
        ax.errorbar(
            list(x),
            render_tops,
            yerr=[
                [below for below, _ in total_spreads],
                [above for _, above in total_spreads],
            ],
            fmt="none",
            ecolor=INK_SECONDARY,
            elinewidth=1.0,
            capsize=3,
            capthick=1.0,
            label=fmt_spread_label(spread_kind, n_runs),
        )
        # Cap labels start above the error bar, not above the bar, so the two
        # don't overprint on the columns with the widest spread.
        label_anchors = [
            top + above for top, (_, above) in zip(render_tops, total_spreads)
        ]

    # The label lines stack above the column in the stack's own bottom-to-top
    # order (handshake, headers, payload -- reading up from the cap mirrors
    # reading down the bar). Offsets are in points, not data units, so the gap
    # between lines stays constant regardless of figure size or the data's
    # scale -- a fixed fraction of `max_total` would compress right along with
    # a shorter figure and start overlapping.
    FIRST_LABEL_OFFSET_PT = 4
    LABEL_LINE_GAP_PT = 13
    for xi, anchor, entries in zip(x, label_anchors, column_labels):
        offset = FIRST_LABEL_OFFSET_PT
        for text, fontsize, color in entries:
            ax.annotate(
                text,
                xy=(xi, anchor),
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


def read_runs(paths):
    """Read each run's `encrypted_bytes` output, returning (run_rows, labels).

    Runs with no parsable protocol rows are dropped with a warning rather than
    contributing an all-zero column set to the mean.
    """
    run_rows = []
    labels = []
    stdin_text = None
    for path in paths:
        if path == "-":
            # Only one run can come from a pipe; re-reading a drained stdin for
            # a second "-" would silently contribute an empty run.
            if stdin_text is None:
                stdin_text = sys.stdin.read()
            text = stdin_text
            label = "<stdin>"
        else:
            with open(path) as f:
                text = f.read()
            label = path
        rows = parse(text)
        if not rows:
            print(
                f"warning: {label} has no protocol rows; skipping it.", file=sys.stderr
            )
            continue
        run_rows.append(rows)
        labels.append(label)
    return run_rows, labels


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        default=["-"],
        metavar="INPUT",
        help="One file holding `encrypted_bytes`'s stdout per run, "
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
    parser.add_argument(
        "--spread",
        choices=("std", "sem", "minmax"),
        default="std",
        help="What the error bars and the ± on each cap label show across "
        "runs: sample standard deviation, standard error of the mean, or the "
        "full min-max range (default: %(default)s)",
    )
    args = parser.parse_args()

    run_rows, labels = read_runs(args.inputs)
    if not run_rows:
        raise SystemExit("No input had any protocol rows.")

    names, per_run = align_runs(run_rows, labels)
    names, per_run = group_small(names, per_run, args.other_threshold)
    plot(names, per_run, args.output, args.spread)


if __name__ == "__main__":
    main()
