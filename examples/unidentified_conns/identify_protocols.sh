#!/usr/bin/env bash
# Post-processes the packet captures written by the `unidentified_conns` Iris application:
# runs every connection in them through tshark's dissectors and prints the most common
# protocols, ranked by how many connections resolved to each one.
#
# The input captures hold only the connections Iris's own parsers could not identify, so this
# is a second opinion on that leftover traffic from an independent set of parsers.
#
# The app shards its output one file per core. Iris pins a connection to a single core for its
# lifetime, so no connection is split across files and the shards can simply be pooled here.
#
# Protocols come from tshark's `frame.protocols` field, i.e. the layers it actually dissected,
# and each connection is reported as the protocol sitting directly above its transport layer.
#
# Caveat: tshark selects some dissectors by well-known port before falling back to its
# heuristic (content-sniffing) dissectors, so a small number of these labels can still be
# port-derived rather than purely parsed.

set -euo pipefail

TOP_N=""
SHOW_HIERARCHY=0

usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") [-n N] [-H] [pcap ...]

  pcap    Packet captures written by the unidentified_conns app
          (default: every unidentified_core*.pcap in the current directory)
  -n N    Only show the top N protocols (default: show all)
  -H      Also print tshark's full protocol hierarchy for each capture
EOF
}

while getopts ":n:Hh" opt; do
    case "$opt" in
        n) TOP_N="$OPTARG" ;;
        H) SHOW_HIERARCHY=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

if ! command -v tshark >/dev/null 2>&1; then
    echo "error: tshark not found. Install it with: sudo apt install tshark" >&2
    exit 1
fi

PCAPS=("$@")
if [[ ${#PCAPS[@]} -eq 0 ]]; then
    shopt -s nullglob
    PCAPS=(unidentified_core*.pcap)
    shopt -u nullglob
fi

if [[ ${#PCAPS[@]} -eq 0 ]]; then
    echo "error: no capture files given, and no unidentified_core*.pcap in $(pwd)." >&2
    echo "Run the unidentified_conns app first, e.g.:" >&2
    echo "  sudo env LD_LIBRARY_PATH=\$LD_LIBRARY_PATH ./target/release/unidentified_conns --config configs/offline.toml" >&2
    exit 1
fi

for pcap in "${PCAPS[@]}"; do
    if [[ ! -f "$pcap" ]]; then
        echo "error: '$pcap' not found." >&2
        exit 1
    fi
done

# One row per frame, tagged with its source file: which TCP or UDP stream the frame belongs to,
# and the protocol layers tshark dissected for it. Stream numbering restarts in every file and
# is separate per transport, so the file name and a transport tag both go into the key.
RANKED=$(for pcap in "${PCAPS[@]}"; do
    tshark -r "$pcap" -T fields -e tcp.stream -e udp.stream -e frame.protocols 2>/dev/null |
        sed "s|^|${pcap}\t|"
done |
    awk -F'\t' '
    {
        if ($2 != "") conn = $1 "T" $2
        else if ($3 != "") conn = $1 "U" $3
        else next

        stack = $4
        if (stack == "") next
        depth = split(stack, layers, ":")

        # Report the layer sitting directly on top of the transport: that is the application
        # protocol. Deeper layers are content dissectors within it (an HTTP response body
        # showing up as "image-gif" or "xml" is still HTTP). The last tcp/udp layer wins, so
        # tunneled traffic is reported as its innermost protocol.
        transport = 0
        for (i = 1; i <= depth; i++)
            if (layers[i] == "tcp" || layers[i] == "udp") transport = i
        if (transport == 0) next

        if (transport == depth) {
            # Nothing above the transport: no payload, or none tshark could dissect.
            proto = layers[transport] "-no-payload"
            score = 0
        } else if (layers[transport + 1] == "data") {
            # Payload present, but opaque to every dissector tshark tried.
            proto = "data-unparsed"
            score = 1
        } else {
            proto = layers[transport + 1]
            score = 2
        }

        # A connection is summarized by its most informative frame: an identified protocol
        # beats opaque payload, which beats a frame that carried no payload at all.
        if (conn in best_score && score <= best_score[conn]) next
        best_score[conn] = score
        best_proto[conn] = proto
    }
    END {
        for (conn in best_proto) print best_proto[conn]
    }' |
    sort | uniq -c | sort -rn)

if [[ -z "$RANKED" ]]; then
    echo "No TCP or UDP connections found in: ${PCAPS[*]}"
    exit 0
fi

TOTAL=$(echo "$RANKED" | awk '{sum += $1} END {print sum}')

echo "Most common protocols across ${#PCAPS[@]} capture file(s) ($TOTAL connections, identified by parsing)"
echo

if [[ -n "$TOP_N" ]]; then
    RANKED=$(echo "$RANKED" | head -n "$TOP_N")
fi

echo "$RANKED" | awk -v total="$TOTAL" '{
    printf "  %-20s %8d   %6.2f%%\n", $2, $1, ($1 / total) * 100
}'

if [[ "$SHOW_HIERARCHY" -eq 1 ]]; then
    for pcap in "${PCAPS[@]}"; do
        echo
        echo "Full protocol hierarchy for $pcap (per frame, from tshark):"
        tshark -r "$pcap" -q -z io,phs 2>/dev/null
    done
fi
