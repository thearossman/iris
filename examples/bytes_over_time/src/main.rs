//! Reports, for each fixed-width time slice (`--slice-ms`, default 1000ms), how many bytes
//! were seen on each of Iris's identified encrypted-protocol connections (TLS, SSH, QUIC,
//! WireGuard, IKE), on heuristically-detected mid-stream QUIC/Zoom traffic (`MaybeQuic`,
//! `MaybeZoom`), and on total TCP/UDP transport traffic -- each protocol split into cleartext
//! handshake bytes vs. encrypted payload bytes, following `examples/encrypted_bytes`.
//!
//! This app is the combination of `examples/concurrent_conns` (fixed-width time slicing,
//! stdout table + CSV output) and `examples/encrypted_bytes` (per-protocol byte attribution
//! and the handshake/payload split) -- see each for the reasoning this app reuses.
//!
//! The per-slice byte counts are printed to stdout (summed across handshake+payload, for
//! readability) and written as wide CSV (one column pair per protocol, plus `tcp_bytes`/
//! `udp_bytes`) to `--outfile` (default `bytes.csv`), one row per slice.
//!
//! ## Why a datatype, not a callback
//! As in `encrypted_bytes`: an L7 callback wrapper only becomes `is_active()` at `L7OnDisc`,
//! by which point the packet that triggered discovery has already been dispatched at
//! `InL4Conn` by the pre-reassembly update. Counting there drops each connection's first data
//! packet(s) outright. `ByteSeries` is a plain (untracked) `#[datatype]` instead, so every
//! packet from the connection's first byte is counted regardless of whether a protocol has
//! been identified yet.
//!
//! ## Why not `L4Pdu::app_body_offset()`
//! Also as in `encrypted_bytes`: `app_offset` is only touched while the L7 layer's `Parse`
//! action is set, which is cleared as soon as headers finish for four of the five protocols
//! here (everything but QUIC) -- so it can't tell "still in handshake" from "deep in payload"
//! for most of a connection's life. `ByteSeries` instead tracks an `in_payload` flag flipped
//! exactly once by an `L7EndHdrs`-level method; every packet after headers finish is counted
//! as payload regardless of parser activity. The packet on which headers finish is counted
//! entirely as handshake (a whole-packet approximation on that one packet), because `InL4Conn`
//! is dispatched before `process_stream` reaches `L7EndHdrs` and flips the flag.
//!
//! ## Why bytes are collected once, at `L4Terminated`, not streamed live
//! `MaybeQuic`/`MaybeZoom` are streaming filters that only accept a connection after up to
//! `MAYBE_QUIC_WINDOW` (12) payload-bearing packets, so which global series a
//! connection's bytes belong to isn't known until the filter decides (or the connection ends).
//! Rather than guess and correct, every connection buffers its own per-slice byte histogram
//! and flushes it once, when the callback filter resolves which protocol (if any) matched.
//!
//! As in `concurrent_conns`, `L4Terminated` is the collection *point*, but each byte is
//! attributed to the slice its packet actually arrived in (from `L4Pdu::ts`), not to "now" --
//! otherwise Iris's inactivity timeouts (60s UDP / 300s TCP by default) would smear a
//! connection's bytes forward to whenever it happened to time out.
//!
//! ## Bounding per-connection memory: sparse buckets + adaptive coarsening
//! Unlike `concurrent_conns` (which holds no per-connection state at all), a byte time series
//! can't fully avoid it -- bytes must be attributed to the slice they arrived in, and which
//! global series they ultimately land in isn't known until teardown. Memory is bounded instead
//! of avoided: each connection's histogram is a sparse `Vec<SliceBytes>` (one entry per slice
//! actually touched, appended in order since packet timestamps are non-decreasing within a
//! connection) capped at `--max-conn-slices` (default 512, ~12KB/conn). Once the cap is hit,
//! the vector is coarsened -- pairwise-merged into half as many entries, each now covering two
//! slices -- so coverage stays complete but temporal resolution degrades, and only
//! logarithmically: at the default 1s slice width a connection gets full 1s resolution for its
//! first ~8.5 minutes, 2s resolution for the next ~17 minutes, 4s for the next ~34, and so on.
//!
//! ## `--min-bytes`
//! As in `encrypted_bytes`: passing `--min-bytes N` excludes any connection whose own total
//! byte count is not more than `N` from every counter and every slice -- checked once per
//! connection, at `L4Terminated`, using that connection's own running total. Default is 0.
//!
//! ## Column overlap
//! As in `encrypted_bytes`: a TLS connection's bytes land in both the `tls_*` columns and
//! `tcp_bytes` (via a *separate* `TransportBytes`-style datatype tracking the same packets).
//! The protocol columns and the transport columns are not meant to be summed together.
//!
//! ## Timestamps are processing time, not capture time
//! As in `concurrent_conns`: `L4Pdu::ts` comes from `Instant::now()` when a packet is
//! processed, not from any timestamp recorded in a capture file. For offline pcap replay an
//! entire trace can be replayed in far less than a second of processing time, so offline runs
//! are useful here only as a correctness smoke test, not a trace-accurate measurement.

use clap::Parser;
use iris_compiler::{callback, datatype, datatype_fn, input_files, iris_end_macros};
use iris_core::protocols::packet::tcp::TCP_PROTOCOL;
use iris_core::protocols::packet::udp::UDP_PROTOCOL;
use iris_core::protocols::stream::SessionProto;
use iris_core::subscription::Tracked;
use iris_core::{config::load_config, L4Pdu, Runtime};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use lazy_static::lazy_static;

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,

    /// Width of each time slice, in milliseconds.
    #[clap(long, value_name = "MS", default_value_t = 1000)]
    slice_ms: u64,

    /// Length of the accounting horizon, in seconds -- does not limit how long the run itself
    /// lasts. Sizes the fixed-size per-slice arrays up front. A connection whose lifetime runs
    /// past this horizon has its bytes folded into the final slice instead of growing the
    /// arrays, and is counted in the overflow warning printed at the end of the run.
    #[clap(long, value_name = "SECS", default_value_t = 48 * 3600)]
    max_duration_secs: u64,

    /// Only count a connection (and the packets in it) if its total byte count is more than N.
    /// 0 (the default) counts every connection.
    #[clap(short, long, value_name = "N", default_value_t = 0)]
    min_bytes: usize,

    /// Cap on how many distinct (possibly coarsened) time-slice entries a single connection's
    /// in-progress byte histogram may hold before it is coarsened (halved) in place. Bounds
    /// per-connection memory at the cost of temporal resolution for very long-lived
    /// connections -- see the module docs.
    #[clap(long, value_name = "N", default_value_t = 512)]
    max_conn_slices: usize,

    /// Path to also write the per-slice byte counts as CSV, one row per slice, columns
    /// `slice_start_s,<proto>_handshake,<proto>_payload,...,tcp_bytes,udp_bytes`.
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "bytes.csv"
    )]
    outfile: PathBuf,
}

lazy_static! {
    /// The run's time origin, captured once in `main` before `runtime.run()` starts -- so
    /// slice 0 always begins at runtime start. See `concurrent_conns`.
    static ref EPOCH: Instant = Instant::now();
}

/// Set once from `--slice-ms` before `runtime.run()`, read on every packet.
static SLICE_MS: AtomicU64 = AtomicU64::new(1000);
/// Set once from `--min-bytes` before `runtime.run()`, read once per connection at
/// `L4Terminated`. 0 means no filtering.
static MIN_BYTES: AtomicUsize = AtomicUsize::new(0);
/// Set once from `--max-conn-slices` before `runtime.run()`, read on every packet.
static MAX_CONN_SLICES: AtomicUsize = AtomicUsize::new(512);

/// Number of protocol series tracked: TLS, SSH, QUIC, WireGuard, IKE, MaybeQuic, MaybeZoom.
const NUM_PROTOS: usize = 7;
const PROTO_NAMES: [&str; NUM_PROTOS] = [
    "TLS",
    "SSH",
    "QUIC",
    "WireGuard",
    "IKE",
    "MaybeQuic",
    "MaybeZoom",
];
/// Lowercase CSV column prefixes, matching [`PROTO_NAMES`] index-for-index.
const PROTO_COLUMNS: [&str; NUM_PROTOS] = [
    "tls",
    "ssh",
    "quic",
    "wireguard",
    "ike",
    "maybe_quic",
    "maybe_zoom",
];

/// Global per-slice handshake/payload byte arrays for one protocol series. Sized once (from
/// `--max-duration-secs`/`--slice-ms`) before `runtime.run()` starts.
struct SeriesArrays {
    handshake: Vec<AtomicU64>,
    payload: Vec<AtomicU64>,
}

impl SeriesArrays {
    fn new(num_slices: usize) -> Self {
        Self {
            handshake: (0..num_slices).map(|_| AtomicU64::new(0)).collect(),
            payload: (0..num_slices).map(|_| AtomicU64::new(0)).collect(),
        }
    }
}

/// Indexed by [`proto_index`]/[`PROTO_NAMES`]: 0 TLS, 1 SSH, 2 QUIC, 3 WireGuard, 4 IKE,
/// 5 MaybeQuic, 6 MaybeZoom.
static PROTO_SERIES: OnceLock<Vec<SeriesArrays>> = OnceLock::new();
/// `[0]` = TCP, `[1]` = UDP; totals only, no handshake/payload split -- see the module docs
/// on why the transport series is tracked separately from the protocol series.
static TRANSPORT_SERIES: OnceLock<[Vec<AtomicU64>; 2]> = OnceLock::new();

/// Total connections collected per series, across all slices. Indexed as [`PROTO_SERIES`].
static PROTO_CONN_COUNTS: [AtomicUsize; NUM_PROTOS] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];
/// Connections whose lifetime extended past `--max-duration-secs` and had some bytes folded
/// into the final slice rather than accurately bucketed.
static OVERFLOWED_CONNS: AtomicUsize = AtomicUsize::new(0);

/// Maps an identified `SessionProto` to its slot in [`PROTO_SERIES`]/[`PROTO_NAMES`] for the
/// five real parsers. `None` for anything else -- unreachable in practice, since
/// `record_enc_series`'s filter only matches these five protocols, but matched defensively
/// rather than assumed. See `concurrent_conns::proto_index`.
fn proto_index(proto: &SessionProto) -> Option<usize> {
    match proto {
        SessionProto::Tls => Some(0),
        SessionProto::Ssh => Some(1),
        SessionProto::Quic => Some(2),
        SessionProto::Wireguard => Some(3),
        SessionProto::Ike => Some(4),
        _ => None,
    }
}

/// Whether a connection with `total_bytes` clears the `--min-bytes` bar, i.e. should be
/// counted. "More than" is strict, so a connection with exactly `min_bytes` bytes is excluded.
/// Lifted from `encrypted_bytes`.
fn clears_min_bytes(total_bytes: usize, min_bytes: usize) -> bool {
    total_bytes > min_bytes
}

#[cfg(test)]
mod min_bytes_tests {
    use super::*;

    #[test]
    fn zero_threshold_excludes_only_empty_connections() {
        assert!(!clears_min_bytes(0, 0));
        assert!(clears_min_bytes(1, 0));
    }

    #[test]
    fn strictly_greater_than() {
        assert!(!clears_min_bytes(100, 100));
        assert!(clears_min_bytes(101, 100));
        assert!(!clears_min_bytes(0, 100));
    }
}

/// Maps a packet's timestamp (an offset from [`EPOCH`], in milliseconds) to the global slice
/// index it falls in, clamped to the last valid index if it runs past the array's fixed
/// horizon. The returned bool is `true` iff clamping was needed.
fn global_slice(ts_ms: u64, slice_ms: u64, num_slices: usize) -> (usize, bool) {
    let last_idx = num_slices - 1;
    let raw = (ts_ms / slice_ms) as usize;
    (raw.min(last_idx), raw > last_idx)
}

#[cfg(test)]
mod global_slice_tests {
    use super::*;

    #[test]
    fn within_horizon() {
        assert_eq!(global_slice(2500, 1000, 10), (2, false));
    }

    #[test]
    fn clamps_past_horizon() {
        assert_eq!(global_slice(10_500, 1000, 5), (4, true));
    }
}

/// One (possibly coarsened) entry in a connection's in-progress byte histogram. `key` is an
/// absolute *coarse* slice index: the connection's current `coarsen_shift` determines how many
/// real slices (`1 << coarsen_shift`) it represents, starting at `key << coarsen_shift`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SliceBytes {
    key: u32,
    handshake: u64,
    payload: u64,
}

/// Appends `(handshake, payload)` bytes at `global_slice`, coarsened by `shift`, onto `buckets`
/// -- extending the last entry if its key matches, else pushing a new one. Packet timestamps
/// are non-decreasing within a connection, so this only ever needs to look at the last entry;
/// defensively, a coarse key *less* than the last one (an out-of-order packet) is folded into
/// the last entry instead of breaking the ordering invariant `coarsen`/flush depend on.
fn push_bytes(
    buckets: &mut Vec<SliceBytes>,
    global_slice: usize,
    shift: u32,
    handshake: u64,
    payload: u64,
) {
    let key = (global_slice >> shift) as u32;
    match buckets.last_mut() {
        Some(last) if last.key == key => {
            last.handshake += handshake;
            last.payload += payload;
        }
        Some(last) if key < last.key => {
            last.handshake += handshake;
            last.payload += payload;
        }
        _ => buckets.push(SliceBytes {
            key,
            handshake,
            payload,
        }),
    }
}

/// Halves `buckets` in place by merging adjacent pairs (summing their bytes, halving their
/// key), doubling the slice width each entry represents. Byte-conserving: the sum of all
/// `handshake`/`payload` fields is unchanged. An odd trailing entry is kept as-is (its pair
/// hasn't arrived yet).
fn coarsen(buckets: &mut Vec<SliceBytes>) {
    let mut merged = Vec::with_capacity(buckets.len().div_ceil(2));
    let mut iter = std::mem::take(buckets).into_iter();
    while let Some(first) = iter.next() {
        match iter.next() {
            Some(second) => merged.push(SliceBytes {
                key: first.key / 2,
                handshake: first.handshake + second.handshake,
                payload: first.payload + second.payload,
            }),
            None => merged.push(SliceBytes {
                key: first.key / 2,
                handshake: first.handshake,
                payload: first.payload,
            }),
        }
    }
    *buckets = merged;
}

#[cfg(test)]
mod bucket_tests {
    use super::*;

    #[test]
    fn same_key_extends_last() {
        let mut buckets = Vec::new();
        push_bytes(&mut buckets, 5, 0, 10, 0);
        push_bytes(&mut buckets, 5, 0, 0, 20);
        assert_eq!(
            buckets,
            vec![SliceBytes {
                key: 5,
                handshake: 10,
                payload: 20
            }]
        );
    }

    #[test]
    fn new_key_pushes() {
        let mut buckets = Vec::new();
        push_bytes(&mut buckets, 5, 0, 10, 0);
        push_bytes(&mut buckets, 6, 0, 0, 20);
        assert_eq!(
            buckets,
            vec![
                SliceBytes {
                    key: 5,
                    handshake: 10,
                    payload: 0
                },
                SliceBytes {
                    key: 6,
                    handshake: 0,
                    payload: 20
                },
            ]
        );
    }

    #[test]
    fn out_of_order_folds_into_last() {
        let mut buckets = Vec::new();
        push_bytes(&mut buckets, 6, 0, 10, 0);
        push_bytes(&mut buckets, 5, 0, 5, 0);
        assert_eq!(
            buckets,
            vec![SliceBytes {
                key: 6,
                handshake: 15,
                payload: 0
            }]
        );
    }

    #[test]
    fn coarsen_halves_and_conserves_bytes() {
        let mut buckets = vec![
            SliceBytes {
                key: 0,
                handshake: 1,
                payload: 2,
            },
            SliceBytes {
                key: 1,
                handshake: 3,
                payload: 4,
            },
            SliceBytes {
                key: 2,
                handshake: 5,
                payload: 6,
            },
        ];
        let total_before: u64 = buckets.iter().map(|b| b.handshake + b.payload).sum();
        coarsen(&mut buckets);
        let total_after: u64 = buckets.iter().map(|b| b.handshake + b.payload).sum();
        assert_eq!(total_before, total_after);
        assert_eq!(
            buckets,
            vec![
                SliceBytes {
                    key: 0,
                    handshake: 4,
                    payload: 6
                },
                SliceBytes {
                    key: 1,
                    handshake: 5,
                    payload: 6
                },
            ]
        );
    }

    #[test]
    fn repeated_coarsening_still_conserves_bytes() {
        let mut buckets: Vec<SliceBytes> = (0..8)
            .map(|i| SliceBytes {
                key: i,
                handshake: i as u64,
                payload: 1,
            })
            .collect();
        let total_before: u64 = buckets.iter().map(|b| b.handshake + b.payload).sum();
        coarsen(&mut buckets);
        coarsen(&mut buckets);
        coarsen(&mut buckets);
        let total_after: u64 = buckets.iter().map(|b| b.handshake + b.payload).sum();
        assert_eq!(total_before, total_after);
        assert_eq!(buckets.len(), 1);
    }
}

/// Distributes one coarse bucket's bytes evenly across the real global slices it covers
/// (`[key << shift, (key << shift) + (1 << shift) - 1]`), with the integer-division remainder
/// going to the first slice, clamping any slice past `num_slices - 1` into the final slice.
/// Returns `true` iff clamping was needed (i.e. this bucket ran past the accounting horizon).
fn flush_bucket(
    bucket: &SliceBytes,
    shift: u32,
    num_slices: usize,
    add: impl Fn(usize, u64, u64),
) -> bool {
    let span = 1usize << shift;
    let first_slice = (bucket.key as usize) << shift;
    let last_idx = num_slices - 1;
    let overflowed = first_slice > last_idx;

    let hs_base = bucket.handshake / span as u64;
    let hs_rem = bucket.handshake % span as u64;
    let pl_base = bucket.payload / span as u64;
    let pl_rem = bucket.payload % span as u64;

    for i in 0..span {
        let slice = (first_slice + i).min(last_idx);
        let hs = hs_base + if i == 0 { hs_rem } else { 0 };
        let pl = pl_base + if i == 0 { pl_rem } else { 0 };
        add(slice, hs, pl);
    }
    overflowed || (first_slice + span - 1) > last_idx
}

#[cfg(test)]
mod flush_bucket_tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn even_split_preserves_total() {
        let bucket = SliceBytes {
            key: 1,
            handshake: 10,
            payload: 21,
        };
        let seen = RefCell::new(Vec::new());
        let overflowed = flush_bucket(&bucket, 2, 100, |slice, hs, pl| {
            seen.borrow_mut().push((slice, hs, pl));
        });
        assert!(!overflowed);
        let seen = seen.into_inner();
        // key=1, shift=2 -> covers global slices 4..=7
        assert_eq!(seen.len(), 4);
        // base (10/4=2, 21/4=5) plus remainder (10%4=2, 21%4=1) lands on the first slice.
        assert_eq!(seen[0], (4, 4, 6));
        let total_hs: u64 = seen.iter().map(|(_, hs, _)| hs).sum();
        let total_pl: u64 = seen.iter().map(|(_, _, pl)| pl).sum();
        assert_eq!(total_hs, 10);
        assert_eq!(total_pl, 21);
    }

    #[test]
    fn clamps_past_horizon() {
        let bucket = SliceBytes {
            key: 3,
            handshake: 8,
            payload: 0,
        };
        let seen = RefCell::new(Vec::new());
        // shift=2 -> covers global slices 12..=15, but num_slices=10 (valid indices 0..=9)
        let overflowed = flush_bucket(&bucket, 2, 10, |slice, hs, pl| {
            seen.borrow_mut().push((slice, hs, pl));
        });
        assert!(overflowed);
        let seen = seen.into_inner();
        assert!(seen.iter().all(|(slice, _, _)| *slice == 9));
        let total_hs: u64 = seen.iter().map(|(_, hs, _)| hs).sum();
        assert_eq!(total_hs, 8);
    }
}

/// Per-connection byte time series: accumulates handshake/payload bytes into a sparse,
/// adaptively-coarsened per-slice histogram from the connection's first packet, and flips
/// `in_payload` once headers finish. See the module docs for why this is a plain (untracked)
/// datatype rather than callback-side accumulation, and why `in_payload` rather than
/// `app_body_offset()`.
#[datatype]
struct ByteSeries {
    l4_proto: usize,
    in_payload: bool,
    buckets: Vec<SliceBytes>,
    coarsen_shift: u32,
}

impl ByteSeries {
    fn total(&self) -> usize {
        self.buckets
            .iter()
            .map(|b| (b.handshake + b.payload) as usize)
            .sum()
    }

    #[datatype_fn("ByteSeries,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) {
        let len = pdu.length();
        if len == 0 {
            return;
        }
        let num_slices = DELTAS_LEN.load(Ordering::Relaxed);
        let slice_ms = SLICE_MS.load(Ordering::Relaxed);
        let ts_ms = pdu.ts.saturating_duration_since(*EPOCH).as_millis() as u64;
        let (slice, _) = global_slice(ts_ms, slice_ms, num_slices);

        let (hs, pl) = if self.in_payload {
            (0, len as u64)
        } else {
            (len as u64, 0)
        };
        push_bytes(&mut self.buckets, slice, self.coarsen_shift, hs, pl);

        let max_slices = MAX_CONN_SLICES.load(Ordering::Relaxed);
        if self.buckets.len() >= max_slices {
            coarsen(&mut self.buckets);
            self.coarsen_shift += 1;
        }
    }

    /// Fires exactly once, when the L7 headers finish. See the module docs.
    ///
    /// `SessionProto` is requested only because a `datatype_fn` must take at least one
    /// parameter -- the cheapest builtin available at this level. Same pattern as
    /// `encrypted_bytes::EncBytes::end_handshake`.
    #[datatype_fn("ByteSeries,level=L7EndHdrs")]
    fn end_handshake(&mut self, _proto: &SessionProto) {
        self.in_payload = true;
    }
}

impl Tracked for ByteSeries {
    fn new(first_pkt: &L4Pdu) -> Self {
        Self {
            l4_proto: first_pkt.ctxt.proto,
            in_payload: false,
            buckets: Vec::new(),
            coarsen_shift: 0,
        }
    }

    fn clear(&mut self) {
        self.in_payload = false;
        self.buckets.clear();
        self.coarsen_shift = 0;
    }
}

/// Flushes one connection's histogram into a `SeriesArrays` destination, applying `--min-bytes`
/// first. Shared by every `L4Terminated` callback below so they can't drift out of sync on how
/// a connection's bytes are expanded back onto the global per-slice arrays.
fn flush_series(series: &ByteSeries, arrays: &SeriesArrays, conn_count: &AtomicUsize) {
    let total = series.total();
    if !clears_min_bytes(total, MIN_BYTES.load(Ordering::Relaxed)) {
        return;
    }
    conn_count.fetch_add(1, Ordering::Relaxed);
    let num_slices = arrays.handshake.len();
    let mut overflowed = false;
    for bucket in &series.buckets {
        let bucket_overflowed =
            flush_bucket(bucket, series.coarsen_shift, num_slices, |slice, hs, pl| {
                if hs > 0 {
                    arrays.handshake[slice].fetch_add(hs, Ordering::Relaxed);
                }
                if pl > 0 {
                    arrays.payload[slice].fetch_add(pl, Ordering::Relaxed);
                }
            });
        overflowed |= bucket_overflowed;
    }
    if overflowed {
        OVERFLOWED_CONNS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Flushes one connection's histogram into the (handshake+payload-summed) transport series --
/// `TRANSPORT_SERIES` has no handshake/payload split, so both are folded together per slice.
fn flush_transport(series: &ByteSeries, dest: &[AtomicU64]) {
    let total = series.total();
    if !clears_min_bytes(total, MIN_BYTES.load(Ordering::Relaxed)) {
        return;
    }
    let num_slices = dest.len();
    let mut overflowed = false;
    for bucket in &series.buckets {
        let bucket_overflowed =
            flush_bucket(bucket, series.coarsen_shift, num_slices, |slice, hs, pl| {
                let bytes = hs + pl;
                if bytes > 0 {
                    dest[slice].fetch_add(bytes, Ordering::Relaxed);
                }
            });
        overflowed |= bucket_overflowed;
    }
    if overflowed {
        OVERFLOWED_CONNS.fetch_add(1, Ordering::Relaxed);
    }
}

/// The filter's OR predicate registers all five parsers; `SessionProto`, read once the
/// connection is torn down, says which one actually matched.
#[callback("tls or ssh or quic or wireguard or ike,level=L4Terminated")]
fn record_enc_series(series: &ByteSeries, proto: &SessionProto) {
    let Some(idx) = proto_index(proto) else {
        return;
    };
    let all_series = PROTO_SERIES.get().expect("PROTO_SERIES initialized");
    flush_series(series, &all_series[idx], &PROTO_CONN_COUNTS[idx]);
}

#[callback("MaybeQuic,level=L4Terminated")]
fn record_maybe_quic_series(series: &ByteSeries) {
    let all_series = PROTO_SERIES.get().expect("PROTO_SERIES initialized");
    flush_series(series, &all_series[5], &PROTO_CONN_COUNTS[5]);
}

#[callback("MaybeZoom,level=L4Terminated")]
fn record_maybe_zoom_series(series: &ByteSeries) {
    let all_series = PROTO_SERIES.get().expect("PROTO_SERIES initialized");
    flush_series(series, &all_series[6], &PROTO_CONN_COUNTS[6]);
}

#[callback("tcp or udp,level=L4Terminated")]
fn record_transport_series(series: &ByteSeries) {
    let transport = TRANSPORT_SERIES
        .get()
        .expect("TRANSPORT_SERIES initialized");
    let idx = match series.l4_proto {
        TCP_PROTOCOL => 0,
        UDP_PROTOCOL => 1,
        _ => return,
    };
    flush_transport(series, &transport[idx]);
}

/// Global slice count, set once in `main` alongside [`PROTO_SERIES`]/[`TRANSPORT_SERIES`] --
/// read on every packet by `ByteSeries::update`, so it's a plain atomic rather than derived
/// from `PROTO_SERIES.get()` on every call.
static DELTAS_LEN: AtomicUsize = AtomicUsize::new(0);

/// Returns `100 * numerator / denominator` as a percentage, or `None` if `denominator` is zero.
fn pct(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        return None;
    }
    Some(100.0 * numerator as f64 / denominator as f64)
}

fn fmt_pct(p: Option<f64>) -> String {
    match p {
        Some(p) => format!("{:>6.2}%", p),
        None => "   n/a ".to_string(),
    }
}

/// Sums a `Vec<AtomicU64>` (relaxed loads).
fn sum_atomics(v: &[AtomicU64]) -> u64 {
    v.iter().map(|a| a.load(Ordering::Relaxed)).sum()
}

/// Per-slice total (handshake+payload) for one protocol series.
fn per_slice_totals(arrays: &SeriesArrays) -> Vec<u64> {
    arrays
        .handshake
        .iter()
        .zip(arrays.payload.iter())
        .map(|(hs, pl)| hs.load(Ordering::Relaxed) + pl.load(Ordering::Relaxed))
        .collect()
}

/// Index of the last slice with any nonzero activity across every series, or `None` if the run
/// saw nothing at all -- the single source of truth for which slices are printed/written,
/// shared by stdout and CSV. Mirrors `concurrent_conns::slice_rows`'s truncation rule.
fn last_nonzero_slice(all_totals: &[Vec<u64>], transport_totals: &[Vec<u64>]) -> Option<usize> {
    let mut last = None;
    for totals in all_totals.iter().chain(transport_totals.iter()) {
        for (i, &v) in totals.iter().enumerate() {
            if v != 0 {
                last = Some(last.map_or(i, |l: usize| l.max(i)));
            }
        }
    }
    last
}

#[cfg(test)]
mod row_tests {
    use super::*;

    #[test]
    fn no_activity_is_none() {
        assert_eq!(last_nonzero_slice(&[vec![0, 0, 0]], &[vec![0, 0]]), None);
    }

    #[test]
    fn finds_max_across_series() {
        assert_eq!(
            last_nonzero_slice(&[vec![1, 0, 0], vec![0, 0, 5]], &[vec![0, 0]]),
            Some(2)
        );
    }
}

/// Writes the wide per-slice CSV: one row per slice up to `last`, columns
/// `slice_start_s,<proto>_handshake,<proto>_payload,...,tcp_bytes,udp_bytes`.
fn write_csv(
    file: &mut File,
    proto_arrays: &[SeriesArrays],
    transport_totals: &[Vec<u64>],
    last: Option<usize>,
    slice_ms: u64,
) {
    let mut header = String::from("slice_start_s");
    for col in PROTO_COLUMNS {
        header.push_str(&format!(",{}_handshake,{}_payload", col, col));
    }
    header.push_str(",tcp_bytes,udp_bytes");
    writeln!(file, "{}", header).unwrap();

    let Some(last) = last else {
        return;
    };
    // Indexes in lockstep across `proto_arrays` and both `transport_totals` rows -- there's no
    // single sequence to `.enumerate()` over here.
    #[allow(clippy::needless_range_loop)]
    for i in 0..=last {
        let offset_s = (i as u64 * slice_ms) as f64 / 1000.0;
        let mut row = format!("{:.3}", offset_s);
        for arrays in proto_arrays {
            let hs = arrays.handshake[i].load(Ordering::Relaxed);
            let pl = arrays.payload[i].load(Ordering::Relaxed);
            row.push_str(&format!(",{},{}", hs, pl));
        }
        row.push_str(&format!(
            ",{},{}",
            transport_totals[0][i], transport_totals[1][i]
        ));
        writeln!(file, "{}", row).unwrap();
    }
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();
    assert!(args.slice_ms > 0, "--slice-ms must be at least 1");
    assert!(
        args.max_duration_secs > 0,
        "--max-duration-secs must be at least 1"
    );
    assert!(
        args.max_conn_slices > 0,
        "--max-conn-slices must be at least 1"
    );

    // Opened up front, before the (potentially hours-long) capture runs, so a bad --outfile
    // path fails immediately instead of losing the whole run's output to a panic afterward.
    let mut outfile = File::create(&args.outfile)
        .unwrap_or_else(|e| panic!("Failed to create {}: {}", args.outfile.display(), e));

    SLICE_MS.store(args.slice_ms, Ordering::Relaxed);
    MIN_BYTES.store(args.min_bytes, Ordering::Relaxed);
    MAX_CONN_SLICES.store(args.max_conn_slices, Ordering::Relaxed);

    let total_ms = args.max_duration_secs.checked_mul(1000).unwrap_or_else(|| {
        panic!(
            "--max-duration-secs {} is too large (overflows when converted to milliseconds)",
            args.max_duration_secs
        )
    });
    let num_slices = (total_ms / args.slice_ms) as usize + 1;
    DELTAS_LEN.store(num_slices, Ordering::Relaxed);

    PROTO_SERIES
        .set(
            (0..NUM_PROTOS)
                .map(|_| SeriesArrays::new(num_slices))
                .collect(),
        )
        .unwrap_or_else(|_| panic!("PROTO_SERIES already initialized"));
    TRANSPORT_SERIES
        .set([
            (0..num_slices).map(|_| AtomicU64::new(0)).collect(),
            (0..num_slices).map(|_| AtomicU64::new(0)).collect(),
        ])
        .unwrap_or_else(|_| panic!("TRANSPORT_SERIES already initialized"));

    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    // Force the epoch now, immediately before packet processing starts.
    lazy_static::initialize(&EPOCH);
    runtime.run();

    let proto_arrays = PROTO_SERIES.get().expect("PROTO_SERIES initialized");
    let transport = TRANSPORT_SERIES
        .get()
        .expect("TRANSPORT_SERIES initialized");

    let all_totals: Vec<Vec<u64>> = proto_arrays.iter().map(per_slice_totals).collect();
    let transport_totals: Vec<Vec<u64>> = transport
        .iter()
        .map(|v| v.iter().map(|a| a.load(Ordering::Relaxed)).collect())
        .collect();
    let last = last_nonzero_slice(&all_totals, &transport_totals);

    println!("=== Bytes per {}ms slice, by protocol ===", args.slice_ms);
    if let Some(last) = last {
        // Indexes in lockstep across `all_totals` (already zipped with `PROTO_NAMES`) and both
        // `transport_totals` rows -- there's no single sequence to `.enumerate()` over here.
        #[allow(clippy::needless_range_loop)]
        for i in 0..=last {
            let offset_s = (i as u64 * args.slice_ms) as f64 / 1000.0;
            let mut line = format!("t={:>10.3}s ", offset_s);
            for (name, totals) in PROTO_NAMES.iter().zip(all_totals.iter()) {
                line.push_str(&format!(" {}={}", name, totals[i]));
            }
            line.push_str(&format!(
                " TCP={} UDP={}",
                transport_totals[0][i], transport_totals[1][i]
            ));
            println!("{}", line);
        }
    } else {
        println!("(no traffic observed)");
    }

    write_csv(
        &mut outfile,
        proto_arrays,
        &transport_totals,
        last,
        args.slice_ms,
    );
    println!(
        "\nWrote per-slice byte counts to {}",
        args.outfile.display()
    );

    let tcp_total = sum_atomics(&transport[0]);
    let udp_total = sum_atomics(&transport[1]);
    let transport_total = tcp_total + udp_total;

    if args.min_bytes > 0 {
        println!(
            "\n(Connections with {} or fewer total bytes are excluded from every count below.)",
            args.min_bytes
        );
    }
    println!("\n=== Encrypted protocol bytes: handshake % vs. payload %, and % of total transport traffic ===");
    for (name, arrays) in PROTO_NAMES.iter().zip(proto_arrays.iter()) {
        let handshake = sum_atomics(&arrays.handshake);
        let payload = sum_atomics(&arrays.payload);
        let total = handshake + payload;
        println!(
            "{:<10} handshake: {}   payload: {}   of total traffic: {}",
            name,
            fmt_pct(pct(handshake, total)),
            fmt_pct(pct(payload, total)),
            fmt_pct(pct(total, transport_total)),
        );
    }

    println!("\n=== Total transport-layer traffic ===");
    println!("TCP: {}", fmt_pct(pct(tcp_total, transport_total)));
    println!("UDP: {}", fmt_pct(pct(udp_total, transport_total)));

    println!("\n=== Connections observed per series ===");
    for (name, count) in PROTO_NAMES.iter().zip(PROTO_CONN_COUNTS.iter()) {
        println!("  {:<10} {}", name, count.load(Ordering::Relaxed));
    }

    let overflowed = OVERFLOWED_CONNS.load(Ordering::Relaxed);
    if overflowed > 0 {
        println!(
            "\nWarning: {} connections extended past --max-duration-secs ({}s) and had bytes \
             folded into the final slice.",
            overflowed, args.max_duration_secs
        );
    }
}
