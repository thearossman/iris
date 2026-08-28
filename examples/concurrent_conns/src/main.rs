//! Reports, for each fixed-width time slice (`--slice-ms`, default 1000ms), how many of
//! Iris's identified encrypted-protocol connections (TLS, SSH, QUIC, WireGuard, IKE, and
//! DTLS-encapsulated CAPWAP) plus heuristically-detected mid-stream QUIC/Zoom/iperf3 traffic
//! (`MaybeQuic`, `MaybeZoom`, `MaybeIperf3`) were concurrently active. eDNS is not counted
//! separately: Iris has no distinct encrypted-DNS parser, and DNS-over-TLS/QUIC traffic is
//! already identified as TLS/QUIC by the parsers those protocols already register.
//!
//! As in `encrypted_bytes`, only DTLS-encapsulated CAPWAP counts here (`capwap.preamble_type =
//! 1`) -- plaintext CAPWAP is not encrypted, so it is excluded from this "concurrent encrypted
//! connections" count. `MaybeQuic`/`MaybeZoom` skip a connection a real parser already claimed,
//! so they never double-count against the six real protocols or each other; `MaybeIperf3` has no
//! such guard and can double-count against any of the others -- see `encrypted_bytes`'s module
//! docs for the full reasoning behind both of those invariants. All nine protocols/heuristics
//! feed the *same* blended concurrency count below: this app tracks "some encrypted or
//! maybe-encrypted connection was active", not a separate time series per protocol -- see
//! `examples/bytes_over_time` for the per-protocol breakdown.
//!
//! The per-slice counts are printed to stdout and also written as two-column CSV
//! (`slice_start_s,active_connections`, one row per slice) to `--outfile` (default
//! `counts.csv`), suitable for plotting directly with a spreadsheet, gnuplot, or
//! `pandas.read_csv`.
//!
//! ## What "active" means
//! A connection is active in a slice if its lifetime `[start_ts, last_ts]` overlaps that
//! slice, where `start_ts`/`last_ts` come from the built-in `ConnDuration` datatype -- the
//! timestamp of the connection's first packet and its most recently seen packet,
//! respectively. This deliberately does *not* use the time `L4Terminated` fires as the
//! connection's end: `L4Terminated` can be delayed well past the last real packet by Iris's
//! inactivity timeouts (60s for UDP, 300s for TCP by default -- see `[conntrack]` in the
//! runtime config), so using it as "when the connection ended" would inflate every
//! connection's counted lifetime by however long it happened to sit idle before timing out.
//! `L4Terminated` is still the right point to *collect* a connection's final `ConnDuration` --
//! it fires exactly once per connection, whether by FIN/RST or timeout, and the end-of-run
//! drain (`ConnTracker::drain`) guarantees every connection still open when the runtime stops
//! reaches it too -- but only `last_ts`, not "now", is used as the interval's end.
//!
//! One consequence: a slice's count is only final once every connection overlapping it has
//! been collected, which for a connection that goes quiet without a clean close can be up to
//! one inactivity timeout after its last real packet. This app reports slice counts once, as
//! a table printed after the run, rather than as a live stream -- so that lag never produces
//! a wrong number, only a delayed one.
//!
//! ## Bucketing without per-connection storage
//! Naively, computing this means recording every connection's `[start, end]` interval and
//! post-processing them into per-slice counts once the run ends. That is intentionally *not*
//! what happens here -- for an hour-plus capture, holding one interval per connection in
//! memory for the whole run does not bound well. Instead, each connection is folded into a
//! shared difference array the moment it is collected: two atomic increments (`+1` at its
//! first overlapping slice, `-1` one slice past its last) fully encode its contribution to
//! every per-slice count, regardless of how many slices it actually spans. A single prefix
//! sum over the array after `runtime.run()` returns recovers the same per-slice active counts
//! that per-connection post-processing would have produced. Memory is `O(slices)`, fixed by
//! `--max-duration-secs` and `--slice-ms` at startup -- 8 bytes per slice, so the default
//! 48-hour horizon at the default 1-second width costs about 1.4MB, regardless of how many
//! connections are observed or how long the run actually lasts (a run stopped after ten
//! minutes still allocates the array sized for the full horizon). A connection whose lifetime
//! runs past `--max-duration-secs` is folded into the final slice rather than growing the
//! array, and counted in the "overflow" warning printed at the end of the run.
//!
//! ## Timestamps are processing time, not capture time
//! `ConnDuration`'s timestamps come from `L4Pdu::ts`, which Iris sets from `Instant::now()`
//! when a packet is processed -- not from any timestamp recorded in a packet capture file.
//! For online/live capture this is exactly the wall-clock time each connection was actually
//! active, which is what this app is for. For offline pcap replay, though, packets are
//! processed as fast as the CPU allows, so an entire multi-hour trace can be replayed inside
//! processing time far shorter than 1 second -- the printed slice table reflects how fast the
//! run went, not the trace's real timeline. Offline runs are useful here only as a
//! correctness smoke test, not as a trace-accurate measurement.

use clap::Parser;
use iris_compiler::{callback, input_files, iris_end_macros};
use iris_core::protocols::stream::SessionProto;
use iris_core::{config::load_config, Runtime};
use iris_datatypes::ConnDuration;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
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
    /// lasts. Sizes the fixed-size slice array up front, so per-connection bookkeeping never
    /// allocates. A connection whose lifetime runs past this horizon is folded into the final
    /// slice instead of growing the array, and counted in the overflow warning printed at the
    /// end of the run.
    #[clap(long, value_name = "SECS", default_value_t = 48 * 3600)]
    max_duration_secs: u64,

    /// Path to also write the per-slice active-connection counts as CSV
    /// (`slice_start_s,active_connections`), one row per slice -- e.g. for plotting with a
    /// spreadsheet, gnuplot, or `pandas.read_csv`.
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "counts.csv"
    )]
    outfile: PathBuf,
}

lazy_static! {
    /// The run's time origin, captured once in `main` before `runtime.run()` starts -- so
    /// slice 0 always begins at runtime start, not at whenever the first connection happens
    /// to be collected.
    static ref EPOCH: Instant = Instant::now();
}

/// Set once from `--slice-ms` before `runtime.run()`, read on every collected connection.
static SLICE_MS: AtomicU64 = AtomicU64::new(1000);

/// The difference array: index `i` holds the net change in active-connection count at the
/// start of slice `i`. Length is `num_slices + 1` -- the extra final slot is where a
/// connection ending in the very last real slice (`num_slices - 1`) places its `-1`, so every
/// real slice can always be decremented one past its own index without a bounds check.
/// Sized once from `--max-duration-secs`/`--slice-ms` before `runtime.run()` starts.
static DELTAS: OnceLock<Vec<AtomicI64>> = OnceLock::new();

/// Total encrypted/maybe-encrypted connections collected, across all nine protocols/heuristics.
static TOTAL_CONNS: AtomicUsize = AtomicUsize::new(0);
/// Connections whose lifetime extended past `--max-duration-secs` and were folded into the
/// final slice rather than accurately bucketed.
static OVERFLOWED_CONNS: AtomicUsize = AtomicUsize::new(0);
/// Per-protocol connection counts, indexed by [`proto_index`] for the six real protocols and
/// by the fixed slots 6/7/8 for `MaybeQuic`/`MaybeZoom`/`MaybeIperf3`.
static PROTO_COUNTS: [AtomicUsize; 9] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];
const PROTO_NAMES: [&str; 9] = [
    "TLS",
    "SSH",
    "QUIC",
    "WireGuard",
    "IKE",
    "CAPWAP",
    "MaybeQuic",
    "MaybeZoom",
    "MaybeIperf3",
];

/// Maps an identified `SessionProto` to its slot in [`PROTO_COUNTS`]/[`PROTO_NAMES`] for the
/// six real parsers. `None` for anything else -- unreachable in practice, since `record_conn`'s
/// filter only matches these six protocols, but matched defensively rather than assumed.
///
/// CAPWAP lands here too even though `record_conn`'s filter restricts it to DTLS-encapsulated
/// connections (`capwap.preamble_type = 1`) -- `SessionProto` itself doesn't encode that
/// distinction, so any CAPWAP connection reaching this function already cleared the filter.
/// `MaybeQuic`/`MaybeZoom`/`MaybeIperf3` (slots 6/7/8) don't go through this function at all --
/// their own callbacks below use fixed indices, since they aren't `SessionProto` variants.
fn proto_index(proto: &SessionProto) -> Option<usize> {
    match proto {
        SessionProto::Tls => Some(0),
        SessionProto::Ssh => Some(1),
        SessionProto::Quic => Some(2),
        SessionProto::Wireguard => Some(3),
        SessionProto::Ike => Some(4),
        SessionProto::Capwap => Some(5),
        _ => None,
    }
}

#[cfg(test)]
mod proto_index_tests {
    use super::*;

    #[test]
    fn recognizes_every_real_protocol() {
        for proto in [
            SessionProto::Tls,
            SessionProto::Ssh,
            SessionProto::Quic,
            SessionProto::Wireguard,
            SessionProto::Ike,
            SessionProto::Capwap,
        ] {
            assert!(
                proto_index(&proto).is_some(),
                "proto_index should recognize {proto:?}"
            );
        }
    }

    #[test]
    fn ignores_undiscovered_and_unhandled_protocols() {
        for proto in [SessionProto::Null, SessionProto::Probing, SessionProto::Dns] {
            assert!(
                proto_index(&proto).is_none(),
                "proto_index should not recognize {proto:?}"
            );
        }
    }
}

/// Maps a connection's `[start_ms, end_ms]` lifetime (both offsets from [`EPOCH`], in
/// milliseconds) to the inclusive range of slice indices it overlaps, clamping into
/// `0..num_slices` if the interval runs past the array's fixed horizon. The returned bool is
/// `true` iff either endpoint had to be clamped, i.e. the connection is not fully accounted
/// for within `num_slices`.
fn slice_bounds(
    start_ms: u64,
    end_ms: u64,
    slice_ms: u64,
    num_slices: usize,
) -> (usize, usize, bool) {
    let last_idx = num_slices - 1;
    let raw_first = (start_ms / slice_ms) as usize;
    let raw_last = (end_ms / slice_ms) as usize;
    let overflowed = raw_first > last_idx || raw_last > last_idx;
    (raw_first.min(last_idx), raw_last.min(last_idx), overflowed)
}

/// Turns a difference array (length `num_slices + 1`; see [`DELTAS`]) into per-slice
/// active-connection counts, one entry per real slice.
fn prefix_sum(deltas: &[i64]) -> Vec<i64> {
    let mut running = 0i64;
    deltas[..deltas.len() - 1]
        .iter()
        .map(|d| {
            running += d;
            running
        })
        .collect()
}

#[cfg(test)]
mod slice_bounds_tests {
    use super::*;

    #[test]
    fn single_slice_connection() {
        assert_eq!(slice_bounds(2100, 2900, 1000, 10), (2, 2, false));
    }

    #[test]
    fn spans_multiple_slices() {
        assert_eq!(slice_bounds(500, 3200, 1000, 10), (0, 3, false));
    }

    #[test]
    fn clamps_end_past_horizon() {
        // num_slices=5 means valid indices 0..=4; a connection ending at slice 10 is folded
        // into slice 4.
        assert_eq!(slice_bounds(500, 10_500, 1000, 5), (0, 4, true));
    }

    #[test]
    fn clamps_start_past_horizon() {
        assert_eq!(slice_bounds(20_000, 21_000, 1000, 5), (4, 4, true));
    }
}

#[cfg(test)]
mod prefix_sum_tests {
    use super::*;

    #[test]
    fn single_connection_interval() {
        // +1 at slice 1, -1 at slice 4 (one past its last real slice, 3).
        let deltas = vec![0, 1, 0, 0, -1, 0];
        assert_eq!(prefix_sum(&deltas), vec![0, 1, 1, 1, 0]);
    }

    #[test]
    fn overlapping_connections() {
        // conn A spans slices 0..=2, conn B spans slices 1..=3; num_slices=4, so len=5.
        let mut deltas = vec![0i64; 5];
        deltas[0] += 1;
        deltas[3] -= 1;
        deltas[1] += 1;
        deltas[4] -= 1;
        assert_eq!(prefix_sum(&deltas), vec![1, 2, 2, 1]);
    }

    #[test]
    fn no_connections() {
        assert_eq!(prefix_sum(&[0, 0, 0]), vec![0, 0]);
    }
}

/// Folds one connection into [`PROTO_COUNTS`]`[idx]`, [`TOTAL_CONNS`], and the [`DELTAS`]
/// difference array. Shared by every collecting callback below (the six real protocols plus the
/// three `Maybe*` heuristics) so they can't drift out of sync on how a connection's active
/// interval is turned into difference-array updates.
fn collect_conn(idx: usize, dur: &ConnDuration) {
    PROTO_COUNTS[idx].fetch_add(1, Ordering::Relaxed);
    TOTAL_CONNS.fetch_add(1, Ordering::Relaxed);

    let deltas = DELTAS
        .get()
        .expect("DELTAS initialized before runtime.run()");
    let num_slices = deltas.len() - 1;
    let slice_ms = SLICE_MS.load(Ordering::Relaxed);
    let start_ms = dur.start_ts.saturating_duration_since(*EPOCH).as_millis() as u64;
    let end_ms = dur.last_ts.saturating_duration_since(*EPOCH).as_millis() as u64;

    let (first, last, overflowed) = slice_bounds(start_ms, end_ms, slice_ms, num_slices);
    if overflowed {
        OVERFLOWED_CONNS.fetch_add(1, Ordering::Relaxed);
    }
    // Exactly two atomic ops encode this connection's contribution to every slice it spans;
    // see the module docs for why this replaces storing (and later bucketing) an interval
    // per connection.
    deltas[first].fetch_add(1, Ordering::Relaxed);
    deltas[last + 1].fetch_add(-1, Ordering::Relaxed);
}

/// Collected once per encrypted connection, at teardown -- see the module docs for why
/// `L4Terminated` is the collection point but `dur.last_ts` (not "now") is the connection's
/// counted end. The CAPWAP term is `capwap.preamble_type = 1`, not bare `capwap` -- see the
/// module docs.
#[callback("tls or ssh or quic or wireguard or ike or capwap.preamble_type = 1,level=L4Terminated")]
fn record_conn(dur: &ConnDuration, proto: &SessionProto) {
    let Some(idx) = proto_index(proto) else {
        return;
    };
    collect_conn(idx, dur);
}

/// `proto` is checked first: a connection a real parser already claimed is skipped here, so it
/// isn't double-counted in both its protocol's slot and this one -- see the module docs.
#[callback("MaybeQuic,level=L4Terminated")]
fn record_maybe_quic_conn(dur: &ConnDuration, proto: &SessionProto) {
    if proto_index(proto).is_some() {
        return;
    }
    collect_conn(6, dur);
}

#[callback("MaybeZoom,level=L4Terminated")]
fn record_maybe_zoom_conn(dur: &ConnDuration, proto: &SessionProto) {
    if proto_index(proto).is_some() {
        return;
    }
    collect_conn(7, dur);
}

/// No `proto_index` guard, unlike `record_maybe_quic_conn`/`record_maybe_zoom_conn` -- following
/// `encrypted_bytes`'s `MAYBE_IPERF3_BYTES`, this is the one slot that can still double-count
/// against any of the others. See the module docs.
#[callback("MaybeIperf3,level=L4Terminated")]
fn record_maybe_iperf3_conn(dur: &ConnDuration) {
    collect_conn(8, dur);
}

/// Returns `100 * numerator / denominator` as a percentage, or `None` if `denominator` is
/// zero (e.g. no encrypted connections were observed at all).
fn pct(numerator: usize, denominator: usize) -> Option<f64> {
    if denominator == 0 {
        return None;
    }
    Some(100.0 * numerator as f64 / denominator as f64)
}

/// Formats a numerator alongside its share of `denominator`, e.g. `"12 (3.4%)"`, or just the
/// bare count if `denominator` is zero.
fn fmt_count_pct(numerator: usize, denominator: usize) -> String {
    match pct(numerator, denominator) {
        Some(p) => format!("{} ({:.1}%)", numerator, p),
        None => numerator.to_string(),
    }
}

#[cfg(test)]
mod pct_tests {
    use super::*;

    #[test]
    fn zero_denominator_is_none() {
        assert_eq!(pct(0, 0), None);
        assert_eq!(fmt_count_pct(5, 0), "5");
    }

    #[test]
    fn whole_and_fractional_shares() {
        assert_eq!(fmt_count_pct(1, 4), "1 (25.0%)");
        assert_eq!(fmt_count_pct(3, 3), "3 (100.0%)");
    }
}

/// Turns per-slice counts into `(offset_seconds, count)` rows, one per slice up to
/// `last_nonzero` inclusive (empty if `None`) -- the single source of truth for which slices
/// get shown, shared by both the stdout table and the CSV file so they can't drift apart.
fn slice_rows(per_slice: &[i64], last_nonzero: Option<usize>, slice_ms: u64) -> Vec<(f64, i64)> {
    let Some(last) = last_nonzero else {
        return Vec::new();
    };
    per_slice[..=last]
        .iter()
        .enumerate()
        .map(|(i, &count)| ((i as u64 * slice_ms) as f64 / 1000.0, count))
        .collect()
}

/// Writes `rows` as CSV (`slice_start_s,active_connections`) to an already-open file. Panics
/// on any I/O failure -- there's no meaningful way to recover a partially written run's output.
fn write_slice_csv(file: &mut File, rows: &[(f64, i64)]) {
    writeln!(file, "slice_start_s,active_connections").unwrap();
    for (offset_s, count) in rows {
        writeln!(file, "{:.3},{}", offset_s, count).unwrap();
    }
}

#[cfg(test)]
mod slice_rows_tests {
    use super::*;

    #[test]
    fn no_activity_is_empty() {
        assert_eq!(slice_rows(&[0, 0, 0], None, 1000), Vec::new());
    }

    #[test]
    fn truncates_at_last_nonzero() {
        assert_eq!(
            slice_rows(&[1, 2, 0, 0], Some(1), 1000),
            vec![(0.0, 1), (1.0, 2)]
        );
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

    // Opened up front, before the (potentially hours-long) capture runs, so a bad --outfile
    // path (unwritable directory, missing parent, etc.) fails immediately instead of losing
    // the whole run's output to a panic after `runtime.run()` returns.
    let mut outfile = File::create(&args.outfile)
        .unwrap_or_else(|e| panic!("Failed to create {}: {}", args.outfile.display(), e));

    SLICE_MS.store(args.slice_ms, Ordering::Relaxed);
    let total_ms = args.max_duration_secs.checked_mul(1000).unwrap_or_else(|| {
        panic!(
            "--max-duration-secs {} is too large (overflows when converted to milliseconds)",
            args.max_duration_secs
        )
    });
    let num_slices = (total_ms / args.slice_ms) as usize + 1;
    DELTAS
        .set((0..=num_slices).map(|_| AtomicI64::new(0)).collect())
        .expect("DELTAS already initialized");

    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    // Force the epoch now, immediately before packet processing starts, so slice 0 lines up
    // with when the capture actually begins rather than including config load / DPDK EAL init
    // time that happened above.
    lazy_static::initialize(&EPOCH);
    runtime.run();

    let deltas = DELTAS.get().expect("DELTAS initialized");
    let loaded: Vec<i64> = deltas.iter().map(|d| d.load(Ordering::Relaxed)).collect();
    let per_slice = prefix_sum(&loaded);

    let mut max_count = 0i64;
    let mut max_slice = 0usize;
    let mut last_nonzero: Option<usize> = None;
    for (i, &count) in per_slice.iter().enumerate() {
        if count != 0 {
            last_nonzero = Some(i);
        }
        if count > max_count {
            max_count = count;
            max_slice = i;
        }
    }
    let rows = slice_rows(&per_slice, last_nonzero, args.slice_ms);

    println!(
        "=== Concurrent encrypted/maybe-encrypted connections (TLS, SSH, QUIC, WireGuard, IKE, \
         CAPWAP, MaybeQuic, MaybeZoom, MaybeIperf3) per {}ms slice ===",
        args.slice_ms
    );
    if rows.is_empty() {
        println!("(no encrypted connections observed)");
    } else {
        for (offset_s, count) in &rows {
            println!("t={:>10.3}s  {}", offset_s, count);
        }
    }

    write_slice_csv(&mut outfile, &rows);
    println!("\nWrote per-slice counts to {}", args.outfile.display());

    let total = TOTAL_CONNS.load(Ordering::Relaxed);
    println!("\n=== Summary ===");
    println!("Encrypted/maybe-encrypted connections observed: {}", total);
    for (name, counter) in PROTO_NAMES.iter().zip(PROTO_COUNTS.iter()) {
        println!(
            "  {:<10} {}",
            name,
            fmt_count_pct(counter.load(Ordering::Relaxed), total)
        );
    }
    if last_nonzero.is_some() {
        let peak_offset_s = (max_slice as u64 * args.slice_ms) as f64 / 1000.0;
        println!("Peak concurrent: {} at t={:.3}s", max_count, peak_offset_s);
    }

    let overflowed = OVERFLOWED_CONNS.load(Ordering::Relaxed);
    if overflowed > 0 {
        println!(
            "\nWarning: {} connections extended past --max-duration-secs ({}s) and were \
             folded into the final slice.",
            overflowed, args.max_duration_secs
        );
    }
}
