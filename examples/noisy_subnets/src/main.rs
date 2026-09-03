//! Per-subnet traffic statistics for a fixed set of monitored networks.
//!
//! ## What it measures
//! Only traffic touching one of seven monitored supernets is counted at all:
//!
//! | Supernet | |
//! |---|---|
//! | `171.64.0.0/14` | `192.168.0.0/16` |
//! | `172.16.0.0/12` | `128.12.0.0/16` |
//! | `10.0.0.0/8`    | `204.63.224.0/21` |
//! |                 | `68.65.160.0/20` |
//!
//! A filter on `ipv4.addr` prefilters in the runtime, so a connection with neither endpoint
//! in a monitored supernet is never tracked. One callback then fires once per surviving
//! TCP/UDP connection at `L4Terminated`, receiving the 5-tuple (`FiveTuple`), the L4
//! payload byte count (`ByteCount`) and the packet count (`PktCount`).
//!
//! Each *monitored* endpoint of the connection is masked to a subnet of `--prefix` bits
//! (default `/24`) and the connection is credited to that subnet. Flow direction is not
//! tracked: a connection between two monitored subnets counts toward both, and one between
//! a monitored subnet and an unmonitored address counts only toward the monitored side.
//! A connection whose endpoints fall in the same subnet is credited once.
//!
//! `--prefix` is clamped per address to be no coarser than the supernet containing it, so a
//! reported subnet never spans addresses outside the monitored ranges. With `--prefix 8`,
//! `171.64.1.2` is still reported under `171.64.0.0/14`, not `171.0.0.0/8`.
//!
//! ## Output
//! One row per subnet, ranked by total bytes descending: connection count, total packets,
//! total bytes, and the distribution of *bytes per connection* -- mean, p10, p25, median,
//! p75, p90, p99. Percentiles are linearly interpolated over the connections credited to
//! that subnet. The top `--top` rows (default 20) go to stdout; `--out <path>` writes every
//! subnet as JSON.
//!
//! ## Run
//! ```
//! sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error \
//!   ./target/release/noisy_subnets --config configs/offline.toml --prefix 28 --out noisy.json
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use clap::Parser;
use iris_compiler::{callback, input_files, iris_end_macros};
use iris_core::{config::load_config, FiveTuple, Runtime};
use iris_datatypes::{ByteCount, PktCount};
use lazy_static::lazy_static;
use serde::Serialize;

/// The supernets we collect statistics for. Traffic touching none of them is ignored.
///
/// Kept in sync by hand with the `ipv4.addr` predicates in [`record`]'s filter -- the filter
/// is a prefilter for the runtime, this table is what attributes an address to a bucket.
const MONITORED: [(Ipv4Addr, u8); 7] = [
    (Ipv4Addr::new(171, 64, 0, 0), 14),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(128, 12, 0, 0), 16),
    (Ipv4Addr::new(204, 63, 224, 0), 21),
    (Ipv4Addr::new(68, 65, 160, 0), 20),
];

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

    /// How many rows to print to stdout.
    #[clap(short, long, value_name = "N", default_value_t = 20)]
    top: usize,

    /// Prefix length used to group monitored addresses into subnets. Clamped per address to
    /// be no coarser than the monitored supernet containing it.
    #[clap(short, long, value_name = "BITS", default_value_t = 24)]
    prefix: u8,

    /// Optional path to write the complete table (every subnet) as JSON.
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    out: Option<PathBuf>,
}

/// Running totals for one subnet, plus the per-connection byte counts the percentiles are
/// computed from at the end of the run.
#[derive(Default)]
struct SubnetStat {
    /// Connections this subnet was an endpoint of.
    conns: u64,
    /// Packets in every connection this subnet was an endpoint of.
    packets: u64,
    /// L4 payload bytes in every connection this subnet was an endpoint of.
    bytes: u64,
    /// One entry per connection credited to this subnet: that connection's byte count.
    conn_bytes: Vec<u64>,
}

lazy_static! {
    /// Keyed by subnet, regardless of whether the subnet was the connection's source or
    /// destination.
    static ref SUBNETS: Mutex<HashMap<Subnet, SubnetStat>> = Mutex::new(HashMap::new());
}

/// Set once from CLI args before the runtime starts; read by the callback on every core.
static PREFIX: AtomicU8 = AtomicU8::new(24);

/// A reported subnet: a network address and the prefix length it was masked to.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Subnet {
    network: Ipv4Addr,
    prefix: u8,
}

impl std::fmt::Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// The subnet `ip` should be counted under, or `None` if `ip` is in no monitored supernet.
///
/// The grouping prefix is `--prefix`, but never coarser than the containing supernet's own
/// prefix, so a bucket cannot span addresses outside the monitored ranges.
fn monitored_subnet(ip: IpAddr) -> Option<Subnet> {
    let IpAddr::V4(addr) = ip else {
        return None;
    };
    let requested = PREFIX.load(Ordering::Relaxed).min(32);
    MONITORED
        .iter()
        .find(|(net, net_prefix)| masked(addr, *net_prefix) == *net)
        .map(|(_, net_prefix)| {
            let prefix = requested.max(*net_prefix);
            Subnet {
                network: masked(addr, prefix),
                prefix,
            }
        })
}

/// `addr` with all but its leading `prefix` bits zeroed.
fn masked(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(u32::from(addr) & mask)
}

fn add(subnet: Subnet, bytes: u64, packets: u64) {
    let mut map = SUBNETS.lock().unwrap();
    let e = map.entry(subnet).or_default();
    e.conns += 1;
    e.packets += packets;
    e.bytes += bytes;
    e.conn_bytes.push(bytes);
}

/// Fires once per TCP/UDP connection with at least one endpoint in a monitored supernet,
/// when the connection terminates (FIN/RST or timeout).
#[callback(
    "(tcp or udp) and (ipv4.addr = 171.64.0.0/14 or ipv4.addr = 172.16.0.0/12 or ipv4.addr = 10.0.0.0/8 or ipv4.addr = 192.168.0.0/16 or ipv4.addr = 128.12.0.0/16 or ipv4.addr = 204.63.224.0/21 or ipv4.addr = 68.65.160.0/20),level=L4Terminated"
)]
fn record(ft: &FiveTuple, bytes: &ByteCount, pkts: &PktCount) {
    let total_bytes = bytes.total() as u64;
    let total_pkts = pkts.total() as u64;

    let orig = monitored_subnet(ft.orig.ip());
    let resp = monitored_subnet(ft.resp.ip());
    if let Some(subnet) = orig {
        add(subnet, total_bytes, total_pkts);
    }
    // Guard against crediting a subnet twice when both endpoints fall in it.
    if let Some(subnet) = resp {
        if orig != Some(subnet) {
            add(subnet, total_bytes, total_pkts);
        }
    }
}

/// One output row: a subnet's totals and its bytes-per-connection distribution.
#[derive(Serialize)]
struct Row {
    subnet: String,
    conns: u64,
    packets: u64,
    bytes: u64,
    /// Bytes per connection, over the connections credited to this subnet.
    mean_conn_bytes: f64,
    p10_conn_bytes: f64,
    p25_conn_bytes: f64,
    median_conn_bytes: f64,
    p75_conn_bytes: f64,
    p90_conn_bytes: f64,
    p99_conn_bytes: f64,
}

/// Linearly interpolated percentile of an ascending-sorted sample, matching the usual
/// "linear" convention (`p0` is the minimum, `p100` the maximum, `p50` the true median).
fn percentile(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (p / 100.0) * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        return sorted[lo] as f64;
    }
    let frac = rank - lo as f64;
    sorted[lo] as f64 * (1.0 - frac) + sorted[hi] as f64 * frac
}

/// Sorts the table into a ranking, noisiest first, computing each subnet's percentiles.
fn ranked() -> Vec<Row> {
    let mut map = SUBNETS.lock().unwrap();
    let mut rows: Vec<Row> = map
        .iter_mut()
        .map(|(subnet, stat)| {
            stat.conn_bytes.sort_unstable();
            let s = &stat.conn_bytes;
            Row {
                subnet: subnet.to_string(),
                conns: stat.conns,
                packets: stat.packets,
                bytes: stat.bytes,
                mean_conn_bytes: if stat.conns == 0 {
                    0.0
                } else {
                    stat.bytes as f64 / stat.conns as f64
                },
                p10_conn_bytes: percentile(s, 10.0),
                p25_conn_bytes: percentile(s, 25.0),
                median_conn_bytes: percentile(s, 50.0),
                p75_conn_bytes: percentile(s, 75.0),
                p90_conn_bytes: percentile(s, 90.0),
                p99_conn_bytes: percentile(s, 99.0),
            }
        })
        .collect();
    rows.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.subnet.cmp(&b.subnet)));
    rows
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.2} {}", UNITS[u])
    }
}

/// Same units as [`human`], for the fractional per-connection statistics.
fn human_f64(bytes: f64) -> String {
    human(bytes.round() as u64)
}

fn print_table(rows: &[Row], top: usize) {
    println!("\n=== Monitored subnets (top {top} of {}) ===", rows.len());
    println!("(byte columns after `bytes` are bytes per connection)\n");
    println!(
        "{:<20}  {:>8}  {:>10}  {:>11}  {:>11}  {:>11}  {:>11}  {:>11}  {:>11}  {:>11}  {:>11}",
        "subnet", "conns", "packets", "bytes", "mean", "p10", "p25", "median", "p75", "p90", "p99"
    );
    for r in rows.iter().take(top) {
        println!(
            "{:<20}  {:>8}  {:>10}  {:>11}  {:>11}  {:>11}  {:>11}  {:>11}  {:>11}  {:>11}  {:>11}",
            r.subnet,
            r.conns,
            r.packets,
            human(r.bytes),
            human_f64(r.mean_conn_bytes),
            human_f64(r.p10_conn_bytes),
            human_f64(r.p25_conn_bytes),
            human_f64(r.median_conn_bytes),
            human_f64(r.p75_conn_bytes),
            human_f64(r.p90_conn_bytes),
            human_f64(r.p99_conn_bytes),
        );
    }
}

#[derive(Serialize)]
struct Report {
    prefix: u8,
    monitored: Vec<String>,
    subnets: Vec<Row>,
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();
    PREFIX.store(args.prefix, Ordering::Relaxed);

    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    let rows = ranked();
    print_table(&rows, args.top);

    if let Some(path) = args.out {
        let report = Report {
            prefix: args.prefix,
            monitored: MONITORED
                .iter()
                .map(|(net, prefix)| format!("{net}/{prefix}"))
                .collect(),
            subnets: rows,
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        std::fs::write(&path, json).unwrap();
        println!("\nWrote full table to {}", path.display());
    }
}
