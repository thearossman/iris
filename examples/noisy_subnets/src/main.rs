//! Rank the "noisiest" subnets by byte volume, separately for subnets acting as the
//! connection *source* (originator) and as the connection *destination* (responder).
//!
//! ## What it measures
//! One callback fires once per TCP/UDP connection, at `L4Terminated`. It receives the
//! connection 5-tuple (`FiveTuple`, from the first packet) and the per-direction L4 byte
//! counts (`ByteCount`, payload bytes excluding packet headers). Each connection's
//! originator IP and responder IP are masked to a subnet prefix (`--v4-prefix` /
//! `--v6-prefix`, default `/24` and `/64`) and the connection's bytes are added to two
//! global tables:
//!
//! - **SRC table**, keyed by the originator's subnet: `sent` += bytes the originator sent,
//!   `recv` += bytes the originator received.
//! - **DST table**, keyed by the responder's subnet: `sent` += bytes the responder sent,
//!   `recv` += bytes the responder received.
//!
//! Both tables also count how many connections touched each subnet. Subnets are ranked by
//! `sent + recv` (total bytes moved on that subnet's behalf) descending.
//!
//! A connection where 10.0.0.5 talks to 93.184.216.34 contributes to `10.0.0.0/24` in the
//! SRC table and to `93.184.216.0/24` in the DST table -- so the same bytes appear once in
//! each ranking, which is what "noisiest source subnets" and "noisiest destination subnets"
//! each want.
//!
//! ## Output
//! Prints the top `--top` rows (default 20) of each table to stdout after the run. With
//! `--out <path>`, also writes the *complete* ranking (every subnet, both tables) as JSON.
//!
//! ## Run
//! ```
//! sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error \
//!   ./target/release/noisy_subnets --config configs/offline.toml --top 25 --out noisy.json
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use clap::Parser;
use iris_compiler::{callback, input_files, iris_end_macros};
use iris_core::{config::load_config, FiveTuple, Runtime};
use iris_datatypes::ByteCount;
use lazy_static::lazy_static;
use serde::Serialize;

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

    /// How many rows of each table to print to stdout.
    #[clap(short, long, value_name = "N", default_value_t = 20)]
    top: usize,

    /// IPv4 prefix length used to group source/destination addresses into subnets.
    #[clap(long, value_name = "BITS", default_value_t = 24)]
    v4_prefix: u8,

    /// IPv6 prefix length used to group source/destination addresses into subnets.
    #[clap(long, value_name = "BITS", default_value_t = 64)]
    v6_prefix: u8,

    /// Optional path to write the complete ranking (all subnets, both tables) as JSON.
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    out: Option<PathBuf>,
}

/// Running totals for one subnet in one role (source or destination).
#[derive(Default, Clone, Copy, Serialize)]
struct SubnetStat {
    /// Bytes sent by hosts in this subnet.
    sent: u64,
    /// Bytes received by hosts in this subnet.
    recv: u64,
    /// Connections in which this subnet took part in this role.
    conns: u64,
}

impl SubnetStat {
    fn total(&self) -> u64 {
        self.sent + self.recv
    }
}

lazy_static! {
    /// Keyed by the originator's subnet.
    static ref SRC: Mutex<HashMap<String, SubnetStat>> = Mutex::new(HashMap::new());
    /// Keyed by the responder's subnet.
    static ref DST: Mutex<HashMap<String, SubnetStat>> = Mutex::new(HashMap::new());
}

/// Set once from CLI args before the runtime starts; read by the callback on every core.
static V4_PREFIX: AtomicU8 = AtomicU8::new(24);
static V6_PREFIX: AtomicU8 = AtomicU8::new(64);

/// Masks `ip` to a subnet prefix and renders it as `network/prefix`.
fn subnet_str(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let p = V4_PREFIX.load(Ordering::Relaxed).min(32);
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            format!("{}/{}", Ipv4Addr::from(u32::from(a) & mask), p)
        }
        IpAddr::V6(a) => {
            let p = V6_PREFIX.load(Ordering::Relaxed).min(128);
            let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            format!("{}/{}", Ipv6Addr::from(u128::from(a) & mask), p)
        }
    }
}

fn add(table: &Mutex<HashMap<String, SubnetStat>>, key: String, sent: u64, recv: u64) {
    let mut map = table.lock().unwrap();
    let e = map.entry(key).or_default();
    e.sent += sent;
    e.recv += recv;
    e.conns += 1;
}

/// Fires once per TCP/UDP connection, when it terminates (FIN/RST or timeout).
#[callback("tcp or udp,level=L4Terminated")]
fn record(ft: &FiveTuple, bytes: &ByteCount) {
    let orig_bytes = bytes.orig() as u64;
    let resp_bytes = bytes.resp() as u64;

    // The originator's subnet sent `orig_bytes` and received `resp_bytes`.
    add(&SRC, subnet_str(ft.orig.ip()), orig_bytes, resp_bytes);
    // The responder's subnet sent `resp_bytes` and received `orig_bytes`.
    add(&DST, subnet_str(ft.resp.ip()), resp_bytes, orig_bytes);
}

#[derive(Serialize)]
struct Row {
    subnet: String,
    #[serde(flatten)]
    stat: SubnetStat,
    total: u64,
    /// This row's `total` as a percentage of all bytes in its table. Every connection
    /// contributes its bytes to exactly one row per table, so the rows' totals sum to the
    /// table's observed traffic and these percentages sum to 100 (barring rounding).
    pct_of_traffic: f64,
}

/// Sorts a table into a ranking, noisiest first.
fn ranked(table: &Mutex<HashMap<String, SubnetStat>>) -> Vec<Row> {
    let stats: Vec<(String, SubnetStat)> = table
        .lock()
        .unwrap()
        .iter()
        .map(|(subnet, stat)| (subnet.clone(), *stat))
        .collect();
    let table_total: u64 = stats.iter().map(|(_, stat)| stat.total()).sum();
    let mut rows: Vec<Row> = stats
        .into_iter()
        .map(|(subnet, stat)| {
            let total = stat.total();
            Row {
                subnet,
                stat,
                total,
                pct_of_traffic: if table_total == 0 {
                    0.0
                } else {
                    100.0 * total as f64 / table_total as f64
                },
            }
        })
        .collect();
    rows.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.subnet.cmp(&b.subnet)));
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

fn print_table(title: &str, rows: &[Row], top: usize) {
    println!("\n=== {title} (top {top} of {}) ===", rows.len());
    println!(
        "{:<24}  {:>12}  {:>9}  {:>12}  {:>12}  {:>8}",
        "subnet", "total", "% traffic", "sent", "recv", "conns"
    );
    for r in rows.iter().take(top) {
        println!(
            "{:<24}  {:>12}  {:>8.2}%  {:>12}  {:>12}  {:>8}",
            r.subnet,
            human(r.total),
            r.pct_of_traffic,
            human(r.stat.sent),
            human(r.stat.recv),
            r.stat.conns
        );
    }
}

#[derive(Serialize)]
struct Report {
    v4_prefix: u8,
    v6_prefix: u8,
    by_source_subnet: Vec<Row>,
    by_dest_subnet: Vec<Row>,
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();
    V4_PREFIX.store(args.v4_prefix, Ordering::Relaxed);
    V6_PREFIX.store(args.v6_prefix, Ordering::Relaxed);

    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    let by_src = ranked(&SRC);
    let by_dst = ranked(&DST);

    print_table("Noisiest source subnets", &by_src, args.top);
    print_table("Noisiest destination subnets", &by_dst, args.top);

    if let Some(path) = args.out {
        let report = Report {
            v4_prefix: args.v4_prefix,
            v6_prefix: args.v6_prefix,
            by_source_subnet: by_src,
            by_dest_subnet: by_dst,
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        std::fs::write(&path, json).unwrap();
        println!("\nWrote full ranking to {}", path.display());
    }
}
