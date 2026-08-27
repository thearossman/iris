//! Rank the "noisiest" subnets by byte volume, counting a subnet's traffic whether it was
//! the *source* or the *destination* of a flow.
//!
//! ## What it measures
//! One callback fires once per TCP/UDP connection, at `L4Terminated`. It receives the
//! connection 5-tuple (`FiveTuple`, from the first packet) and the L4 byte count
//! (`ByteCount`, payload bytes excluding packet headers). Both endpoint IPs are masked to a
//! subnet prefix (`--v4-prefix` / `--v6-prefix`, default `/24` and `/64`), and the
//! connection's total bytes are added to *each* endpoint subnet's running total -- the
//! direction of the flow is not tracked.
//!
//! So a connection where 10.0.0.5 talks to 93.184.216.34 moving 1 MiB adds 1 MiB to both
//! `10.0.0.0/24` and `93.184.216.0/24`. A subnet's total is therefore "bytes in every flow
//! this subnet took part in, either end". Subnets are ranked by that total descending.
//!
//! `pct_of_traffic` is a subnet's total over the sum of all connections' bytes. Because a
//! flow's bytes count toward both of its endpoints, these percentages do not sum to 100%.
//!
//! ## Output
//! Prints the top `--top` subnet rows (default 20) to stdout after the run, then the 5
//! noisiest individual public addresses with the share of total traffic each carries, then
//! the share of all connection bytes that belonged to a flow with at least one endpoint in
//! private IP space (RFC 1918 for IPv4, `fc00::/7` unique-local for IPv6). With
//! `--out <path>`, also writes the complete subnet ranking (every subnet) as JSON.
//!
//! ## Run
//! ```
//! sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error \
//!   ./target/release/noisy_subnets --config configs/offline.toml --top 25 --out noisy.json
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
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

    /// How many rows to print to stdout.
    #[clap(short, long, value_name = "N", default_value_t = 20)]
    top: usize,

    /// IPv4 prefix length used to group addresses into subnets.
    #[clap(long, value_name = "BITS", default_value_t = 24)]
    v4_prefix: u8,

    /// IPv6 prefix length used to group addresses into subnets.
    #[clap(long, value_name = "BITS", default_value_t = 64)]
    v6_prefix: u8,

    /// Optional path to write the complete ranking (every subnet) as JSON.
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    out: Option<PathBuf>,
}

/// Running totals for one subnet.
#[derive(Default, Clone, Copy, Serialize)]
struct SubnetStat {
    /// Bytes in every flow this subnet was an endpoint of (either end).
    bytes: u64,
    /// Flows this subnet was an endpoint of.
    conns: u64,
}

/// Running totals for one individual endpoint address.
#[derive(Default, Clone, Copy)]
struct IpStat {
    /// Bytes in every flow this address was an endpoint of (either end).
    bytes: u64,
    /// Flows this address was an endpoint of.
    conns: u64,
}

lazy_static! {
    /// Keyed by subnet, regardless of whether the subnet was the flow's source or destination.
    static ref SUBNETS: Mutex<HashMap<String, SubnetStat>> = Mutex::new(HashMap::new());

    /// Keyed by individual public (non-private) address, source or destination alike.
    static ref PUBLIC_IPS: Mutex<HashMap<IpAddr, IpStat>> = Mutex::new(HashMap::new());
}

/// Sum of every connection's byte count, counted once per connection. Denominator for
/// `pct_of_traffic`.
static TOTAL_BYTES: AtomicU64 = AtomicU64::new(0);

/// Sum of the byte count of every connection with at least one endpoint in private IP space
/// (RFC 1918 for IPv4, `fc00::/7` unique-local for IPv6). Counted once per connection.
static PRIVATE_BYTES: AtomicU64 = AtomicU64::new(0);

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

/// Whether `ip` falls in private (non-globally-routable "internal") address space:
/// RFC 1918 (`10/8`, `172.16/12`, `192.168/16`) for IPv4, unique-local (`fc00::/7`) for IPv6.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private(),
        IpAddr::V6(a) => a.is_unique_local(),
    }
}

/// Whether `ip` is a "public" address: routable on the open internet, i.e. not private and
/// not one of the other special-use ranges (loopback, link-local, multicast, broadcast,
/// unspecified, documentation).
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            !a.is_private()
                && !a.is_loopback()
                && !a.is_link_local()
                && !a.is_multicast()
                && !a.is_broadcast()
                && !a.is_unspecified()
                && !a.is_documentation()
        }
        IpAddr::V6(a) => {
            !a.is_unique_local()
                && !a.is_loopback()
                && !a.is_multicast()
                && !a.is_unspecified()
                && !a.is_unicast_link_local()
        }
    }
}

fn add(key: String, bytes: u64) {
    let mut map = SUBNETS.lock().unwrap();
    let e = map.entry(key).or_default();
    e.bytes += bytes;
    e.conns += 1;
}

fn add_public_ip(ip: IpAddr, bytes: u64) {
    let mut map = PUBLIC_IPS.lock().unwrap();
    let e = map.entry(ip).or_default();
    e.bytes += bytes;
    e.conns += 1;
}

/// Fires once per TCP/UDP connection, when it terminates (FIN/RST or timeout).
#[callback("tcp or udp,level=L4Terminated")]
fn record(ft: &FiveTuple, bytes: &ByteCount) {
    let total = bytes.total() as u64;
    TOTAL_BYTES.fetch_add(total, Ordering::Relaxed);
    let src_ip = ft.orig.ip();
    let dst_ip = ft.resp.ip();
    if is_private(src_ip) || is_private(dst_ip) {
        PRIVATE_BYTES.fetch_add(total, Ordering::Relaxed);
    }
    if is_public(src_ip) {
        add_public_ip(src_ip, total);
    }
    // Guard against crediting an address twice when both endpoints are it.
    if is_public(dst_ip) && dst_ip != src_ip {
        add_public_ip(dst_ip, total);
    }

    let src = subnet_str(src_ip);
    let dst = subnet_str(dst_ip);
    add(src.clone(), total);
    // Guard against crediting a subnet twice when both endpoints fall in it.
    if dst != src {
        add(dst, total);
    }
}

#[derive(Serialize)]
struct Row {
    subnet: String,
    bytes: u64,
    conns: u64,
    /// `bytes` over the sum of all connections' bytes. A flow counts toward both of its
    /// endpoint subnets, so these do not sum to 100%.
    pct_of_traffic: f64,
}

/// Sorts the table into a ranking, noisiest first.
fn ranked() -> Vec<Row> {
    let total_traffic = TOTAL_BYTES.load(Ordering::Relaxed);
    let mut rows: Vec<Row> = SUBNETS
        .lock()
        .unwrap()
        .iter()
        .map(|(subnet, stat)| Row {
            subnet: subnet.clone(),
            bytes: stat.bytes,
            conns: stat.conns,
            pct_of_traffic: if total_traffic == 0 {
                0.0
            } else {
                100.0 * stat.bytes as f64 / total_traffic as f64
            },
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

fn print_table(rows: &[Row], top: usize) {
    println!("\n=== Noisiest subnets (top {top} of {}) ===", rows.len());
    println!(
        "{:<24}  {:>12}  {:>9}  {:>8}",
        "subnet", "bytes", "% traffic", "conns"
    );
    for r in rows.iter().take(top) {
        println!(
            "{:<24}  {:>12}  {:>8.2}%  {:>8}",
            r.subnet,
            human(r.bytes),
            r.pct_of_traffic,
            r.conns
        );
    }
}

/// Prints the `n` noisiest individual public addresses and the share of total traffic each
/// carries. As with the subnet table, a flow's bytes count toward both of its endpoints, so
/// these percentages need not sum to anything in particular.
fn print_top_public_ips(n: usize) {
    let total_traffic = TOTAL_BYTES.load(Ordering::Relaxed);
    let mut rows: Vec<(IpAddr, IpStat)> = PUBLIC_IPS
        .lock()
        .unwrap()
        .iter()
        .map(|(ip, stat)| (*ip, *stat))
        .collect();
    rows.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then_with(|| a.0.cmp(&b.0)));

    println!("\n=== Noisiest public IPs (top {n} of {}) ===", rows.len());
    println!(
        "{:<39}  {:>12}  {:>9}  {:>8}",
        "address", "bytes", "% traffic", "conns"
    );
    for (ip, stat) in rows.iter().take(n) {
        let pct = if total_traffic == 0 {
            0.0
        } else {
            100.0 * stat.bytes as f64 / total_traffic as f64
        };
        println!(
            "{:<39}  {:>12}  {:>8.2}%  {:>8}",
            ip.to_string(),
            human(stat.bytes),
            pct,
            stat.conns
        );
    }
}

#[derive(Serialize)]
struct Report {
    v4_prefix: u8,
    v6_prefix: u8,
    subnets: Vec<Row>,
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

    let rows = ranked();
    print_table(&rows, args.top);
    print_top_public_ips(5);

    let total_bytes = TOTAL_BYTES.load(Ordering::Relaxed);
    let private_bytes = PRIVATE_BYTES.load(Ordering::Relaxed);
    let private_pct = if total_bytes == 0 {
        0.0
    } else {
        100.0 * private_bytes as f64 / total_bytes as f64
    };
    println!(
        "\nBytes in flows with >=1 private-space endpoint: {} of {} ({private_pct:.2}%)",
        human(private_bytes),
        human(total_bytes),
    );

    if let Some(path) = args.out {
        let report = Report {
            v4_prefix: args.v4_prefix,
            v6_prefix: args.v6_prefix,
            subnets: rows,
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        std::fs::write(&path, json).unwrap();
        println!("\nWrote full ranking to {}", path.display());
    }
}
