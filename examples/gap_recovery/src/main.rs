//! Reports how much of each TCP connection's stream Iris actually reassembled.
//!
//! Iris does not discard a connection when a sequence-number gap cannot be filled.
//! It abandons the gap, resumes at the next buffered segment, and records the bytes
//! lost. This app makes that visible, and is the vehicle for checking the behavior
//! end to end against a lossy trace.
//!
//! Build a lossy trace by dropping every 37th packet, point `configs/offline.toml`
//! at it, and compare against a run on a build without gap recovery:
//!
//! ```text
//! python3 -c "from scapy.all import *; p=rdpcap('traces/small_flows.pcap'); \
//!     wrpcap('/tmp/lossy.pcap',[x for i,x in enumerate(p) if i%37])"
//! sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH ./target/release/gap_recovery \
//!     --config configs/offline.toml
//! ```
//!
//! Expect: strictly more connections reported than before (connections that hit an
//! out-of-order buffer overflow used to vanish entirely), non-zero missing bytes,
//! and TLS handshakes delivered with `complete() == false`.

use clap::Parser;
use iris_compiler::*;
use iris_core::{config::load_config, Runtime};
use iris_datatypes::{ConnRecord, ReassemblyStats, TlsHandshake};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

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
}

// Callbacks run on multiple cores, so tallies must be atomic.
static CONNS: AtomicU64 = AtomicU64::new(0);
static GAPPED_CONNS: AtomicU64 = AtomicU64::new(0);
static MISSING_BYTES: AtomicU64 = AtomicU64::new(0);
static RECOVERED_BYTES: AtomicU64 = AtomicU64::new(0);
static TRUNCATED_TLS: AtomicU64 = AtomicU64::new(0);
static START_UNOBSERVED_CONNS: AtomicU64 = AtomicU64::new(0);

/// Every TCP connection, whether or not its stream was complete.
#[callback("tcp,level=L4Terminated")]
fn tally_conn(reassembly: &ReassemblyStats, record: &ConnRecord) {
    CONNS.fetch_add(1, Ordering::Relaxed);
    if reassembly.start_unobserved() {
        // Either adopted mid-stream (needs an `init_*` option) or reassembly gave
        // up waiting for a direction's stream start.
        START_UNOBSERVED_CONNS.fetch_add(1, Ordering::Relaxed);
    }
    if reassembly.complete() {
        return;
    }
    GAPPED_CONNS.fetch_add(1, Ordering::Relaxed);
    MISSING_BYTES.fetch_add(reassembly.missing_bytes(), Ordering::Relaxed);
    RECOVERED_BYTES.fetch_add(reassembly.recovered_bytes(), Ordering::Relaxed);

    // `ConnRecord` is the observational view: it counts every hole in the sequence
    // space, including ones reassembly never had to give up on. So its figure
    // should bound the reassembly view from above.
    let observed_missing = record.orig.missed_bytes() + record.resp.missed_bytes();
    println!(
        "{}: {} gaps, {} bytes missing ({} observed), {} bytes recovered after gaps",
        record.five_tuple,
        reassembly.nb_gaps(),
        reassembly.missing_bytes(),
        observed_missing,
        reassembly.recovered_bytes(),
    );
}

/// A TLS handshake still delivered despite the stream having holes: the parser
/// finalized on the gap and handed back what it had managed to extract.
#[callback("tls,level=L4Terminated")]
fn tally_truncated_tls(tls: &TlsHandshake, reassembly: &ReassemblyStats) {
    if reassembly.complete() {
        return;
    }
    TRUNCATED_TLS.fetch_add(1, Ordering::Relaxed);
    println!(
        "Recovered TLS handshake over a lossy stream (sni {:?}, {} bytes missing)",
        tls.sni(),
        reassembly.missing_bytes(),
    );
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    let conns = CONNS.load(Ordering::Relaxed);
    let gapped = GAPPED_CONNS.load(Ordering::Relaxed);
    println!("\n=== Reassembly summary ===");
    println!("TCP connections delivered: {}", conns);
    println!("  with unfilled gaps:      {}", gapped);
    println!(
        "  bytes never observed:    {}",
        MISSING_BYTES.load(Ordering::Relaxed)
    );
    println!(
        "  bytes recovered past a gap: {}",
        RECOVERED_BYTES.load(Ordering::Relaxed)
    );
    println!(
        "  TLS handshakes recovered from lossy streams: {}",
        TRUNCATED_TLS.load(Ordering::Relaxed)
    );
    println!(
        "  stream start never observed:  {}",
        START_UNOBSERVED_CONNS.load(Ordering::Relaxed)
    );
}
