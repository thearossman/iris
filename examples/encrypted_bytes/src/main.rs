//! Counts bytes across all of Iris's encrypted stream protocols (TLS, SSH, QUIC,
//! WireGuard, IKE), split into cleartext handshake bytes vs. encrypted payload bytes, plus
//! total TCP and UDP traffic.
//!
//! ## Handshake vs. payload split
//! This deliberately does NOT use `L4Pdu::app_body_offset()`/`pdu.ctxt.app_offset`, despite
//! that looking like the obvious per-packet signal. It isn't reliable for this purpose:
//! `process_stream` is the only code that ever sets it
//! (`core/src/conntrack/conn/conn_layers.rs`), and `process_stream` is only invoked while
//! the L7 layer's `Actions::Parse` bit is set. That bit is cleared as soon as headers
//! finish for any parser reporting `ParsingState::Stop` -- which is TLS, SSH, WireGuard,
//! and IKE (only QUIC reports `Parsing`). So for four of the five protocols here,
//! `app_offset` is never touched again after the handshake packet and just sits at its
//! per-packet default of `None` on every later packet, even ones deep in the encrypted
//! payload -- indistinguishable from "still in the handshake". (There's a second wrinkle
//! on the transition packet itself: `consume_stream` can invoke `process_stream` a second
//! time in the same pass when a precise split offset was reported, and that second call
//! unconditionally resets `app_offset` to `Some(0)` before any subscriber ever observes the
//! precise offset -- so even TLS/SSH's sub-packet split is never actually visible here.)
//!
//! Instead, this tracks an `in_payload` flag per connection, flipped exactly once by an
//! `L7EndHdrs`-level callback method (the same pattern `TlsCbStreaming` in
//! `examples/basic/src/main.rs` uses). `L7EndHdrs` fires exactly once, when the handshake
//! completes, and is dispatched before that same packet's `InL4Conn` update
//! (`ConnInfo::consume_stream` calls `process_stream`/`exec_state_tx` -- which is what
//! dispatches `L7EndHdrs` -- before `new_packet`, which dispatches `InL4Conn`). So the one
//! packet on which the handshake completes is counted entirely as payload (a whole-packet
//! granularity approximation on that single packet), and -- critically, unlike the
//! `app_offset` approach -- every packet after it is correctly counted as payload too,
//! regardless of whether the parser is still actively running.
//!
//! ## `--min-bytes`
//! Passing `--min-bytes N` excludes any connection whose own total byte count (handshake +
//! payload for `EncBytesCallback`, tcp + udp for `TransportBytes`) is not more than `N` --
//! its packets never reach any global counter at all, rather than being counted and then
//! subtracted out. The check happens once per connection, in each callback's own
//! `L4Terminated` handler, using that connection's own running total; the two callbacks never
//! need to compare notes, since a connection matched by both tracks the same packets and so
//! arrives at the same total independently. Default is 0, i.e. no filtering.

use clap::Parser;
use iris_compiler::{callback, callback_fn, datatype, datatype_fn, input_files, iris_end_macros};
use iris_core::protocols::packet::tcp::TCP_PROTOCOL;
use iris_core::protocols::packet::udp::UDP_PROTOCOL;
use iris_core::protocols::stream::SessionProto;
use iris_core::subscription::{StreamingCallback, Tracked};
use iris_core::{config::load_config, L4Pdu, Runtime};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

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

    /// Only count a connection (and the packets in it) if its total byte count is more than N.
    /// 0 (the default) counts every connection.
    #[clap(short, long, value_name = "N", default_value_t = 0)]
    min_bytes: usize,
}

/// Set from `--min-bytes`, read once per connection at `L4Terminated` by both
/// `EncBytesCallback::finalize` and `record_transport_bytes`. 0 means no filtering.
static MIN_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Whether a connection with `total_bytes` clears the `--min-bytes` bar, i.e. should be
/// counted. "More than" is strict, so a connection with exactly `min_bytes` bytes is excluded.
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

/// Running handshake/payload byte totals for one encrypted protocol.
struct ByteTotals {
    handshake: AtomicUsize,
    payload: AtomicUsize,
}

impl ByteTotals {
    fn new() -> Self {
        Self {
            handshake: AtomicUsize::new(0),
            payload: AtomicUsize::new(0),
        }
    }

    fn add(&self, handshake: usize, payload: usize) {
        self.handshake.fetch_add(handshake, Ordering::Relaxed);
        self.payload.fetch_add(payload, Ordering::Relaxed);
    }
}

lazy_static! {
    static ref TLS_BYTES: ByteTotals = ByteTotals::new();
    static ref SSH_BYTES: ByteTotals = ByteTotals::new();
    static ref QUIC_BYTES: ByteTotals = ByteTotals::new();
    static ref WIREGUARD_BYTES: ByteTotals = ByteTotals::new();
    static ref IKE_BYTES: ByteTotals = ByteTotals::new();
    static ref TCP_BYTES: AtomicUsize = AtomicUsize::new(0);
    static ref UDP_BYTES: AtomicUsize = AtomicUsize::new(0);
}

/// One stateful callback across all five encrypted protocols: the filter's OR predicate
/// registers all five parsers, and `SessionProto` (read once the connection is torn down)
/// tells us which one actually matched, so the handshake/payload split logic itself never
/// needs to know which protocol it's looking at -- it only reacts to generic `L4Pdu`/state-
/// transition events.
#[callback("tls or ssh or quic or wireguard or ike")]
#[derive(Debug)]
struct EncBytesCallback {
    in_payload: bool,
    handshake_bytes: usize,
    payload_bytes: usize,
}

impl StreamingCallback for EncBytesCallback {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            in_payload: false,
            handshake_bytes: 0,
            payload_bytes: 0,
        }
    }

    fn clear(&mut self) {}
}

impl EncBytesCallback {
    #[callback_fn("EncBytesCallback,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) -> bool {
        let len = pdu.length();
        if len > 0 {
            if self.in_payload {
                self.payload_bytes += len;
            } else {
                self.handshake_bytes += len;
            }
        }
        true
    }

    /// Fires exactly once, when the handshake completes. See the module docs for why this
    /// (rather than `app_offset`) is the reliable signal, and why it's dispatched before
    /// this same packet's `update` above.
    #[callback_fn("EncBytesCallback,level=L7EndHdrs")]
    fn end_handshake(&mut self) -> bool {
        self.in_payload = true;
        true
    }

    #[callback_fn("EncBytesCallback,level=L4Terminated")]
    fn finalize(&mut self, proto: &SessionProto) -> bool {
        let totals = match proto {
            SessionProto::Tls => &*TLS_BYTES,
            SessionProto::Ssh => &*SSH_BYTES,
            SessionProto::Quic => &*QUIC_BYTES,
            SessionProto::Wireguard => &*WIREGUARD_BYTES,
            SessionProto::Ike => &*IKE_BYTES,
            _ => return false,
        };
        // Below the bar: none of this connection's bytes are added, not even to a "dropped"
        // bucket -- excluded connections are invisible to every printed total.
        let total = self.handshake_bytes + self.payload_bytes;
        if !clears_min_bytes(total, MIN_BYTES.load(Ordering::Relaxed)) {
            return false;
        }
        totals.add(self.handshake_bytes, self.payload_bytes);
        false
    }
}

/// Per-connection tracked datatype for total TCP/UDP traffic, independent of whether an
/// application-layer protocol was ever identified on the connection.
#[datatype]
struct TransportBytes {
    tcp_bytes: usize,
    udp_bytes: usize,
}

impl TransportBytes {
    #[datatype_fn("TransportBytes,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) {
        let len = pdu.length();
        if len == 0 {
            return;
        }
        match pdu.ctxt.proto {
            TCP_PROTOCOL => self.tcp_bytes += len,
            UDP_PROTOCOL => self.udp_bytes += len,
            _ => {}
        }
    }
}

impl Tracked for TransportBytes {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            tcp_bytes: 0,
            udp_bytes: 0,
        }
    }

    fn clear(&mut self) {
        self.tcp_bytes = 0;
        self.udp_bytes = 0;
    }
}

#[callback("tcp or udp,level=L4Terminated")]
fn record_transport_bytes(bytes: &TransportBytes) {
    // Same threshold, applied to this callback's own total; see the `--min-bytes` module docs
    // for why the two callbacks don't need to coordinate to agree on which connections count.
    let total = bytes.tcp_bytes + bytes.udp_bytes;
    if !clears_min_bytes(total, MIN_BYTES.load(Ordering::Relaxed)) {
        return;
    }
    TCP_BYTES.fetch_add(bytes.tcp_bytes, Ordering::Relaxed);
    UDP_BYTES.fetch_add(bytes.udp_bytes, Ordering::Relaxed);
}

/// Returns `100 * numerator / denominator` as a percentage, or `None` if `denominator` is
/// zero (e.g. a protocol that was never observed in this trace).
fn pct(numerator: usize, denominator: usize) -> Option<f64> {
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

/// Prints one protocol's handshake/payload split and its share of total transport traffic.
fn print_proto(name: &str, totals: &ByteTotals, transport_total: usize) {
    let handshake = totals.handshake.load(Ordering::Relaxed);
    let payload = totals.payload.load(Ordering::Relaxed);
    let total = handshake + payload;
    println!(
        "{:<10} handshake: {}   payload: {}   of total traffic: {}",
        name,
        fmt_pct(pct(handshake, total)),
        fmt_pct(pct(payload, total)),
        fmt_pct(pct(total, transport_total)),
    );
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();
    MIN_BYTES.store(args.min_bytes, Ordering::Relaxed);
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    let tcp_bytes = TCP_BYTES.load(Ordering::Relaxed);
    let udp_bytes = UDP_BYTES.load(Ordering::Relaxed);
    let transport_total = tcp_bytes + udp_bytes;

    if args.min_bytes > 0 {
        println!(
            "\n(Connections with {} or fewer total bytes are excluded from every count below.)",
            args.min_bytes
        );
    }
    println!("\n=== Encrypted protocol bytes: handshake % vs. payload %, and % of total transport traffic ===");
    print_proto("TLS", &TLS_BYTES, transport_total);
    print_proto("SSH", &SSH_BYTES, transport_total);
    print_proto("QUIC", &QUIC_BYTES, transport_total);
    print_proto("WireGuard", &WIREGUARD_BYTES, transport_total);
    print_proto("IKE", &IKE_BYTES, transport_total);

    println!("\n=== Total transport-layer traffic ===");
    println!("TCP: {}", fmt_pct(pct(tcp_bytes, transport_total)));
    println!("UDP: {}", fmt_pct(pct(udp_bytes, transport_total)));
}
