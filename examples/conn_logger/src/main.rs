/// Connection logger
///
/// For every TCP or UDP connection Iris observes this application records:
///
///   • Anonymized source/destination IPs (CryptoPAN, prefix-preserving AES-128)
///   • Source/destination ports
///   • Start wall-clock timestamp and end timestamp
///   • Flow end reason  (FIN | RST | Timeout)
///   • Non-SYN/ACK TCP flags seen over the lifetime of the connection
///
/// Per 10-second window:
///   • Packet count, total packet bytes, L4-payload bytes  (each direction)
///   • Duration of the window (ms)
///   • Jitter: std-dev of inter-arrival times in µs  (each direction)
///   • TCP only: min/max/mean receive-window size  (each direction)
///   • TCP only: retransmission count, sequence-gap count
///
/// For applicable connections, additional records are written (same file,
/// linked by five-tuple):
///   • TLS / QUIC: SNI observed in the handshake
///   • DNS: query domain, response code, answers
///   • HTTP: method, host, URI, status code
///
/// Output: per-core JSONL files named conn_log_<N>.jsonl
use clap::Parser;
use iris_compiler::*;
use iris_core::subscription::StreamingCallback;
use iris_core::{config::load_config, CoreId, FiveTuple, L4Pdu, Runtime};
use iris_core::protocols::packet::tcp::TCP_PROTOCOL;
use iris_datatypes::{DnsTransaction, HttpTransaction, QuicStream, TlsHandshake};
use serde::Serialize;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

mod cryptopan;
mod flow_windows;
mod tcp_state;
mod writer;

use cryptopan::CryptoPAN;
use flow_windows::{FlowWindows, WindowRecord};
use tcp_state::TcpFlowState;

// ---------------------------------------------------------------------------
// Global CryptoPAN instance (set once from CLI before the runtime starts)
// ---------------------------------------------------------------------------

static CRYPTOPAN: OnceLock<CryptoPAN> = OnceLock::new();

fn anonymize(ip: IpAddr) -> String {
    CRYPTOPAN
        .get()
        .expect("CryptoPAN not initialized")
        .anonymize(ip)
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[clap(about = "Per-connection feature logger with CryptoPAN IP anonymization")]
struct Args {
    /// Path to the Iris runtime config TOML file.
    #[clap(short, long, parse(from_os_str), default_value = "./configs/offline.toml")]
    config: PathBuf,

    /// 32-byte hex-encoded CryptoPAN key (64 hex characters).
    /// If omitted a built-in test key is used — CHANGE THIS IN PRODUCTION.
    #[clap(
        short,
        long,
        default_value = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )]
    key: String,
}

fn parse_hex_key(s: &str) -> [u8; 32] {
    let s = s.trim();
    assert_eq!(s.len(), 64, "CryptoPAN key must be 64 hex characters (32 bytes)");
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let byte = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
            .expect("invalid hex character in key");
        out[i] = byte;
    }
    out
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// ConnLogger — thin streaming callback; feature extraction is in FlowWindows
// and TcpFlowState datatypes
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ConnLogRecord {
    #[serde(rename = "type")]
    record_type: &'static str,
    orig_ip: String,
    orig_port: u16,
    resp_ip: String,
    resp_port: u16,
    proto: &'static str,
    start_ms: u64,
    end_ms: u64,
    duration_ms: u64,
    end_reason: &'static str,
    /// Non-SYN/ACK TCP flags observed (URG, PSH, RST, FIN seen outside handshake).
    tcp_flags: Vec<&'static str>,
    windows: Vec<WindowRecord>,
}

// Filter out CAPWAP traffic
#[derive(Debug)]
#[callback("tcp or (udp and udp.port != 5247 and udp.port != 5246)")]
struct ConnLogger {
    orig_ip: String,
    orig_port: u16,
    resp_ip: String,
    resp_port: u16,
    proto: &'static str,
    start_wall_ms: u64,
}

impl StreamingCallback for ConnLogger {
    fn new(first_pkt: &L4Pdu) -> Self {
        let ft = FiveTuple::from_ctxt(&first_pkt.ctxt);
        Self {
            orig_ip: anonymize(ft.orig.ip()),
            orig_port: ft.orig.port(),
            resp_ip: anonymize(ft.resp.ip()),
            resp_port: ft.resp.port(),
            proto: if ft.proto == TCP_PROTOCOL { "TCP" } else { "UDP" },
            start_wall_ms: now_unix_ms(),
        }
    }

    fn clear(&mut self) {}
}

impl ConnLogger {
    #[callback_fn("ConnLogger,level=L4Terminated")]
    fn on_terminated(
        &mut self,
        windows: &FlowWindows,
        tcp: &TcpFlowState,
        core: &CoreId,
    ) -> bool {
        // Capture the monotonic instant first so that all_windows and the
        // wall-clock end_ms reflect the same point in time.
        let end_ts = Instant::now();
        let end_wall_ms = now_unix_ms();
        let duration_ms = end_wall_ms.saturating_sub(self.start_wall_ms);

        let record = ConnLogRecord {
            record_type: "conn",
            orig_ip: self.orig_ip.clone(),
            orig_port: self.orig_port,
            resp_ip: self.resp_ip.clone(),
            resp_port: self.resp_port,
            proto: self.proto,
            start_ms: self.start_wall_ms,
            end_ms: end_wall_ms,
            duration_ms,
            end_reason: tcp.end_reason(),
            tcp_flags: tcp.flag_names(),
            windows: windows.all_windows(end_ts),
        };

        writer::with_writer(core, |w| serde_json::to_writer(w, &record));

        false
    }
}

// ---------------------------------------------------------------------------
// Helpers shared by protocol callbacks
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct AnonFt {
    orig_ip: String,
    orig_port: u16,
    resp_ip: String,
    resp_port: u16,
    proto: &'static str,
}

fn anon_ft(ft: &FiveTuple) -> AnonFt {
    AnonFt {
        orig_ip: anonymize(ft.orig.ip()),
        orig_port: ft.orig.port(),
        resp_ip: anonymize(ft.resp.ip()),
        resp_port: ft.resp.port(),
        proto: if ft.proto == TCP_PROTOCOL { "TCP" } else { "UDP" },
    }
}

// ---------------------------------------------------------------------------
// TLS SNI
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct TlsRecord {
    #[serde(rename = "type")]
    record_type: &'static str,
    five_tuple: AnonFt,
    sni: String,
}

#[callback("tls")]
fn log_tls(tls: &TlsHandshake, ft: &FiveTuple, core: &CoreId) {
    let sni = tls.sni();
    if sni.is_empty() {
        return;
    }
    let record = TlsRecord {
        record_type: "tls",
        five_tuple: anon_ft(ft),
        sni: sni.to_owned(),
    };
    writer::with_writer(core, |w| serde_json::to_writer(w, &record));
}

// ---------------------------------------------------------------------------
// QUIC SNI
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct QuicRecord {
    #[serde(rename = "type")]
    record_type: &'static str,
    five_tuple: AnonFt,
    sni: String,
}

#[callback("quic and udp.port != 5247 and udp.port != 5246")]
fn log_quic(quic: &QuicStream, ft: &FiveTuple, core: &CoreId) {
    let sni = quic.tls.sni();
    if sni.is_empty() {
        return;
    }
    let record = QuicRecord {
        record_type: "quic",
        five_tuple: anon_ft(ft),
        sni: sni.to_owned(),
    };
    writer::with_writer(core, |w| serde_json::to_writer(w, &record));
}

// ---------------------------------------------------------------------------
// DNS transactions
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct DnsRecord {
    #[serde(rename = "type")]
    record_type: &'static str,
    five_tuple: AnonFt,
    query: String,
    rcode: String,
    answers: Vec<String>,
}

#[callback("dns")]
fn log_dns(dns: &DnsTransaction, ft: &FiveTuple, core: &CoreId) {
    use dns_parser::ResponseCode;
    use iris_core::protocols::stream::dns::Data;

    let query = dns.query_domain().to_owned();
    if query.is_empty() {
        return;
    }

    let (rcode, answers) = match &dns.response {
        None => ("NoResponse".to_owned(), vec![]),
        Some(resp) => {
            let rcode = match resp.response_code {
                ResponseCode::NoError => "NoError".to_owned(),
                ResponseCode::FormatError => "FormatError".to_owned(),
                ResponseCode::ServerFailure => "ServerFailure".to_owned(),
                ResponseCode::NameError => "NameError".to_owned(),
                ResponseCode::NotImplemented => "NotImplemented".to_owned(),
                ResponseCode::Refused => "Refused".to_owned(),
                ResponseCode::Reserved(n) => format!("Reserved({})", n),
            };
            let answers = resp
                .answers
                .iter()
                .map(|r| match &r.data {
                    Data::A(a) => a.0.to_string(),
                    Data::Aaaa(a) => a.0.to_string(),
                    Data::Cname(c) => c.clone(),
                    Data::Ptr(p) => p.clone(),
                    Data::Ns(n) => n.clone(),
                    Data::Mx(m) => format!("{} {}", m.preference, m.exchange),
                    Data::Txt(t) => t.clone(),
                    Data::Srv(s) => format!("{}:{}", s.target, s.port),
                    Data::Soa(s) => s.primary_ns.clone(),
                    Data::Unknown => "unknown".to_owned(),
                })
                .collect();
            (rcode, answers)
        }
    };

    let record = DnsRecord {
        record_type: "dns",
        five_tuple: anon_ft(ft),
        query,
        rcode,
        answers,
    };
    writer::with_writer(core, |w| serde_json::to_writer(w, &record));
}

// ---------------------------------------------------------------------------
// HTTP transactions
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct HttpRecord {
    #[serde(rename = "type")]
    record_type: &'static str,
    five_tuple: AnonFt,
    method: String,
    host: String,
    uri: String,
    status: u16,
}

#[callback("http")]
fn log_http(http: &HttpTransaction, ft: &FiveTuple, core: &CoreId) {
    let host = http.host().to_owned();
    let uri = http.uri().to_owned();
    if host.is_empty() && uri.is_empty() {
        return;
    }
    let record = HttpRecord {
        record_type: "http",
        five_tuple: anon_ft(ft),
        method: http.method().to_owned(),
        host,
        uri,
        status: http.status_code(),
    };
    writer::with_writer(core, |w| serde_json::to_writer(w, &record));
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();

    let args = Args::parse();
    let key = parse_hex_key(&args.key);
    CRYPTOPAN.set(CryptoPAN::new(&key)).expect("CryptoPAN already initialized");

    writer::init_writers();

    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    writer::flush_writers();
    writer::finalize_writers();
    writer::combine_writers();
}
