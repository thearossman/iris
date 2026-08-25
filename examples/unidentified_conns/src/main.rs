//! Writes a raw packet capture containing a sample of the connections that Iris's stateful
//! parsers could *not* identify.
//!
//! All of Iris's session parsers (TLS, DNS, HTTP, QUIC, SSH, WireGuard, IKE) are registered
//! and run against every TCP/UDP connection. Connections that any of them successfully
//! identifies are discarded; the ones left over -- where protocol discovery failed outright,
//! or never completed -- have their raw packets written out.
//!
//! ## Keeping up at line rate
//! Buffering every packet of every connection would not survive a real link, so the sampling
//! decision is made once, in `StreamingCallback::new`, from the connection's five-tuple alone.
//! Connections that lose the draw unsubscribe on their very first packet by returning `false`,
//! which tears down all tracking for them -- no frames buffered, and Iris stops running the
//! L7 parsers over them too. Only the sampled minority ever costs anything.
//!
//! A sampled connection is only written out if it also carries at least `--min-bytes` of
//! captured frame data. Whether it clears that bar is not knowable until teardown, so the
//! check happens in `finalize` alongside the identified/unanswered checks -- the frames are
//! still buffered as they arrive, but a connection that falls short is dropped rather than
//! written. This filters out trickle connections that carry too little to be worth dissecting.
//!
//! Output is sharded one pcap file per core, each behind its own `BufWriter`, so RX cores
//! never contend on a shared writer or interleave frames into the same file. The accompanying
//! `identify_protocols.sh` script reads the whole set back and post-processes it with `tshark`,
//! whose independent dissectors work out what the leftover traffic actually is -- again by
//! parsing, not by assuming a port number implies a protocol.
//!
//! `--no-pcap` skips capturing entirely: no frames are copied or written, and no `.pcap` files
//! are created. Only the connection-level counts -- identified/unanswered/per-protocol, still
//! computed from `SessionProto` and the five-tuple rather than from buffered bytes -- are
//! produced. Useful for a quick read on parser coverage without the I/O and memory cost of
//! actually capturing anything.
//!
//! ## IP anonymization
//! Passing `--anon-key` rewrites the source and destination IP address of every frame with
//! Crypto-PAn (`cryptopan` module) before it is written, so a capture meant to leave a trusted
//! network does not carry real addresses. Anonymization is prefix-preserving -- two hosts that
//! share a real subnet still share an anonymized one -- and runs once per written connection,
//! in `finalize`, so connections that turn out to be identified or unsampled never pay for it.

mod cryptopan;

use clap::Parser;
use cryptopan::CryptoPAN;
use iris_compiler::{callback, callback_fn, input_files, iris_end_macros};
use iris_core::protocols::packet::tcp::TCP_PROTOCOL;
use iris_core::protocols::stream::SessionProto;
use iris_core::subscription::StreamingCallback;
use iris_core::{config::load_config, CoreId, FiveTuple, L4Pdu, Runtime};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

#[derive(Parser, Debug)]
struct Args {
    /// Iris runtime config (points at the packet capture to read in offline mode).
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,

    /// Prefix for the per-core output captures, written as `<prefix>_core<N>.pcap`.
    #[clap(short, long, value_name = "PREFIX", default_value = "unidentified")]
    outfile_prefix: String,

    /// Sample one in every N connections. 1 records every connection, which is only viable
    /// offline or on a very quiet link.
    #[clap(short, long, value_name = "N", default_value_t = 100)]
    sample_rate: u64,

    /// Keep at most this many frames per sampled connection; 0 for no limit. Bounds the memory
    /// a single long-lived connection can hold before it terminates.
    #[clap(short, long, value_name = "N", default_value_t = 128)]
    max_frames: usize,

    /// Only write a sampled connection if its captured frames total at least this many bytes;
    /// 0 records regardless of size. Drops trickle connections that carry too little payload to
    /// be worth dissecting. Measured over the bytes actually buffered, so a connection truncated
    /// at --max-frames is judged on those frames alone.
    #[clap(long, value_name = "N", default_value_t = 0)]
    min_bytes: usize,

    /// Path to a 32-byte binary key file. If given, every frame's source and destination IP
    /// is rewritten with Crypto-PAn before being written out. Generate one with:
    /// `openssl rand -out anon.key 32`. If omitted, captures carry real IP addresses.
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    anon_key: Option<PathBuf>,

    /// Trailing bits of each IPv4 address to anonymize; leading bits are left in plaintext.
    /// Only meaningful with --anon-key.
    #[clap(long, value_name = "N", default_value_t = 32)]
    anon_bits_v4: u32,

    /// Trailing bits of each IPv6 address to anonymize; leading bits are left in plaintext.
    /// Only meaningful with --anon-key.
    #[clap(long, value_name = "N", default_value_t = 128)]
    anon_bits_v6: u32,

    /// Skip capturing packets entirely: no frames are buffered or written, and no .pcap files
    /// are created. Only the connection-level counts (identified/unanswered/per-protocol) are
    /// produced. Makes --outfile-prefix, --max-frames, and --anon-key* irrelevant.
    #[clap(long)]
    no_pcap: bool,
}

/// Sampling denominator, read once per connection by [`SampledConn::new`].
///
/// A static is the only way to get a CLI argument into `new`, which the framework calls with
/// just the connection's first packet. The load is `Relaxed`: it is written once before the
/// runtime starts and only read afterwards, so no ordering guarantees are needed.
static SAMPLE_RATE: AtomicU64 = AtomicU64::new(1);

/// Per-connection frame ceiling, read on every buffered packet. `usize::MAX` means no limit.
static MAX_FRAMES: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Minimum captured bytes a sampled connection must carry to be written out; read once per
/// connection in `finalize`. 0 means no threshold.
static MIN_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Set from `--no-pcap`. When true, `update` never copies packet data into `self.frames`, and
/// `finalize` never anonymizes or writes it -- the connection-level counts (identified,
/// unanswered, per-protocol) are produced exactly as normal, since those come from `SessionProto`
/// and the five-tuple/`dir` bit rather than from the buffered bytes.
static NO_PCAP: AtomicBool = AtomicBool::new(false);

/// Connections seen at teardown that a parser did identify.
static CONNS_IDENTIFIED: AtomicUsize = AtomicUsize::new(0);
/// Sampled connections that no parser identified, i.e. those written out.
static CONNS_WRITTEN: AtomicUsize = AtomicUsize::new(0);
/// Written connections that hit [`MAX_FRAMES`] and so appear truncated in the capture.
static CONNS_TRUNCATED: AtomicUsize = AtomicUsize::new(0);
/// TCP connections dropped because the responder never sent anything (unanswered SYNs).
static CONNS_UNANSWERED: AtomicUsize = AtomicUsize::new(0);
/// Sampled, unidentified connections dropped for carrying fewer than [`MIN_BYTES`] bytes.
static CONNS_BELOW_THRESHOLD: AtomicUsize = AtomicUsize::new(0);

/// Per-protocol counts of *identified* connections (the ones dropped from the capture, not the
/// ones written to it), one counter per parser named in the callback filter. Incremented once
/// each in `finalize` and printed as a summary at the end of the run -- this is a cheap,
/// approximate read on parser coverage that falls out of a check the app is already doing.
static COUNT_TLS: AtomicUsize = AtomicUsize::new(0);
static COUNT_DNS: AtomicUsize = AtomicUsize::new(0);
static COUNT_HTTP: AtomicUsize = AtomicUsize::new(0);
static COUNT_QUIC: AtomicUsize = AtomicUsize::new(0);
static COUNT_SSH: AtomicUsize = AtomicUsize::new(0);
static COUNT_WIREGUARD: AtomicUsize = AtomicUsize::new(0);
static COUNT_IKE: AtomicUsize = AtomicUsize::new(0);
/// Identified but not one of the seven counters above. Only reachable if `SessionProto` grows a
/// new identified variant the match below doesn't yet know about; kept as a safety net so that
/// degrades to "uncounted" instead of a compile error or a panic.
static COUNT_OTHER: AtomicUsize = AtomicUsize::new(0);

/// Set only when `--anon-key` is given; `finalize` anonymizes a connection's frames iff this
/// is populated, so omitting the flag costs nothing beyond the `Option` check.
static CRYPTOPAN: OnceLock<CryptoPAN> = OnceLock::new();

/// Decides whether a connection joins the sample, purely from its five-tuple.
///
/// Deterministic and shared-state-free by design: at line rate a global counter would put an
/// atomic read-modify-write on the path of every new connection across every core. Hashing
/// instead costs a few ALU ops on data already in registers, and has the useful side effect
/// that the same connection is sampled consistently across runs.
///
/// This is the SplitMix64 finalizer, which avalanches well enough that taking it modulo the
/// sample rate does not correlate with any structure in addresses or ports.
fn should_sample(five_tuple: &FiveTuple) -> bool {
    fn endpoint_bits(addr: &SocketAddr) -> u64 {
        let ip = match addr.ip() {
            std::net::IpAddr::V4(v4) => u32::from(v4) as u64,
            // Fold the halves together; the low bits carry the host portion.
            std::net::IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                (bits as u64) ^ ((bits >> 64) as u64)
            }
        };
        ip.rotate_left(16) ^ addr.port() as u64
    }

    let mut z = endpoint_bits(&five_tuple.orig)
        ^ endpoint_bits(&five_tuple.resp).rotate_left(32)
        ^ (five_tuple.proto as u64) << 8;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;

    z.is_multiple_of(SAMPLE_RATE.load(Ordering::Relaxed))
}

/// One sampled connection's raw frames, accumulated until teardown.
///
/// The filter matches all TCP and UDP connections rather than naming protocols, because the
/// connections of interest are exactly the ones no protocol predicate would match. Iris only
/// compiles in the parsers that some filter or datatype needs, so `parsers=` registers all
/// seven explicitly -- without it no parsing would happen at all and every connection would
/// look unidentified.
#[callback("tcp or udp,parsers=tls&dns&http&quic&ssh&wireguard&ike")]
#[derive(Debug)]
struct SampledConn {
    sampled: bool,
    frames: Vec<Vec<u8>>,
    truncated: bool,
    /// Running total of captured frame bytes, compared against [`MIN_BYTES`] at teardown.
    /// Counts only the bytes actually buffered, so frames dropped past [`MAX_FRAMES`] do not
    /// contribute -- a truncated connection is judged on what was kept.
    total_bytes: usize,
    /// TCP connections that never draw a single packet from the responder are unanswered SYNs:
    /// scans, backscatter, and failed connects. They have no payload to identify by definition,
    /// so recording them buries the genuinely unknown traffic. Tracked here and dropped at
    /// teardown -- whether a response ever arrives is not knowable until then.
    is_tcp: bool,
    saw_responder: bool,
}

impl StreamingCallback for SampledConn {
    /// Runs once per connection, on its first packet. This is where a connection is admitted
    /// to or excluded from the sample; everything downstream just honors that decision.
    fn new(first_pkt: &L4Pdu) -> Self {
        Self {
            sampled: should_sample(&FiveTuple::from_ctxt(&first_pkt.ctxt)),
            frames: Vec::new(),
            truncated: false,
            total_bytes: 0,
            is_tcp: first_pkt.ctxt.proto == TCP_PROTOCOL,
            saw_responder: false,
        }
    }

    fn clear(&mut self) {
        self.frames = Vec::with_capacity(0);
        self.truncated = false;
        self.total_bytes = 0;
    }
}

impl SampledConn {
    /// `InL4Conn` delivers packets as they arrive and without TCP reassembly, which is what a
    /// faithful packet capture needs -- reassembled streams would not round-trip back into
    /// individual frames.
    ///
    /// Returning `false` unsubscribes from the connection entirely, so an unsampled connection
    /// costs exactly one call: it never buffers a frame and Iris stops tracking and parsing it.
    ///
    /// A connection that reaches the frame cap deliberately stays subscribed and merely stops
    /// buffering. Unsubscribing would also skip `finalize`, losing the connection from the
    /// capture altogether -- and whether it is even wanted is not known until teardown, when
    /// protocol discovery has finished. The frames kept are the *first* ones, which is what
    /// matters downstream: dissectors identify a protocol from the start of a connection.
    ///
    /// Under `--no-pcap` this skips the copy into `self.frames` entirely -- that copy is the
    /// actual "packet capturing" cost the flag exists to avoid -- but still adds the packet's
    /// length to `total_bytes`, so `--min-bytes` and the run summary behave identically to a
    /// normal run; only the bytes themselves are never retained.
    #[callback_fn("SampledConn,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) -> bool {
        if !self.sampled {
            return false;
        }
        // `dir` is true for orig -> resp, so anything else is the responder answering.
        self.saw_responder |= !pdu.dir;
        if NO_PCAP.load(Ordering::Relaxed) {
            self.total_bytes += pdu.mbuf_ref().data().len();
        } else if self.frames.len() < MAX_FRAMES.load(Ordering::Relaxed) {
            let frame = pdu.mbuf_ref().data().to_vec();
            self.total_bytes += frame.len();
            self.frames.push(frame);
        } else {
            self.truncated = true;
        }
        true
    }

    /// Fires at teardown (FIN/ACK sequence or timeout), by which point protocol discovery has
    /// either settled on a protocol or given up. Returns `false` because the connection is
    /// finished either way and there is nothing further to receive.
    #[callback_fn("SampledConn,level=L4Terminated")]
    fn finalize(&mut self, proto: &SessionProto, core_id: &CoreId) -> bool {
        // Checked before anything else: an unanswered SYN is not evidence about parser
        // coverage either way, so it should not land in the capture or in the counts.
        if self.is_tcp && !self.saw_responder {
            CONNS_UNANSWERED.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // `Null` means every registered parser rejected the connection; `Probing` means
        // discovery never concluded (e.g. a connection too short to classify).
        if !matches!(proto, SessionProto::Null | SessionProto::Probing) {
            CONNS_IDENTIFIED.fetch_add(1, Ordering::Relaxed);
            let counter = match proto {
                SessionProto::Tls => &COUNT_TLS,
                SessionProto::Dns => &COUNT_DNS,
                SessionProto::Http => &COUNT_HTTP,
                SessionProto::Quic => &COUNT_QUIC,
                SessionProto::Ssh => &COUNT_SSH,
                SessionProto::Wireguard => &COUNT_WIREGUARD,
                SessionProto::Ike => &COUNT_IKE,
                _ => &COUNT_OTHER,
            };
            counter.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // A connection that carried too little data to be worth dissecting is dropped here
        // rather than written. Judged on the bytes actually buffered, so a truncation at
        // --max-frames cannot push a connection over the bar on frames that were discarded.
        if self.total_bytes < MIN_BYTES.load(Ordering::Relaxed) {
            CONNS_BELOW_THRESHOLD.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        if !NO_PCAP.load(Ordering::Relaxed) {
            if let Some(cp) = CRYPTOPAN.get() {
                for frame in &mut self.frames {
                    anonymize_frame(frame, cp);
                }
            }

            writer(core_id)
                .lock()
                .unwrap()
                .write_conn(&self.frames)
                .unwrap_or_else(|e| {
                    panic!("Failed to write capture for core {}: {}", core_id.raw(), e)
                });
        }
        CONNS_WRITTEN.fetch_add(1, Ordering::Relaxed);
        if self.truncated {
            CONNS_TRUNCATED.fetch_add(1, Ordering::Relaxed);
        }
        false
    }
}

/// Per-core capture files, indexed by raw core ID. Core IDs need not be contiguous, so slots
/// for cores the runtime is not using stay `None`.
static WRITERS: OnceLock<Vec<Option<Mutex<PcapWriter>>>> = OnceLock::new();

/// The capture file for `core_id`.
///
/// Each core touches only its own writer, so the mutex is never contended -- it is here to
/// satisfy the borrow checker rather than to arbitrate, and is taken once per written
/// connection rather than once per packet.
fn writer(core_id: &CoreId) -> &'static Mutex<PcapWriter> {
    WRITERS
        .get()
        .expect("writers not initialized")
        .get(core_id.raw() as usize)
        .and_then(|w| w.as_ref())
        .unwrap_or_else(|| panic!("No capture file for core {}", core_id.raw()))
}

const PCAP_MAGIC: u32 = 0xa1b2_c3d4;
const LINKTYPE_ETHERNET: u32 = 1;
const SNAPLEN: u32 = 65_535;
/// Sized so that a burst of full-MTU frames lands in memory rather than in a write syscall.
const WRITE_BUF_BYTES: usize = 1 << 20;

/// Minimal writer for the classic libpcap file format, which is a 24-byte global header
/// followed by a 16-byte header and the raw bytes for each frame. Writing it directly avoids
/// pulling `libpcap` into an example that only ever appends whole Ethernet frames.
///
/// Iris does not surface the original capture timestamps to subscribers, so every frame is
/// written with a zero timestamp. Protocol dissection does not depend on them; anything
/// timing-related in the output capture is meaningless by construction.
struct PcapWriter {
    inner: BufWriter<File>,
}

impl PcapWriter {
    fn create(path: &PathBuf) -> std::io::Result<Self> {
        let mut inner = BufWriter::with_capacity(WRITE_BUF_BYTES, File::create(path)?);
        inner.write_all(&PCAP_MAGIC.to_le_bytes())?;
        inner.write_all(&2u16.to_le_bytes())?; // major version
        inner.write_all(&4u16.to_le_bytes())?; // minor version
        inner.write_all(&0i32.to_le_bytes())?; // GMT-to-local correction
        inner.write_all(&0u32.to_le_bytes())?; // timestamp accuracy
        inner.write_all(&SNAPLEN.to_le_bytes())?;
        inner.write_all(&LINKTYPE_ETHERNET.to_le_bytes())?;
        Ok(Self { inner })
    }

    fn write_conn(&mut self, frames: &[Vec<u8>]) -> std::io::Result<()> {
        for frame in frames {
            let caplen = frame.len().min(SNAPLEN as usize);
            self.inner.write_all(&0u32.to_le_bytes())?; // timestamp seconds
            self.inner.write_all(&0u32.to_le_bytes())?; // timestamp microseconds
            self.inner.write_all(&(caplen as u32).to_le_bytes())?;
            self.inner.write_all(&(frame.len() as u32).to_le_bytes())?; // original length
            self.inner.write_all(&frame[..caplen])?;
        }
        Ok(())
    }
}

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;

/// Rewrites the source and destination IP address of one Ethernet frame in place, using `cp`.
///
/// Frames Iris hands to subscribers are always carried over IPv4 or IPv6 -- its conntrack is
/// scoped to IP-layer connections -- so only those two ethertypes are handled. Anything else
/// (or a frame too short to hold a full header at the expected offset) is left untouched;
/// that should not happen for frames this app buffers, but silently skipping rather than
/// panicking means a malformed frame degrades to "not anonymized" instead of crashing the run.
///
/// VLAN tags (802.1Q and QinQ) are unwrapped first so the real ethertype is used.
fn anonymize_frame(frame: &mut [u8], cp: &CryptoPAN) {
    let mut offset = 14usize; // past dst MAC, src MAC, ethertype
    if frame.len() < offset {
        return;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    while ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ {
        if frame.len() < offset + 4 {
            return;
        }
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }

    match ethertype {
        ETHERTYPE_IPV4 => anonymize_ipv4_header(frame, offset, cp),
        ETHERTYPE_IPV6 => anonymize_ipv6_header(frame, offset, cp),
        _ => {}
    }
}

/// Rewrites the src/dst addresses of the IPv4 header at `frame[ip_off..]` and recomputes the
/// header checksum over it.
///
/// The TCP/UDP checksum, which also covers the addresses via the pseudo-header, is
/// deliberately left stale rather than recomputed. This matches most captures already:
/// checksum offload means on-the-wire transport checksums are frequently invalid before this
/// even runs, and `tshark` does not validate them by default (see the script's caveat note).
/// Recomputing them would mean walking IPv4 options and the full payload for comparatively
/// little benefit.
fn anonymize_ipv4_header(frame: &mut [u8], ip_off: usize, cp: &CryptoPAN) {
    if frame.len() < ip_off + 20 {
        return;
    }
    let src = Ipv4Addr::new(
        frame[ip_off + 12],
        frame[ip_off + 13],
        frame[ip_off + 14],
        frame[ip_off + 15],
    );
    let dst = Ipv4Addr::new(
        frame[ip_off + 16],
        frame[ip_off + 17],
        frame[ip_off + 18],
        frame[ip_off + 19],
    );
    frame[ip_off + 12..ip_off + 16].copy_from_slice(&cp.anonymize_ipv4(src).octets());
    frame[ip_off + 16..ip_off + 20].copy_from_slice(&cp.anonymize_ipv4(dst).octets());

    // RFC 791 SS3.1: ones'-complement sum of all 16-bit header words, checksum field zeroed
    // during the sum, complemented at the end.
    let ihl = (frame[ip_off] & 0x0F) as usize * 4;
    if ihl < 20 || frame.len() < ip_off + ihl {
        return;
    }
    frame[ip_off + 10] = 0;
    frame[ip_off + 11] = 0;
    let mut sum: u32 = frame[ip_off..ip_off + ihl]
        .chunks_exact(2)
        .map(|w| u16::from_be_bytes([w[0], w[1]]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    frame[ip_off + 10..ip_off + 12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
}

/// Rewrites the src/dst addresses of the fixed 40-byte IPv6 header at `frame[ip_off..]`.
/// IPv6 has no header checksum, unlike IPv4, so there is nothing to recompute here; the same
/// stale-transport-checksum tradeoff described in `anonymize_ipv4_header` still applies.
fn anonymize_ipv6_header(frame: &mut [u8], ip_off: usize, cp: &CryptoPAN) {
    if frame.len() < ip_off + 40 {
        return;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&frame[ip_off + 8..ip_off + 24]);
    dst.copy_from_slice(&frame[ip_off + 24..ip_off + 40]);
    frame[ip_off + 8..ip_off + 24]
        .copy_from_slice(&cp.anonymize_ipv6(Ipv6Addr::from(src)).octets());
    frame[ip_off + 24..ip_off + 40]
        .copy_from_slice(&cp.anonymize_ipv6(Ipv6Addr::from(dst)).octets());
}

/// Returns `100 * numerator / denominator`, or `None` if `denominator` is zero (e.g. no
/// connections were sampled at all).
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
        assert_eq!(pct(5, 0), None);
        assert_eq!(fmt_count_pct(5, 0), "5");
    }

    #[test]
    fn whole_and_fractional_shares() {
        assert_eq!(pct(1, 4), Some(25.0));
        assert_eq!(fmt_count_pct(1, 4), "1 (25.0%)");
        assert_eq!(fmt_count_pct(1, 3), "1 (33.3%)");
        assert_eq!(fmt_count_pct(3, 3), "3 (100.0%)");
        assert_eq!(fmt_count_pct(0, 3), "0 (0.0%)");
    }
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();

    assert!(args.sample_rate > 0, "--sample-rate must be at least 1");
    SAMPLE_RATE.store(args.sample_rate, Ordering::Relaxed);
    MAX_FRAMES.store(
        // 0 is the "no limit" spelling; the buffering path just compares against the ceiling.
        if args.max_frames == 0 {
            usize::MAX
        } else {
            args.max_frames
        },
        Ordering::Relaxed,
    );

    MIN_BYTES.store(args.min_bytes, Ordering::Relaxed);
    NO_PCAP.store(args.no_pcap, Ordering::Relaxed);

    if let Some(key_path) = &args.anon_key {
        let key_bytes = std::fs::read(key_path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", key_path.display(), e));
        let key: [u8; 32] = key_bytes.as_slice().try_into().unwrap_or_else(|_| {
            panic!(
                "{} must be exactly 32 bytes (got {}); generate one with `openssl rand -out {} 32`",
                key_path.display(),
                key_bytes.len(),
                key_path.display()
            )
        });
        CRYPTOPAN
            .set(CryptoPAN::new(&key, args.anon_bits_v4, args.anon_bits_v6))
            .expect("cryptopan already initialized");
    }

    let config = load_config(&args.config);

    if !args.no_pcap {
        let core_ids = config.get_all_core_ids();
        let nb_slots = core_ids.iter().map(|c| c.raw() as usize).max().unwrap_or(0) + 1;
        let mut writers = Vec::with_capacity(nb_slots);
        writers.resize_with(nb_slots, || None);
        for core_id in &core_ids {
            let path = PathBuf::from(format!(
                "{}_core{}.pcap",
                args.outfile_prefix,
                core_id.raw()
            ));
            let pcap = PcapWriter::create(&path)
                .unwrap_or_else(|e| panic!("Failed to create {}: {}", path.display(), e));
            writers[core_id.raw() as usize] = Some(Mutex::new(pcap));
        }
        WRITERS
            .set(writers)
            .ok()
            .expect("writers already initialized");
    }

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    // WRITERS is only populated when capturing, so there's nothing to flush under --no-pcap.
    if let Some(writers) = WRITERS.get() {
        for pcap in writers.iter().flatten() {
            pcap.lock().unwrap().inner.flush().unwrap();
        }
    }

    // Counts cover sampled connections only: unsampled ones unsubscribe on their first packet
    // and so never reach `finalize`, which is exactly the work being avoided. Every sampled
    // connection lands in exactly one of these four buckets, so their sum (`total_sampled`) is
    // the full sampled population.
    let identified = CONNS_IDENTIFIED.load(Ordering::Relaxed);
    let unanswered = CONNS_UNANSWERED.load(Ordering::Relaxed);
    let below_threshold = CONNS_BELOW_THRESHOLD.load(Ordering::Relaxed);
    let written = CONNS_WRITTEN.load(Ordering::Relaxed);
    let total_sampled = identified + unanswered + below_threshold + written;

    // Unanswered SYNs and below-threshold connections are noise -- scans, backscatter, trickle
    // traffic -- not a population the identified/unidentified split or protocol breakdown
    // should be measured against. `real_sampled` excludes them, so "identified" and "written"
    // are shares of the connections that were actually candidates for identification, and
    // together sum to exactly 100% of it (they're its only two components).
    let real_sampled = identified + written;

    if args.no_pcap {
        println!(
            "\nSampled 1 in {} connections. Of those, identified {} by parsing; {} were \
             unidentified (packet capture skipped: --no-pcap).",
            args.sample_rate,
            fmt_count_pct(identified, real_sampled),
            fmt_count_pct(written, real_sampled),
        );
    } else {
        println!(
            "\nSampled 1 in {} connections. Of those, identified {} by parsing and wrote {} \
             unidentified ones to {}_core*.pcap",
            args.sample_rate,
            fmt_count_pct(identified, real_sampled),
            fmt_count_pct(written, real_sampled),
            args.outfile_prefix,
        );
    }
    // Unlike the lines above, this one *is* a share of every sampled connection -- it's
    // reporting how much of the full population unanswered SYNs made up, so `total_sampled`
    // (not `real_sampled`, which excludes them by definition) is the right denominator here.
    println!(
        "Skipped {} unanswered SYNs (TCP connections the responder never answered).",
        fmt_count_pct(unanswered, total_sampled)
    );

    let mut by_protocol = vec![
        ("TLS", COUNT_TLS.load(Ordering::Relaxed)),
        ("DNS", COUNT_DNS.load(Ordering::Relaxed)),
        ("HTTP", COUNT_HTTP.load(Ordering::Relaxed)),
        ("QUIC", COUNT_QUIC.load(Ordering::Relaxed)),
        ("SSH", COUNT_SSH.load(Ordering::Relaxed)),
        ("WireGuard", COUNT_WIREGUARD.load(Ordering::Relaxed)),
        ("IKE", COUNT_IKE.load(Ordering::Relaxed)),
        ("other", COUNT_OTHER.load(Ordering::Relaxed)),
    ];
    by_protocol.sort_by_key(|&(_, count)| std::cmp::Reverse(count));
    println!("\nIdentified connections by protocol (these were dropped, not written):");
    for (name, count) in by_protocol {
        if count > 0 {
            // Share of `real_sampled`, the same denominator as "identified" above -- so these
            // rows sum to exactly the "identified" percentage, with "unidentified" as the
            // complement, rather than each protocol being diluted by scan/junk traffic that
            // was never a candidate for identification in the first place.
            println!("  {:<10} {}", name, fmt_count_pct(count, real_sampled));
        }
    }
    // Also a share of the full sampled population, for the same reason as the unanswered-SYN
    // line above: this line describes how much of everything got excluded, so it can't use the
    // denominator that excludes it.
    if args.min_bytes > 0 {
        println!(
            "Skipped {} connections carrying fewer than {} captured bytes (--min-bytes).",
            fmt_count_pct(below_threshold, total_sampled),
            args.min_bytes
        );
    }
    if !args.no_pcap {
        if CRYPTOPAN.get().is_some() {
            println!("IP addresses in the capture were anonymized with Crypto-PAn.");
        } else {
            println!("IP addresses in the capture are NOT anonymized (pass --anon-key to enable).");
        }
    }

    let truncated = CONNS_TRUNCATED.load(Ordering::Relaxed);
    if truncated > 0 {
        println!(
            // Share of *written* connections -- truncation is only ever recorded for a
            // connection that made it to disk, so `written` is the right denominator here.
            "{} of them hit the {}-frame cap and were truncated to their first {} frames.",
            fmt_count_pct(truncated, written),
            args.max_frames,
            args.max_frames
        );
    }
    if args.no_pcap {
        println!("No .pcap files were written (--no-pcap).");
    } else {
        println!(
            "Run ./examples/unidentified_conns/identify_protocols.sh {}_core*.pcap to see what they actually are.",
            args.outfile_prefix
        );
    }
}
