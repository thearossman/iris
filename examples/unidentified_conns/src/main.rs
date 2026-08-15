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
//! Output is sharded one pcap file per core, each behind its own `BufWriter`, so RX cores
//! never contend on a shared writer or interleave frames into the same file. The accompanying
//! `identify_protocols.sh` script reads the whole set back and post-processes it with `tshark`,
//! whose independent dissectors work out what the leftover traffic actually is -- again by
//! parsing, not by assuming a port number implies a protocol.

use clap::Parser;
use iris_compiler::{callback, callback_fn, input_files, iris_end_macros};
use iris_core::protocols::stream::SessionProto;
use iris_core::subscription::StreamingCallback;
use iris_core::{config::load_config, CoreId, FiveTuple, L4Pdu, Runtime};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
}

/// Sampling denominator, read once per connection by [`SampledConn::new`].
///
/// A static is the only way to get a CLI argument into `new`, which the framework calls with
/// just the connection's first packet. The load is `Relaxed`: it is written once before the
/// runtime starts and only read afterwards, so no ordering guarantees are needed.
static SAMPLE_RATE: AtomicU64 = AtomicU64::new(1);

/// Per-connection frame ceiling, read on every buffered packet. `usize::MAX` means no limit.
static MAX_FRAMES: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Connections seen at teardown that a parser did identify.
static CONNS_IDENTIFIED: AtomicUsize = AtomicUsize::new(0);
/// Sampled connections that no parser identified, i.e. those written out.
static CONNS_WRITTEN: AtomicUsize = AtomicUsize::new(0);
/// Written connections that hit [`MAX_FRAMES`] and so appear truncated in the capture.
static CONNS_TRUNCATED: AtomicUsize = AtomicUsize::new(0);

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
}

impl StreamingCallback for SampledConn {
    /// Runs once per connection, on its first packet. This is where a connection is admitted
    /// to or excluded from the sample; everything downstream just honors that decision.
    fn new(first_pkt: &L4Pdu) -> Self {
        Self {
            sampled: should_sample(&FiveTuple::from_ctxt(&first_pkt.ctxt)),
            frames: Vec::new(),
            truncated: false,
        }
    }

    fn clear(&mut self) {
        self.frames = Vec::with_capacity(0);
        self.truncated = false;
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
    #[callback_fn("SampledConn,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) -> bool {
        if !self.sampled {
            return false;
        }
        if self.frames.len() < MAX_FRAMES.load(Ordering::Relaxed) {
            self.frames.push(pdu.mbuf_ref().data().to_vec());
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
        // `Null` means every registered parser rejected the connection; `Probing` means
        // discovery never concluded (e.g. a connection too short to classify).
        if !matches!(proto, SessionProto::Null | SessionProto::Probing) {
            CONNS_IDENTIFIED.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        writer(core_id)
            .lock()
            .unwrap()
            .write_conn(&self.frames)
            .unwrap_or_else(|e| {
                panic!("Failed to write capture for core {}: {}", core_id.raw(), e)
            });
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

    let config = load_config(&args.config);

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

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    for pcap in WRITERS.get().unwrap().iter().flatten() {
        pcap.lock().unwrap().inner.flush().unwrap();
    }

    // Counts cover sampled connections only: unsampled ones unsubscribe on their first packet
    // and so never reach `finalize`, which is exactly the work being avoided.
    println!(
        "\nSampled 1 in {} connections. Of those, identified {} by parsing and wrote {} \
         unidentified ones to {}_core*.pcap",
        args.sample_rate,
        CONNS_IDENTIFIED.load(Ordering::Relaxed),
        CONNS_WRITTEN.load(Ordering::Relaxed),
        args.outfile_prefix,
    );
    let truncated = CONNS_TRUNCATED.load(Ordering::Relaxed);
    if truncated > 0 {
        println!(
            "{} of them hit the {}-frame cap and were truncated to their first {} frames.",
            truncated, args.max_frames, args.max_frames
        );
    }
    println!(
        "Run ./examples/unidentified_conns/identify_protocols.sh {}_core*.pcap to see what they actually are.",
        args.outfile_prefix
    );
}
