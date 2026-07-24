use iris_compiler::*;
use iris_core::{L4Pdu, Mbuf};
use iris_core::config::load_config;
use iris_core::{CoreId, Runtime};
use iris_core::subscription::StreamingCallback;

mod writer;

use clap::Parser;
use iris_datatypes::TlsHandshake;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

// Capture 1 connection out of every `SAMPLE_N`. 1 = capture everything.
// Set once from `--sample` before the runtime starts, then read per flow.
static SAMPLE_N: AtomicU64 = AtomicU64::new(1);

// Number of leading packets to capture per sampled connection (the TLS
// handshake and a little payload), after which we stop tracking the flow.
const MAX_PKTS: u32 = 13;

// Decide once per connection whether to capture it, by hashing its 5-tuple.
// Deterministic, so the choice is stable for the life of the flow.
fn should_sample(first_pkt: &L4Pdu) -> bool {
    let n = SAMPLE_N.load(Ordering::Relaxed);
    if n <= 1 {
        return true;
    }
    let mut hasher = DefaultHasher::new();
    first_pkt.ctxt.src.hash(&mut hasher);
    first_pkt.ctxt.dst.hash(&mut hasher);
    hasher.finish() % n == 0
}

#[derive(Debug)]
#[callback("tls")]
struct TlsCbStreaming {
    sample: bool,
    mbufs: Vec<Mbuf>,
    hshk: bool,
}

impl StreamingCallback for TlsCbStreaming {
    fn new(first_pkt: &L4Pdu) -> Self {
        Self {
            sample: should_sample(first_pkt),
            mbufs: Vec::new(),
            hshk: false,
        }
    }
    fn clear(&mut self) {
        self.mbufs.clear();
    }
}

impl TlsCbStreaming {
    #[callback_fn("TlsCbStreaming,level=InL4Stream")]
    fn update(&mut self, pdu: &L4Pdu) -> bool {
        // Not sampling this flow: stop tracking it immediately so no reassembly
        // work is spent on it.
        if !self.sample {
            return false;
        }
        if self.mbufs.len() < MAX_PKTS as usize {
            self.mbufs.push(Mbuf::new_ref(pdu.mbuf_ref()));
        }
        true
    }

    // Handshake parsed; unsubscribe
    #[callback_fn("TlsCbStreaming")]
    fn on_hshk(&mut self, _: &TlsHandshake) -> bool {
        self.hshk = true;
        false
    }

    #[callback_fn("TlsCbStreaming,level=L4Terminated")]
    fn on_term(&mut self, core: &CoreId) -> bool {
        assert!(!self.hshk);
        if self.sample && !self.mbufs.is_empty() {
            writer::write_mbufs(&self.mbufs, core);
            self.mbufs.clear();
        }
        false
    }
}



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
    /// Capture 1 out of every N connections (1 = capture all). Raise this to
    /// shed load and reduce drops under high traffic.
    #[clap(short, long, value_name = "N", default_value = "1")]
    sample: u64,
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    writer::init_files();

    let args = Args::parse();
    SAMPLE_N.store(args.sample.max(1), Ordering::Relaxed);
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    writer::flush_files();
}
