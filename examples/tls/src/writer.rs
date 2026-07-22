use iris_core::{CoreId, Mbuf};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

// Per-core memoization of the (deterministic) prefix-preserving anonymization.
// The same src/dst addresses recur on every packet of a flow and across flows
// to the same server, so this turns a 32/128-iteration PRF loop per address
// into a hashmap hit almost every time. Kept per core, so there is no locking.
#[derive(Default)]
struct AnonCache {
    v4: HashMap<u32, u32>,
    v6: HashMap<u128, u128>,
}

pub struct PrefixPreservingAnonymizer {
    key: u64,
}

impl PrefixPreservingAnonymizer {
    pub fn new(key: u64) -> Self {
        Self { key }
    }

    fn prf(&self, prefix: u128, prefix_len: u8) -> u64 {
        let mut x = self.key
            ^ (prefix as u64)
            ^ ((prefix >> 64) as u64)
            ^ (prefix_len as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn anonymize_ipv4(&self, addr: u32) -> u32 {
        let mut result: u32 = 0;
        for i in 0..32u32 {
            let prefix_len = i;
            let prefix: u128 = if prefix_len == 0 {
                0
            } else {
                (addr >> (32 - prefix_len)) as u128
            };
            let pseudorandom_bit = (self.prf(prefix, prefix_len as u8) & 1) as u32;
            let original_bit = (addr >> (31 - i)) & 1;
            let anon_bit = original_bit ^ pseudorandom_bit;
            result |= anon_bit << (31 - i);
        }
        result
    }

    pub fn anonymize_ipv6(&self, addr: u128) -> u128 {
        let mut result: u128 = 0;
        for i in 0..128u32 {
            let prefix_len = i;
            let prefix: u128 = if prefix_len == 0 {
                0
            } else {
                addr >> (128 - prefix_len)
            };
            let pseudorandom_bit = (self.prf(prefix, prefix_len as u8) & 1) as u128;
            let original_bit = (addr >> (127 - i)) & 1;
            let anon_bit = original_bit ^ pseudorandom_bit;
            result |= anon_bit << (127 - i);
        }
        result
    }
}

const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;

fn ipv4_checksum(header: &mut [u8]) {
    header[10] = 0;
    header[11] = 0;

    let mut sum: u32 = 0;
    let mut chunks = header.chunks_exact(2);
    for chunk in &mut chunks {
        let word = ((chunk[0] as u32) << 8) | (chunk[1] as u32);
        sum = sum.wrapping_add(word);
    }
    if let [last] = chunks.remainder() {
        sum = sum.wrapping_add((*last as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    header[10] = (checksum >> 8) as u8;
    header[11] = (checksum & 0xFF) as u8;
}

// Anonymize the source/destination IP addresses of a single packet in place,
// memoizing results in `cache`. Operating on the caller's buffer avoids a
// per-packet heap allocation, which matters on the multi-Gbps hot path.
fn anonymize_in_place(
    pkt: &mut [u8],
    anonymizer: &PrefixPreservingAnonymizer,
    cache: &mut AnonCache,
) {
    if pkt.len() < 14 {
        return; // not even a full Ethernet header
    }

    let mut ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
    let mut offset = 14usize;

    // Skip over any 802.1Q / 802.1ad VLAN tags.
    while ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ {
        if pkt.len() < offset + 4 {
            return;
        }
        ethertype = u16::from_be_bytes([pkt[offset + 2], pkt[offset + 3]]);
        offset += 4;
    }

    match ethertype {
        ETHERTYPE_IPV4 => {
            if pkt.len() < offset + 20 {
                return;
            }
            let ihl = ((pkt[offset] & 0x0F) as usize) * 4;
            if ihl < 20 || pkt.len() < offset + ihl {
                return;
            }

            let src = u32::from_be_bytes([
                pkt[offset + 12],
                pkt[offset + 13],
                pkt[offset + 14],
                pkt[offset + 15],
            ]);
            let dst = u32::from_be_bytes([
                pkt[offset + 16],
                pkt[offset + 17],
                pkt[offset + 18],
                pkt[offset + 19],
            ]);

            let anon_src = *cache.v4.entry(src).or_insert_with(|| anonymizer.anonymize_ipv4(src));
            let anon_dst = *cache.v4.entry(dst).or_insert_with(|| anonymizer.anonymize_ipv4(dst));

            pkt[offset + 12..offset + 16].copy_from_slice(&anon_src.to_be_bytes());
            pkt[offset + 16..offset + 20].copy_from_slice(&anon_dst.to_be_bytes());

            ipv4_checksum(&mut pkt[offset..offset + ihl]);
            // Note: this does not touch TCP/UDP checksums. Those cover
            // the IP addresses via the pseudo-header, so they'll no
            // longer validate. If downstream tooling checks L4
            // checksums, recompute those too (or have it ignore them --
            // this is standard practice for anonymized captures).
        }
        ETHERTYPE_IPV6 => {
            if pkt.len() < offset + 40 {
                return;
            }
            let src = u128::from_be_bytes(pkt[offset + 8..offset + 24].try_into().unwrap());
            let dst = u128::from_be_bytes(pkt[offset + 24..offset + 40].try_into().unwrap());

            let anon_src = *cache.v6.entry(src).or_insert_with(|| anonymizer.anonymize_ipv6(src));
            let anon_dst = *cache.v6.entry(dst).or_insert_with(|| anonymizer.anonymize_ipv6(dst));

            pkt[offset + 8..offset + 24].copy_from_slice(&anon_src.to_be_bytes());
            pkt[offset + 24..offset + 40].copy_from_slice(&anon_dst.to_be_bytes());
            // IPv6 base header has no checksum field of its own.
        }
        _ => {
            // ARP or anything else: leave untouched.
        }
    }
}

const PCAP_MAGIC: u32 = 0xA1B2_C3D4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const LINKTYPE_ETHERNET: u32 = 1;

fn write_pcap_global_header(buf: &mut Vec<u8>) {
    buf.extend_from_slice(&PCAP_MAGIC.to_le_bytes());
    buf.extend_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
    buf.extend_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    buf.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    buf.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
}

// Flush once the buffer reaches ~1 MiB, so writes are large and sequential.
const FLUSH_THRESHOLD: usize = 1 << 20;
// Give the buffer headroom past the threshold so appending the final packet of
// a batch never triggers a reallocation before we flush.
const BUF_CAPACITY: usize = FLUSH_THRESHOLD + (64 << 10);
// Size of a pcap per-record header (2x u32 timestamp + 2x u32 length).
const RECORD_HEADER_LEN: usize = 16;
// Number of buffers cycled between each core and its writer thread. This bounds
// in-flight memory and is the slack we have before a disk stall forces the
// producer to drop packets rather than block RX.
const NUM_BUFFERS: usize = 8;

/// Producer side of a per-core pcap stream, owned by (and only touched by) one
/// packet-processing core.
///
/// Packets are serialized (16-byte record header + payload) into a large
/// in-memory buffer and anonymized in place -- pure CPU/memory work, no
/// syscalls. When a buffer fills it is handed to a background writer thread over
/// `full_tx` and a recycled buffer is pulled from `free_rx`; the core never
/// issues a `write_all` itself, so disk stalls cannot back up onto RX. If no
/// free buffer is available (writer behind), packets are dropped and counted
/// rather than blocking the core.
pub struct PcapWriter {
    // Current fill buffer (record data only; the global header is written to the
    // file by the writer thread). `None` means we are waiting on a free buffer.
    buf: Option<Vec<u8>>,
    // Full buffers handed to the writer thread.
    full_tx: Sender<Vec<u8>>,
    // Emptied buffers returned by the writer thread for reuse.
    free_rx: Receiver<Vec<u8>>,
    anonymizer: PrefixPreservingAnonymizer,
    cache: AnonCache,
    // Packets dropped because no free buffer was available (writer fell behind).
    dropped: u64,
}

impl PcapWriter {
    // Grab a recycled buffer if the writer thread has returned one.
    fn take_free_buffer(&mut self) -> Option<Vec<u8>> {
        self.free_rx.try_recv().ok().map(|mut b| {
            b.clear();
            b
        })
    }

    // Serialize `data` into the current buffer as one pcap record, anonymizing
    // its IP addresses in place, and hand the buffer off once it is full.
    fn write_packet(&mut self, data: &[u8], ts: SystemTime) {
        let mut buf = match self.buf.take().or_else(|| self.take_free_buffer()) {
            Some(b) => b,
            None => {
                // All buffers are in flight: the writer thread is behind. Drop
                // this packet instead of stalling the RX core.
                self.dropped += 1;
                return;
            }
        };

        let since_epoch = ts.duration_since(UNIX_EPOCH).unwrap_or_default();
        let ts_sec = since_epoch.as_secs() as u32;
        let ts_usec = since_epoch.subsec_micros();
        let len = data.len() as u32;

        let mut header = [0u8; RECORD_HEADER_LEN];
        header[0..4].copy_from_slice(&ts_sec.to_le_bytes());
        header[4..8].copy_from_slice(&ts_usec.to_le_bytes());
        header[8..12].copy_from_slice(&len.to_le_bytes()); // captured length
        header[12..16].copy_from_slice(&len.to_le_bytes()); // original length
        buf.extend_from_slice(&header);

        let payload_start = buf.len();
        buf.extend_from_slice(data);
        anonymize_in_place(&mut buf[payload_start..], &self.anonymizer, &mut self.cache);

        if buf.len() >= FLUSH_THRESHOLD {
            // Hand off to the writer thread; grab a fresh buffer for next time
            // (may be None, in which case the next write_packet retries/drops).
            let _ = self.full_tx.send(buf);
            self.buf = self.take_free_buffer();
        } else {
            self.buf = Some(buf);
        }
    }

    // Push whatever is buffered to the writer thread. Called at shutdown.
    fn flush(&mut self) {
        if let Some(buf) = self.buf.take() {
            if !buf.is_empty() {
                let _ = self.full_tx.send(buf);
            }
        }
    }
}

// Background writer thread: owns the file and does the only disk I/O. Receives
// full buffers, writes them sequentially, and returns the emptied buffers for
// reuse. Exits when the producer drops `full_tx`.
fn writer_thread(mut file: File, full_rx: Receiver<Vec<u8>>, free_tx: Sender<Vec<u8>>) {
    let mut header = Vec::with_capacity(24);
    write_pcap_global_header(&mut header);
    if let Err(e) = file.write_all(&header) {
        eprintln!("pcap header write failed: {e}");
    }

    while let Ok(buf) = full_rx.recv() {
        if let Err(e) = file.write_all(&buf) {
            eprintln!("pcap write failed: {e}");
        }
        // Return the buffer for reuse; if the producer is gone, just drop it.
        let _ = free_tx.send(buf);
    }
    let _ = file.flush();
}

// Number of cores being used by the runtime; should match config file.
const NUM_CORES: usize = 16;
// Add 1 for ARR_LEN to avoid overflow; one core is used as main_core.
const ARR_LEN: usize = NUM_CORES + 1;
// Prefix for the per-core output pcap files.
pub const OUTFILE_PREFIX: &str = "tls_";
// Fixed key so anonymization is consistent across cores and runs.
const ANON_KEY: u64 = 0x1234_5678_9ABC_DEF0;

struct WriterSystem {
    writers: [AtomicPtr<PcapWriter>; ARR_LEN],
    threads: Mutex<Vec<JoinHandle<()>>>,
}

static SYSTEM: OnceLock<WriterSystem> = OnceLock::new();

fn system() -> &'static WriterSystem {
    SYSTEM.get_or_init(|| {
        let mut threads = Vec::with_capacity(ARR_LEN);
        let writers = std::array::from_fn(|core_id| {
            let file_name = format!("{}{}.pcap", OUTFILE_PREFIX, core_id);
            let file = File::create(&file_name).unwrap();

            let (full_tx, full_rx) = channel::<Vec<u8>>();
            let (free_tx, free_rx) = channel::<Vec<u8>>();
            // Pre-seed the free pool so the producer has buffers to fill.
            for _ in 0..NUM_BUFFERS {
                free_tx.send(Vec::with_capacity(BUF_CAPACITY)).unwrap();
            }

            threads.push(std::thread::spawn(move || {
                writer_thread(file, full_rx, free_tx);
            }));

            let wtr = PcapWriter {
                buf: None,
                full_tx,
                free_rx,
                anonymizer: PrefixPreservingAnonymizer::new(ANON_KEY),
                cache: AnonCache::default(),
                dropped: 0,
            };
            AtomicPtr::new(Box::into_raw(Box::new(wtr)))
        });
        WriterSystem {
            writers,
            threads: Mutex::new(threads),
        }
    })
}

pub fn init_files() {
    let _ = system();
}

// Anonymize and append a batch of buffered packets to the calling core's pcap
// file. Copies the frame bytes into the writer's buffer, which is handed off to
// the background writer thread once full -- the RX core never blocks on disk.
// Each core only ever touches its own writer, so the `&mut` is not aliased.
pub fn write_mbufs(mbufs: &[Mbuf], core_id: &CoreId) {
    let ptr = system().writers[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    let ts = SystemTime::now();
    for mbuf in mbufs {
        wtr.write_packet(mbuf.data(), ts);
    }
}

// Flush buffered data, tear down the writer threads, and report any drops.
// Call once, from the main core, after the runtime has stopped.
pub fn flush_files() {
    let sys = system();
    let mut total_dropped = 0u64;
    for core_id in 0..ARR_LEN {
        let ptr = sys.writers[core_id].load(Ordering::Relaxed);
        // Reclaim ownership so dropping the box closes `full_tx`, which lets the
        // corresponding writer thread's recv loop terminate.
        let mut wtr = unsafe { Box::from_raw(ptr) };
        wtr.flush();
        total_dropped += wtr.dropped;
        drop(wtr);
    }
    // Every `full_tx` is now dropped, so threads will finish their queue and
    // exit; join them so all data is durably written before we return.
    for handle in sys.threads.lock().unwrap().drain(..) {
        let _ = handle.join();
    }
    if total_dropped > 0 {
        eprintln!("warning: dropped {total_dropped} packets at the writer (disk could not keep up)");
    }
}