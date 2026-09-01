use crate::config::{ConnTrackConfig, OfflineConfig};
use crate::conntrack::{ConnTracker, TrackerConfig};
use crate::dpdk;
use crate::lcore::{CoreId, SocketId};
use crate::memory::mbuf::Mbuf;
use crate::memory::mempool::Mempool;
use crate::stats::{packet_ledger, record, Outcome};
use crate::subscription::*;

use std::collections::BTreeMap;
use std::ffi::CString;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cpu_time::ProcessTime;
use pcap::Capture;

/// A frame's capture timestamp as a `Duration` since the Unix epoch.
///
/// Split out from the replay loop so the (fiddly, and on some platforms differently-typed)
/// `timeval` arithmetic is unit-testable without a pcap. Negative `tv_sec`/`tv_usec` --
/// which a corrupt or hand-built pcap can carry -- clamp to zero rather than wrapping.
fn capture_ts(ts: &libc::timeval) -> Duration {
    Duration::new(ts.tv_sec.max(0) as u64, (ts.tv_usec.max(0) as u32) * 1000)
}

/// The instant to stamp a frame with, given the replay clock's `base` instant, the capture
/// timestamp of the trace's `first` frame, and this frame's capture timestamp `ts`.
///
/// A frame whose capture timestamp precedes the first frame's -- traces are not always
/// perfectly ordered -- stamps at `base` rather than before it, keeping the clock handed to
/// connection tracking monotonically at or after the runtime's start. That matters: the
/// timer wheel subtracts its own start instant from these timestamps.
fn replay_instant(base: Instant, first: Duration, ts: Duration) -> Instant {
    base + ts.saturating_sub(first)
}

#[cfg(test)]
mod replay_clock_tests {
    use super::*;

    #[test]
    fn capture_ts_converts_seconds_and_micros() {
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 250_000,
        };
        assert_eq!(capture_ts(&tv), Duration::from_millis(5250));
    }

    #[test]
    fn capture_ts_clamps_negative() {
        let tv = libc::timeval {
            tv_sec: -1,
            tv_usec: -1,
        };
        assert_eq!(capture_ts(&tv), Duration::ZERO);
    }

    #[test]
    fn replay_instant_offsets_from_first_frame() {
        let base = Instant::now();
        let first = Duration::from_secs(1_700_000_000);
        let ts = first + Duration::from_millis(4200);
        assert_eq!(
            replay_instant(base, first, ts),
            base + Duration::from_millis(4200)
        );
    }

    #[test]
    fn replay_instant_never_precedes_base() {
        let base = Instant::now();
        let first = Duration::from_secs(1_700_000_000);
        let ts = first - Duration::from_secs(3);
        assert_eq!(replay_instant(base, first, ts), base);
    }
}

pub(crate) struct OfflineRuntime<S>
where
    S: Subscribable,
{
    pub(crate) mempool_name: String,
    pub(crate) subscription: Arc<Subscription<S>>,
    pub(crate) options: OfflineOptions,
    id: CoreId,
}

impl<S> OfflineRuntime<S>
where
    S: Subscribable,
{
    pub(crate) fn new(
        options: OfflineOptions,
        mempools: &BTreeMap<SocketId, Mempool>,
        subscription: Arc<Subscription<S>>,
    ) -> Self {
        let core_id = CoreId(unsafe { dpdk::rte_lcore_id() } as u32);
        let mempool_name = mempools
            .get(&core_id.socket_id())
            .expect("Get offline mempool")
            .name()
            .to_string();
        OfflineRuntime {
            mempool_name,
            subscription,
            options,
            id: core_id,
        }
    }

    pub(crate) fn run(&self) {
        log::info!(
            "Launched offline analysis. Processing pcap: {}",
            self.options.offline.pcap,
        );

        let mut nb_pkts = 0;
        let mut nb_bytes = 0;

        let config = TrackerConfig::from(&self.options.conntrack);
        let registry = S::Tracked::parsers();
        log::debug!("{:#?}", registry);
        let mut stream_table = ConnTracker::<S::Tracked>::new(config, registry, self.id);

        let mempool_raw = self.get_mempool_raw();
        let pcap = self.options.offline.pcap.as_str();
        let mut cap = Capture::from_file(pcap).expect("Error opening pcap. Aborting.");
        // Taken after the tracker (and so after its timer wheel's own start instant) so that
        // every replayed timestamp is at or after the wheel's origin -- it subtracts the two.
        let replay_clock = self.options.offline.replay_clock;
        let base = Instant::now();
        let mut first_capture_ts: Option<Duration> = None;
        let start = ProcessTime::try_now().expect("Getting process time failed");
        while let Ok(frame) = cap.next() {
            if frame.header.len as usize > self.options.offline.mtu {
                continue;
            }
            let now = if replay_clock {
                let ts = capture_ts(&frame.header.ts);
                replay_instant(base, *first_capture_ts.get_or_insert(ts), ts)
            } else {
                Instant::now()
            };
            let mbuf = Mbuf::from_bytes(frame.data, mempool_raw)
                .expect("Unable to allocate mbuf. Try increasing mempool size.");
            nb_pkts += 1;
            nb_bytes += mbuf.data_len() as u64;
            record(Outcome::Received, mbuf.data_len() as u64);

            /* Apply the packet filter to get actions */
            let cont = self.subscription.filter_packet(&mbuf, &self.id);
            if cont {
                self.subscription
                    .process_packet(mbuf, &mut stream_table, now);
            } else {
                record(Outcome::IgnoredByPacketFilter, mbuf.data_len() as u64);
            }
            // Inactivity timeouts are a first-class part of how a live run attributes and
            // terminates connections, so the replay clock drives them too -- otherwise every
            // connection in the trace would survive to the `drain` below. `check_inactive`
            // rate-limits itself to the configured `timeout_resolution`, so calling it per
            // frame is cheap. Under the processing-time clock a whole trace usually replays
            // inside one resolution period, leaving the historical behavior unchanged.
            stream_table.check_inactive(&self.subscription, now);
        }

        // // Deliver remaining data in table
        stream_table.drain(&self.subscription);
        let cpu_time = start.elapsed();
        println!("Processed: {} pkts, {} bytes", nb_pkts, nb_bytes);
        println!("CPU time: {:?}ms", cpu_time.as_millis());
        print!("{}", packet_ledger());
    }

    pub(crate) fn get_mempool_raw(&self) -> *mut dpdk::rte_mempool {
        let cname = CString::new(self.mempool_name.clone()).expect("Invalid CString conversion");
        unsafe { dpdk::rte_mempool_lookup(cname.as_ptr()) }
    }
}

/// Read-only runtime options for the offline core
#[derive(Debug)]
pub(crate) struct OfflineOptions {
    pub(crate) offline: OfflineConfig,
    pub(crate) conntrack: ConnTrackConfig,
}
