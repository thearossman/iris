//! Per-core accounting of where every received frame ended up.
//!
//! The counters in [`super`] answer "how much of X did we see". This answers a different and,
//! when an application's totals come out lower than the link they were measured on, more
//! urgent question: **of the bytes the runtime received, which ones never reached a
//! subscription, and why?**
//!
//! Iris drops traffic in several places between the NIC and a connection's tracked data, and
//! most of those drops are silent -- a `bail!`, an early `return`, or a `log::error!` that a
//! production run has turned off. On a live high-traffic link they are not rare edge cases:
//!
//! * A TCP connection is only ever created from a bare SYN (`Conn::new_tcp`). Every packet of
//!   a flow that was already in progress when the capture started is dropped, forever -- and
//!   the flows already in progress are exactly the long-lived, high-byte ones.
//! * Once the connection table is full, new connections are dropped wholesale.
//! * A connection no subscription still needs is put in a drop state; its later packets are
//!   discarded.
//!
//! [`PacketLedger`] partitions received frames across those outcomes so the shortfall can be
//! attributed rather than guessed at. Every received frame is counted in exactly one terminal
//! bucket, so `received` equals the sum of the rest -- which the printed summary checks.
//!
//! Counters are plain thread-locals, incremented on the core that owns the packet, and are
//! never drained (unlike the Prometheus path in [`super`], which resets as it scrapes), so a
//! snapshot at the end of a run reports the whole run.

use std::cell::Cell;
use std::fmt;

/// A packet count and the on-wire bytes those packets carried.
///
/// Bytes are `Mbuf::data_len()` -- the whole captured frame, Ethernet header included -- the
/// same unit as the runtime's `Processed: N pkts, M bytes` banner.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    pub pkts: u64,
    pub bytes: u64,
}

impl Tally {
    fn add(&mut self, bytes: u64) {
        self.pkts += 1;
        self.bytes += bytes;
    }

    fn merge(&mut self, other: Tally) {
        self.pkts += other.pkts;
        self.bytes += other.bytes;
    }
}

/// Where the frames one core received ended up. See the module docs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PacketLedger {
    /// Every frame the core pulled off its queues (or read from the pcap).
    pub received: Tally,
    /// Rejected by the generated packet filter before connection tracking.
    pub ignored_by_packet_filter: Tally,
    /// No layer-4 context could be parsed: not IPv4/IPv6, not TCP/UDP, a non-first IP
    /// fragment, or truncated. ARP and ICMP land here.
    pub not_transport: Tally,
    /// TCP frames belonging to a flow whose SYN was never observed. Iris cannot open a
    /// connection for these, so every one of them is dropped -- including all subsequent
    /// packets of that flow, which retry (and fail) connection creation one by one.
    pub dropped_no_syn: Tally,
    /// Dropped because the connection table was at `max_connections`.
    pub dropped_table_full: Tally,
    /// Dropped because the connection is in a drop state -- no subscription still needs it,
    /// or it was discarded (e.g. out-of-order tolerance exceeded).
    pub dropped_unmatched: Tally,
    /// Accepted into connection tracking, and so visible to subscriptions.
    pub tracked_tcp: Tally,
    /// Accepted into connection tracking, and so visible to subscriptions.
    pub tracked_udp: Tally,
    /// Connections opened.
    pub new_tcp_conns: u64,
    /// Connections opened.
    pub new_udp_conns: u64,
    /// Connections removed after delivering `L4Terminated` -- by FIN/RST, by inactivity
    /// timeout, or by the end-of-run drain.
    pub conns_terminated: u64,
    /// Connections removed *without* delivering `L4Terminated`, because they entered a drop
    /// state first -- most often TCP reassembly giving up after `max_out_of_order` segments
    /// piled up behind a sequence hole.
    ///
    /// This is the expensive one for any application that accumulates per-connection state
    /// and emits it at `L4Terminated`: the connection's whole accumulated total is discarded,
    /// not just the packets that went missing. One dropped packet early in an elephant flow
    /// can therefore cost every byte that flow ever carried. A live capture with any RX drop
    /// at all will show a nonzero count here.
    pub conns_discarded: u64,
}

impl PacketLedger {
    /// Frames accepted into connection tracking, TCP and UDP together.
    pub fn tracked(&self) -> Tally {
        let mut tally = self.tracked_tcp;
        tally.merge(self.tracked_udp);
        tally
    }

    /// Frames received but never handed to a subscription, for any reason.
    pub fn dropped(&self) -> Tally {
        let mut tally = self.ignored_by_packet_filter;
        tally.merge(self.not_transport);
        tally.merge(self.dropped_no_syn);
        tally.merge(self.dropped_table_full);
        tally.merge(self.dropped_unmatched);
        tally
    }

    /// Adds another core's ledger into this one.
    pub fn merge(&mut self, other: PacketLedger) {
        self.received.merge(other.received);
        self.ignored_by_packet_filter
            .merge(other.ignored_by_packet_filter);
        self.not_transport.merge(other.not_transport);
        self.dropped_no_syn.merge(other.dropped_no_syn);
        self.dropped_table_full.merge(other.dropped_table_full);
        self.dropped_unmatched.merge(other.dropped_unmatched);
        self.tracked_tcp.merge(other.tracked_tcp);
        self.tracked_udp.merge(other.tracked_udp);
        self.new_tcp_conns += other.new_tcp_conns;
        self.new_udp_conns += other.new_udp_conns;
        self.conns_terminated += other.conns_terminated;
        self.conns_discarded += other.conns_discarded;
    }

    /// `received` minus every terminal bucket. Zero unless a drop path is unaccounted for --
    /// the printed summary flags a nonzero value rather than hiding it.
    pub fn unaccounted(&self) -> i64 {
        let counted = self.dropped().bytes + self.tracked().bytes;
        self.received.bytes as i64 - counted as i64
    }
}

fn pct(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    100.0 * numerator as f64 / denominator as f64
}

impl fmt::Display for PacketLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total = self.received.bytes;
        let rows = [
            ("received", self.received),
            ("  ignored by packet filter", self.ignored_by_packet_filter),
            ("  not TCP/UDP (or unparseable)", self.not_transport),
            ("  dropped: TCP with no SYN seen", self.dropped_no_syn),
            ("  dropped: connection table full", self.dropped_table_full),
            ("  dropped: connection unmatched", self.dropped_unmatched),
            ("  tracked: TCP", self.tracked_tcp),
            ("  tracked: UDP", self.tracked_udp),
        ];

        writeln!(f, "=== Packet accounting (on-wire bytes) ===")?;
        for (label, tally) in rows {
            writeln!(
                f,
                "  {:<34} {:>16} pkts {:>20} bytes  {:>6.2}%",
                label,
                tally.pkts,
                tally.bytes,
                pct(tally.bytes, total)
            )?;
        }
        writeln!(
            f,
            "  {:<34} {:>16} TCP {:>21} UDP",
            "connections opened", self.new_tcp_conns, self.new_udp_conns
        )?;
        let closed = self.conns_terminated + self.conns_discarded;
        writeln!(
            f,
            "  {:<34} {:>16} delivered {:>15} discarded  {:>6.2}% lost",
            "connections closed",
            self.conns_terminated,
            self.conns_discarded,
            pct(self.conns_discarded, closed)
        )?;
        let unaccounted = self.unaccounted();
        if unaccounted != 0 {
            writeln!(f, "  WARNING: {unaccounted} bytes unaccounted for")?;
        }
        Ok(())
    }
}

thread_local! {
    static LEDGER: Cell<PacketLedger> = const { Cell::new(PacketLedger {
        received: Tally { pkts: 0, bytes: 0 },
        ignored_by_packet_filter: Tally { pkts: 0, bytes: 0 },
        not_transport: Tally { pkts: 0, bytes: 0 },
        dropped_no_syn: Tally { pkts: 0, bytes: 0 },
        dropped_table_full: Tally { pkts: 0, bytes: 0 },
        dropped_unmatched: Tally { pkts: 0, bytes: 0 },
        tracked_tcp: Tally { pkts: 0, bytes: 0 },
        tracked_udp: Tally { pkts: 0, bytes: 0 },
        new_tcp_conns: 0,
        new_udp_conns: 0,
        conns_terminated: 0,
        conns_discarded: 0,
    }) };
}

/// Which bucket a frame ended up in. One call per frame per bucket.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Outcome {
    Received,
    IgnoredByPacketFilter,
    NotTransport,
    DroppedNoSyn,
    DroppedTableFull,
    DroppedUnmatched,
    TrackedTcp,
    TrackedUdp,
}

/// Records one frame of `bytes` against `outcome` on the calling core.
#[inline]
pub(crate) fn record(outcome: Outcome, bytes: u64) {
    LEDGER.with(|cell| {
        let mut ledger = cell.get();
        match outcome {
            Outcome::Received => ledger.received.add(bytes),
            Outcome::IgnoredByPacketFilter => ledger.ignored_by_packet_filter.add(bytes),
            Outcome::NotTransport => ledger.not_transport.add(bytes),
            Outcome::DroppedNoSyn => ledger.dropped_no_syn.add(bytes),
            Outcome::DroppedTableFull => ledger.dropped_table_full.add(bytes),
            Outcome::DroppedUnmatched => ledger.dropped_unmatched.add(bytes),
            Outcome::TrackedTcp => ledger.tracked_tcp.add(bytes),
            Outcome::TrackedUdp => ledger.tracked_udp.add(bytes),
        }
        cell.set(ledger);
    });
}

/// Records a newly opened connection on the calling core.
#[inline]
pub(crate) fn record_new_conn(is_tcp: bool) {
    LEDGER.with(|cell| {
        let mut ledger = cell.get();
        if is_tcp {
            ledger.new_tcp_conns += 1;
        } else {
            ledger.new_udp_conns += 1;
        }
        cell.set(ledger);
    });
}

/// Records a connection leaving the table: `delivered` is whether it got to run its
/// `L4Terminated` state transition, i.e. whether subscriptions saw anything it accumulated.
#[inline]
pub(crate) fn record_conn_closed(delivered: bool) {
    LEDGER.with(|cell| {
        let mut ledger = cell.get();
        if delivered {
            ledger.conns_terminated += 1;
        } else {
            ledger.conns_discarded += 1;
        }
        cell.set(ledger);
    });
}

/// The calling core's ledger so far. Non-draining: call it as often as you like.
pub fn packet_ledger() -> PacketLedger {
    LEDGER.with(|cell| cell.get())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tally(pkts: u64, bytes: u64) -> Tally {
        Tally { pkts, bytes }
    }

    #[test]
    fn buckets_partition_received() {
        let ledger = PacketLedger {
            received: tally(10, 1000),
            ignored_by_packet_filter: tally(1, 100),
            not_transport: tally(2, 200),
            dropped_no_syn: tally(3, 300),
            tracked_tcp: tally(4, 400),
            ..Default::default()
        };
        assert_eq!(ledger.dropped(), tally(6, 600));
        assert_eq!(ledger.tracked(), tally(4, 400));
        assert_eq!(ledger.unaccounted(), 0);
    }

    #[test]
    fn unaccounted_is_signed() {
        let ledger = PacketLedger {
            received: tally(1, 100),
            tracked_udp: tally(2, 250),
            ..Default::default()
        };
        assert_eq!(ledger.unaccounted(), -150);
    }

    #[test]
    fn merge_sums_every_bucket() {
        let mut a = PacketLedger {
            received: tally(1, 10),
            tracked_tcp: tally(1, 10),
            new_tcp_conns: 1,
            ..Default::default()
        };
        let b = PacketLedger {
            received: tally(2, 20),
            tracked_udp: tally(2, 20),
            new_udp_conns: 3,
            ..Default::default()
        };
        a.merge(b);
        assert_eq!(a.received, tally(3, 30));
        assert_eq!(a.tracked(), tally(3, 30));
        assert_eq!(a.new_tcp_conns, 1);
        assert_eq!(a.new_udp_conns, 3);
        assert_eq!(a.unaccounted(), 0);
    }

    #[test]
    fn recording_accumulates_on_this_thread() {
        // Thread-local, and every other test runs on its own thread, so this starts at zero.
        let before = packet_ledger();
        record(Outcome::Received, 64);
        record(Outcome::DroppedNoSyn, 64);
        record_new_conn(true);
        let after = packet_ledger();
        assert_eq!(after.received.bytes - before.received.bytes, 64);
        assert_eq!(after.dropped_no_syn.pkts - before.dropped_no_syn.pkts, 1);
        assert_eq!(after.new_tcp_conns - before.new_tcp_conns, 1);
    }
}
