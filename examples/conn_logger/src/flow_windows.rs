/// Per-connection traffic checkpoints, triggered by traffic volume rather
/// than wall-clock time.
///
/// Tracks, for each checkpoint within a connection:
///   - Packet counts, packet bytes (per direction)
///   - Jitter (std-dev of inter-packet delay in µs, per direction)
///   - TCP only: receive-window min/max/mean (per direction)
///   - TCP only: retransmission count, sequence-gap count
///
/// A checkpoint closes once `CHECKPOINT_BYTES` combined bytes have been seen
/// since the last one, or (for sparse/idle connections that may never reach
/// that threshold) once `IDLE_CHECKPOINT_CAP` has elapsed since the last one.
/// Because the byte trigger depends only on this connection's own traffic,
/// not a shared clock, different connections reach it at different real
/// times: there's no wall-clock boundary for many connections to
/// synchronize on. A byte-threshold checkpoint also has a roughly fixed
/// "information budget," so its *duration* is a self-normalizing, directly
/// comparable proxy for instantaneous bitrate across connections (a short
/// duration to fill the same byte budget means higher throughput).
///
/// Note: `orig_jitter_us` and `resp_jitter_us` are always 0.0 for `idx == 0`
/// (there is no prior intra-checkpoint packet to measure a gap against).
/// The TCP-only fields are omitted entirely (not serialized as zeros) for
/// UDP connections, and are otherwise sampled starting from the first packet.
use crate::checkpoint_dispatch::{CheckpointOutRecord, CHECKPOINT_DISPATCHER};

use iris_compiler::*;
use iris_core::protocols::packet::ethernet::Ethernet;
use iris_core::protocols::packet::ipv4::Ipv4;
use iris_core::protocols::packet::ipv6::Ipv6;
use iris_core::protocols::packet::tcp::{Tcp, TCP_PROTOCOL};
use iris_core::protocols::packet::Packet;
use iris_core::{CoreId, FiveTuple, L4Pdu, Mbuf};
use serde::Serialize;
use std::time::{Duration, Instant};

/// Combined (orig + resp) bytes that trigger a checkpoint close. Tunable:
/// smaller values give finer intra-connection resolution at the cost of
/// more output records (rough guide: a 10 MB flow emits ~10 checkpoints at
/// the default, a 1 GB flow ~1,000).
const CHECKPOINT_BYTES: u64 = 1024 * 1024;

/// Fallback trigger for sparse/idle connections that may never reach
/// `CHECKPOINT_BYTES`: close the checkpoint anyway once this much time has
/// elapsed since it opened. Long enough that it essentially never fires for
/// active connections (which hit the byte trigger long before this), so it
/// doesn't reintroduce a shared-clock synchronization risk across them.
const IDLE_CHECKPOINT_CAP: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Welford online variance — min/max variant (TCP window stats)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct WelfordStats {
    count: u64,
    mean: f64,
    m2: f64,
    min: f64,
    max: f64,
}

impl Default for WelfordStats {
    fn default() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
            // Sentinel values so branchless min/max work correctly from the
            // very first sample without a special-case count==1 check.
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
        }
    }
}

impl WelfordStats {
    #[inline]
    fn update(&mut self, v: f64) {
        self.count += 1;
        // Branchless min/max (compiles to MINSD/MAXSD on x86-64).
        if v < self.min {
            self.min = v;
        }
        if v > self.max {
            self.max = v;
        }
        let delta = v - self.mean;
        self.mean += delta / self.count as f64;
        self.m2 += delta * (v - self.mean);
    }

    #[inline]
    fn mean(&self) -> f64 {
        self.mean
    }

    /// Finite min/max (returns 0.0 when no samples have been observed).
    #[inline]
    fn min_or_zero(&self) -> f64 {
        if self.count == 0 { 0.0 } else { self.min }
    }

    #[inline]
    fn max_or_zero(&self) -> f64 {
        if self.count == 0 { 0.0 } else { self.max }
    }
}

// ---------------------------------------------------------------------------
// Welford online variance — no min/max (IAT / jitter)
// ---------------------------------------------------------------------------

/// Lighter variant used for inter-arrival time: only stddev is needed, so
/// min and max fields are omitted.  16 bytes smaller per instance than
/// WelfordStats, and one fewer branch per packet.
#[derive(Debug, Clone, Default)]
struct IatStats {
    count: u64,
    mean: f64,
    m2: f64,
}

impl IatStats {
    #[inline]
    fn update(&mut self, v: f64) {
        self.count += 1;
        let delta = v - self.mean;
        self.mean += delta / self.count as f64;
        self.m2 += delta * (v - self.mean);
    }

    #[inline]
    fn stddev(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            (self.m2 / (self.count - 1) as f64).sqrt()
        }
    }
}

// ---------------------------------------------------------------------------
// TCP sequence-number tracking (retransmissions + gaps)
// ---------------------------------------------------------------------------

/// RFC 1323 wrapping less-than.
#[inline]
fn seq_lt(lhs: u32, rhs: u32) -> bool {
    (lhs.wrapping_sub(rhs) as i32) < 0
}

#[derive(Debug, Clone, Default)]
struct TcpDirState {
    hwm: Option<u32>,
    next_exp: Option<u32>,
}

impl TcpDirState {
    /// Returns `(is_retransmission, is_new_gap)`.
    #[inline]
    fn observe(&mut self, seq_no: u32, length: u32, flags: u8) -> (bool, bool) {
        use iris_core::protocols::packet::tcp::SYN;

        if length == 0 && (flags & SYN == 0) {
            return (false, false);
        }

        let seq_end = if flags & SYN != 0 {
            seq_no.wrapping_add(1).wrapping_add(length)
        } else {
            seq_no.wrapping_add(length)
        };

        let is_retrans = self.hwm.map(|h| !seq_lt(h, seq_end)).unwrap_or(false);
        let is_gap = self
            .next_exp
            .map(|ne| length > 0 && seq_lt(ne, seq_no))
            .unwrap_or(false);

        match self.hwm {
            Some(h) if seq_lt(h, seq_end) => self.hwm = Some(seq_end),
            None => self.hwm = Some(seq_end),
            _ => {}
        }

        if !is_retrans && !is_gap && length > 0 {
            self.next_exp = Some(seq_end);
        } else if self.next_exp.is_none() && length > 0 {
            self.next_exp = Some(seq_end);
        }

        (is_retrans, is_gap)
    }
}

// ---------------------------------------------------------------------------
// Per-checkpoint accumulator and serializable record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct WindowAcc {
    orig_pkts: u64,
    resp_pkts: u64,
    orig_pkt_bytes: u64,
    resp_pkt_bytes: u64,
    orig_iat_us: IatStats,
    resp_iat_us: IatStats,
    orig_win: WelfordStats,
    resp_win: WelfordStats,
    tcp_retransmissions: u64,
    tcp_seq_gaps: u64,
}

impl WindowAcc {
    fn is_empty(&self) -> bool {
        self.orig_pkts == 0 && self.resp_pkts == 0
    }

    /// `is_tcp` controls whether `TcpCheckpointStats` is included at all: UDP
    /// connections have no TCP receive-window/retransmission semantics, so
    /// their checkpoints omit those fields entirely rather than reporting
    /// zeros.
    fn finalize(&self, idx: u32, start_ms: u64, end_ms: u64, is_tcp: bool) -> CheckpointRecord {
        CheckpointRecord {
            idx,
            start_ms,
            end_ms,
            orig_pkts: self.orig_pkts,
            resp_pkts: self.resp_pkts,
            orig_pkt_bytes: self.orig_pkt_bytes,
            resp_pkt_bytes: self.resp_pkt_bytes,
            orig_jitter_us: self.orig_iat_us.stddev(),
            resp_jitter_us: self.resp_iat_us.stddev(),
            tcp: is_tcp.then(|| TcpCheckpointStats {
                tcp_orig_win_min: self.orig_win.min_or_zero(),
                tcp_orig_win_max: self.orig_win.max_or_zero(),
                tcp_orig_win_mean: self.orig_win.mean(),
                tcp_resp_win_min: self.resp_win.min_or_zero(),
                tcp_resp_win_max: self.resp_win.max_or_zero(),
                tcp_resp_win_mean: self.resp_win.mean(),
                tcp_retransmissions: self.tcp_retransmissions,
                tcp_seq_gaps: self.tcp_seq_gaps,
            }),
        }
    }
}

/// TCP-only per-checkpoint stats. Flattened into `CheckpointRecord`'s JSON
/// output when present, and omitted entirely (not even as zeros) for UDP
/// checkpoints.
#[derive(Debug, Clone, Serialize)]
pub struct TcpCheckpointStats {
    pub tcp_orig_win_min: f64,
    pub tcp_orig_win_max: f64,
    pub tcp_orig_win_mean: f64,
    pub tcp_resp_win_min: f64,
    pub tcp_resp_win_max: f64,
    pub tcp_resp_win_mean: f64,
    pub tcp_retransmissions: u64,
    pub tcp_seq_gaps: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckpointRecord {
    pub idx: u32,
    /// Milliseconds from connection start.
    pub start_ms: u64,
    /// Milliseconds from connection start.
    pub end_ms: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_pkt_bytes: u64,
    pub resp_pkt_bytes: u64,
    /// Std-dev of inter-arrival time in µs.
    pub orig_jitter_us: f64,
    pub resp_jitter_us: f64,
    #[serde(flatten)]
    pub tcp: Option<TcpCheckpointStats>,
}

// ---------------------------------------------------------------------------
// FlowWindows datatype
// ---------------------------------------------------------------------------

fn tcp_window_size(pdu: &L4Pdu) -> Option<u16> {
    let mbuf: &Mbuf = pdu.mbuf_ref();
    // Use the already-known IP version from the connection context to avoid
    // the failed IPv4 parse attempt on every IPv6 packet.
    //
    // NOTE: 802.1Q VLAN-tagged frames are not supported.  On such networks
    // the inner EtherType is hidden behind a VLAN tag, so parse_to::<Ipv4/6>()
    // fails and this function returns None, leaving all tcp_*_win_* fields as
    // 0.0 in the output.
    if let Ok(eth) = mbuf.parse_to::<Ethernet>() {
        if pdu.ctxt.src.is_ipv4() {
            if let Ok(ip4) = eth.parse_to::<Ipv4>() {
                if let Ok(tcp) = ip4.parse_to::<Tcp>() {
                    return Some(tcp.window());
                }
            }
        } else if let Ok(ip6) = eth.parse_to::<Ipv6>() {
            if let Ok(tcp) = ip6.parse_to::<Tcp>() {
                return Some(tcp.window());
            }
        }
    }
    None
}

#[datatype]
#[derive(Debug)]
pub struct FlowWindows {
    /// Timestamp of the first packet (used to compute checkpoint offsets).
    pub start_ts: Instant,
    /// Set once from the first packet's context; used to tag each streamed
    /// checkpoint with a joinable identity (see `dispatch`), since `FlowWindows`
    /// itself never sees `ConnLogger`'s already-anonymized fields.
    ft: FiveTuple,
    curr: WindowAcc,
    curr_start: Instant,
    curr_idx: u32,
    orig_last_ts: Option<Instant>,
    resp_last_ts: Option<Instant>,
    is_tcp: bool,
    orig_tcp: TcpDirState,
    resp_tcp: TcpDirState,
}

impl FlowWindows {
    pub fn new(first_pkt: &L4Pdu) -> Self {
        let now = first_pkt.ts;
        Self {
            start_ts: now,
            ft: FiveTuple::from_ctxt(&first_pkt.ctxt),
            curr: WindowAcc::default(),
            curr_start: now,
            curr_idx: 0,
            orig_last_ts: None,
            resp_last_ts: None,
            is_tcp: first_pkt.ctxt.proto == TCP_PROTOCOL,
            orig_tcp: TcpDirState::default(),
            resp_tcp: TcpDirState::default(),
        }
    }

    /// Dispatch a finalized checkpoint off the RX core instead of serializing
    /// and writing it inline; see `checkpoint_dispatch`. A no-op if the
    /// dispatcher hasn't been initialized (e.g. in unit tests).
    fn dispatch(&self, checkpoint: CheckpointRecord, core: &CoreId) {
        if let Some(dispatcher) = CHECKPOINT_DISPATCHER.get() {
            let event = CheckpointOutRecord {
                record_type: "checkpoint",
                five_tuple: crate::anon_ft(&self.ft),
                checkpoint,
            };
            let _ = dispatcher.dispatch(event, Some(core));
        }
    }

    /// Close out the checkpoint ending at `now`.
    ///
    /// Only called from `update()` right after accounting for the current
    /// packet (either because that pushed combined bytes past
    /// `CHECKPOINT_BYTES`, or because `IDLE_CHECKPOINT_CAP` elapsed since the
    /// checkpoint opened), so `curr` always has at least that one packet in
    /// it — unlike the old wall-clock design, a checkpoint boundary can never
    /// be reached without a packet driving it, so there's no empty-checkpoint
    /// case to guard against here.
    fn close_checkpoint(&mut self, now: Instant) {
        // Reset per-direction timestamps so each checkpoint's jitter is
        // computed from intra-checkpoint IATs only; a cross-checkpoint gap
        // could otherwise skew the stddev of the next checkpoint.
        self.orig_last_ts = None;
        self.resp_last_ts = None;

        let start_ms = self.curr_start.duration_since(self.start_ts).as_millis() as u64;
        let end_ms = now.duration_since(self.start_ts).as_millis() as u64;
        let record = self
            .curr
            .finalize(self.curr_idx, start_ms, end_ms, self.is_tcp);
        self.curr_idx += 1;
        self.curr = WindowAcc::default();
        self.curr_start = now;

        // `datatype_fn`s (unlike `callback_fn`s) only allow a single builtin
        // parameter — `pdu` here — so `CoreId` can't be requested directly;
        // derive it the same way the checkpoint workers do (see
        // checkpoint_dispatch), since we're necessarily running on whichever
        // RX core owns this connection.
        let core = CoreId(unsafe { iris_core::rte_lcore_id() } as u32);
        self.dispatch(record, &core);
    }

    /// Whether the still-open partial checkpoint has anything worth
    /// reporting. False only when it's both empty and at least one checkpoint
    /// has already been dispatched for this connection — an empty checkpoint
    /// immediately following a real one carries no information. A connection
    /// that never closed any checkpoint always reports its (possibly empty)
    /// sole one, so every connection gets at least one record.
    fn should_emit_final(&self) -> bool {
        !(self.curr.is_empty() && self.curr_idx > 0)
    }

    /// Dispatch the final, still-open partial checkpoint. Call at connection
    /// termination with `end_ts = Instant::now()`.
    pub fn flush_final(&self, end_ts: Instant, core: &CoreId) {
        if !self.should_emit_final() {
            return;
        }
        let start_ms = self.curr_start.duration_since(self.start_ts).as_millis() as u64;
        let end_ms = end_ts.duration_since(self.start_ts).as_millis() as u64;
        let record = self
            .curr
            .finalize(self.curr_idx, start_ms, end_ms, self.is_tcp);
        self.dispatch(record, core);
    }

    #[datatype_fn("FlowWindows,level=InL4Conn")]
    pub fn update(&mut self, pdu: &L4Pdu) {
        let now = pdu.ts;
        let is_orig = pdu.dir;
        let pkt_bytes = pdu.mbuf_ref().data_len() as u64;

        if is_orig {
            self.curr.orig_pkts += 1;
            self.curr.orig_pkt_bytes += pkt_bytes;
            // Only compute jitter for flows that have crossed at least one
            // checkpoint.  orig_last_ts is reset by close_checkpoint so each
            // checkpoint's jitter reflects intra-checkpoint IATs only.
            if self.curr_idx > 0 {
                if let Some(prev) = self.orig_last_ts {
                    self.curr
                        .orig_iat_us
                        .update(now.duration_since(prev).as_micros() as f64);
                }
            }
            self.orig_last_ts = Some(now);
        } else {
            self.curr.resp_pkts += 1;
            self.curr.resp_pkt_bytes += pkt_bytes;
            if self.curr_idx > 0 {
                if let Some(prev) = self.resp_last_ts {
                    self.curr
                        .resp_iat_us
                        .update(now.duration_since(prev).as_micros() as f64);
                }
            }
            self.resp_last_ts = Some(now);
        }

        if self.is_tcp {
            if let Some(win) = tcp_window_size(pdu) {
                if is_orig {
                    self.curr.orig_win.update(win as f64);
                } else {
                    self.curr.resp_win.update(win as f64);
                }
            }

            let state = if is_orig {
                &mut self.orig_tcp
            } else {
                &mut self.resp_tcp
            };
            let (retrans, gap) =
                state.observe(pdu.seq_no(), pdu.length() as u32, pdu.flags());
            if retrans {
                self.curr.tcp_retransmissions += 1;
            }
            if gap {
                self.curr.tcp_seq_gaps += 1;
            }
        }

        // Close the checkpoint once enough traffic (or, for sparse
        // connections, enough elapsed time) has accumulated. Unlike a
        // wall-clock boundary, there's no shared "when" for two different
        // connections to synchronize on: each reaches its own byte
        // threshold at a different real time, driven by its own traffic.
        let total_bytes = self.curr.orig_pkt_bytes + self.curr.resp_pkt_bytes;
        if total_bytes >= CHECKPOINT_BYTES
            || now.duration_since(self.curr_start) >= IDLE_CHECKPOINT_CAP
        {
            self.close_checkpoint(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `FlowWindows` directly (bypassing `new`/`update`, which
    /// require a live `L4Pdu`/mbuf) so checkpoint-closing logic can be
    /// exercised with synthetic timestamps. `close_checkpoint`/`flush_final`
    /// dispatch through `CHECKPOINT_DISPATCHER`, which is never initialized in
    /// unit tests, so dispatch is a harmless no-op here — these tests only
    /// check `FlowWindows`'s own bookkeeping (`curr`/`curr_idx`/`curr_start`).
    /// Record-content behavior (TCP-stats inclusion, JSON shape) is tested
    /// directly against `WindowAcc::finalize` below instead, since that's
    /// unaffected by the dispatch change and doesn't need this scaffolding.
    fn empty_flow(start: Instant) -> FlowWindows {
        FlowWindows {
            start_ts: start,
            ft: FiveTuple {
                orig: "10.0.0.1:1234".parse().unwrap(),
                resp: "10.0.0.2:80".parse().unwrap(),
                proto: TCP_PROTOCOL,
            },
            curr: WindowAcc::default(),
            curr_start: start,
            curr_idx: 0,
            orig_last_ts: None,
            resp_last_ts: None,
            is_tcp: false,
            orig_tcp: TcpDirState::default(),
            resp_tcp: TcpDirState::default(),
        }
    }

    #[test]
    fn checkpoint_closes_after_byte_threshold() {
        let start = Instant::now();
        let mut fw = empty_flow(start);
        fw.curr.orig_pkts = 5;
        fw.curr.orig_pkt_bytes = CHECKPOINT_BYTES;

        fw.close_checkpoint(start + Duration::from_millis(1));

        assert_eq!(fw.curr_idx, 1);
        assert_eq!(fw.curr_start, start + Duration::from_millis(1));
        // curr resets to empty for the next checkpoint.
        assert!(fw.curr.is_empty());
    }

    #[test]
    fn checkpoint_closes_after_idle_cap_even_under_byte_threshold() {
        let start = Instant::now();
        let mut fw = empty_flow(start);
        // Well under CHECKPOINT_BYTES, but IDLE_CHECKPOINT_CAP has elapsed.
        fw.curr.orig_pkts = 1;
        fw.curr.orig_pkt_bytes = 64;

        let closed_at = start + IDLE_CHECKPOINT_CAP;
        fw.close_checkpoint(closed_at);

        assert_eq!(fw.curr_idx, 1);
        assert_eq!(fw.curr_start, closed_at);
        assert!(fw.curr.is_empty());
    }

    #[test]
    fn should_emit_final_is_true_when_nothing_closed_yet() {
        let start = Instant::now();
        let fw = empty_flow(start);
        // No packets were ever recorded and nothing has been closed yet:
        // every connection must get at least one record.
        assert!(fw.should_emit_final());
    }

    #[test]
    fn should_emit_final_is_false_for_empty_trailing_checkpoint_after_a_real_one() {
        let start = Instant::now();
        let mut fw = empty_flow(start);
        fw.curr.orig_pkts = 5;
        fw.curr.orig_pkt_bytes = CHECKPOINT_BYTES;
        fw.close_checkpoint(start + Duration::from_secs(1));
        // curr is now empty (freshly reset); connection goes idle and terminates.
        assert!(fw.curr.is_empty());

        assert!(
            !fw.should_emit_final(),
            "trailing empty checkpoint should be dropped"
        );
    }

    #[test]
    fn should_emit_final_is_true_when_curr_has_data() {
        let start = Instant::now();
        let mut fw = empty_flow(start);
        fw.curr.orig_pkts = 5;
        fw.curr.orig_pkt_bytes = CHECKPOINT_BYTES;
        fw.close_checkpoint(start + Duration::from_secs(1));
        fw.curr.orig_pkts = 1;

        assert!(fw.should_emit_final());
    }

    #[test]
    fn udp_finalize_omits_tcp_stats() {
        let mut acc = WindowAcc::default();
        acc.orig_pkts = 5;

        let record = acc.finalize(0, 0, 1000, false);

        assert!(record.tcp.is_none());
    }

    #[test]
    fn tcp_finalize_includes_tcp_stats() {
        let mut acc = WindowAcc::default();
        acc.orig_pkts = 5;
        acc.orig_win.update(4096.0);

        let record = acc.finalize(0, 0, 1000, true);

        let tcp = record
            .tcp
            .as_ref()
            .expect("TCP checkpoint must include tcp stats");
        assert_eq!(tcp.tcp_orig_win_max, 4096.0);
    }

    #[test]
    fn udp_finalize_json_has_no_tcp_keys() {
        let mut acc = WindowAcc::default();
        acc.orig_pkts = 5;

        let record = acc.finalize(0, 0, 1000, false);

        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("tcp_orig_win"), "UDP checkpoint JSON: {json}");
        assert!(!json.contains("tcp_retransmissions"), "UDP checkpoint JSON: {json}");
    }
}
