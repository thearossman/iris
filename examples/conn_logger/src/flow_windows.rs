/// Per-10-second windowed connection features.
///
/// Tracks, for each 10-second window within a connection:
///   - Packet counts, packet bytes, payload bytes (per direction)
///   - Jitter (std-dev of inter-packet delay in µs, per direction)
///   - TCP: receive-window min/max/mean (per direction)
///   - TCP: retransmission count, sequence-gap count
///
/// Note: `orig_jitter_us` and `resp_jitter_us` are always 0.0 for `idx == 0`
/// (there is no prior intra-window packet to measure a gap against).
/// `tcp_*_win_*` fields are sampled starting from the very first packet.
///
/// Windows with zero packets are not emitted on their own: a run of idle
/// 10-second windows is folded into the next (or final) window instead,
/// producing one wider, longer-duration window rather than many empty
/// records.
use iris_compiler::*;
use iris_core::protocols::packet::ethernet::Ethernet;
use iris_core::protocols::packet::ipv4::Ipv4;
use iris_core::protocols::packet::ipv6::Ipv6;
use iris_core::protocols::packet::tcp::{Tcp, TCP_PROTOCOL};
use iris_core::protocols::packet::Packet;
use iris_core::{L4Pdu, Mbuf};
use serde::Serialize;
use std::time::{Duration, Instant};

pub const WINDOW_SECS: u64 = 10;

// Pre-compute the Duration once so the per-packet comparison is a simple
// 128-bit integer compare against a constant.
const WINDOW_DURATION: Duration = Duration::from_secs(WINDOW_SECS);

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
// Per-window accumulator and serializable record
// ---------------------------------------------------------------------------

/// 192 bytes — fits in exactly 3 cache lines.
#[derive(Debug, Clone, Default)]
struct WindowAcc {
    orig_pkts: u64,
    resp_pkts: u64,
    orig_pkt_bytes: u64,
    resp_pkt_bytes: u64,
    orig_payload_bytes: u64,
    resp_payload_bytes: u64,
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

    fn finalize(&self, idx: u32, start_ms: u64, end_ms: u64) -> WindowRecord {
        WindowRecord {
            idx,
            start_ms,
            end_ms,
            orig_pkts: self.orig_pkts,
            resp_pkts: self.resp_pkts,
            orig_pkt_bytes: self.orig_pkt_bytes,
            resp_pkt_bytes: self.resp_pkt_bytes,
            orig_payload_bytes: self.orig_payload_bytes,
            resp_payload_bytes: self.resp_payload_bytes,
            orig_jitter_us: self.orig_iat_us.stddev(),
            resp_jitter_us: self.resp_iat_us.stddev(),
            tcp_orig_win_min: self.orig_win.min_or_zero(),
            tcp_orig_win_max: self.orig_win.max_or_zero(),
            tcp_orig_win_mean: self.orig_win.mean(),
            tcp_resp_win_min: self.resp_win.min_or_zero(),
            tcp_resp_win_max: self.resp_win.max_or_zero(),
            tcp_resp_win_mean: self.resp_win.mean(),
            tcp_retransmissions: self.tcp_retransmissions,
            tcp_seq_gaps: self.tcp_seq_gaps,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowRecord {
    pub idx: u32,
    /// Milliseconds from connection start.
    pub start_ms: u64,
    /// Milliseconds from connection start.
    pub end_ms: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_pkt_bytes: u64,
    pub resp_pkt_bytes: u64,
    pub orig_payload_bytes: u64,
    pub resp_payload_bytes: u64,
    /// Std-dev of inter-arrival time in µs.
    pub orig_jitter_us: f64,
    pub resp_jitter_us: f64,
    pub tcp_orig_win_min: f64,
    pub tcp_orig_win_max: f64,
    pub tcp_orig_win_mean: f64,
    pub tcp_resp_win_min: f64,
    pub tcp_resp_win_max: f64,
    pub tcp_resp_win_mean: f64,
    pub tcp_retransmissions: u64,
    pub tcp_seq_gaps: u64,
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
    /// Timestamp of the first packet (used to compute window offsets).
    pub start_ts: Instant,
    completed: Vec<WindowRecord>,
    curr: WindowAcc,
    curr_start: Instant,
    /// Next WINDOW_DURATION boundary to check against. Unlike `curr_start`,
    /// this always advances by exactly one WINDOW_DURATION per boundary
    /// crossing, even when the window at that boundary is idle and folded
    /// forward instead of flushed (see `flush_window`).
    next_boundary: Instant,
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
            // Defer allocation: most connections are short-lived and never
            // cross a window boundary, so Vec::new() avoids allocating until
            // the first flush at 10 seconds.
            completed: Vec::new(),
            curr: WindowAcc::default(),
            curr_start: now,
            next_boundary: now + WINDOW_DURATION,
            curr_idx: 0,
            orig_last_ts: None,
            resp_last_ts: None,
            is_tcp: first_pkt.ctxt.proto == TCP_PROTOCOL,
            orig_tcp: TcpDirState::default(),
            resp_tcp: TcpDirState::default(),
        }
    }

    /// Close out the window ending at `boundary`.
    ///
    /// If the window accumulated no packets, it is *not* emitted as its own
    /// record: `curr_start` is left in place so the idle span is folded into
    /// whichever window eventually contains traffic (or into the final
    /// partial window at connection termination), producing one wider window
    /// instead of a run of empty ones. Per-direction timestamps are still
    /// reset so a later packet's jitter isn't skewed by the gap.
    fn flush_window(&mut self, boundary: Instant) {
        // Reset per-direction timestamps so each window's jitter is computed
        // from intra-window IATs only; a cross-boundary (or cross-idle-span)
        // gap can be seconds long and would badly skew the stddev of the
        // next window.
        self.orig_last_ts = None;
        self.resp_last_ts = None;

        if self.curr.is_empty() {
            return;
        }

        let start_ms = self.curr_start.duration_since(self.start_ts).as_millis() as u64;
        let end_ms = boundary.duration_since(self.start_ts).as_millis() as u64;
        self.completed
            .push(self.curr.finalize(self.curr_idx, start_ms, end_ms));
        self.curr_idx += 1;
        self.curr = WindowAcc::default();
        self.curr_start = boundary;
    }

    /// Return all completed windows plus the current partial window.
    /// Call at connection termination with `end_ts = Instant::now()`.
    pub fn all_windows(&self, end_ts: Instant) -> Vec<WindowRecord> {
        let mut all = self.completed.clone();
        // Skip an empty trailing window the same way flush_window does,
        // unless it would be the connection's only record.
        if !self.curr.is_empty() || self.completed.is_empty() {
            let start_ms = self.curr_start.duration_since(self.start_ts).as_millis() as u64;
            let end_ms = end_ts.duration_since(self.start_ts).as_millis() as u64;
            all.push(self.curr.finalize(self.curr_idx, start_ms, end_ms));
        }
        all
    }

    #[datatype_fn("FlowWindows,level=InL4Conn")]
    pub fn update(&mut self, pdu: &L4Pdu) {
        let now = pdu.ts;

        // Advance one WINDOW_DURATION boundary at a time, not just once per
        // arrival. A single `if` would produce a window wider than
        // WINDOW_SECS whenever packets arrive more than 10 seconds apart.
        // Idle boundaries fold forward into the current window rather than
        // each producing their own empty WindowRecord (see flush_window).
        while now >= self.next_boundary {
            self.flush_window(self.next_boundary);
            self.next_boundary += WINDOW_DURATION;
        }

        let is_orig = pdu.dir;
        let pkt_bytes = pdu.mbuf_ref().data_len() as u64;
        let payload_bytes = pdu.length() as u64;

        if is_orig {
            self.curr.orig_pkts += 1;
            self.curr.orig_pkt_bytes += pkt_bytes;
            self.curr.orig_payload_bytes += payload_bytes;
            // Only compute jitter for flows that have crossed at least one
            // 10-second boundary.  orig_last_ts is reset by flush_window so
            // each window's jitter reflects intra-window IATs only.
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
            self.curr.resp_payload_bytes += payload_bytes;
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `FlowWindows` directly (bypassing `new`/`update`, which
    /// require a live `L4Pdu`/mbuf) so the boundary-merging logic can be
    /// exercised with synthetic timestamps.
    fn empty_flow(start: Instant) -> FlowWindows {
        FlowWindows {
            start_ts: start,
            completed: Vec::new(),
            curr: WindowAcc::default(),
            curr_start: start,
            next_boundary: start + WINDOW_DURATION,
            curr_idx: 0,
            orig_last_ts: None,
            resp_last_ts: None,
            is_tcp: false,
            orig_tcp: TcpDirState::default(),
            resp_tcp: TcpDirState::default(),
        }
    }

    #[test]
    fn idle_boundary_is_not_flushed_as_its_own_window() {
        let start = Instant::now();
        let mut fw = empty_flow(start);

        // Cross one boundary with zero packets accumulated.
        fw.flush_window(start + WINDOW_DURATION);

        assert!(fw.completed.is_empty(), "empty window must not be emitted");
        assert_eq!(fw.curr_idx, 0);
        // curr_start stays put so the idle span folds into whatever comes next.
        assert_eq!(fw.curr_start, start);
    }

    #[test]
    fn multiple_idle_boundaries_merge_into_one_wide_window() {
        let start = Instant::now();
        let mut fw = empty_flow(start);

        // Three idle boundaries pass with no traffic...
        fw.flush_window(start + WINDOW_DURATION);
        fw.flush_window(start + WINDOW_DURATION * 2);
        fw.flush_window(start + WINDOW_DURATION * 3);
        // ...then a packet arrives in the 4th window.
        fw.curr.orig_pkts = 1;
        fw.flush_window(start + WINDOW_DURATION * 4);

        assert_eq!(fw.completed.len(), 1, "idle windows must collapse to one record");
        let record = &fw.completed[0];
        // The single emitted window spans all four window-durations
        assert_eq!(record.start_ms, 0);
        assert_eq!(record.end_ms, (WINDOW_DURATION * 4).as_millis() as u64);
        assert_eq!(record.idx, 0);
        assert_eq!(fw.curr_idx, 1);
    }

    #[test]
    fn non_idle_boundary_flushes_normally() {
        let start = Instant::now();
        let mut fw = empty_flow(start);
        fw.curr.orig_pkts = 5;

        fw.flush_window(start + WINDOW_DURATION);

        assert_eq!(fw.completed.len(), 1);
        assert_eq!(fw.completed[0].orig_pkts, 5);
        assert_eq!(fw.curr_idx, 1);
        assert_eq!(fw.curr_start, start + WINDOW_DURATION);
    }

    #[test]
    fn all_windows_omits_empty_trailing_window_when_data_exists() {
        let start = Instant::now();
        let mut fw = empty_flow(start);
        fw.curr.orig_pkts = 5;
        fw.flush_window(start + WINDOW_DURATION);
        // curr is now empty (freshly reset); connection goes idle and terminates.
        assert!(fw.curr.is_empty());

        let all = fw.all_windows(start + WINDOW_DURATION * 3);
        assert_eq!(all.len(), 1, "trailing idle window should be dropped");
    }

    #[test]
    fn all_windows_keeps_sole_window_even_if_empty() {
        let start = Instant::now();
        let fw = empty_flow(start);
        // No packets were ever recorded and nothing has been flushed yet.
        let all = fw.all_windows(start);
        assert_eq!(all.len(), 1, "must always emit at least one record");
    }
}
