/// Per-10-second windowed connection features.
///
/// Tracks, for each 10-second window within a connection:
///   - Packet counts, packet bytes, payload bytes (per direction)
///   - Jitter (std-dev of inter-packet delay in µs, per direction)
///   - TCP: receive-window min/max/mean (per direction)
///   - TCP: retransmission count, sequence-gap count
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
            // Most connections span fewer than 4 windows; pre-allocating
            // avoids the first few reallocation copies.
            completed: Vec::with_capacity(4),
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

    /// Flush the current window and start a new one anchored at `now`.
    fn flush_window(&mut self, now: Instant) {
        let start_ms = self.curr_start.duration_since(self.start_ts).as_millis() as u64;
        let end_ms = now.duration_since(self.start_ts).as_millis() as u64;
        self.completed
            .push(self.curr.finalize(self.curr_idx, start_ms, end_ms));
        self.curr_idx += 1;
        self.curr = WindowAcc::default();
        self.curr_start = now;
    }

    /// Return all completed windows plus the current partial window.
    /// Call at connection termination with `end_ts = Instant::now()`.
    pub fn all_windows(&self, end_ts: Instant) -> Vec<WindowRecord> {
        let mut all = self.completed.clone();
        let start_ms = self.curr_start.duration_since(self.start_ts).as_millis() as u64;
        let end_ms = end_ts.duration_since(self.start_ts).as_millis() as u64;
        all.push(self.curr.finalize(self.curr_idx, start_ms, end_ms));
        all
    }

    #[datatype_fn("FlowWindows,level=InL4Conn")]
    pub fn update(&mut self, pdu: &L4Pdu) {
        let now = pdu.ts;

        // Flush one window per WINDOW_DURATION boundary, not just once per
        // arrival.  A single `if` would produce a window wider than
        // WINDOW_SECS whenever packets arrive more than 10 seconds apart.
        while now.duration_since(self.curr_start) >= WINDOW_DURATION {
            self.flush_window(self.curr_start + WINDOW_DURATION);
        }

        let is_orig = pdu.dir;
        let pkt_bytes = pdu.mbuf_ref().data_len() as u64;
        let payload_bytes = pdu.length() as u64;

        if is_orig {
            self.curr.orig_pkts += 1;
            self.curr.orig_pkt_bytes += pkt_bytes;
            self.curr.orig_payload_bytes += payload_bytes;
            if let Some(prev) = self.orig_last_ts {
                self.curr
                    .orig_iat_us
                    .update(now.duration_since(prev).as_micros() as f64);
            }
            self.orig_last_ts = Some(now);
        } else {
            self.curr.resp_pkts += 1;
            self.curr.resp_pkt_bytes += pkt_bytes;
            self.curr.resp_payload_bytes += payload_bytes;
            if let Some(prev) = self.resp_last_ts {
                self.curr
                    .resp_iat_us
                    .update(now.duration_since(prev).as_micros() as f64);
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
