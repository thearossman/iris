//! Various individual connection-level subscribable types for TCP and/or UDP
//! connection information, statistics, and state history.

#[allow(unused_imports)]
use iris_compiler::{datatype, datatype_fn};
use iris_core::conntrack::conn::tcp_conn::reassembly::wrapping_lt;
use iris_core::protocols::packet::tcp::ACK;
use iris_core::protocols::packet::{ethernet::Ethernet, ipv4::Ipv4, ipv6::Ipv6, tcp::Tcp, Packet};
use iris_core::subscription::Tracked;
use iris_core::L4Pdu;
use serde::ser::{Serialize, SerializeSeq, SerializeStruct, Serializer};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Tracks the start (first packet seen) and end (last packet seen)
/// times of a connection
#[cfg_attr(not(feature = "skip_expand"), datatype)]
#[derive(Debug, Clone)]
pub struct ConnDuration {
    pub start_ts: Instant,
    pub last_ts: Instant,
}

impl Serialize for ConnDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ConnDuration", 1)?;

        let duration = self.last_ts - self.start_ts;
        state.serialize_field("duration", &duration.as_millis())?;
        state.end()
    }
}

impl ConnDuration {
    /// The duration of the connection in milliseconds
    pub fn duration_ms(&self) -> u128 {
        (self.last_ts - self.start_ts).as_millis()
    }

    /// The duration of the connection as std::time::Duration
    pub fn duration(&self) -> Duration {
        self.last_ts - self.start_ts
    }
}

impl ConnDuration {
    #[inline]
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("ConnDuration,level=InL4Conn")
    )]
    pub fn update(&mut self, pdu: &L4Pdu) {
        self.last_ts = pdu.ts;
    }
}

impl Tracked for ConnDuration {
    fn new(_first_pkt: &L4Pdu) -> Self {
        let now = Instant::now();
        Self {
            start_ts: now,
            last_ts: now,
        }
    }

    #[inline]
    fn clear(&mut self) {}
}

/// The number of packets observed in a connection
#[derive(Debug, serde::Serialize, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct PktCount {
    pub orig: usize,
    pub resp: usize,
}

impl PktCount {
    pub fn total(&self) -> usize {
        self.orig + self.resp
    }

    pub fn orig(&self) -> usize {
        self.orig
    }

    pub fn resp(&self) -> usize {
        self.resp
    }
}

impl PktCount {
    #[inline]
    #[cfg_attr(not(feature = "skip_expand"), datatype_fn("PktCount,level=InL4Conn"))]
    pub fn update(&mut self, pdu: &L4Pdu) {
        if pdu.dir {
            self.orig += 1;
        } else {
            self.resp += 1;
        }
    }
}

impl Tracked for PktCount {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { orig: 0, resp: 0 }
    }

    #[inline]
    fn clear(&mut self) {}
}

/// The number of bytes, excluding packet headers, in each
/// flow in a connection connection
#[derive(Debug, serde::Serialize, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct ByteCount {
    pub orig: usize,
    pub resp: usize,
}

impl ByteCount {
    pub fn total(&self) -> usize {
        self.orig + self.resp
    }

    pub fn orig(&self) -> usize {
        self.orig
    }

    pub fn resp(&self) -> usize {
        self.resp
    }
}

impl ByteCount {
    #[inline]
    #[cfg_attr(not(feature = "skip_expand"), datatype_fn("ByteCount,level=InL4Conn"))]
    pub fn update(&mut self, pdu: &L4Pdu) {
        if pdu.dir {
            self.orig += pdu.length();
        } else {
            self.resp += pdu.length();
        }
    }
}

impl Tracked for ByteCount {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { orig: 0, resp: 0 }
    }

    #[inline]
    fn clear(&mut self) {}
}

/// Tracked data for packet inter-arrival times
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct InterArrivals {
    pkt_count_ctos: usize,
    pkt_count_stoc: usize,
    last_pkt_ctos: Instant,
    last_pkt_stoc: Instant,
    pub interarrivals_ctos: Vec<Duration>,
    /// Interarrival durations server-to-client (resp.) flow
    pub interarrivals_stoc: Vec<Duration>,
}

impl InterArrivals {
    pub fn new_empty() -> Self {
        let now = Instant::now();
        Self {
            pkt_count_ctos: 0,
            pkt_count_stoc: 0,
            last_pkt_ctos: now,
            last_pkt_stoc: now,
            interarrivals_ctos: Vec::new(),
            interarrivals_stoc: Vec::new(),
        }
    }
}

impl InterArrivals {
    #[inline]
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("InterArrivals,level=InL4Conn")
    )]
    pub fn update(&mut self, pdu: &L4Pdu) {
        let now = Instant::now();
        if pdu.dir {
            self.pkt_count_ctos += 1;
            if self.pkt_count_ctos > 1 {
                self.interarrivals_ctos.push(now - self.last_pkt_ctos);
            }
            self.last_pkt_ctos = now;
        } else {
            self.pkt_count_stoc += 1;
            if self.pkt_count_stoc > 1 {
                self.interarrivals_stoc.push(now - self.last_pkt_stoc);
            }
            self.last_pkt_stoc = now;
        }
    }
}

impl Tracked for InterArrivals {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self::new_empty()
    }

    #[inline]
    fn clear(&mut self) {
        self.interarrivals_ctos.clear();
        self.interarrivals_stoc.clear();
    }
}

struct DurationVec<'a>(&'a Vec<Duration>);
impl Serialize for DurationVec<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for dur in self.0 {
            seq.serialize_element(&dur.as_nanos())?;
        }
        seq.end()
    }
}

impl Serialize for InterArrivals {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("InterArrivals", 4)?;
        state.serialize_field("interarrivals_ctos", &DurationVec(&self.interarrivals_ctos))?;
        state.serialize_field("interarrivals_stoc", &DurationVec(&self.interarrivals_stoc))?;
        state.end()
    }
}

use crate::connection::update_history;

/// Connection history.
///
/// This represents a summary of the connection history in the order the packets were observed,
/// with letters encoded as a vector of bytes. This is a simplified version of [state history in
/// Zeek](https://docs.zeek.org/en/v5.0.0/scripts/base/protocols/conn/main.zeek.html), and the
/// meanings of each letter are similar: If the event comes from the originator, the letter is
/// uppercase; if the event comes from the responder, the letter is lowercase.
/// - S: a pure SYN with only the SYN bit set (may have payload)
/// - H: a pure SYNACK with only the SYN and ACK bits set (may have payload)
/// - A: a pure ACK with only the ACK bit set and no payload
/// - D: segment contains non-zero payload length
/// - F: the segment has the FIN bit set (may have other flags and/or payload)
/// - R: segment has the RST bit set (may have other flags and/or payload)
///
/// Each letter is recorded a maximum of once in either direction.
#[derive(Default, Debug, serde::Serialize, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct ConnHistory {
    pub history: Vec<u8>,
}

impl ConnHistory {
    #[inline]
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("ConnHistory,level=InL4Conn")
    )]
    pub fn update(&mut self, pdu: &L4Pdu) {
        if pdu.dir {
            update_history(&mut self.history, pdu, 0x0);
        } else {
            update_history(&mut self.history, pdu, 0x20);
        }
    }
}

impl Tracked for ConnHistory {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            history: Vec::with_capacity(16),
        }
    }

    #[inline]
    fn clear(&mut self) {}
}

/// -------------------------------------------------------------------------- ///

#[inline]
fn tcp_window(pdu: &L4Pdu) -> Option<u16> {
    let eth = Packet::parse_to::<Ethernet>(pdu.mbuf_ref()).ok()?;
    if let Ok(ipv4) = eth.parse_to::<Ipv4>() {
        ipv4.parse_to::<Tcp>().ok().map(|t| t.window())
    } else if let Ok(ipv6) = eth.parse_to::<Ipv6>() {
        ipv6.parse_to::<Tcp>().ok().map(|t| t.window())
    } else {
        None
    }
}

/// Smoothed RTT and RTT variance estimated from ACK timing (RFC 6298).
///
/// RTT samples are derived from the time between a data segment leaving the
/// originator and the corresponding ACK arriving from the responder.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct TcpRtt {
    /// Smoothed RTT estimate in microseconds.
    pub srtt_us: u64,
    /// RTT variance in microseconds.
    pub rttvar_us: u64,
    /// Min RTT sample in microseconds.
    pub min_rtt_us: u64,
    /// Number of RTT samples collected.
    pub sample_count: u64,
    // [Accounting] pending sends: (seq_end, send_ts).  seq_end = seq_no + payload_len.
    pending: VecDeque<(u32, Instant)>,
}

impl TcpRtt {
    /// Smoothed RTT as a `Duration`.
    pub fn srtt(&self) -> Duration {
        Duration::from_micros(self.srtt_us)
    }

    /// RTT variance as a `Duration`.
    pub fn rttvar(&self) -> Duration {
        Duration::from_micros(self.rttvar_us)
    }

    /// Minimum RTT observed as a `Duration`.
    pub fn min_rtt(&self) -> Option<Duration> {
        if self.sample_count == 0 {
            None
        } else {
            Some(Duration::from_micros(self.min_rtt_us))
        }
    }
}

const MAX_PENDING: usize = 256;

impl TcpRtt {
    #[inline]
    #[cfg_attr(not(feature = "skip_expand"), datatype_fn("TcpRtt,level=InL4Conn"))]
    pub fn update(&mut self, pdu: &L4Pdu) {
        if pdu.dir {
            // Orig to resp
            if pdu.length() > 0 {
                let seq_end = pdu.seq_no().wrapping_add(pdu.length() as u32);
                self.pending.push_back((seq_end, pdu.ts));
                // Bound the queue to avoid unbounded growth under loss.
                if self.pending.len() > MAX_PENDING {
                    self.pending.pop_front();
                }
            }
        } else {
            // Resp to orig
            let ack = pdu.ack_no();
            while let Some(&(seq_end, send_ts)) = self.pending.front() {
                if !wrapping_lt(seq_end, ack) && seq_end != ack {
                    break;
                }
                self.pending.pop_front();
                let rtt_us = pdu.ts.duration_since(send_ts).as_micros() as u64;
                if rtt_us == 0 {
                    continue;
                }
                if self.sample_count == 0 {
                    self.srtt_us = rtt_us;
                    self.rttvar_us = rtt_us / 2;
                    self.min_rtt_us = rtt_us;
                } else {
                    // RFC 6298: RTTVAR = (3/4)*RTTVAR + (1/4)*|SRTT - R|
                    //           SRTT   = (7/8)*SRTT   + (1/8)*R
                    let diff = if rtt_us > self.srtt_us {
                        rtt_us - self.srtt_us
                    } else {
                        self.srtt_us - rtt_us
                    };
                    self.rttvar_us = (3 * self.rttvar_us + diff) / 4;
                    self.srtt_us = (7 * self.srtt_us + rtt_us) / 8;
                    if rtt_us < self.min_rtt_us {
                        self.min_rtt_us = rtt_us;
                    }
                }
                self.sample_count += 1;
            }
        }
    }
}

impl Tracked for TcpRtt {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            srtt_us: 0,
            rttvar_us: 0,
            min_rtt_us: u64::MAX,
            sample_count: 0,
            pending: VecDeque::new(),
        }
    }

    #[inline]
    fn clear(&mut self) {}
}

impl Serialize for TcpRtt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("TcpRtt", 4)?;
        state.serialize_field("srtt_us", &self.srtt_us)?;
        state.serialize_field("rttvar_us", &self.rttvar_us)?;
        state.serialize_field(
            "min_rtt_us",
            &if self.sample_count > 0 {
                Some(self.min_rtt_us)
            } else {
                None
            },
        )?;
        state.serialize_field("sample_count", &self.sample_count)?;
        state.end()
    }
}

/// -------------------------------------------------------------------------- ///

/// Counts of retransmitted segments per direction.
///
/// A segment is counted as a retransmit when its sequence number falls
/// entirely within data already sent in that direction (i.e., seq_no + len <=
/// highest sequence number previously observed).
#[derive(Debug, serde::Serialize, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct TcpRetransmits {
    /// Retransmits from originator.
    pub orig: u64,
    /// Retransmits from responder.
    pub resp: u64,
    // Highest seq_end (seq + payload) seen in each direction.
    max_seq_orig: u32,
    max_seq_resp: u32,
    orig_initialized: bool,
    resp_initialized: bool,
}

impl TcpRetransmits {
    /// Total retransmits across both directions.
    pub fn total(&self) -> u64 {
        self.orig + self.resp
    }
}

impl TcpRetransmits {
    #[inline]
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("TcpRetransmits,level=InL4Conn")
    )]
    pub fn update(&mut self, pdu: &L4Pdu) {
        if pdu.length() == 0 {
            return;
        }
        let seq_end = pdu.seq_no().wrapping_add(pdu.length() as u32);
        if pdu.dir {
            if self.orig_initialized && wrapping_lt(seq_end, self.max_seq_orig) {
                self.orig += 1;
            } else {
                self.max_seq_orig = seq_end;
                self.orig_initialized = true;
            }
        } else if self.resp_initialized && wrapping_lt(seq_end, self.max_seq_resp) {
            self.resp += 1;
        } else {
            self.max_seq_resp = seq_end;
            self.resp_initialized = true;
        }
    }
}

impl Tracked for TcpRetransmits {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            orig: 0,
            resp: 0,
            max_seq_orig: 0,
            max_seq_resp: 0,
            orig_initialized: false,
            resp_initialized: false,
        }
    }

    #[inline]
    fn clear(&mut self) {}
}

/// --------------------------------------------------------------------------- ///

const SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

/// A single sample of bytes-in-flight and receiver window taken every 100 ms.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InFlightSample {
    /// Milliseconds since the start of the connection.
    pub elapsed_ms: u64,
    /// Estimated bytes currently in flight (unacknowledged).
    pub bytes_in_flight: u32,
    /// Receiver window advertised in this packet (bytes).
    pub rwnd: u16,
}

/// Bytes in flight and TCP receiver window, sampled every 100 ms.
///
/// `bytes_in_flight` is approximated as the difference between the highest
/// sequence number sent by the originator and the highest acknowledgment
/// number sent by the responder.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct TcpInFlight {
    pub samples: Vec<InFlightSample>,
    start_ts: Instant,
    last_sample_ts: Instant,
    max_seq_sent: u32,
    max_ack_recv: u32,
    last_rwnd: u16,
    initialized: bool,
}

impl TcpInFlight {
    #[inline]
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("TcpInFlight,level=InL4Conn")
    )]
    pub fn update(&mut self, pdu: &L4Pdu) {
        if pdu.dir {
            if pdu.length() > 0 {
                let seq_end = pdu.seq_no().wrapping_add(pdu.length() as u32);
                if !self.initialized || !wrapping_lt(seq_end, self.max_seq_sent) {
                    self.max_seq_sent = seq_end;
                    self.initialized = true;
                }
            }
        } else {
            if pdu.flags() & ACK != 0 {
                let ack = pdu.ack_no();
                if !wrapping_lt(ack, self.max_ack_recv) {
                    self.max_ack_recv = ack;
                }
            }
            if let Some(w) = tcp_window(pdu) {
                self.last_rwnd = w;
            }
        }

        if pdu.ts.duration_since(self.last_sample_ts) >= SAMPLE_INTERVAL {
            let bytes_in_flight = self.max_seq_sent.wrapping_sub(self.max_ack_recv);
            self.samples.push(InFlightSample {
                elapsed_ms: pdu.ts.duration_since(self.start_ts).as_millis() as u64,
                bytes_in_flight,
                rwnd: self.last_rwnd,
            });
            self.last_sample_ts = pdu.ts;
        }
    }
}

impl Tracked for TcpInFlight {
    fn new(first_pkt: &L4Pdu) -> Self {
        let now = first_pkt.ts;
        Self {
            samples: Vec::new(),
            start_ts: now,
            last_sample_ts: now,
            max_seq_sent: 0,
            max_ack_recv: 0,
            last_rwnd: 0,
            initialized: false,
        }
    }

    #[inline]
    fn clear(&mut self) {
        self.samples.clear();
    }
}

impl Serialize for TcpInFlight {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("TcpInFlight", 1)?;
        state.serialize_field("samples", &self.samples)?;
        state.end()
    }
}


/// --------------------------------------------------------------------------- ///

/// Counts of loss events (retransmits) and reorder events per direction.
///
/// - **Loss** is detected when a data segment's entire sequence range has
///   already been received (full duplicate).
/// - **Reorder** is detected when a segment arrives with a sequence number
///   earlier than the highest seen so far but still carries new data
///   (partial overlap or fill-in from a gap).
#[derive(Debug, serde::Serialize, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct TcpLossReorder {
    /// Loss events (full retransmits) originator -> responder.
    pub loss_orig: u64,
    /// Loss events responder -> originator.
    pub loss_resp: u64,
    /// Reorder events originator -> responder.
    pub reorder_orig: u64,
    /// Reorder events responder -> originator.
    pub reorder_resp: u64,
    max_seq_orig: u32,
    max_seq_resp: u32,
    orig_initialized: bool,
    resp_initialized: bool,
}

impl TcpLossReorder {
    #[inline]
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("TcpLossReorder,level=InL4Conn")
    )]
    pub fn update(&mut self, pdu: &L4Pdu) {
        if pdu.length() == 0 {
            return;
        }
        let seq_start = pdu.seq_no();
        let seq_end = seq_start.wrapping_add(pdu.length() as u32);
        if pdu.dir {
            if self.orig_initialized {
                if wrapping_lt(seq_end, self.max_seq_orig) || seq_end == self.max_seq_orig {
                    // Entire segment already covered: retransmit/loss.
                    self.loss_orig += 1;
                } else if wrapping_lt(seq_start, self.max_seq_orig) {
                    // Partial overlap: out-of-order fill.
                    self.reorder_orig += 1;
                    self.max_seq_orig = seq_end;
                } else {
                    self.max_seq_orig = seq_end;
                }
            } else {
                self.max_seq_orig = seq_end;
                self.orig_initialized = true;
            }
        } else if self.resp_initialized {
            if wrapping_lt(seq_end, self.max_seq_resp) || seq_end == self.max_seq_resp {
                self.loss_resp += 1;
            } else if wrapping_lt(seq_start, self.max_seq_resp) {
                self.reorder_resp += 1;
                self.max_seq_resp = seq_end;
            } else {
                self.max_seq_resp = seq_end;
            }
        } else {
            self.max_seq_resp = seq_end;
            self.resp_initialized = true;
        }
    }
}

impl Tracked for TcpLossReorder {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            loss_orig: 0,
            loss_resp: 0,
            reorder_orig: 0,
            reorder_resp: 0,
            max_seq_orig: 0,
            max_seq_resp: 0,
            orig_initialized: false,
            resp_initialized: false,
        }
    }

    #[inline]
    fn clear(&mut self) {}
}


/// --------------------------------------------------------------------------- ///

/// A single queuing-delay sample.
#[derive(Debug, Clone, serde::Serialize)]
pub struct QueuingDelaySample {
    /// Milliseconds since connection start.
    pub elapsed_ms: u64,
    /// Queuing delay in microseconds (current RTT − minimum RTT seen so far).
    pub queuing_delay_us: u64,
}

/// Queuing delay (RTT minus minimum RTT) recorded for each RTT sample.
///
/// Queuing delay approximates the extra latency introduced by bufferbloat or
/// congestion queuing on the path.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct TcpQueuingDelay {
    pub samples: Vec<QueuingDelaySample>,
    start_ts: Instant,
    min_rtt_us: u64,
    pending: VecDeque<(u32, Instant)>,
}

impl TcpQueuingDelay {
    #[inline]
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("TcpQueuingDelay,level=InL4Conn")
    )]
    pub fn update(&mut self, pdu: &L4Pdu) {
        if pdu.dir {
            if pdu.length() > 0 {
                let seq_end = pdu.seq_no().wrapping_add(pdu.length() as u32);
                self.pending.push_back((seq_end, pdu.ts));
                if self.pending.len() > 256 {
                    self.pending.pop_front();
                }
            }
        } else {
            let ack = pdu.ack_no();
            while let Some(&(seq_end, send_ts)) = self.pending.front() {
                if !wrapping_lt(seq_end, ack) && seq_end != ack {
                    break;
                }
                self.pending.pop_front();
                let rtt_us = pdu.ts.duration_since(send_ts).as_micros() as u64;
                if rtt_us == 0 {
                    continue;
                }
                if rtt_us < self.min_rtt_us {
                    self.min_rtt_us = rtt_us;
                }
                let queuing_delay_us = rtt_us.saturating_sub(self.min_rtt_us);
                self.samples.push(QueuingDelaySample {
                    elapsed_ms: pdu.ts.duration_since(self.start_ts).as_millis() as u64,
                    queuing_delay_us,
                });
            }
        }
    }
}

impl Tracked for TcpQueuingDelay {
    fn new(first_pkt: &L4Pdu) -> Self {
        Self {
            samples: Vec::new(),
            start_ts: first_pkt.ts,
            min_rtt_us: u64::MAX,
            pending: VecDeque::new(),
        }
    }

    #[inline]
    fn clear(&mut self) {
        self.samples.clear();
    }
}

impl Serialize for TcpQueuingDelay {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("TcpQueuingDelay", 1)?;
        state.serialize_field("samples", &self.samples)?;
        state.end()
    }
}


/// --------------------------------------------------------------------------- ///

/// A single latency-inflation sample.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LatencyInflationSample {
    /// Milliseconds since connection start.
    pub elapsed_ms: u64,
    /// Ratio of current RTT to the minimum (base) RTT, scaled ×1000.
    /// A value of 1000 means no inflation; 2000 means 2× inflation.
    pub inflation_permille: u64,
}

/// Latency inflation: ratio of the current RTT to the minimum (base) RTT.
///
/// Inflation > 1 indicates that the connection is experiencing elevated
/// latency relative to its best observed round-trip time, typically due to
/// queue buildup.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct TcpLatencyInflation {
    pub samples: Vec<LatencyInflationSample>,
    start_ts: Instant,
    min_rtt_us: u64,
    pending: VecDeque<(u32, Instant)>,
}

impl TcpLatencyInflation {
    #[inline]
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("TcpLatencyInflation,level=InL4Conn")
    )]
    pub fn update(&mut self, pdu: &L4Pdu) {
        if pdu.dir {
            if pdu.length() > 0 {
                let seq_end = pdu.seq_no().wrapping_add(pdu.length() as u32);
                self.pending.push_back((seq_end, pdu.ts));
                if self.pending.len() > 256 {
                    self.pending.pop_front();
                }
            }
        } else {
            let ack = pdu.ack_no();
            while let Some(&(seq_end, send_ts)) = self.pending.front() {
                if !wrapping_lt(seq_end, ack) && seq_end != ack {
                    break;
                }
                self.pending.pop_front();
                let rtt_us = pdu.ts.duration_since(send_ts).as_micros() as u64;
                if rtt_us == 0 {
                    continue;
                }
                if rtt_us < self.min_rtt_us {
                    self.min_rtt_us = rtt_us;
                }
                // inflation_permille = (rtt / min_rtt) * 1000
                let inflation_permille = rtt_us * 1000 / self.min_rtt_us;
                self.samples.push(LatencyInflationSample {
                    elapsed_ms: pdu.ts.duration_since(self.start_ts).as_millis() as u64,
                    inflation_permille,
                });
            }
        }
    }
}

impl Tracked for TcpLatencyInflation {
    fn new(first_pkt: &L4Pdu) -> Self {
        Self {
            samples: Vec::new(),
            start_ts: first_pkt.ts,
            min_rtt_us: u64::MAX,
            pending: VecDeque::new(),
        }
    }

    #[inline]
    fn clear(&mut self) {
        self.samples.clear();
    }
}

impl Serialize for TcpLatencyInflation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("TcpLatencyInflation", 1)?;
        state.serialize_field("samples", &self.samples)?;
        state.end()
    }
}


/// --------------------------------------------------------------------------- ///

/// A single throughput sample.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TcpThroughputSample {
    /// Ms since connection start.
    pub elapsed_ms: u64,
    /// Bytes acknowledged (delivered) during the preceding 100 ms interval,
    /// originator → responder direction.
    pub bytes_acked_orig: u64,
    /// Bytes acknowledged responder → originator direction.
    pub bytes_acked_resp: u64,
}

/// Throughput sampled every 100 ms.
///
/// Throughput is estimated from the advancement of the acknowledgment number
/// in each direction: bytes newly acknowledged since the last sample.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct TcpThroughput {
    pub samples: Vec<TcpThroughputSample>,
    start_ts: Instant,
    last_sample_ts: Instant,
    // Highest ack seen per direction during the current interval.
    last_ack_orig: u32,
    last_ack_resp: u32,
    // Bytes acked accumulated within the current 100 ms window.
    interval_bytes_orig: u64,
    interval_bytes_resp: u64,
    orig_ack_initialized: bool,
    resp_ack_initialized: bool,
}

impl TcpThroughput {
    #[inline]
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("TcpThroughput,level=InL4Conn")
    )]
    pub fn update(&mut self, pdu: &L4Pdu) {
        if pdu.flags() & ACK != 0 {
            let ack = pdu.ack_no();
            if pdu.dir {
                // Orig sending an ACK → data flowing resp→orig; ACK covers resp data.
                if self.resp_ack_initialized {
                    if !wrapping_lt(ack, self.last_ack_orig) && ack != self.last_ack_orig {
                        let delta = ack.wrapping_sub(self.last_ack_orig) as u64;
                        self.interval_bytes_resp += delta;
                        self.last_ack_orig = ack;
                    }
                } else {
                    self.last_ack_orig = ack;
                    self.resp_ack_initialized = true;
                }
            } else {
                // Resp sending an ACK → data flowing orig→resp.
                if self.orig_ack_initialized {
                    if !wrapping_lt(ack, self.last_ack_resp) && ack != self.last_ack_resp {
                        let delta = ack.wrapping_sub(self.last_ack_resp) as u64;
                        self.interval_bytes_orig += delta;
                        self.last_ack_resp = ack;
                    }
                } else {
                    self.last_ack_resp = ack;
                    self.orig_ack_initialized = true;
                }
            }
        }

        if pdu.ts.duration_since(self.last_sample_ts) >= SAMPLE_INTERVAL {
            self.samples.push(TcpThroughputSample {
                elapsed_ms: pdu.ts.duration_since(self.start_ts).as_millis() as u64,
                bytes_acked_orig: self.interval_bytes_orig,
                bytes_acked_resp: self.interval_bytes_resp,
            });
            self.interval_bytes_orig = 0;
            self.interval_bytes_resp = 0;
            self.last_sample_ts = pdu.ts;
        }
    }
}

impl Tracked for TcpThroughput {
    fn new(first_pkt: &L4Pdu) -> Self {
        let now = first_pkt.ts;
        Self {
            samples: Vec::new(),
            start_ts: now,
            last_sample_ts: now,
            last_ack_orig: 0,
            last_ack_resp: 0,
            interval_bytes_orig: 0,
            interval_bytes_resp: 0,
            orig_ack_initialized: false,
            resp_ack_initialized: false,
        }
    }

    #[inline]
    fn clear(&mut self) {
        self.samples.clear();
    }
}

impl Serialize for TcpThroughput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("TcpThroughput", 1)?;
        state.serialize_field("samples", &self.samples)?;
        state.end()
    }
}
