//! A streaming filter that heuristically accepts connections that look like
//! iperf3 traffic on [`IPERF3_PORT`] (5201, iperf3's default for both its
//! TCP control/data channel and, with `-u`, its UDP data channel).
//!
//! This filter has two independent paths, of very different strength:
//!
//! - **UDP path** (real structural fingerprint): every iperf3 UDP test
//!   datagram's payload starts with a fixed 12-byte, big-endian header --
//!   `sec` (4B), `usec` (4B, always `< 1_000_000` since it's a valid
//!   sub-second value), and a send-sequence counter (4B) that increases with
//!   each datagram sent -- per `esnet/iperf`'s `src/iperf_udp.c`. Both the
//!   per-packet `usec` check and the cross-packet increasing-sequence check
//!   must hold before a connection is accepted.
//! - **TCP path** (best-effort only): iperf3's default TCP mode sends
//!   random payload bytes (the `--repeating-payload` flag, which switches to
//!   iperf2-style repeating ASCII `'0'..'9'`, is opt-in and not detected
//!   here), so there is no byte-level signature to check. Instead this path
//!   looks at flow shape: whether most of a connection's early
//!   payload-bearing packets are near-full-size TCP segments, the pattern a
//!   sustained bulk send produces. This is a much weaker signal than the UDP
//!   path -- it will also accept other sustained bulk TCP transfers that
//!   happen to use port 5201 -- so it should be treated as a hint, not a
//!   fingerprint.

#[allow(unused_imports)]
use iris_compiler::{filter, filter_fn};
use iris_core::protocols::packet::tcp::TCP_PROTOCOL;
use iris_core::protocols::packet::udp::UDP_PROTOCOL;
use iris_core::subscription::{FilterResult, StreamingFilter};
use iris_core::L4Pdu;

/// Port iperf3 traffic is expected on: its TCP control/data channel, and
/// (with `-u`) the UDP data channel -- both default to the same port.
pub const IPERF3_PORT: u16 = 5201;

/// Number of payload-bearing UDP packets inspected before making a decision.
pub const MAYBE_IPERF3_UDP_WINDOW: usize = 10;
/// Fraction of the first [`MAYBE_IPERF3_UDP_WINDOW`] payload-bearing UDP
/// packets that must carry a plausible iperf3 header for the connection to
/// be accepted. The per-packet `usec` check alone is a much stronger
/// discriminator than `MaybeQuic`'s 2-bit check or `MaybeZoom`'s 4-value
/// byte allowlist (roughly 1 in 4096 on random bytes vs. roughly 1 in 4 or
/// 1 in 64), so a smaller window and looser fraction are still a materially
/// lower compound false-positive rate.
pub const MAYBE_IPERF3_UDP_MIN_FRACTION: f64 = 0.8;
/// Minimum payload-bearing UDP packets needed to judge a connection that
/// ended before [`MAYBE_IPERF3_UDP_WINDOW`] was reached. Lower than
/// `MaybeQuic`'s floor -- iperf3 UDP tests can be as short as `-t 1` -- since
/// the per-packet signal is strong enough to trust fewer samples.
pub const MAYBE_IPERF3_UDP_MIN_PKTS: usize = 5;

/// Number of payload-bearing TCP packets inspected before making a decision.
pub const MAYBE_IPERF3_TCP_WINDOW: usize = 20;
/// Fraction of the first [`MAYBE_IPERF3_TCP_WINDOW`] payload-bearing TCP
/// packets that must be near-full-size segments for the connection to be
/// accepted. Set high because segment-size regularity alone is common to any
/// sustained bulk transfer, not just iperf3.
pub const MAYBE_IPERF3_TCP_MIN_FRACTION: f64 = 0.9;
/// Minimum payload-bearing TCP packets needed to judge a connection that
/// ended before [`MAYBE_IPERF3_TCP_WINDOW`] was reached.
pub const MAYBE_IPERF3_TCP_MIN_PKTS: usize = 10;
/// Minimum payload length (bytes) for a TCP segment to count as "near-full
/// size". `pdu.length()` is the L4 payload length with IP/TCP headers
/// already stripped, so a segment filling a standard 1500-byte-MTU path
/// lands around 1448-1460 bytes; this leaves headroom for TCP options.
pub const TCP_LARGE_SEGMENT_MIN: usize = 1400;

/// Checks that bytes `4..8` of `payload` look like a valid iperf3 UDP header
/// `usec` field: a sub-second microsecond value, i.e. `< 1_000_000`.
#[inline]
fn has_plausible_usec_field(payload: &[u8]) -> bool {
    payload.len() >= 12 && u32::from_be_bytes(payload[4..8].try_into().unwrap()) < 1_000_000
}

/// Reads the send-sequence counter from bytes `8..12` of `payload`. Only
/// call this on a payload that has already passed
/// [`has_plausible_usec_field`].
#[inline]
fn seq_field(payload: &[u8]) -> u32 {
    u32::from_be_bytes(payload[8..12].try_into().unwrap())
}

/// Number of matching packets required within a full window of
/// [`MAYBE_IPERF3_UDP_WINDOW`] packets to meet
/// [`MAYBE_IPERF3_UDP_MIN_FRACTION`].
#[inline]
fn required_udp_matches() -> usize {
    (MAYBE_IPERF3_UDP_WINDOW as f64 * MAYBE_IPERF3_UDP_MIN_FRACTION).ceil() as usize
}

/// Number of matching packets required within a full window of
/// [`MAYBE_IPERF3_TCP_WINDOW`] packets to meet
/// [`MAYBE_IPERF3_TCP_MIN_FRACTION`].
#[inline]
fn required_tcp_matches() -> usize {
    (MAYBE_IPERF3_TCP_WINDOW as f64 * MAYBE_IPERF3_TCP_MIN_FRACTION).ceil() as usize
}

/// Accepts a connection on [`IPERF3_PORT`] once it looks like iperf3
/// traffic: for UDP, most of its first [`MAYBE_IPERF3_UDP_WINDOW`]
/// payload-bearing packets carry a plausible iperf3 header whose
/// send-sequence field increases across matches; for TCP, most of its first
/// [`MAYBE_IPERF3_TCP_WINDOW`] payload-bearing packets are near-full-size
/// segments (a much weaker, best-effort signal -- see the module docs).
/// Connections on any other port are dropped immediately.
#[cfg_attr(not(feature = "skip_expand"), filter)]
#[derive(Debug)]
pub struct MaybeIperf3 {
    /// The connection's L4 protocol, set once from the first packet and
    /// never touched by `clear()` -- it identifies which of the two paths
    /// below applies to this connection, not per-decision evaluation state.
    l4_proto: usize,
    /// Payload-bearing packets inspected so far.
    seen: usize,
    /// Of those, how many matched the relevant path's per-packet check.
    matched: usize,
    /// UDP path only: the most recent matched packet's send-sequence value.
    last_seq: Option<u32>,
    /// UDP path only: true once a matched packet's send-sequence exceeded
    /// the previous matched packet's.
    increasing_seen: bool,
}

impl StreamingFilter for MaybeIperf3 {
    fn new(first_packet: &L4Pdu) -> Self {
        Self {
            l4_proto: first_packet.ctxt.proto,
            seen: 0,
            matched: 0,
            last_seq: None,
            increasing_seen: false,
        }
    }

    fn clear(&mut self) {
        self.seen = 0;
        self.matched = 0;
        self.last_seq = None;
        self.increasing_seen = false;
    }
}

impl MaybeIperf3 {
    /// Updates UDP-path counts from one payload.
    fn record_udp(&mut self, data: &[u8]) {
        self.seen += 1;
        if !has_plausible_usec_field(data) {
            return;
        }
        self.matched += 1;
        let seq = seq_field(data);
        if let Some(prev) = self.last_seq {
            if seq > prev {
                self.increasing_seen = true;
            }
        }
        self.last_seq = Some(seq);
    }

    /// Resolves the current UDP-path counts to a `FilterResult`.
    fn decide_udp(&self) -> FilterResult {
        let required = required_udp_matches();
        if self.matched >= required && self.increasing_seen {
            return FilterResult::Accept;
        }
        if self.seen >= MAYBE_IPERF3_UDP_WINDOW {
            // Window exhausted
            return FilterResult::Drop;
        }
        // Impossible to reach required number of matches
        let remaining = MAYBE_IPERF3_UDP_WINDOW - self.seen;
        if self.matched + remaining < required {
            return FilterResult::Drop;
        }
        // Not enough evidence yet
        FilterResult::Continue
    }

    /// Reached only if the connection terminated before the UDP window
    /// filled. The fraction is applied to the packets actually observed,
    /// but only once there are enough of them to be meaningful.
    fn terminated_udp(&self) -> FilterResult {
        if self.seen >= MAYBE_IPERF3_UDP_MIN_PKTS
            && self.increasing_seen
            && self.matched as f64 >= self.seen as f64 * MAYBE_IPERF3_UDP_MIN_FRACTION
        {
            FilterResult::Accept
        } else {
            FilterResult::Drop
        }
    }

    /// Updates TCP-path counts from one payload's length.
    fn record_tcp(&mut self, len: usize) {
        self.seen += 1;
        if len >= TCP_LARGE_SEGMENT_MIN {
            self.matched += 1;
        }
    }

    /// Resolves the current TCP-path counts to a `FilterResult`.
    fn decide_tcp(&self) -> FilterResult {
        let required = required_tcp_matches();
        if self.matched >= required {
            return FilterResult::Accept;
        }
        if self.seen >= MAYBE_IPERF3_TCP_WINDOW {
            // Window exhausted
            return FilterResult::Drop;
        }
        // Impossible to reach required number of matches
        let remaining = MAYBE_IPERF3_TCP_WINDOW - self.seen;
        if self.matched + remaining < required {
            return FilterResult::Drop;
        }
        // Not enough evidence yet
        FilterResult::Continue
    }

    /// Reached only if the connection terminated before the TCP window
    /// filled. The fraction is applied to the packets actually observed,
    /// but only once there are enough of them to be meaningful.
    fn terminated_tcp(&self) -> FilterResult {
        if self.seen >= MAYBE_IPERF3_TCP_MIN_PKTS
            && self.matched as f64 >= self.seen as f64 * MAYBE_IPERF3_TCP_MIN_FRACTION
        {
            FilterResult::Accept
        } else {
            FilterResult::Drop
        }
    }

    #[cfg_attr(not(feature = "skip_expand"), filter_fn("MaybeIperf3,level=InL4Conn"))]
    pub fn update(&mut self, pdu: &L4Pdu) -> FilterResult {
        match pdu.ctxt.proto {
            UDP_PROTOCOL => {
                // Drop traffic not on IPERF3_PORT
                if pdu.ctxt.src.port() != IPERF3_PORT && pdu.ctxt.dst.port() != IPERF3_PORT {
                    return FilterResult::Drop;
                }
                // Skip packets with no payload
                if pdu.length() == 0 {
                    return FilterResult::Continue;
                }
                if let Ok(data) = pdu.mbuf_ref().get_data_slice(pdu.offset(), pdu.length()) {
                    self.record_udp(data);
                }
                self.decide_udp()
            }
            TCP_PROTOCOL => {
                // Drop traffic not on IPERF3_PORT
                if pdu.ctxt.src.port() != IPERF3_PORT && pdu.ctxt.dst.port() != IPERF3_PORT {
                    return FilterResult::Drop;
                }
                // Skip packets with no payload -- this also keeps pure ACKs
                // (which carry no TCP payload) from diluting the TCP path's
                // segment-size evidence.
                if pdu.length() == 0 {
                    return FilterResult::Continue;
                }
                self.record_tcp(pdu.length());
                self.decide_tcp()
            }
            _ => FilterResult::Drop,
        }
    }

    #[cfg_attr(
        not(feature = "skip_expand"),
        filter_fn("MaybeIperf3,level=L4Terminated")
    )]
    pub fn terminated(&self) -> FilterResult {
        match self.l4_proto {
            UDP_PROTOCOL => self.terminated_udp(),
            TCP_PROTOCOL => self.terminated_tcp(),
            _ => FilterResult::Drop,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a 12-byte iperf3-UDP-style payload: 4 zero bytes (`sec`,
    /// irrelevant to these checks), then `usec` and `seq` big-endian.
    fn udp_payload(usec: u32, seq: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 4];
        buf.extend_from_slice(&usec.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf
    }

    #[test]
    fn plausible_usec_field_check() {
        assert!(has_plausible_usec_field(&udp_payload(0, 0)));
        assert!(has_plausible_usec_field(&udp_payload(999_999, 0)));
        assert!(!has_plausible_usec_field(&udp_payload(1_000_000, 0)));
        assert!(!has_plausible_usec_field(&udp_payload(u32::MAX, 0)));
        assert!(!has_plausible_usec_field(&[0u8; 11])); // too short
        assert!(!has_plausible_usec_field(&[]));
    }

    #[test]
    fn seq_field_extracts_the_counter() {
        assert_eq!(seq_field(&udp_payload(0, 256)), 256);
        assert_eq!(seq_field(&udp_payload(0, 0)), 0);
    }

    #[test]
    fn required_udp_matches_matches_configured_threshold() {
        // 10 * 0.8 = 8.0, so 8 of 10.
        assert_eq!(required_udp_matches(), 8);
    }

    #[test]
    fn required_tcp_matches_matches_configured_threshold() {
        // 20 * 0.9 = 18.0, so 18 of 20.
        assert_eq!(required_tcp_matches(), 18);
    }

    #[test]
    fn terminated_udp_drops_flows_below_the_evidence_floor() {
        let mut f = MaybeIperf3::new_for_test(UDP_PROTOCOL);
        for i in 0..(MAYBE_IPERF3_UDP_MIN_PKTS - 1) {
            f.record_udp(&udp_payload(0, i as u32));
        }
        assert!(matches!(f.terminated_udp(), FilterResult::Drop));

        let mut f = MaybeIperf3::new_for_test(UDP_PROTOCOL);
        for i in 0..MAYBE_IPERF3_UDP_MIN_PKTS {
            f.record_udp(&udp_payload(0, i as u32));
        }
        assert!(matches!(f.terminated_udp(), FilterResult::Accept));
    }

    #[test]
    fn terminated_udp_applies_fraction_to_observed_packets() {
        let mut f = MaybeIperf3::new_for_test(UDP_PROTOCOL);
        for i in 0..8 {
            f.record_udp(&udp_payload(0, i as u32));
        }
        for _ in 0..2 {
            f.record_udp(&udp_payload(1_000_000, 0)); // not a plausible header
        }
        // 10 seen, 8 matched, increasing -- 80% >= 80%
        assert_eq!(f.seen, 10);
        assert!(matches!(f.terminated_udp(), FilterResult::Accept));

        let mut f = MaybeIperf3::new_for_test(UDP_PROTOCOL);
        for i in 0..7 {
            f.record_udp(&udp_payload(0, i as u32));
        }
        for _ in 0..3 {
            f.record_udp(&udp_payload(1_000_000, 0));
        }
        // 10 seen, 7 matched -- 70% < 80%
        assert!(matches!(f.terminated_udp(), FilterResult::Drop));
    }

    #[test]
    fn terminated_udp_rejects_a_constant_sequence_counter() {
        // Every packet matches (100%), but the sequence counter never
        // increases -- e.g. constant zero padding coincidentally passing
        // the usec check.
        let mut f = MaybeIperf3::new_for_test(UDP_PROTOCOL);
        for _ in 0..MAYBE_IPERF3_UDP_WINDOW {
            f.record_udp(&udp_payload(0, 42));
        }
        assert!(matches!(f.terminated_udp(), FilterResult::Drop));
    }

    #[test]
    fn decide_udp_drops_once_window_exhausted_on_constant_seq() {
        let mut f = MaybeIperf3::new_for_test(UDP_PROTOCOL);
        let mut result = FilterResult::Continue;
        for _ in 0..MAYBE_IPERF3_UDP_WINDOW {
            f.record_udp(&udp_payload(0, 7));
            result = f.decide_udp();
        }
        assert!(matches!(result, FilterResult::Drop));
    }

    #[test]
    fn decide_udp_accepts_once_seq_starts_increasing() {
        let mut f = MaybeIperf3::new_for_test(UDP_PROTOCOL);
        for _ in 0..(required_udp_matches() - 1) {
            f.record_udp(&udp_payload(0, 5));
        }
        assert!(matches!(f.decide_udp(), FilterResult::Continue));
        f.record_udp(&udp_payload(0, 6));
        assert!(matches!(f.decide_udp(), FilterResult::Accept));
    }

    #[test]
    fn tcp_large_segment_threshold() {
        let mut f = MaybeIperf3::new_for_test(TCP_PROTOCOL);
        f.record_tcp(TCP_LARGE_SEGMENT_MIN);
        assert_eq!(f.matched, 1);

        let mut f = MaybeIperf3::new_for_test(TCP_PROTOCOL);
        f.record_tcp(TCP_LARGE_SEGMENT_MIN - 1);
        assert_eq!(f.matched, 0);
    }

    #[test]
    fn decide_tcp_drops_once_window_exhausted_below_threshold() {
        let mut f = MaybeIperf3::new_for_test(TCP_PROTOCOL);
        let mut result = FilterResult::Continue;
        for i in 0..MAYBE_IPERF3_TCP_WINDOW {
            if i < 5 {
                f.record_tcp(TCP_LARGE_SEGMENT_MIN);
            } else {
                f.record_tcp(0);
            }
            result = f.decide_tcp();
        }
        assert!(matches!(result, FilterResult::Drop));
    }

    #[test]
    fn decide_tcp_accepts_once_threshold_reached() {
        let mut f = MaybeIperf3::new_for_test(TCP_PROTOCOL);
        for _ in 0..(required_tcp_matches() - 1) {
            f.record_tcp(TCP_LARGE_SEGMENT_MIN);
        }
        assert!(matches!(f.decide_tcp(), FilterResult::Continue));
        f.record_tcp(TCP_LARGE_SEGMENT_MIN);
        assert!(matches!(f.decide_tcp(), FilterResult::Accept));
    }

    #[test]
    fn terminated_tcp_drops_flows_below_the_evidence_floor() {
        let mut f = MaybeIperf3::new_for_test(TCP_PROTOCOL);
        for _ in 0..(MAYBE_IPERF3_TCP_MIN_PKTS - 1) {
            f.record_tcp(TCP_LARGE_SEGMENT_MIN);
        }
        assert!(matches!(f.terminated_tcp(), FilterResult::Drop));

        let mut f = MaybeIperf3::new_for_test(TCP_PROTOCOL);
        for _ in 0..MAYBE_IPERF3_TCP_MIN_PKTS {
            f.record_tcp(TCP_LARGE_SEGMENT_MIN);
        }
        assert!(matches!(f.terminated_tcp(), FilterResult::Accept));
    }

    #[test]
    fn terminated_dispatches_on_l4_proto() {
        // A UDP-mode connection whose evidence would fail the TCP path's
        // (looser-on-count, higher-fraction) checks and vice versa --
        // confirms `terminated()` uses the *right* path, not just any path.
        let mut udp_conn = MaybeIperf3::new_for_test(UDP_PROTOCOL);
        for i in 0..MAYBE_IPERF3_UDP_MIN_PKTS {
            udp_conn.record_udp(&udp_payload(0, i as u32));
        }
        assert!(matches!(udp_conn.terminated(), FilterResult::Accept));

        let mut tcp_conn = MaybeIperf3::new_for_test(TCP_PROTOCOL);
        for _ in 0..MAYBE_IPERF3_TCP_MIN_PKTS {
            tcp_conn.record_tcp(TCP_LARGE_SEGMENT_MIN);
        }
        assert!(matches!(tcp_conn.terminated(), FilterResult::Accept));
    }

    impl MaybeIperf3 {
        fn new_for_test(l4_proto: usize) -> Self {
            Self {
                l4_proto,
                seen: 0,
                matched: 0,
                last_seq: None,
                increasing_seen: false,
            }
        }
    }
}
