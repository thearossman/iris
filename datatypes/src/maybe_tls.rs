//! A streaming filter that heuristically accepts TCP connections carrying TLS
//! whose handshake was never observed.
//!
//! The `tls` parser identifies a connection from its ClientHello. On a live tap
//! that is a severe restriction: a connection already established when the
//! capture started has no handshake to find, so it is never labelled TLS -- and
//! long-lived flows are exactly the ones carrying most of a link's bytes. (Iris
//! also refuses to open a TCP connection at all without a SYN, which
//! `stats::PacketLedger::dropped_no_syn` measures; this filter only helps once
//! that population is trackable.) `MaybeTls` recovers those connections from the
//! record layer alone.
//!
//! ## Why record chaining, and not a per-packet shape test
//! The sibling heuristics ([`super::MaybeQuic`], [`super::MaybeZoom`]) score each
//! datagram's first byte, because UDP datagram boundaries are message
//! boundaries. TLS has no such luck: it is a byte stream, records are up to
//! 16KB, and a bulk sender's records are packed back-to-back into the stream
//! with no regard for segment boundaries. Only about one TCP segment in eleven
//! of a 16KB-record download even begins at a record boundary, and which one is
//! unpredictable, so "does this packet start with a TLS record header" is a test
//! that mostly fails on genuine TLS.
//!
//! What is distinctive about TLS is not any single header but that record
//! headers *chain*: a header at stream offset `p` declaring length `L` places
//! the next header at exactly `p + 5 + L`. So the filter finds one plausible
//! header, then predicts where the following one must be and checks. A single
//! header is weak evidence -- roughly 1 in 4 million byte positions matches by
//! chance (see [`record_length`]) -- but a header found *at a predicted offset*
//! is independent evidence of the same strength, so
//! [`MAYBE_TLS_MIN_CHAINED`] confirmations in a row put the false-positive rate
//! far below anything else in the pipeline. That is why this filter has no
//! "fraction of packets matched" threshold: chained confirmations are not a
//! majority vote, they are a lock.
//!
//! ## What breaks a chain
//! Chains are tracked per direction over payload bytes in *arrival* order, not
//! reassembled order, because this filter runs at `InL4Conn`. A retransmission,
//! a reordering, or a gap therefore desynchronizes the byte count and the next
//! prediction fails. That is treated as ordinary: the chain resets and the
//! filter re-anchors on a later segment. A header that straddles a segment
//! boundary (about 4 bytes in 1460, so ~0.3% of records) can't be validated in
//! place and also resets the chain. None of this costs correctness, only the
//! packets spent re-locking, and the connections this filter exists for have
//! thousands to spare.
//!
//! ## Cost
//! Once a chain is locked the work is O(1) per segment: one predicted offset,
//! one 5-byte check. Only an unlocked direction scans, and only the first
//! [`MAYBE_TLS_SCAN_LIMIT`] byte positions of the segment, which is enough to
//! find a boundary within a handful of segments while keeping the per-packet
//! cost bounded on a saturated link.

#[allow(unused_imports)]
use iris_compiler::{filter, filter_fn};
use iris_core::protocols::packet::tcp::TCP_PROTOCOL;
use iris_core::protocols::stream::SessionProto;
use iris_core::subscription::{FilterResult, StreamingFilter};
use iris_core::L4Pdu;

/// Payload-bearing packets inspected before giving up on a connection.
///
/// Much larger than [`super::MAYBE_QUIC_WINDOW`] on purpose: a bulk TLS sender
/// emits one record per ~11 segments, so confirming
/// [`MAYBE_TLS_MIN_CHAINED`] chained records takes tens of packets even when
/// everything goes right, and re-anchoring after a retransmission costs more.
pub const MAYBE_TLS_WINDOW: usize = 96;

/// Record headers that must be found *at a predicted offset* before the
/// connection is accepted. The anchor header that starts a chain is not counted,
/// so this many independent confirmations are required on top of it.
///
/// Three puts the chance of accepting arbitrary binary traffic on the order of
/// `1e-20` -- see [`record_length`] for the per-header figure. Two would already
/// be far below the noise floor; three costs little and leaves room for the
/// content-type and version sets to be loosened later without revisiting this.
pub const MAYBE_TLS_MIN_CHAINED: u32 = 3;

/// Byte positions from the start of a segment searched for a chain anchor while
/// a direction is unlocked. Bounds the per-packet cost of the scan; a record
/// boundary lands in this prefix often enough to lock on within a few segments.
pub const MAYBE_TLS_SCAN_LIMIT: usize = 256;

/// TCP ports TLS is expected on. A connection on any other port is dropped
/// without inspection, as in [`super::MaybeQuic`]: the chain test is strong
/// enough to stand alone, but there is no reason to spend the scan on traffic
/// that is not plausibly TLS in the first place.
///
/// 443 (HTTPS), 465 (SMTPS), 853 (DNS-over-TLS), 993 (IMAPS), 995 (POP3S),
/// 8443 (alt HTTPS).
pub const TLS_PORTS: [u16; 6] = [443, 465, 853, 993, 995, 8443];

/// TLS record layer header length: content type, two-byte legacy version,
/// two-byte length (RFC 8446 Section 5.1).
const RECORD_HEADER_LEN: usize = 5;

/// Largest a record's payload may be. RFC 8446 caps ciphertext at `2^14 + 256`.
const MAX_RECORD_LEN: u16 = 16_640;

/// `application_data`. Mid-stream this is essentially every record: TLS 1.3
/// carries handshake and alert messages inside it too.
const CONTENT_APPLICATION_DATA: u8 = 0x17;
/// `change_cipher_spec`, `alert`, `handshake`, `application_data`. Kept as a set
/// rather than just `application_data` so a mid-stream rekey or close_notify
/// doesn't break a chain -- they are as valid a link in it as any other record.
const CONTENT_TYPES: [u8; 4] = [0x14, 0x15, 0x16, CONTENT_APPLICATION_DATA];

/// Validates a TLS record header at the start of `bytes` and returns the total
/// record size (header plus declared payload), or `None`.
///
/// Three independent constraints, which together make a chance match at an
/// arbitrary byte position rare -- roughly `(4/256) * (3/65536) * (16640/65536)`,
/// about 1 in 4 million:
///
/// - content type in [`CONTENT_TYPES`],
/// - `legacy_record_version` in `0x0301..=0x0303`. TLS 1.3 pins this to `0x0303`
///   on application data (RFC 8446 Section 5.1) and never sends `0x0304` in the
///   record layer, so the range covers TLS 1.0 through 1.3 as they appear on the
///   wire,
/// - a nonzero declared length no greater than [`MAX_RECORD_LEN`]. Zero-length
///   application data is forbidden, and a zero here would make a chain stand
///   still rather than advance.
#[inline]
fn record_length(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < RECORD_HEADER_LEN {
        return None;
    }
    if !CONTENT_TYPES.contains(&bytes[0]) {
        return None;
    }
    let version = u16::from_be_bytes([bytes[1], bytes[2]]);
    if !(0x0301..=0x0303).contains(&version) {
        return None;
    }
    let length = u16::from_be_bytes([bytes[3], bytes[4]]);
    if length == 0 || length > MAX_RECORD_LEN {
        return None;
    }
    Some(RECORD_HEADER_LEN as u64 + length as u64)
}

/// One direction's record-chain state, over payload bytes in arrival order.
#[derive(Debug, Default, Clone, Copy)]
struct Direction {
    /// Payload bytes seen in this direction so far. The chain's coordinate
    /// system; retransmissions inflate it, which is what breaks a chain.
    pos: u64,
    /// Offset (in `pos` terms) where the next record header is predicted, once
    /// a chain is anchored.
    next: Option<u64>,
    /// Confirmations in the current chain -- headers found where predicted.
    chained: u32,
    /// Longest chain this direction has reached, kept across resets so a chain
    /// broken by a retransmission still counts toward the verdict.
    best: u32,
}

impl Direction {
    /// Consumes one segment's payload, advancing the chain and re-anchoring as
    /// many times as the segment allows.
    ///
    /// Alternates between the two halves rather than doing one pass of each: a
    /// freshly anchored chain must be followed within the *same* segment (small
    /// records mean several links per segment), and a chain that breaks
    /// mid-segment should re-anchor from just past the candidate that failed
    /// rather than waiting for the next packet. Both loops make strict forward
    /// progress -- a record is at least `RECORD_HEADER_LEN + 1` bytes, and each
    /// re-anchor starts past the previous candidate -- so this terminates.
    fn consume(&mut self, data: &[u8]) {
        let seg_start = self.pos;
        let seg_end = seg_start + data.len() as u64;
        self.pos = seg_end;
        let mut scan_from = 0usize;

        loop {
            while let Some(expected) = self.next {
                if expected >= seg_end {
                    // Prediction lands in a later segment; nothing to check yet.
                    return;
                }
                if expected < seg_start || expected + RECORD_HEADER_LEN as u64 > seg_end {
                    // The header straddles this segment's tail and cannot be
                    // read in place (or, defensively, the byte count ran
                    // backwards). Either way, re-anchor; see the module docs.
                    break;
                }
                let offset = (expected - seg_start) as usize;
                match record_length(&data[offset..]) {
                    Some(size) => {
                        self.chained += 1;
                        self.best = self.best.max(self.chained);
                        self.next = Some(expected + size);
                    }
                    // A retransmission, reordering, or gap desynchronized the
                    // byte count, or this was never TLS.
                    None => break,
                }
            }

            self.next = None;
            self.chained = 0;
            match self.anchor(data, seg_start, scan_from) {
                Some(candidate) => scan_from = candidate + 1,
                None => return,
            }
        }
    }

    /// Looks for a plausible record header at or after `scan_from` and, if one
    /// is found, predicts where the following header must be. Returns the offset
    /// the anchor was found at, so a chain that fails can resume the search past
    /// it. The anchor itself is not counted as evidence -- only the
    /// confirmations that follow it.
    fn anchor(&mut self, data: &[u8], seg_start: u64, scan_from: usize) -> Option<usize> {
        let last = data.len().checked_sub(RECORD_HEADER_LEN)?;
        for offset in scan_from..=last.min(MAYBE_TLS_SCAN_LIMIT) {
            if let Some(size) = record_length(&data[offset..]) {
                self.next = Some(seg_start + offset as u64 + size);
                return Some(offset);
            }
        }
        None
    }
}

/// Accepts a TCP connection on a [`TLS_PORTS`] port once one direction has
/// confirmed [`MAYBE_TLS_MIN_CHAINED`] TLS record headers at predicted stream
/// offsets. Non-TCP or non-TLS-port connections are dropped immediately.
///
/// Only one direction has to lock on. Requiring both would discard the bulk
/// downloads this filter is for, where the client direction is pure ACKs and
/// carries almost no records.
#[cfg_attr(not(feature = "skip_expand"), filter)]
#[derive(Debug)]
pub struct MaybeTls {
    /// Payload-bearing packets inspected so far, both directions.
    seen: usize,
    /// Originator -> responder.
    orig: Direction,
    /// Responder -> originator.
    resp: Direction,
}

impl StreamingFilter for MaybeTls {
    fn new(_first_packet: &L4Pdu) -> Self {
        Self {
            seen: 0,
            orig: Direction::default(),
            resp: Direction::default(),
        }
    }

    fn clear(&mut self) {
        self.seen = 0;
        self.orig = Direction::default();
        self.resp = Direction::default();
    }
}

impl MaybeTls {
    /// Longest chain confirmed in either direction.
    #[inline]
    fn best_chain(&self) -> u32 {
        self.orig.best.max(self.resp.best)
    }

    /// Whether the evidence is sufficient. Deliberately the same test in
    /// `update` and `terminated`: a chain is a lock, not a rate, so there is
    /// nothing to prorate against a connection that ended early.
    #[inline]
    fn locked(&self) -> bool {
        self.best_chain() >= MAYBE_TLS_MIN_CHAINED
    }

    /// Feeds one direction's payload into its chain.
    fn record(&mut self, dir: bool, data: &[u8]) {
        self.seen += 1;
        if dir {
            self.orig.consume(data);
        } else {
            self.resp.consume(data);
        }
    }

    fn decide(&self) -> FilterResult {
        if self.locked() {
            FilterResult::Accept
        } else if self.seen >= MAYBE_TLS_WINDOW {
            FilterResult::Drop
        } else {
            FilterResult::Continue
        }
    }

    #[cfg_attr(not(feature = "skip_expand"), filter_fn("MaybeTls,level=InL4Conn"))]
    pub fn update(&mut self, pdu: &L4Pdu) -> FilterResult {
        if pdu.ctxt.proto != TCP_PROTOCOL
            || !(TLS_PORTS.contains(&pdu.ctxt.src.port())
                || TLS_PORTS.contains(&pdu.ctxt.dst.port()))
        {
            return FilterResult::Drop;
        }
        if pdu.length() == 0 {
            return FilterResult::Continue;
        }
        if let Ok(data) = pdu.mbuf_ref().get_data_slice(pdu.offset(), pdu.length()) {
            self.record(pdu.dir, data);
        }
        self.decide()
    }

    /// Vetoes the connection once a parser has identified it, so `MaybeTls`
    /// reports only what the parsers missed -- the same arrangement as
    /// [`super::MaybeQuic::unclaimed`].
    ///
    /// This matters more here than it does for QUIC. A connection whose
    /// ClientHello *was* captured reaches `L7OnDisc` within a packet or two,
    /// long before a chain can confirm, so handshake-visible TLS is vetoed and
    /// stays the `tls` parser's. What survives is precisely the mid-stream
    /// population: no ClientHello, so the `tls` probe never concludes,
    /// `L7OnDisc` is never dispatched, and the heuristic runs to its own
    /// verdict.
    #[cfg_attr(not(feature = "skip_expand"), filter_fn("MaybeTls,level=L7OnDisc"))]
    pub fn unclaimed(&self, proto: &SessionProto) -> FilterResult {
        match proto {
            SessionProto::Tls
            | SessionProto::Dns
            | SessionProto::Http
            | SessionProto::Quic
            | SessionProto::Ssh
            | SessionProto::Wireguard
            | SessionProto::Ike
            | SessionProto::Capwap => FilterResult::Drop,
            SessionProto::Null | SessionProto::Probing => FilterResult::Continue,
            // Transport-layer variants exist for the filter AST and are never
            // produced by `ConnParser::protocol`; listed rather than wildcarded
            // so adding an L7 parser is a compile error here instead of a
            // silent hole in the veto.
            SessionProto::Ipv4 | SessionProto::Ipv6 | SessionProto::Tcp | SessionProto::Udp => {
                FilterResult::Continue
            }
        }
    }

    /// Reached only if the connection ended before the window filled.
    #[cfg_attr(not(feature = "skip_expand"), filter_fn("MaybeTls,level=L4Terminated"))]
    pub fn terminated(&self) -> FilterResult {
        if self.locked() {
            FilterResult::Accept
        } else {
            FilterResult::Drop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl MaybeTls {
        fn new_for_test() -> Self {
            Self {
                seen: 0,
                orig: Direction::default(),
                resp: Direction::default(),
            }
        }
    }

    /// One application-data record: header plus `len` bytes of ciphertext.
    fn record(len: u16) -> Vec<u8> {
        let mut out = vec![CONTENT_APPLICATION_DATA, 0x03, 0x03];
        out.extend_from_slice(&len.to_be_bytes());
        out.extend(std::iter::repeat_n(0xab, len as usize));
        out
    }

    /// Splits a byte stream into `mss`-sized segments, as TCP would.
    fn segments(stream: &[u8], mss: usize) -> Vec<Vec<u8>> {
        stream.chunks(mss).map(|c| c.to_vec()).collect()
    }

    #[test]
    fn header_validation_rejects_each_malformed_field() {
        assert_eq!(record_length(&[0x17, 0x03, 0x03, 0x00, 0x20]), Some(37));
        // Unknown content type.
        assert_eq!(record_length(&[0x99, 0x03, 0x03, 0x00, 0x20]), None);
        // Version outside 0x0301..=0x0303.
        assert_eq!(record_length(&[0x17, 0x03, 0x04, 0x00, 0x20]), None);
        assert_eq!(record_length(&[0x17, 0x02, 0x03, 0x00, 0x20]), None);
        // Zero length would leave a chain standing still.
        assert_eq!(record_length(&[0x17, 0x03, 0x03, 0x00, 0x00]), None);
        // Over the RFC 8446 ciphertext cap.
        assert_eq!(record_length(&[0x17, 0x03, 0x03, 0xff, 0xff]), None);
        // Truncated.
        assert_eq!(record_length(&[0x17, 0x03, 0x03, 0x00]), None);
    }

    #[test]
    fn every_content_type_links_a_chain() {
        for ty in CONTENT_TYPES {
            assert!(
                record_length(&[ty, 0x03, 0x03, 0x00, 0x10]).is_some(),
                "content type {ty:#04x} should be accepted"
            );
        }
    }

    #[test]
    fn bulk_download_locks_on_despite_unaligned_records() {
        // The case the filter exists for: 16KB records packed back-to-back and
        // segmented at 1460 bytes, so almost no segment starts on a boundary.
        let mut stream = Vec::new();
        for _ in 0..6 {
            stream.extend(record(16_384));
        }
        let mut f = MaybeTls::new_for_test();
        let mut result = FilterResult::Continue;
        for seg in segments(&stream, 1460) {
            f.record(false, &seg);
            result = f.decide();
            if matches!(result, FilterResult::Accept) {
                break;
            }
        }
        assert!(matches!(result, FilterResult::Accept));
        assert!(f.best_chain() >= MAYBE_TLS_MIN_CHAINED);
    }

    #[test]
    fn several_small_records_in_one_segment_all_chain() {
        let mut stream = Vec::new();
        for _ in 0..8 {
            stream.extend(record(64));
        }
        let mut f = MaybeTls::new_for_test();
        f.record(true, &stream);
        // One anchor plus seven confirmations, all inside a single segment.
        assert_eq!(f.orig.best, 7);
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    #[test]
    fn one_anchor_alone_is_not_enough() {
        // A single plausible header proves nothing; only confirmations count.
        let mut f = MaybeTls::new_for_test();
        f.record(true, &record(64)[..40]);
        assert_eq!(f.orig.best, 0);
        assert!(matches!(f.decide(), FilterResult::Continue));
    }

    #[test]
    fn directions_are_tracked_independently() {
        // Interleaving the two halves of a connection must not desynchronize
        // either chain -- each counts only its own payload bytes.
        let mut stream = Vec::new();
        for _ in 0..6 {
            stream.extend(record(200));
        }
        let mut f = MaybeTls::new_for_test();
        for seg in segments(&stream, 300) {
            f.record(false, &seg);
            f.record(true, b"\x00\x01\x02 not tls at all, just filler bytes");
        }
        assert!(f.resp.best >= MAYBE_TLS_MIN_CHAINED);
        assert_eq!(f.orig.best, 0);
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    #[test]
    fn a_retransmission_breaks_the_chain_but_the_filter_re_locks() {
        let mut stream = Vec::new();
        for _ in 0..10 {
            stream.extend(record(500));
        }
        let segs = segments(&stream, 400);
        let mut f = MaybeTls::new_for_test();
        for (i, seg) in segs.iter().enumerate() {
            f.record(false, seg);
            // Duplicate an early segment, desynchronizing the byte count.
            if i == 1 {
                f.record(false, seg);
            }
        }
        assert!(matches!(f.decide(), FilterResult::Accept));
    }

    #[test]
    fn plain_http_is_rejected() {
        // Cleartext on 443 happens (misconfiguration, redirects, scanners).
        let body: Vec<u8> = std::iter::repeat_n(b'x', 1400).collect();
        let mut f = MaybeTls::new_for_test();
        let mut result = FilterResult::Continue;
        for _ in 0..MAYBE_TLS_WINDOW {
            let mut seg = b"HTTP/1.1 200 OK\r\nContent-Length: 1400\r\n\r\n".to_vec();
            seg.extend_from_slice(&body);
            f.record(false, &seg);
            result = f.decide();
        }
        assert_eq!(f.best_chain(), 0);
        assert!(matches!(result, FilterResult::Drop));
        assert!(matches!(f.terminated(), FilterResult::Drop));
    }

    #[test]
    fn incompressible_binary_traffic_is_rejected() {
        // A pseudorandom stream on 443 -- an encrypted non-TLS tunnel, say.
        // Isolated headers will appear by chance; chaining is what rejects it.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut seg = [0u8; 1400];
        let mut f = MaybeTls::new_for_test();
        let mut result = FilterResult::Continue;
        for _ in 0..MAYBE_TLS_WINDOW {
            for byte in seg.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            f.record(false, &seg);
            result = f.decide();
        }
        assert!(f.best_chain() < MAYBE_TLS_MIN_CHAINED);
        assert!(matches!(result, FilterResult::Drop));
    }

    #[test]
    fn the_window_eventually_gives_up() {
        let mut f = MaybeTls::new_for_test();
        for _ in 0..MAYBE_TLS_WINDOW - 1 {
            f.record(true, b"nothing resembling a record header here at all");
        }
        assert!(matches!(f.decide(), FilterResult::Continue));
        f.record(true, b"nothing resembling a record header here at all");
        assert!(matches!(f.decide(), FilterResult::Drop));
    }

    #[test]
    fn a_parser_identifying_the_connection_vetoes_the_heuristic() {
        let f = MaybeTls::new_for_test();
        for proto in [
            SessionProto::Tls,
            SessionProto::Http,
            SessionProto::Dns,
            SessionProto::Quic,
            SessionProto::Ssh,
            SessionProto::Wireguard,
            SessionProto::Ike,
            SessionProto::Capwap,
        ] {
            assert!(
                matches!(f.unclaimed(&proto), FilterResult::Drop),
                "{proto:?} should veto"
            );
        }
        for proto in [SessionProto::Probing, SessionProto::Null] {
            assert!(
                matches!(f.unclaimed(&proto), FilterResult::Continue),
                "{proto:?} should not veto"
            );
        }
    }

    #[test]
    fn tls_ports_cover_https_and_the_common_starttls_replacements() {
        assert!(TLS_PORTS.contains(&443));
        assert!(TLS_PORTS.contains(&853));
        assert!(TLS_PORTS.contains(&993));
        assert!(TLS_PORTS.contains(&8443));
        assert!(!TLS_PORTS.contains(&80));
    }

    #[test]
    fn the_anchor_scan_is_bounded() {
        // A record boundary past the scan limit is not found in this segment;
        // the filter waits for one that falls inside the prefix it inspects.
        let mut seg = vec![0u8; MAYBE_TLS_SCAN_LIMIT + 64];
        let hdr = record(32);
        let at = MAYBE_TLS_SCAN_LIMIT + 8;
        seg[at..at + RECORD_HEADER_LEN].copy_from_slice(&hdr[..RECORD_HEADER_LEN]);
        let mut dir = Direction::default();
        dir.consume(&seg);
        assert_eq!(dir.next, None);
    }
}
