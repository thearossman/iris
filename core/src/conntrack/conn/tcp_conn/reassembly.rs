use crate::conntrack::conn::conn_info::ConnInfo;
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::packet::tcp::{FIN, RST, SYN};
use crate::protocols::stream::ParserRegistry;
use crate::stats::{
    StatExt, TCP_OOO_OVERFLOW, TCP_OOO_SEGMENT_DROPPED, TCP_REASSEMBLY_GAPS,
    TCP_REASSEMBLY_GAP_BYTES, TCP_SEGMENTS_AFTER_GAP,
};
use crate::subscription::{Subscription, Trackable};

use std::collections::VecDeque;

/// Represents a uni-directional TCP flow
#[derive(Debug)]
pub(crate) struct TcpFlow {
    /// Expected sequence number of next segment
    pub(super) next_seq: Option<u32>,
    /// Last-seen ack number for peer's flow
    pub(crate) last_ack: Option<u32>,
    /// Flow status for consumed control packets.
    /// Matches TCP flag bits.
    pub(super) consumed_flags: u8,
    /// Out-of-order buffer
    pub(crate) ooo_buf: OutOfOrderBuffer,
    /// Number observed (not necessarily reassembled) packets
    pub(crate) observed: usize,
    /// The start of this flow's stream was never observed, so the number of
    /// bytes missing before the first delivered segment is unknown.
    pub(crate) start_unknown: bool,
}

impl TcpFlow {
    /// Creates a default TCP flow
    #[inline]
    pub(super) fn default(capacity: usize) -> Self {
        TcpFlow {
            next_seq: None,
            last_ack: None,
            consumed_flags: 0,
            ooo_buf: OutOfOrderBuffer::new(capacity),
            observed: 0,
            start_unknown: false,
        }
    }

    /// Creates a new TCP flow with given next sequence number, flags,
    /// and out-of-order buffer
    #[inline]
    pub(super) fn new(capacity: usize, next_seq: u32, flags: u8, ack: u32) -> Self {
        TcpFlow {
            next_seq: Some(next_seq),
            last_ack: Some(ack),
            consumed_flags: flags,
            ooo_buf: OutOfOrderBuffer::new(capacity),
            observed: 1,
            start_unknown: false,
        }
    }

    /// Creates a TCP flow adopted from the middle of a stream: `next_seq` is taken
    /// from the first observed segment, and everything before it is a gap of
    /// unknown size.
    #[inline]
    pub(super) fn new_midstream(capacity: usize, next_seq: u32, flags: u8, ack: u32) -> Self {
        TcpFlow {
            start_unknown: true,
            ..TcpFlow::new(capacity, next_seq, flags, ack)
        }
    }

    /// Creates a TCP flow for a direction that has not been observed at all. Its
    /// stream start is unknown, unlike a flow awaiting a SYN/ACK.
    #[inline]
    pub(super) fn unobserved(capacity: usize) -> Self {
        TcpFlow {
            start_unknown: true,
            ..TcpFlow::default(capacity)
        }
    }

    /// Attempt to insert incoming data segment into flow.
    /// Buffer future segments and drop old segments.
    ///
    /// If the out-of-order buffer is full, reassembly gives up on a sequence gap
    /// (see [`TcpFlow::skip_gap`]) rather than discarding the connection. The
    /// arriving segment takes part in that decision, so no re-dispatch is needed.
    #[inline]
    pub(super) fn insert_segment<T: Trackable>(
        &mut self,
        mut segment: L4Pdu,
        info: &mut ConnInfo<T>,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        self.observed += 1;
        segment.ctxt.reassembled = true;

        let length = segment.length() as u32;
        let cur_seq = segment.seq_no();

        if let Some(next_seq) = self.next_seq {
            if next_seq == cur_seq {
                // Segment is the next expected segment in the sequence
                self.consumed_flags |= segment.flags();
                if segment.flags() & RST != 0 {
                    info.consume_stream(&mut segment, subscription, registry);
                    return;
                }
                let expected_seq = seq_after(cur_seq, length, segment.flags());
                info.consume_stream(&mut segment, subscription, registry);
                self.last_ack = Some(segment.ack_no());
                self.flush_ooo_buffer::<T>(expected_seq, info, subscription, registry);
            } else if wrapping_lt(next_seq, cur_seq) {
                // Segment comes after the next expected segment
                self.buffer_ooo_seg(segment, info, subscription, registry);
            } else if let Some(expected_seq) = overlap(&mut segment, next_seq) {
                // Segment starts before the next expected segment but has new data
                self.consumed_flags |= segment.flags();
                info.consume_stream(&mut segment, subscription, registry);
                self.last_ack = Some(segment.ack_no());
                self.flush_ooo_buffer::<T>(expected_seq, info, subscription, registry);
            } else {
                // Segment contains old data
                log::debug!(
                    "Dropping old segment. cur: {} expect: {}",
                    cur_seq,
                    next_seq
                );
                segment.mark_no_payload();
                drop(segment);
            }
        } else if self.start_unknown {
            // This direction of an adopted mid-stream connection. Take the first
            // segment we see as the stream start rather than buffering it until the
            // reassembly deadline. Checked ahead of the SYN/ACK arm below, which
            // would otherwise claim any ACK-flagged packet -- including the bare ACK
            // that completes a handshake we joined at the SYN/ACK -- and burn a
            // sequence number on a SYN that is not there.
            //
            // A SYN is the exception worth catching: it carries this flow's ISN, so
            // one arriving late -- reordered behind the SYN/ACK we adopted on --
            // tells us exactly where the stream began, and the start is no longer
            // unknown. `seq_after` already charges the SYN its sequence number, so
            // only the flags change.
            let start_known = segment.flags() & SYN != 0;
            let expected_seq = seq_after(cur_seq, length, segment.flags());
            self.next_seq = Some(expected_seq);
            self.start_unknown = !start_known;
            self.consumed_flags |= segment.flags();
            self.last_ack = Some(segment.ack_no());
            segment.ctxt.stream_start_unknown = !start_known;
            info.consume_stream(&mut segment, subscription, registry);
            self.flush_ooo_buffer::<T>(expected_seq, info, subscription, registry);
        } else if segment.flags() & SYN != 0 {
            // The SYN/ACK responding to the originator's SYN. Tested on SYN alone:
            // `SYN | ACK` also matches a bare ACK, which would take this arm if it
            // arrived before the SYN/ACK and be charged a sequence number for a SYN
            // that is not there, leaving `next_seq` one past the truth for the rest
            // of the flow.
            let expected_seq = seq_after(cur_seq, length, segment.flags());
            self.next_seq = Some(expected_seq);
            self.consumed_flags |= segment.flags();
            self.last_ack = Some(segment.ack_no());
            info.consume_stream(&mut segment, subscription, registry);
            self.flush_ooo_buffer::<T>(expected_seq, info, subscription, registry);
        } else {
            // Buffer anything else until the SYN/ACK fixes this flow's sequence
            // origin. That includes a bare ACK arriving early: it carries no
            // stream position we can trust yet.
            self.buffer_ooo_seg(segment, info, subscription, registry);
        }
    }

    /// Insert packet into the ooo buffer.
    ///
    /// On overflow, give up on a sequence gap to free at least one slot. The
    /// arriving segment is buffered *first*, so it competes as a resume point:
    /// skipping past data already in hand would lose more of the stream than
    /// necessary. The buffer therefore sits one segment over capacity for the
    /// duration of the skip, which then flushes at least one segment out.
    #[inline]
    fn buffer_ooo_seg<T: Trackable>(
        &mut self,
        segment: L4Pdu,
        info: &mut ConnInfo<T>,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        let full = self.ooo_buf.is_full();
        self.ooo_buf.insert_back(segment);
        if !full {
            return;
        }
        log::debug!("Out-of-order buffer full; abandoning oldest sequence gap");
        TCP_OOO_OVERFLOW.inc();
        if !self.skip_gap(info, subscription, registry) {
            // No progress possible: the connection was dropped mid-flush, so
            // `skip_gap` left the buffer untouched. Restore the capacity invariant
            // by discarding the newest segment only.
            if let Some(mut segment) = self.ooo_buf.buf.pop_back() {
                segment.mark_no_payload();
            }
            TCP_OOO_SEGMENT_DROPPED.inc();
        }
    }

    /// Permanently give up on the sequence gap in front of this flow: resume at the
    /// lowest buffered sequence number and flush everything that becomes contiguous.
    ///
    /// The number of skipped bytes is recorded on the flow and stamped onto the
    /// resuming segment as [`L4Pdu::gap_before`], so parsers and subscriptions can
    /// tell that the stream is no longer byte-contiguous.
    ///
    /// Returns `true` if the buffer made progress.
    #[inline]
    pub(super) fn skip_gap<T: Trackable>(
        &mut self,
        info: &mut ConnInfo<T>,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) -> bool {
        if info.drop() {
            return false;
        }
        let seqs: Vec<u32> = self.ooo_buf.buf.iter().map(|s| s.seq_no()).collect();
        // With no expected sequence number yet, the lowest buffered segment becomes
        // the stream start. Nothing is "skipped": the size of the missing prefix is
        // unknowable, so the gap is zero and the flow is flagged instead.
        let start_unknown = self.next_seq.is_none();
        let (resume_seq, gap) = match self.next_seq {
            Some(next_seq) => match select_resume_seq(next_seq, &seqs) {
                Some(resume) => resume,
                None => return false,
            },
            None => match lowest_seq(&seqs) {
                Some(seq) => (seq, 0),
                None => return false,
            },
        };

        self.start_unknown |= start_unknown;
        TCP_REASSEMBLY_GAPS.inc();
        TCP_REASSEMBLY_GAP_BYTES.inc_by(u64::from(gap));
        log::debug!(
            "Abandoning sequence gap of {} bytes; resuming at {}",
            gap,
            resume_seq
        );

        // Stamp the resuming segment so the gap is visible downstream. Exactly one:
        // `flush_ordered` scans from the front, so the first segment at `resume_seq`
        // is the one it will consume. Stamping duplicate retransmissions too would
        // double-count the same gap in any subscription that survives the overlap
        // check and sees a second marked segment.
        if let Some(seg) = self
            .ooo_buf
            .buf
            .iter_mut()
            .find(|s| s.seq_no() == resume_seq)
        {
            seg.ctxt.gap_before = gap;
            seg.ctxt.stream_start_unknown |= start_unknown;
            TCP_SEGMENTS_AFTER_GAP.inc();
        }

        self.next_seq = Some(resume_seq);
        self.flush_ooo_buffer::<T>(resume_seq, info, subscription, registry);
        true
    }

    /// Flushes the flow's out-of-order buffer given the next expected
    /// sequence number and updates the flow's new next expected
    /// sequence number and status after the flush.
    #[inline]
    pub(super) fn flush_ooo_buffer<T: Trackable>(
        &mut self,
        expected_seq: u32,
        info: &mut ConnInfo<T>,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        if info.drop() {
            return;
        }
        let next_seq = self.ooo_buf.flush_ordered::<T>(
            expected_seq,
            &mut self.last_ack,
            &mut self.consumed_flags,
            info,
            subscription,
            registry,
        );
        self.next_seq = Some(next_seq);
    }
}

/// A buffer to hold reordered TCP segments
#[derive(Debug)]
pub(crate) struct OutOfOrderBuffer {
    capacity: usize,
    pub(crate) buf: VecDeque<L4Pdu>,
}

impl OutOfOrderBuffer {
    /// Creates a new OutOfOrderBuffer with capacity
    fn new(capacity: usize) -> Self {
        OutOfOrderBuffer {
            capacity,
            buf: VecDeque::new(),
        }
    }

    /// Is empty
    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Buffer is at capacity; the next insert would overflow.
    pub(crate) fn is_full(&self) -> bool {
        self.len() >= self.capacity
    }

    /// Returns the number of elements in the buffer
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    /// Inserts segment at the end of the buffer.
    ///
    /// Capacity is enforced by the caller via [`OutOfOrderBuffer::is_full`]:
    /// [`TcpFlow::buffer_ooo_seg`] deliberately exceeds it by one segment while it
    /// decides which sequence gap to abandon.
    fn insert_back(&mut self, segment: L4Pdu) {
        log::debug!("insert with seq : {:#?}", segment.seq_no());
        self.buf.push_back(segment);
    }

    /// Consumes segments with expected data, retains segments with future data,
    /// and drops segments with old data.
    /// Returns the next expected sequence number and control flags of consumed segments.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn flush_ordered<T: Trackable>(
        &mut self,
        expected_seq: u32,
        last_ack: &mut Option<u32>,
        consumed_flags: &mut u8,
        info: &mut ConnInfo<T>,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) -> u32 {
        let mut next_seq = expected_seq;
        let mut index = 0;
        while index < self.len() {
            if info.drop() {
                return next_seq;
            }

            // unwraps ok because index < len
            let cur_seq = self.buf.get_mut(index).unwrap().seq_no();
            log::debug!("Flushing...current seq: {:#?}", cur_seq);

            if next_seq == cur_seq {
                let mut segment = self.buf.remove(index).unwrap();
                *consumed_flags |= segment.flags();
                if segment.flags() & RST != 0 {
                    info.consume_stream(&mut segment, subscription, registry);
                    return next_seq;
                }
                next_seq = seq_after(next_seq, segment.length() as u32, segment.flags());
                info.consume_stream(&mut segment, subscription, registry);
                *last_ack = Some(segment.ack_no());
                index = 0;
            } else if wrapping_lt(next_seq, cur_seq) {
                index += 1;
            } else {
                let mut segment = self.buf.remove(index).unwrap();
                if let Some(update_seq) = overlap(&mut segment, next_seq) {
                    next_seq = update_seq;
                    *consumed_flags |= segment.flags();
                    info.consume_stream(&mut segment, subscription, registry);
                    *last_ack = Some(segment.ack_no());
                    index = 0;
                } else {
                    log::debug!("Dropping old segment during flush.");
                    segment.mark_no_payload();
                    drop(segment);
                }
            }
        }
        next_seq
    }
}

/// Pick the sequence number at which to resume after abandoning a gap.
///
/// Given the next expected sequence number and the sequence numbers of the
/// currently buffered out-of-order segments, returns the lowest buffered sequence
/// number that lies ahead of `next_seq`, paired with the number of bytes skipped
/// to reach it. Returns `None` when nothing buffered is ahead of `next_seq`, in
/// which case skipping would make no progress.
///
/// Kept free of `L4Pdu` so the wrapping arithmetic is unit-testable without DPDK.
pub(crate) fn select_resume_seq(next_seq: u32, seqs: &[u32]) -> Option<(u32, u32)> {
    let resume = seqs
        .iter()
        .copied()
        .filter(|seq| wrapping_lt(next_seq, *seq))
        .reduce(|acc, seq| if wrapping_lt(seq, acc) { seq } else { acc })?;
    Some((resume, resume.wrapping_sub(next_seq)))
}

/// The lowest of `seqs` under TCP's wrapping order, or `None` if empty.
///
/// Used when a flow has no expected sequence number yet -- the responder of an
/// adopted mid-stream connection -- where every buffered segment is a candidate
/// stream start and the earliest one loses the least data. `select_resume_seq`
/// cannot serve here: it is a *strict* comparison against a basis sequence number,
/// so it would exclude that basis from its own candidate set and, with a single
/// buffered segment, never make progress at all.
pub(crate) fn lowest_seq(seqs: &[u32]) -> Option<u32> {
    seqs.iter()
        .copied()
        .reduce(|acc, seq| if wrapping_lt(seq, acc) { seq } else { acc })
}

/// The sequence number one past the last byte a segment occupies.
///
/// TCP's sequence space is not just payload: a SYN and a FIN each consume a
/// sequence number of their own *in addition to* any data the segment carries, so
/// a FIN that arrives with a payload advances the stream by `length + 1`.
///
/// Every site that moves a flow's `next_seq` past a consumed segment shares this
/// definition. They have to: a segment can reach `consume_stream` either directly
/// from [`TcpFlow::insert_segment`] or later out of the out-of-order buffer, and if
/// those paths disagreed the same connection would end up with a different
/// `next_seq` depending on which one it took. The two sites that add 1
/// unconditionally are not exceptions -- SYN is a precondition of the arm they sit
/// in, not something they test for.
///
/// Kept free of `L4Pdu` so the wrapping arithmetic is unit-testable without DPDK.
pub(crate) fn seq_after(seq: u32, length: u32, flags: u8) -> u32 {
    let end_seq = seq.wrapping_add(length);
    // A segment with both flags set is not a real stream (SYN+FIN is a scan
    // artifact); one sequence number is as good an answer as any.
    match flags & (SYN | FIN) != 0 {
        true => end_seq.wrapping_add(1),
        false => end_seq,
    }
}

pub fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     insure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}

/// Check if a segment has overlapping data with the received bytes.
/// Returns the new expected sequence number if there is overlap
fn overlap(segment: &mut L4Pdu, expected_seq: u32) -> Option<u32> {
    let length = segment.length();
    let cur_seq = segment.seq_no();
    let end_seq = seq_after(cur_seq, length as u32, segment.flags());

    if wrapping_lt(expected_seq, end_seq) {
        // contains new data
        let new_data_len = end_seq.wrapping_sub(expected_seq);
        let overlap_data_len = expected_seq.wrapping_sub(cur_seq);

        log::debug!("Overlap with new data size : {:#?}", new_data_len);
        segment.ctxt.offset += overlap_data_len as usize;
        segment.ctxt.length = new_data_len as usize;
        Some(end_seq)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Flags the reassembly logic itself never has to name.
    use crate::protocols::packet::tcp::{ACK, PSH};

    #[test]
    fn core_select_resume_seq_empty_buffer() {
        assert_eq!(select_resume_seq(1000, &[]), None);
    }

    #[test]
    fn core_select_resume_seq_all_stale() {
        // Everything buffered is at or behind the expected sequence number, so
        // skipping the gap would not advance the stream.
        assert_eq!(select_resume_seq(1000, &[1000, 900, 500]), None);
    }

    #[test]
    fn core_select_resume_seq_single_future_segment() {
        assert_eq!(select_resume_seq(1000, &[1500]), Some((1500, 500)));
    }

    #[test]
    fn core_select_resume_seq_picks_minimum() {
        // The minimal skip is the right one: resume as early as the buffer allows.
        assert_eq!(
            select_resume_seq(1000, &[4000, 1200, 9000, 1500]),
            Some((1200, 200))
        );
    }

    #[test]
    fn core_select_resume_seq_ignores_stale_among_future() {
        assert_eq!(
            select_resume_seq(1000, &[800, 2000, 1000, 1400]),
            Some((1400, 400))
        );
    }

    #[test]
    fn core_select_resume_seq_wraps_around_zero() {
        // Expected sequence number near the top of the space; buffered segments
        // have already wrapped past 2^32.
        let next_seq = u32::MAX - 99;
        assert_eq!(select_resume_seq(next_seq, &[400, 50]), Some((50, 150)));
    }

    #[test]
    fn core_lowest_seq_empty() {
        assert_eq!(lowest_seq(&[]), None);
    }

    #[test]
    fn core_lowest_seq_single() {
        // The one-segment case that matters: a flow with no expected sequence
        // number must be able to adopt its only buffered segment as the stream
        // start. `select_resume_seq` cannot, because its comparison is strict.
        assert_eq!(lowest_seq(&[1500]), Some(1500));
        assert_eq!(select_resume_seq(1500, &[1500]), None);
    }

    #[test]
    fn core_lowest_seq_ignores_arrival_order() {
        // Segments are buffered in arrival order, not sequence order, so the front
        // of the buffer is no guide to the lowest sequence number.
        assert_eq!(lowest_seq(&[9000, 1200, 4000, 1500]), Some(1200));
    }

    #[test]
    fn core_lowest_seq_wraps_around_zero() {
        assert_eq!(lowest_seq(&[50, u32::MAX - 99, 400]), Some(u32::MAX - 99));
    }

    #[test]
    fn core_seq_after_plain_data() {
        // No control flag: the segment occupies exactly its payload.
        assert_eq!(seq_after(1000, 500, PSH | ACK), 1500);
        assert_eq!(seq_after(1000, 0, ACK), 1000);
    }

    #[test]
    fn core_seq_after_fin_with_payload() {
        // The regression this test exists for: a FIN occupies one sequence number
        // *after* its payload, so the payload length must not be discarded.
        assert_eq!(seq_after(1000, 500, FIN | PSH | ACK), 1501);
    }

    #[test]
    fn core_seq_after_fin_without_payload() {
        // The common bare FIN/ACK, where payload-discarding and additive forms
        // happen to agree -- which is why the bug went unnoticed.
        assert_eq!(seq_after(1000, 0, FIN | ACK), 1001);
    }

    #[test]
    fn core_seq_after_syn_with_payload() {
        // TCP Fast Open and the like: a SYN also occupies a sequence number of its
        // own on top of any data it carries.
        assert_eq!(seq_after(1000, 20, SYN), 1021);
        assert_eq!(seq_after(1000, 0, SYN | ACK), 1001);
    }

    #[test]
    fn core_seq_after_syn_and_fin_costs_one() {
        // SYN+FIN is not a real stream; it must still be charged a bounded amount,
        // not one sequence number per flag.
        assert_eq!(seq_after(1000, 0, SYN | FIN), 1001);
        assert_eq!(seq_after(1000, 7, SYN | FIN), 1008);
    }

    #[test]
    fn core_seq_after_rst_is_not_charged() {
        // RST consumes no sequence space. Reassembly returns early on RST anyway,
        // but the helper must not quietly disagree with that.
        assert_eq!(seq_after(1000, 0, RST | ACK), 1000);
    }

    #[test]
    fn core_seq_after_wraps_around_zero() {
        // Payload straddling 2^32.
        assert_eq!(seq_after(u32::MAX - 9, 20, PSH | ACK), 10);
        // The wrap falls on the FIN's own sequence number, not on payload: the
        // payload ends exactly at u32::MAX and the FIN takes that last slot.
        assert_eq!(seq_after(u32::MAX - 5, 5, FIN | ACK), 0);
        assert_eq!(seq_after(u32::MAX, 0, FIN | ACK), 0);
        // Payload alone reaches exactly 2^32; the FIN pushes one past it.
        assert_eq!(seq_after(u32::MAX - 99, 100, FIN | PSH | ACK), 1);
    }

    #[test]
    fn core_seq_after_matches_peer_ack_for_fin_with_payload() {
        // Real teardown from `traces/small_flows.pcap` (192.168.3.131:55955 <->
        // 207.46.148.38:80), the shape that could not terminate before this was
        // shared: the server's FIN/PSH/ACK carries 279 bytes at seq 3974155009, and
        // the client acknowledges 3974155289 -- payload *and* FIN.
        //
        // `TcpConn::is_terminated` compares one side's `last_ack` against the
        // other's `next_seq`, so anything but the peer's own ack number here leaves
        // the connection unterminatable. Discarding the payload length, as the
        // in-order arm used to, yielded 3974155010 and stranded the client's final
        // ACK in the out-of-order buffer.
        let ack_sent_by_peer = 3974155289u32;
        assert_eq!(
            seq_after(3974155009, 279, FIN | PSH | ACK),
            ack_sent_by_peer
        );
    }

    #[test]
    fn core_select_resume_seq_stale_across_wrap() {
        // A segment just behind a wrapped `next_seq` must not be treated as future.
        let next_seq = 100u32;
        assert_eq!(
            select_resume_seq(next_seq, &[u32::MAX - 10, 900]),
            Some((900, 800))
        );
    }
}
