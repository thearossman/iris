//! Per-connection accounting of TCP stream data that reassembly gave up on.
//!
//! Iris does not discard a connection when a sequence-number gap cannot be filled:
//! it abandons the gap, resumes at the next buffered segment, and marks that
//! segment with the number of bytes lost (see
//! [`L4Pdu::gap_before`](iris_core::conntrack::pdu::L4Pdu::gap_before)). This
//! datatype accumulates those marks so an application can tell how much of the
//! stream it actually saw.
//!
//! ## Relationship to [`ConnRecord`](crate::ConnRecord)
//!
//! [`ConnRecord`]'s `Flow` also reports gaps, via `content_gaps()` and
//! `missed_bytes()`, but the two answer different questions:
//!
//! - `ConnRecord` is the **observational** view. It is built from unreassembled
//!   packets and reports every hole in the sequence space, including holes that
//!   were later filled by a retransmission and holes reassembly never had to give
//!   up on.
//! - `ReassemblyStats` is the **reassembly** view. It reports only the gaps that
//!   were permanently abandoned -- the bytes no subscription or parser ever saw.
//!
//! So `ReassemblyStats::missing_bytes()` is bounded above by the sum of
//! `ConnRecord`'s per-flow `missed_bytes()`.

#[allow(unused_imports)]
use iris_compiler::{datatype, datatype_fn};
use iris_core::conntrack::pdu::L4Pdu;
use iris_core::subscription::Tracked;

use serde::Serialize;

/// Reassembly gap accounting for one direction of a connection.
#[derive(Debug, Default, Clone, Serialize)]
pub struct GapStats {
    /// Number of sequence-number gaps permanently given up on in this direction.
    pub nb_gaps: u64,
    /// Total stream bytes never observed, summed over those gaps.
    pub missing_bytes: u64,
    /// Payload bytes delivered after at least one gap. These bytes are real and
    /// were parsed, but they are not stream-contiguous with what preceded them.
    pub bytes_after_gap: u64,
    /// The beginning of this direction's stream was never observed, so an unknown
    /// number of bytes precede the first segment seen. Set either when the
    /// connection was adopted from the middle of a stream, or when reassembly gave
    /// up waiting for this direction's stream start. See
    /// [`ReassemblyStats::start_unobserved`] for why those are not distinguished.
    ///
    /// Those bytes are *not* counted in `missing_bytes`, which only reports gaps of
    /// known size.
    pub start_unknown: bool,
}

impl GapStats {
    /// The whole of this direction's stream was observed: no abandoned gaps, and
    /// the stream start was seen.
    #[inline]
    pub fn complete(&self) -> bool {
        self.nb_gaps == 0 && !self.start_unknown
    }
}

/// How much of a connection's reassembled stream was lost to unfilled sequence
/// gaps.
///
/// A subscription that receives a session alongside this datatype can tell whether
/// the session was parsed over a complete stream: a delivered session plus
/// `!complete()` means the application-layer record is truncated or was recovered
/// after loss.
///
/// See the [module documentation](self) for how this differs from the gap
/// reporting on [`ConnRecord`](crate::ConnRecord).
///
/// ## Cost — read before subscribing
///
/// This datatype updates at `InL4Stream`, which grants L4 `Actions::Parse` for the
/// whole lifetime of every matched connection. Subscribing to it therefore turns on
/// **full TCP reassembly for every connection the filter matches, for as long as
/// they live** -- not just while application-layer headers are being parsed. Each
/// direction can hold up to `max_out_of_order` mbufs for that entire time.
///
/// With a broad filter such as `tcp` that is every TCP connection on the wire, and
/// at high line rates it is enough to exhaust the mempool. Pair it with as narrow a
/// filter as the analysis allows, and size `max_out_of_order` accordingly.
///
/// If all you need is *whether* a connection lost data rather than a byte-accurate
/// account, [`ConnRecord`](crate::ConnRecord)'s `content_gaps()` and
/// `missed_bytes()` are computed from unreassembled packets at `InL4Conn` and cost
/// nothing extra.
#[derive(Debug, Default, Clone, Serialize)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct ReassemblyStats {
    /// Originator (client to server) direction.
    pub orig: GapStats,
    /// Responder (server to client) direction.
    pub resp: GapStats,
}

impl ReassemblyStats {
    /// The reassembled stream is byte-complete in both directions: no gaps were
    /// abandoned and neither stream start was missed.
    #[inline]
    pub fn complete(&self) -> bool {
        self.orig.complete() && self.resp.complete()
    }

    /// The beginning of at least one direction's stream was never observed, so an
    /// unknown number of bytes precede everything reported here.
    ///
    /// Two situations produce this, and they are not distinguished:
    /// - the connection was adopted from the middle of a stream (one of the
    ///   `init_*` options on `ConnTrackConfig`, all off by default);
    /// - reassembly gave up waiting for a direction's stream start and adopted the
    ///   lowest buffered segment instead, which a normal connection can hit if its
    ///   responder buffer fills before the SYN/ACK is observed.
    ///
    /// So this does *not* imply the connection was adopted mid-stream.
    #[inline]
    pub fn start_unobserved(&self) -> bool {
        self.orig.start_unknown || self.resp.start_unknown
    }

    /// Total stream bytes never observed, across both directions.
    #[inline]
    pub fn missing_bytes(&self) -> u64 {
        self.orig.missing_bytes + self.resp.missing_bytes
    }

    /// Total number of abandoned gaps, across both directions.
    #[inline]
    pub fn nb_gaps(&self) -> u64 {
        self.orig.nb_gaps + self.resp.nb_gaps
    }

    /// Total payload bytes delivered after a gap, across both directions.
    ///
    /// This is the data that would have been silently discarded before Iris
    /// recovered across gaps.
    #[inline]
    pub fn recovered_bytes(&self) -> u64 {
        self.orig.bytes_after_gap + self.resp.bytes_after_gap
    }
}

impl ReassemblyStats {
    /// Accumulate from reassembled segments.
    ///
    /// `InL4Stream` rather than `InL4Conn`: `gap_before` is set by reassembly, so
    /// it is only meaningful on the post-reassembly pass.
    #[inline]
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("ReassemblyStats,level=InL4Stream")
    )]
    pub fn update(&mut self, pdu: &L4Pdu) {
        let gap = pdu.gap_before();
        let flow = if pdu.dir {
            &mut self.orig
        } else {
            &mut self.resp
        };
        if gap > 0 {
            flow.nb_gaps += 1;
            flow.missing_bytes += u64::from(gap);
        }
        if pdu.stream_start_unknown() {
            flow.start_unknown = true;
        }
        // Every segment from this direction's first gap onwards is post-gap data,
        // not just the one carrying the mark. Keyed off *this* direction: the two
        // directions are independent streams, and counting the responder's bytes as
        // post-gap because the originator lost data would contradict
        // `resp.complete()`.
        if !flow.complete() {
            flow.bytes_after_gap += pdu.length() as u64;
        }
    }
}

impl Tracked for ReassemblyStats {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self::default()
    }

    #[inline]
    fn clear(&mut self) {}
}
