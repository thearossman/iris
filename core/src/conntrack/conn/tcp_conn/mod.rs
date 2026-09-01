pub mod reassembly;

use self::reassembly::TcpFlow;
use crate::conntrack::conn::conn_info::ConnInfo;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::protocols::packet::tcp::{ACK, SYN};
use crate::protocols::packet::tcp::{FIN, RST};
use crate::protocols::stream::ParserRegistry;
use crate::subscription::{Subscription, Trackable};

pub(crate) struct TcpConn {
    pub(crate) ctos: TcpFlow,
    pub(crate) stoc: TcpFlow,
    handshake_done: bool,
}

impl TcpConn {
    pub(crate) fn new_on_syn(ctxt: L4Context, max_ooo: usize) -> Self {
        let flags = ctxt.flags;
        let next_seq = ctxt.seq_no.wrapping_add(1 + ctxt.length as u32);
        let ack = ctxt.ack_no;
        TcpConn {
            ctos: TcpFlow::new(max_ooo, next_seq, flags, ack),
            stoc: TcpFlow::default(max_ooo),
            handshake_done: false,
        }
    }

    /// Adopts a connection already in progress, from a packet that is not a bare
    /// SYN.
    ///
    /// `dir` is the direction of the observed packet. Its flow resumes at that
    /// packet's sequence number; the peer's flow has been observed not at all, so
    /// its stream start is unknown.
    ///
    /// Whether the *observed* flow's start is unknown depends on the packet: a SYN,
    /// bare or with ACK, carries the sender's ISN, so adopting on a SYN/ACK pins
    /// the responder's origin exactly. Only a packet without SYN -- data, FIN, RST
    /// -- leaves that flow's start genuinely unknown.
    ///
    /// The handshake is recorded as done without dispatching `L4EndHshk`: the L4
    /// layer must leave its pre-handshake state for payload to flow, but we did not
    /// see a handshake and must not claim otherwise.
    ///
    /// Note that where a flow *is* marked `start_unknown`, the first segment is
    /// still not stamped with `gap_before`. That is deliberate: a non-zero `gap_before`
    /// during protocol discovery makes L7 conclude discovery failed, which would
    /// render `init_data` useless. Probing an adopted connection from wherever the
    /// stream was picked up is the only chance to identify it, and accepting the
    /// extra risk of misidentification is precisely what enabling the flag opts
    /// into.
    pub(crate) fn new_midstream(ctxt: L4Context, dir: bool, max_ooo: usize) -> Self {
        // This packet is consumed directly rather than passed through reassembly,
        // so `next_seq` must already be past it. SYN and FIN each occupy a
        // sequence number of their own on top of any payload.
        let mut next_seq = ctxt.seq_no.wrapping_add(ctxt.length as u32);
        if ctxt.flags & (SYN | FIN) != 0 {
            next_seq = next_seq.wrapping_add(1);
        }
        // A SYN carries the sender's ISN, so this flow's origin is known after all.
        let observed = match ctxt.flags & SYN != 0 {
            true => TcpFlow::new(max_ooo, next_seq, ctxt.flags, ctxt.ack_no),
            false => TcpFlow::new_midstream(max_ooo, next_seq, ctxt.flags, ctxt.ack_no),
        };
        let unobserved = TcpFlow::unobserved(max_ooo);
        let (ctos, stoc) = if dir {
            (observed, unobserved)
        } else {
            (unobserved, observed)
        };
        TcpConn {
            ctos,
            stoc,
            handshake_done: true,
        }
    }

    /// Insert TCP segment ordered into ctos or stoc flow
    #[inline]
    pub(crate) fn reassemble<T: Trackable>(
        &mut self,
        segment: L4Pdu,
        info: &mut ConnInfo<T>,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        if segment.dir {
            self.ctos
                .insert_segment::<T>(segment, info, subscription, registry);
        } else {
            self.stoc
                .insert_segment::<T>(segment, info, subscription, registry);
        }
        if self.handshake_done() {
            self.handshake_done = true;
            info.handshake_done(subscription);
        }
    }

    /// Permanently give up on every outstanding sequence gap in both directions,
    /// delivering all buffered out-of-order data.
    ///
    /// The loops terminate: a `skip_gap` that returns `true` has flushed at least
    /// one buffered segment, and it returns `false` when no progress is possible --
    /// the connection was dropped mid-flush, or nothing buffered sits ahead of
    /// `next_seq`. Invoked when the reassembly deadline expires and on every
    /// termination path, so post-gap data is never silently discarded.
    #[inline]
    pub(crate) fn recover_gaps<T: Trackable>(
        &mut self,
        info: &mut ConnInfo<T>,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        while !self.ctos.ooo_buf.is_empty() && self.ctos.skip_gap(info, subscription, registry) {}
        while !self.stoc.ooo_buf.is_empty() && self.stoc.skip_gap(info, subscription, registry) {}
    }

    /// Returns `true` if either direction is stalled behind an unfilled sequence gap.
    #[inline]
    pub(crate) fn has_pending_gap(&self) -> bool {
        !self.ctos.ooo_buf.is_empty() || !self.stoc.ooo_buf.is_empty()
    }

    /// Returns true if the PDU currently being processed is the last
    /// packet in the TCP handshake.
    /// Note: we define this pretty loosely -- we just require that both sides have sent SYNs and ACKs,
    /// but we don't check the sequence numbers of those SYNs/ACKs.
    #[inline]
    pub(crate) fn handshake_done(&self) -> bool {
        !self.handshake_done
            && self.ctos.consumed_flags & (SYN | ACK) != 0
            && self.stoc.consumed_flags & (SYN | ACK) != 0
    }

    #[inline]
    pub(crate) fn flow_len(&self, dir: bool) -> usize {
        if dir {
            self.ctos.observed
        } else {
            self.stoc.observed
        }
    }

    #[inline]
    pub(crate) fn total_len(&self) -> usize {
        self.ctos.observed + self.stoc.observed
    }

    /// Returns `true` if the connection should be terminated
    #[inline]
    pub(crate) fn is_terminated(&self) -> bool {
        // Both sides have sent, reassembled, and acknowledged FIN, or RST has been sent
        (self.ctos.consumed_flags & self.stoc.consumed_flags & FIN != 0
            && self.ctos.last_ack == self.stoc.next_seq
            && self.stoc.last_ack == self.ctos.next_seq)
            || (self.ctos.consumed_flags & RST | self.stoc.consumed_flags & RST) != 0
    }

    /// Returns the correct inactivity timeout.
    ///
    /// While either direction is stalled behind a sequence gap, the shorter
    /// `reassembly_timeout` applies: it is the deadline for that gap to be filled
    /// before Iris gives up on it, not a deadline for the connection.
    #[inline]
    pub(crate) fn inactivity_timeout(
        &self,
        default_inactivity_timeout: usize,
        reassembly_timeout: usize,
    ) -> usize {
        match self.has_pending_gap() {
            false => default_inactivity_timeout,
            true => reassembly_timeout,
        }
    }

    /// Updates connection termination flags
    // Useful if desired to track TCP connections without reassembly
    #[inline]
    pub(super) fn update_flags(&mut self, flags: u8, dir: bool) {
        if dir {
            self.ctos.consumed_flags |= flags;
        } else {
            self.stoc.consumed_flags |= flags;
        }
    }
}
