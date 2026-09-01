//! Per-connection state management.
//!
//! Tracks a TCP or UDP connection, performs stream reassembly, and (via ConnInfo)
//! manages protocol parser state throughout the duration of the connection.
//!
//! Developers should not have to directly interact with anything in this module, but
//! it must be public for generated code.

pub mod conn_actions;
pub mod conn_info;
pub mod conn_layers;
pub mod conn_state;
pub mod tcp_conn;
pub mod udp_conn;

pub use conn_info::ConnInfo;

use self::tcp_conn::TcpConn;
use crate::conntrack::conn::udp_conn::UdpConn;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::lcore::CoreId;
use crate::protocols::packet::tcp::{ACK, RST, SYN};
use crate::protocols::stream::ParserRegistry;
use crate::stats::{
    StatExt, DROPPED_MIDDLE_OF_CONNECTION_TCP_BYTE, DROPPED_MIDDLE_OF_CONNECTION_TCP_PKT,
};
use crate::subscription::{Subscription, Trackable};

use anyhow::{bail, Result};
use std::time::Instant;

/// Tracks either a TCP or a UDP connection.
///
/// Performs zero-copy stream reassembly for TCP connections and tracks UDP connections.
pub(crate) enum L4Conn {
    Tcp(TcpConn),
    Udp(UdpConn),
}

/// Connection state.
pub(crate) struct Conn<T>
where
    T: Trackable,
{
    /// Timestamp of the last observed packet in the connection.
    pub(crate) last_seen_ts: Instant,
    /// Amount of time (in milliseconds) before the connection should be expired for inactivity.
    pub(crate) inactivity_window: usize,
    /// When the connection's live timerwheel entry is due to fire, in milliseconds
    /// since the wheel's epoch; `usize::MAX` before the first insert.
    ///
    /// The wheel schedules a connection once, at insert time, so a deadline that
    /// later moves *earlier* -- a sequence gap opening, which swaps in the shorter
    /// reassembly timeout -- would otherwise go unnoticed until the originally
    /// scheduled bucket came round. Comparing absolute deadlines (rather than
    /// windows, which are not comparable across different `last_seen_ts`) drives a
    /// re-insert at the earlier bucket.
    ///
    /// It doubles as the wheel's liveness token: an entry whose stored deadline no
    /// longer matches this field has been superseded and is discarded on sweep, so
    /// re-inserting never accumulates duplicates.
    pub(crate) scheduled_expiry: usize,
    /// Layer-4 connection tracking.
    pub(crate) l4conn: L4Conn,
    /// Connection tracking for filtering and parsing.
    pub(crate) info: ConnInfo<T>,
}

impl<T> Conn<T>
where
    T: Trackable,
{
    /// Creates a new TCP connection from `ctxt` with an initial inactivity window of
    /// `initial_timeout` and a maximum out-or-order tolerance of `max_ooo`. This means that there
    /// can be at most `max_ooo` packets buffered out of sequence before Iris chooses to discard
    /// the connection.
    pub(super) fn new_tcp(
        initial_timeout: usize,
        max_ooo: usize,
        pdu: &L4Pdu,
        core_id: CoreId,
    ) -> Result<Self> {
        let tcp_conn = if pdu.ctxt.flags & SYN != 0
            && pdu.ctxt.flags & ACK == 0
            && pdu.ctxt.flags & RST == 0
        {
            TcpConn::new_on_syn(pdu.ctxt, max_ooo)
        } else {
            DROPPED_MIDDLE_OF_CONNECTION_TCP_PKT.inc();
            DROPPED_MIDDLE_OF_CONNECTION_TCP_BYTE.inc_by(pdu.mbuf.data_len() as u64);
            bail!("Not SYN")
        };
        Ok(Conn {
            last_seen_ts: pdu.ts,
            inactivity_window: initial_timeout,
            scheduled_expiry: usize::MAX,
            l4conn: L4Conn::Tcp(tcp_conn),
            info: ConnInfo::new(pdu, core_id),
        })
    }

    /// Creates a new UDP connection from `ctxt` with an initial inactivity window of
    /// `initial_timeout`.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn new_udp(initial_timeout: usize, pdu: &L4Pdu, core_id: CoreId) -> Result<Self> {
        let udp_conn = UdpConn;
        Ok(Conn {
            last_seen_ts: pdu.ts,
            inactivity_window: initial_timeout,
            scheduled_expiry: usize::MAX,
            l4conn: L4Conn::Udp(udp_conn),
            info: ConnInfo::new(pdu, core_id),
        })
    }

    #[allow(dead_code)]
    pub(super) fn flow_len(&self, dir: bool) -> Option<usize> {
        match &self.l4conn {
            L4Conn::Tcp(tcp_conn) => Some(tcp_conn.flow_len(dir)),
            L4Conn::Udp(_) => None,
        }
    }

    #[allow(dead_code)]
    pub(super) fn total_len(&self) -> Option<usize> {
        match &self.l4conn {
            L4Conn::Tcp(tcp_conn) => Some(tcp_conn.total_len()),
            L4Conn::Udp(_) => None,
        }
    }

    /// Updates a connection on the arrival of a new packet.
    pub(super) fn update(
        &mut self,
        mut pdu: L4Pdu,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        // Pre-reassembly update
        if self.info.linfo.actions.needs_update() {
            self.info.new_packet(&pdu, subscription);
        }

        // Case 1: no need to pass through parsing/reassembly infrastructure,
        // but still may need to track for termination.
        if !self.info.needs_reassembly() {
            self.update_tcp_flags(pdu.flags(), pdu.dir);
            return;
        }

        // Case 2: reassembly/parsing needed
        match &mut self.l4conn {
            L4Conn::Tcp(tcp_conn) => {
                tcp_conn.reassemble(pdu, &mut self.info, subscription, registry);
                // Check if, after actions update, the framework/subscriptions
                // no longer require receiving reassembled traffic.
                if !self.info.needs_reassembly() {
                    // Safe to discard out-of-order buffers
                    if !tcp_conn.ctos.ooo_buf.is_empty() {
                        tcp_conn.ctos.ooo_buf.buf.clear();
                    }
                    if !tcp_conn.stoc.ooo_buf.is_empty() {
                        tcp_conn.stoc.ooo_buf.buf.clear();
                    }
                }
            }
            L4Conn::Udp(_) => {
                // Mark the post-parse pass, exactly as the first-packet path in
                // `ConnTracker::process_packet` does. UDP has no reassembly, so without this
                // the `new_packet` inside `consume_stream` still reports `InL4Conn` -- the
                // same transition already dispatched by the pre-reassembly update above --
                // and every InL4Conn datatype, callback, and streaming filter sees each UDP
                // packet twice.
                pdu.ctxt.reassembled = true;
                self.info.consume_stream(&mut pdu, subscription, registry)
            }
        }
    }

    /// Updates flags
    #[inline]
    pub(super) fn update_tcp_flags(&mut self, flags: u8, dir: bool) {
        if let L4Conn::Tcp(tcp_conn) = &mut self.l4conn {
            tcp_conn.update_flags(flags, dir);
        }
    }

    /// Returns `true` if the connection should be removed from the conn. table.
    /// Note UDP connections are kept for a buffer period. UDP packets
    /// that pass the packet filter stage are assumed to represent an
    /// existing or new connection and are inserted into the connection
    /// table. Keeping UDP connections in "drop" state for a buffer
    /// period prevents dropped connections from being re-inserted.
    pub(super) fn remove_from_table(&self) -> bool {
        match &self.l4conn {
            L4Conn::Udp(_) => false,
            _ => self.info.drop(),
        }
    }

    /// Returns `true` if PDUs for this connection should be dropped.
    /// This happens for UDP connections that no longer require tracking,
    /// but we keep it around (with no assoc. data) to avoid re-insertion.
    /// Note - consider in future ways to track removed UDP connections
    /// in more efficient way.
    pub(super) fn drop_pdu(&self) -> bool {
        self.info.drop()
    }

    /// Returns `true` if the connection has been naturally terminated.
    pub(super) fn terminated(&self) -> bool {
        match &self.l4conn {
            L4Conn::Tcp(tcp_conn) => tcp_conn.is_terminated(),
            L4Conn::Udp(_udp_conn) => false,
        }
    }

    /// Returns the `true` if the packet represented by `ctxt` is in the direction of originator ->
    /// responder.
    pub(super) fn packet_dir(&self, ctxt: &L4Context) -> bool {
        self.info.cdata.five_tuple.orig == ctxt.src
    }

    /// Returns `true` if this is a TCP connection stalled behind an unfilled
    /// sequence gap.
    pub(super) fn has_pending_gap(&self) -> bool {
        match &self.l4conn {
            L4Conn::Tcp(tcp_conn) => tcp_conn.has_pending_gap(),
            L4Conn::Udp(_) => false,
        }
    }

    /// Permanently give up on any outstanding sequence gaps, delivering the
    /// buffered out-of-order data that sits beyond them.
    pub(crate) fn recover_gaps(
        &mut self,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        if let L4Conn::Tcp(tcp_conn) = &mut self.l4conn {
            tcp_conn.recover_gaps(&mut self.info, subscription, registry);
        }
    }

    /// Invokes connection termination tasks that are triggered when any of the following conditions
    /// occur:
    /// - the connection naturally terminates (e.g., FIN/RST)
    /// - the connection expires due to inactivity
    /// - the connection is drained at the end of the run
    ///
    /// Any data still buffered behind an unfilled sequence gap is recovered first,
    /// so it reaches parsers and subscriptions instead of being freed with the
    /// connection. This matters most when draining at end of run: for an offline
    /// pcap, every gap is unfillable at EOF.
    pub(crate) fn terminate(
        &mut self,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        self.recover_gaps(subscription, registry);
        self.info.handle_terminate(subscription);
    }
}
