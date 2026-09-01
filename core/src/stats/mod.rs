use std::cell::Cell;

#[cfg(feature = "prometheus")]
mod prometheus;

#[cfg(feature = "prometheus")]
pub use prometheus::*;

thread_local! {
    pub(crate) static IGNORED_BY_PACKET_FILTER_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static IGNORED_BY_PACKET_FILTER_BYTE: Cell<u64> = const { Cell::new(0) };
    pub(crate) static DROPPED_MIDDLE_OF_CONNECTION_TCP_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static DROPPED_MIDDLE_OF_CONNECTION_TCP_BYTE: Cell<u64> = const { Cell::new(0) };
    /// Times a per-direction out-of-order buffer hit `max_out_of_order`.
    pub(crate) static TCP_OOO_OVERFLOW: Cell<u64> = const { Cell::new(0) };
    /// Sequence-number gaps that reassembly permanently gave up on.
    pub(crate) static TCP_REASSEMBLY_GAPS: Cell<u64> = const { Cell::new(0) };
    /// Stream bytes never observed, summed over all abandoned gaps.
    pub(crate) static TCP_REASSEMBLY_GAP_BYTES: Cell<u64> = const { Cell::new(0) };
    /// Segments delivered to subscriptions after an abandoned gap.
    pub(crate) static TCP_SEGMENTS_AFTER_GAP: Cell<u64> = const { Cell::new(0) };
    /// Segments dropped because the out-of-order buffer could not be drained.
    pub(crate) static TCP_OOO_SEGMENT_DROPPED: Cell<u64> = const { Cell::new(0) };
    /// Times the reassembly deadline expired on a connection stalled behind a gap.
    pub(crate) static TCP_REASSEMBLY_TIMEOUTS: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TOTAL_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TOTAL_BYTE: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TCP_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TCP_BYTE: Cell<u64> = const { Cell::new(0) };
    pub(crate) static UDP_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static UDP_BYTE: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TCP_NEW_CONNECTIONS: Cell<u64> = const { Cell::new(0) };
    pub(crate) static UDP_NEW_CONNECTIONS: Cell<u64> = const { Cell::new(0) };
    pub(crate) static IDLE_CYCLES: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TOTAL_CYCLES: Cell<u64> = const { Cell::new(0) };

    #[cfg(feature = "prometheus")]
    pub(crate) static PROMETHEUS: std::cell::OnceCell<prometheus::PerCorePrometheusStats> = const { std::cell::OnceCell::new() };
}

pub(crate) trait StatExt: Sized {
    fn inc(&'static self) {
        self.inc_by(1);
    }
    fn inc_by(&'static self, val: u64);
}

impl StatExt for std::thread::LocalKey<Cell<u64>> {
    fn inc_by(&'static self, val: u64) {
        self.set(self.get() + val);
    }
}
