#![allow(unused_macros)]
macro_rules! tsc_start {
    ( $start:ident ) => {
        let $start = unsafe { $crate::dpdk::rte_rdtsc() };
    };
}

macro_rules! tsc_record {
    ( $timers:expr, $timer:expr, $start:ident ) => {
        $timers.record($timer, unsafe { $crate::dpdk::rte_rdtsc() } - $start, 1);
    };
    ( $timers:expr, $timer:expr, $start:ident, $sample:literal ) => {
        $timers.record(
            $timer,
            unsafe { $crate::dpdk::rte_rdtsc() } - $start,
            $sample,
        );
    };
}
