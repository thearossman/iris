use crate::conntrack::{Conn, ConnId};
use crate::protocols::stream::ParserRegistry;
use crate::stats::{StatExt, TCP_REASSEMBLY_TIMEOUTS};
use crate::subscription::{Subscription, Trackable};

use hashlink::linked_hash_map::LinkedHashMap;
use hashlink::linked_hash_map::RawEntryMut;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Tracks inactive connection expiration.
pub(super) struct TimerWheel {
    /// Period to check for inactive connections.
    period: Duration,
    /// Start time of the `TimerWheel`.
    start_ts: Instant,
    /// Previous check time of the `TimerWheel`.
    prev_ts: Instant,
    /// Index of the next bucket to expire.
    next_bucket: usize,
    /// List of timers. Each entry pairs a connection with the deadline it was
    /// scheduled for (milliseconds since `start_ts`); see
    /// [`Conn::scheduled_expiry`].
    timers: Vec<VecDeque<(ConnId, usize)>>,
}

impl TimerWheel {
    /// Creates a new `TimerWheel` with a maximum timeout of `max_timeout` and a timeout check
    /// period of `timeout_resolution`.
    pub(super) fn new(max_timeout: usize, timeout_resolution: usize) -> Self {
        if timeout_resolution > max_timeout {
            panic!("Timeout check period must be smaller than maximum inactivity timeout")
        }
        let start_ts = Instant::now();
        let period = Duration::from_millis(timeout_resolution as u64);
        TimerWheel {
            period,
            start_ts,
            prev_ts: start_ts,
            next_bucket: 0,
            timers: vec![VecDeque::new(); max_timeout / timeout_resolution],
        }
    }

    /// When a connection last seen at `last_seen_ts` expires, in milliseconds since
    /// the wheel's epoch. Comparable across connections and across time, unlike the
    /// inactivity window on its own.
    #[inline]
    pub(super) fn expire_time(&self, last_seen_ts: Instant, inactivity_window: usize) -> usize {
        (last_seen_ts - self.start_ts).as_millis() as usize + inactivity_window
    }

    /// Insert a new connection ID into the timerwheel, returning the deadline the
    /// entry was filed under. The caller must store it in
    /// [`Conn::scheduled_expiry`]: an entry whose deadline does not match is treated
    /// as superseded and discarded on sweep.
    #[inline]
    pub(super) fn insert(
        &mut self,
        conn_id: &ConnId,
        last_seen_ts: Instant,
        inactivity_window: usize,
    ) -> usize {
        let expire_time = self.expire_time(last_seen_ts, inactivity_window);
        let period = self.period.as_millis() as usize;
        let timer_index = (expire_time / period) % self.timers.len();
        log::debug!("Inserting into index: {}, {:?}", timer_index, expire_time);
        self.timers[timer_index].push_back((conn_id.to_owned(), expire_time));
        expire_time
    }

    /// Checks for and remove inactive connections.
    #[inline]
    pub(super) fn check_inactive<T: Trackable>(
        &mut self,
        table: &mut LinkedHashMap<ConnId, Conn<T>>,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
        tcp_inactivity_timeout: usize,
        now: Instant,
    ) {
        let table_len = table.len();
        if now - self.prev_ts >= self.period {
            self.prev_ts = now;
            let nb_removed =
                self.remove_inactive(now, table, subscription, registry, tcp_inactivity_timeout);
            log::debug!(
                "expired: {} ({})",
                nb_removed,
                nb_removed as f64 / table_len as f64
            );
            log::debug!("new table size: {}", table.len());
        }
    }

    /// Removes connections that have been inactive for at least their inactivity window time
    /// period.
    ///
    /// A connection stalled behind a sequence gap carries the shorter
    /// `tcp_reassembly_timeout` as its window. When that window expires but the
    /// connection is not yet inactive by the normal `tcp_inactivity_timeout`, the
    /// expiry means "this gap is never going to be filled" rather than "this
    /// connection is over": the gap is abandoned, its buffered data delivered, and
    /// the connection re-queued under the normal timeout.
    ///
    /// Returns the number of connections removed.
    #[inline]
    pub(super) fn remove_inactive<T: Trackable>(
        &mut self,
        now: Instant,
        table: &mut LinkedHashMap<ConnId, Conn<T>>,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
        tcp_inactivity_timeout: usize,
    ) -> usize {
        let period = self.period.as_millis() as usize;
        let nb_buckets = self.timers.len();
        let mut not_expired: Vec<(usize, ConnId, usize)> = vec![];
        let check_time = (now - self.start_ts).as_millis() as usize / period * period;

        let mut cnt_exp = 0;
        let last_expire_bucket = check_time / period;
        log::debug!(
            "check time: {}, next: {}, last: {}",
            check_time,
            self.next_bucket,
            last_expire_bucket
        );

        for expire_bucket in self.next_bucket..last_expire_bucket {
            log::debug!(
                "bucket: {}, index: {}",
                expire_bucket,
                expire_bucket % nb_buckets
            );
            let list = &mut self.timers[expire_bucket % nb_buckets];

            for (conn_id, scheduled_expiry) in list.drain(..) {
                if let RawEntryMut::Occupied(mut occupied) =
                    table.raw_entry_mut().from_key(&conn_id)
                {
                    let conn = occupied.get_mut();
                    if scheduled_expiry != conn.scheduled_expiry {
                        // Superseded by an earlier re-insert (a sequence gap moved
                        // the deadline forward). Dropping the stale entry keeps
                        // exactly one live entry per connection, so rescheduling
                        // cannot accumulate duplicates over a long-lived connection.
                        continue;
                    }
                    let last_seen_time = (conn.last_seen_ts - self.start_ts).as_millis() as usize;
                    log::debug!("Last seen time: {}", last_seen_time);
                    let expire_time = last_seen_time + conn.inactivity_window;
                    if expire_time >= check_time {
                        let timer_index = (expire_time / period) % nb_buckets;
                        conn.scheduled_expiry = expire_time;
                        not_expired.push((timer_index, conn_id, expire_time));
                        continue;
                    }

                    // The reassembly deadline, not inactivity: give up on the gap
                    // and keep the connection under the normal timeout.
                    if conn.has_pending_gap()
                        && last_seen_time + tcp_inactivity_timeout >= check_time
                    {
                        TCP_REASSEMBLY_TIMEOUTS.inc();
                        conn.recover_gaps(subscription, registry);
                        if conn.remove_from_table() {
                            // A subscription lost interest during the flush.
                            occupied.remove();
                        } else if conn.terminated() {
                            // Skipping the gap let `next_seq` catch up with
                            // `last_ack`, so the FIN/ACK sequence is now complete.
                            // Such a connection could never terminate naturally
                            // while the gap stood.
                            cnt_exp += 1;
                            conn.terminate(subscription, registry);
                            occupied.remove();
                        } else {
                            conn.inactivity_window = tcp_inactivity_timeout;
                            let expire_time = last_seen_time + tcp_inactivity_timeout;
                            let timer_index = (expire_time / period) % nb_buckets;
                            conn.scheduled_expiry = expire_time;
                            not_expired.push((timer_index, conn_id, expire_time));
                        }
                        continue;
                    }

                    cnt_exp += 1;
                    conn.terminate(subscription, registry);
                    occupied.remove();
                }
            }
            for (timer_index, conn_id, expire_time) in not_expired.drain(..) {
                self.timers[timer_index].push_back((conn_id, expire_time));
            }
        }
        self.next_bucket = last_expire_bucket;
        cnt_exp
    }
}
