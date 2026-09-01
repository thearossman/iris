//! Counts bytes across all of Iris's encrypted stream protocols (TLS, SSH, QUIC,
//! WireGuard, IKE, and DTLS-encapsulated CAPWAP -- see "CAPWAP bytes" below, on why only the
//! DTLS-encapsulated half of CAPWAP counts as "encrypted" here), split three ways into
//! cleartext handshake bytes, encrypted payload bytes, and the transport/network/link header
//! bytes carrying that payload, plus heuristically-detected mid-stream QUIC, Zoom, and iperf3
//! traffic (`MaybeQuic`/`MaybeZoom`/`MaybeIperf3`, which have no handshake to split out -- see
//! "`MaybeQuic`/`MaybeZoom`/`MaybeIperf3` bytes" below), plus total TCP and UDP traffic.
//!
//! ## Byte unit: on-wire bytes, split into payload and headers
//! Every count in this app is denominated in on-wire bytes: `Mbuf::data_len()`
//! (`pdu.mbuf.data_len()`), the length of the whole captured frame -- Ethernet, IP, and
//! TCP/UDP headers included, plus the L4 payload. `EncBytes`, `TransportBytes`, and
//! `WireBytes` below all read it directly off the `L4Pdu` each one updates from. `WireBytes`
//! is a local datatype standing in for the shared `iris_datatypes::ByteCount`, which is
//! defined to *exclude* headers (`datatypes/src/conn_fts.rs`) and would otherwise put the
//! `MaybeQuic`/`MaybeZoom`/`MaybeIperf3` rows on a different unit than the rest of this app.
//! Every ratio this app prints is therefore apples-to-apples with every other ratio it prints.
//!
//! Within that unit, each connection's bytes land in three buckets, and every protocol row is
//! reported as all three:
//!
//! - `handshake` -- *whole frames*, headers included, for every packet up to and including the
//!   one on which the L7 headers finish (see "Handshake vs. payload split" below).
//! - `payload` -- for every packet after that, just the bytes after the TCP or UDP header:
//!   the encrypted application data itself.
//! - `headers` -- for those same later packets, the Ethernet + IP + TCP/UDP header bytes
//!   carrying that payload. This is the per-connection cost of the encrypted bulk transfer
//!   that isn't the transfer, which is the thing worth seeing next to it.
//!
//! `split_wire_bytes` (below) does the split, from `pdu.ctxt.offset` -- the offset into the
//! frame where the L4 payload begins, which for the unreassembled PDUs this app sees is
//! exactly the Ethernet + IP + L4 header length -- and `pdu.ctxt.length`, the payload length
//! the IP header declares. It takes the header half as `data_len() - payload` rather than as
//! `offset` directly, so the two halves always sum back to the full frame: Ethernet padding on
//! an undersized frame (the 6 trailing bytes of a 60-byte pure ACK, say) is overhead that is
//! neither IP-declared payload nor a header, and this puts it in `headers` instead of dropping
//! it or miscounting it as encrypted data.
//!
//! Because the buckets partition the frame rather than sampling it, `handshake + payload +
//! headers` is still every on-wire byte of the connection -- the same per-connection total
//! this app counted before the payload/header split existed, just itemized. A pure ACK or an
//! empty UDP encapsulation is not zero-weight: it carries no payload, so all of it lands in
//! `handshake` or `headers` depending on which side of the boundary it falls on (and, for
//! `TransportBytes`, in `tcp`/`udp` as a whole frame either way).
//!
//! That whole-connection total is the same unit as the runtime's own startup banner,
//! `Processed: N pkts, M bytes` (`core/src/runtime/offline.rs`), which sums that same
//! `mbuf.data_len()` over every captured frame. The two totals still won't necessarily match,
//! though: the banner sums *every* frame the runtime saw, including non-TCP/UDP traffic (ARP,
//! ICMP, malformed packets) this app never tracks, while `TransportBytes` below only sums
//! frames belonging to a TCP or UDP connection. This app's own TCP+UDP total is therefore a
//! lower bound on the banner's total, not necessarily equal to it.
//!
//! ## Handshake vs. payload split
//! This deliberately does NOT use `L4Pdu::app_body_offset()`/`pdu.ctxt.app_offset`, despite
//! that looking like the obvious per-packet signal. It isn't reliable for this purpose:
//! `process_stream` is the only code that ever sets it
//! (`core/src/conntrack/conn/conn_layers.rs`), and `process_stream` is only invoked while
//! the L7 layer's `Actions::Parse` bit is set. That bit is cleared as soon as headers
//! finish for any parser reporting `ParsingState::Stop` -- which is TLS, SSH, WireGuard,
//! IKE, and CAPWAP (only QUIC reports `Parsing`). So for five of the six protocols here,
//! `app_offset` is never touched again after the handshake packet and just sits at its
//! per-packet default of `None` on every later packet, even ones deep in the encrypted
//! payload -- indistinguishable from "still in the handshake". (There's a second wrinkle
//! on the transition packet itself: `consume_stream` can invoke `process_stream` a second
//! time in the same pass when a precise split offset was reported, and that second call
//! unconditionally resets `app_offset` to `Some(0)` before any subscriber ever observes the
//! precise offset -- so even TLS/SSH's sub-packet split is never actually visible here.)
//!
//! Instead, `EncBytes` tracks an `in_payload` flag per connection, flipped exactly once by
//! an `L7EndHdrs`-level method. Unlike the `app_offset` approach, every packet after the
//! headers finish is correctly split into payload and headers regardless of whether the parser
//! is still actively running.
//!
//! The packet on which the headers finish is counted entirely as *handshake* -- a
//! whole-packet granularity approximation on that single packet. `Conn::update` dispatches
//! `InL4Conn` from its pre-reassembly update, before handing the packet to
//! reassembly/parsing, so that packet is accumulated before `process_stream` reaches
//! `L7EndHdrs` and flips the flag.
//!
//! ## Why a datatype and not a callback
//! The byte counting lives in a `Tracked` datatype rather than in `#[callback_fn]` methods.
//! A callback method only runs while its wrapper `is_active()`, which is set when the
//! filter pattern matches -- for an L7 subscription, at `L7OnDisc`. But the packet that
//! *triggers* discovery has already been dispatched at `InL4Conn` by that pre-reassembly
//! update, while the callback is still `Matching`. Counting there dropped each connection's
//! first data packet outright: on `traces/tls_single_flow.pcap` that was the connection's whole
//! first packet -- the ClientHello frame, headers included -- and protocols whose discovery
//! spans several packets (QUIC) lost more.
//! Datatypes update unconditionally, so these totals cover the connection from its first
//! byte. The numbers therefore mean "all bytes of a connection that turned out to be TLS",
//! not "bytes observed after we knew it was TLS".
//!
//! ## CAPWAP bytes
//! CAPWAP (`core/src/protocols/stream/capwap`) is included alongside the other four
//! protocols in this list, but only its DTLS-encapsulated traffic: the CAPWAP term in
//! `record_enc_bytes`'s filter is `capwap.preamble_type = 1`, not bare `capwap`, so a
//! connection is counted here only if its preamble declared DTLS ([`Capwap::is_dtls`],
//! detected structurally by checking that what follows the header looks like a DTLS record --
//! never decrypted or handshake-verified; see the parser's module docs). `is_dtls()` itself
//! is a `bool` and can't be used directly as a filter predicate (the DSL's `Value` enum has no
//! boolean variant); `preamble_type = 1` is `is_dtls()` spelled the way the filter can express
//! it.
//!
//! Plaintext CAPWAP -- the common case, since both its channels are cleartext by default --
//! is deliberately excluded: unlike DTLS CAPWAP, it isn't encrypted, so counting it here would
//! misrepresent `CAPWAP_BYTES`'s `payload` bucket as "encrypted bytes" when it wasn't.
//! Excluded connections aren't lost, just not broken out into their own row: their bytes still
//! land in the unconditional `tcp`/`udp` transport totals (`record_transport_bytes`) below.
//! CAPWAP is grouped with TLS/SSH/WireGuard/IKE here (rather than off on its own) because,
//! DTLS-encapsulated or not, it has the same shape for this app's purposes -- a
//! single-fixed-header parser reporting `ParsingState::Stop`.
//!
//! ## `MaybeQuic`/`MaybeZoom`/`MaybeIperf3` bytes
//! `MaybeQuic`, `MaybeZoom`, and `MaybeIperf3` (`datatypes/src/maybe_quic.rs`,
//! `datatypes/src/maybe_zoom.rs`, `datatypes/src/maybe_iperf3.rs`) are heuristic streaming
//! filters, not real L7 parsers -- they never fire `L7EndHdrs`, so there's no handshake/payload
//! boundary to detect for them. Every packet on a connection they accept is split into payload
//! and headers as if the whole connection were past that boundary; `handshake` stays 0 for
//! `MAYBE_QUIC_BYTES`/`MAYBE_ZOOM_BYTES`/`MAYBE_IPERF3_BYTES`.
//! `MaybeIperf3` itself covers both a real fingerprint (its UDP path) and a much weaker,
//! best-effort heuristic (its TCP path) -- see that filter's own module docs; both paths land
//! in the same `MAYBE_IPERF3_BYTES` total here since a connection is only ever judged by one
//! of the two.
//!
//! Neither filter consults the real parsers' results, so a connection the `quic` parser
//! identifies can also satisfy `MaybeQuic` (e.g. one stray long-header packet among its first
//! `MAYBE_QUIC_WINDOW` payload packets still clears `MAYBE_QUIC_MIN_FRACTION`). The generated
//! `L4Terminated` dispatch does not chain these as `else if` -- a custom filter predicate is
//! never mutually exclusive with a protocol predicate (`Predicate::is_excl`,
//! `core/src/filter/ast.rs`) -- so both `record_enc_bytes` and `record_maybe_quic_bytes` would
//! otherwise fire for the same connection. `enc_totals` is the single source of truth for
//! "a real parser already claimed this connection" -- CAPWAP included; both
//! `record_maybe_quic_bytes` and `record_maybe_zoom_bytes` skip a connection it recognizes, so
//! every connection lands in at most one of the eight protocol rows (the six real-parser rows
//! plus `MaybeQuic`/`MaybeZoom`). `MaybeIperf3` has no such guard, so it's the one row that can
//! still double-count against any of the others.
//!
//! `MaybeQuic` and `MaybeZoom` need no such guard against each other: their first-byte tests
//! are disjoint (`ZOOM_FIRST_BYTES` all have their top two bits `00`; a QUIC short header
//! requires `01`), and their accept thresholds sum to more than one
//! (`MAYBE_QUIC_MIN_FRACTION` + `MAYBE_ZOOM_MIN_FRACTION` = 0.9 + 0.95 > 1.0), so no packet
//! sequence can clear both within the same window.
//!
//! ## `--min-bytes`
//! Passing `--min-bytes N` excludes any connection whose own total on-wire byte count (see
//! "Byte unit" above; handshake + payload + headers for `EncBytes`, tcp + udp for
//! `TransportBytes`, payload + headers for `WireBytes`) is not more than `N` --
//! its packets never reach any global counter at all, rather than being counted and then
//! subtracted out. The check happens once per connection, in each callback's own
//! `L4Terminated` handler, using that connection's own running total; the two callbacks never
//! need to compare notes, since a connection matched by both tracks the same packets and so
//! arrives at the same total independently. Default is 0, i.e. no filtering.

use clap::Parser;
use iris_compiler::{callback, datatype, datatype_fn, input_files, iris_end_macros};
use iris_core::protocols::packet::tcp::TCP_PROTOCOL;
use iris_core::protocols::packet::udp::UDP_PROTOCOL;
use iris_core::protocols::stream::SessionProto;
use iris_core::subscription::Tracked;
use iris_core::{config::load_config, L4Pdu, Runtime};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use lazy_static::lazy_static;

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,

    /// Only count a connection (and the packets in it) if its total on-wire byte count
    /// (see module docs -- full packets, headers included) is more than N. 0 (the default)
    /// counts every connection.
    #[clap(short, long, value_name = "N", default_value_t = 0)]
    min_bytes: usize,
}

/// Set from `--min-bytes`, read once per connection at `L4Terminated` by both
/// `record_enc_bytes` and `record_transport_bytes`. 0 means no filtering.
static MIN_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Whether a connection with `total_bytes` clears the `--min-bytes` bar, i.e. should be
/// counted. "More than" is strict, so a connection with exactly `min_bytes` bytes is excluded.
fn clears_min_bytes(total_bytes: usize, min_bytes: usize) -> bool {
    total_bytes > min_bytes
}

#[cfg(test)]
mod min_bytes_tests {
    use super::*;

    #[test]
    fn zero_threshold_excludes_only_empty_connections() {
        assert!(!clears_min_bytes(0, 0));
        assert!(clears_min_bytes(1, 0));
    }

    #[test]
    fn strictly_greater_than() {
        assert!(!clears_min_bytes(100, 100));
        assert!(clears_min_bytes(101, 100));
        assert!(!clears_min_bytes(0, 100));
    }
}

/// Running handshake/payload/header byte totals for one encrypted protocol. See "Byte unit"
/// in the module docs for what each bucket holds; together they account for every on-wire
/// byte of every connection that landed in this protocol's row.
struct ByteTotals {
    handshake: AtomicUsize,
    payload: AtomicUsize,
    headers: AtomicUsize,
}

impl ByteTotals {
    fn new() -> Self {
        Self {
            handshake: AtomicUsize::new(0),
            payload: AtomicUsize::new(0),
            headers: AtomicUsize::new(0),
        }
    }

    fn add(&self, handshake: usize, payload: usize, headers: usize) {
        self.handshake.fetch_add(handshake, Ordering::Relaxed);
        self.payload.fetch_add(payload, Ordering::Relaxed);
        self.headers.fetch_add(headers, Ordering::Relaxed);
    }
}

/// Splits one packet's `wire` on-wire bytes into `(payload, headers)`: the L4 payload, and
/// everything else in the frame (Ethernet + IP + TCP/UDP headers, plus any Ethernet padding).
///
/// `offset` is `L4Context::offset` and `length` is `L4Context::length`. Both are taken as
/// upper bounds rather than trusted outright -- `length` comes from the IP header's declared
/// total length, which a truncated or malformed capture can inflate past what the frame
/// actually holds. Clamping payload to what's really there, then defining headers as the
/// remainder, keeps `payload + headers == wire` unconditionally, so the printed buckets always
/// partition the connection's bytes. See "Byte unit" in the module docs.
fn split_wire_bytes(wire: usize, offset: usize, length: usize) -> (usize, usize) {
    let payload = length.min(wire.saturating_sub(offset));
    (payload, wire - payload)
}

#[cfg(test)]
mod split_wire_bytes_tests {
    use super::*;

    /// A typical full-size TCP frame: 14 (Ethernet) + 20 (IPv4) + 20 (TCP) of header.
    #[test]
    fn splits_a_normal_frame() {
        assert_eq!(split_wire_bytes(1514, 54, 1460), (1460, 54));
    }

    /// A 60-byte pure ACK: no payload, and the 6 bytes of Ethernet padding past the headers
    /// are overhead, so the whole frame is header bytes.
    #[test]
    fn pads_count_as_headers_not_payload() {
        assert_eq!(split_wire_bytes(60, 54, 0), (0, 60));
    }

    /// A capture whose IP header declares more payload than the frame carries: payload is
    /// clamped to the bytes actually present rather than exceeding the frame.
    #[test]
    fn clamps_a_declared_length_past_the_end_of_the_frame() {
        assert_eq!(split_wire_bytes(200, 54, 1460), (146, 54));
    }

    /// Whatever the inputs, the two halves always sum back to the full frame.
    #[test]
    fn always_partitions_the_frame() {
        for &(wire, offset, length) in &[
            (1514, 54, 1460),
            (60, 54, 0),
            (200, 54, 1460),
            (42, 54, 0),
            (0, 0, 0),
        ] {
            let (payload, headers) = split_wire_bytes(wire, offset, length);
            assert_eq!(payload + headers, wire, "{wire}/{offset}/{length}");
        }
    }
}

lazy_static! {
    static ref TLS_BYTES: ByteTotals = ByteTotals::new();
    static ref SSH_BYTES: ByteTotals = ByteTotals::new();
    static ref QUIC_BYTES: ByteTotals = ByteTotals::new();
    static ref WIREGUARD_BYTES: ByteTotals = ByteTotals::new();
    static ref IKE_BYTES: ByteTotals = ByteTotals::new();
    static ref CAPWAP_BYTES: ByteTotals = ByteTotals::new();
    static ref MAYBE_QUIC_BYTES: ByteTotals = ByteTotals::new();
    static ref MAYBE_ZOOM_BYTES: ByteTotals = ByteTotals::new();
    static ref MAYBE_IPERF3_BYTES: ByteTotals = ByteTotals::new();
    static ref TCP_BYTES: AtomicUsize = AtomicUsize::new(0);
    static ref UDP_BYTES: AtomicUsize = AtomicUsize::new(0);
}

/// Per-connection handshake/payload/header byte split.
///
/// This is a `Tracked` datatype, not accumulation inside the callback, and that distinction
/// is load-bearing -- see "Why a datatype and not a callback" in the module docs. It reacts
/// only to generic `L4Pdu`/state-transition events, so it never needs to know which of the
/// six protocols it is looking at; `record_enc_bytes` reads `SessionProto` at teardown to
/// decide which bucket the result lands in.
#[datatype]
struct EncBytes {
    in_payload: bool,
    handshake_bytes: usize,
    payload_bytes: usize,
    header_bytes: usize,
}

impl EncBytes {
    fn total(&self) -> usize {
        self.handshake_bytes + self.payload_bytes + self.header_bytes
    }

    #[datatype_fn("EncBytes,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) {
        let len = pdu.mbuf.data_len();
        if self.in_payload {
            let (payload, headers) = split_wire_bytes(len, pdu.ctxt.offset, pdu.ctxt.length);
            self.payload_bytes += payload;
            self.header_bytes += headers;
        } else {
            // Handshake packets are counted as whole frames -- their own header/payload split
            // isn't the question this app is asking of them.
            self.handshake_bytes += len;
        }
    }

    /// Fires exactly once, when the L7 headers finish. See the module docs for why this
    /// (rather than `app_offset`) is the reliable signal.
    ///
    /// `SessionProto` is requested only because a `datatype_fn` must take at least one
    /// parameter (`datatype_func_to_tokens` panics otherwise). It is the cheapest builtin
    /// available at this level -- a plain `last_protocol()` read -- and registers no parser.
    #[datatype_fn("EncBytes,level=L7EndHdrs")]
    fn end_handshake(&mut self, _proto: &SessionProto) {
        self.in_payload = true;
    }
}

impl Tracked for EncBytes {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            in_payload: false,
            handshake_bytes: 0,
            payload_bytes: 0,
            header_bytes: 0,
        }
    }

    fn clear(&mut self) {
        self.in_payload = false;
        self.handshake_bytes = 0;
        self.payload_bytes = 0;
        self.header_bytes = 0;
    }
}

/// The `ByteTotals` bucket a connection identified as `proto` by a real L7 parser lands in, or
/// `None` if no such parser claimed it (`SessionProto::Null`/`Probing`, or another protocol
/// this app doesn't track). This is the single source of truth for "a real parser already
/// claimed this connection" -- both `record_maybe_quic_bytes` and `record_maybe_zoom_bytes`
/// call it to skip connections it recognizes. See "`MaybeQuic`/`MaybeZoom`/`MaybeIperf3` bytes"
/// above.
fn enc_totals(proto: &SessionProto) -> Option<&'static ByteTotals> {
    match proto {
        SessionProto::Tls => Some(&*TLS_BYTES),
        SessionProto::Ssh => Some(&*SSH_BYTES),
        SessionProto::Quic => Some(&*QUIC_BYTES),
        SessionProto::Wireguard => Some(&*WIREGUARD_BYTES),
        SessionProto::Ike => Some(&*IKE_BYTES),
        SessionProto::Capwap => Some(&*CAPWAP_BYTES),
        _ => None,
    }
}

#[cfg(test)]
mod enc_totals_tests {
    use super::*;

    #[test]
    fn recognizes_every_tracked_protocol() {
        for proto in [
            SessionProto::Tls,
            SessionProto::Ssh,
            SessionProto::Quic,
            SessionProto::Wireguard,
            SessionProto::Ike,
            SessionProto::Capwap,
        ] {
            assert!(
                enc_totals(&proto).is_some(),
                "enc_totals should recognize {proto:?}"
            );
        }
    }

    #[test]
    fn ignores_undiscovered_and_unhandled_protocols() {
        for proto in [SessionProto::Null, SessionProto::Probing, SessionProto::Dns] {
            assert!(
                enc_totals(&proto).is_none(),
                "enc_totals should not recognize {proto:?}"
            );
        }
    }
}

/// The filter's OR predicate registers all six parsers; `SessionProto`, read once the
/// connection is torn down, says which one actually matched.
///
/// The CAPWAP term is `capwap.preamble_type = 1`, not bare `capwap`, so that only
/// DTLS-encapsulated CAPWAP connections are counted here -- see "CAPWAP bytes" in the module
/// docs. `preamble_type = 1` is `is_dtls()` spelled as a filter predicate: `is_dtls()` itself
/// returns `bool`, which the filter DSL can't compare against a literal (see
/// `core/src/filter/ast.rs`'s `Value` enum), but the `u8` it's derived from can.
#[callback("tls or ssh or quic or wireguard or ike or capwap.preamble_type = 1,level=L4Terminated")]
fn record_enc_bytes(bytes: &EncBytes, proto: &SessionProto) {
    let Some(totals) = enc_totals(proto) else {
        return;
    };
    // Below the bar: none of this connection's bytes are added, not even to a "dropped"
    // bucket -- excluded connections are invisible to every printed total.
    if !clears_min_bytes(bytes.total(), MIN_BYTES.load(Ordering::Relaxed)) {
        return;
    }
    totals.add(
        bytes.handshake_bytes,
        bytes.payload_bytes,
        bytes.header_bytes,
    );
}

/// Per-connection tracked datatype for total TCP/UDP traffic, independent of whether an
/// application-layer protocol was ever identified on the connection.
#[datatype]
struct TransportBytes {
    tcp_bytes: usize,
    udp_bytes: usize,
}

impl TransportBytes {
    #[datatype_fn("TransportBytes,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) {
        let len = pdu.mbuf.data_len();
        match pdu.ctxt.proto {
            TCP_PROTOCOL => self.tcp_bytes += len,
            UDP_PROTOCOL => self.udp_bytes += len,
            _ => {}
        }
    }
}

impl Tracked for TransportBytes {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            tcp_bytes: 0,
            udp_bytes: 0,
        }
    }

    fn clear(&mut self) {
        self.tcp_bytes = 0;
        self.udp_bytes = 0;
    }
}

#[callback("tcp or udp,level=L4Terminated")]
fn record_transport_bytes(bytes: &TransportBytes) {
    // Same threshold, applied to this callback's own total; see the `--min-bytes` module docs
    // for why the two callbacks don't need to coordinate to agree on which connections count.
    let total = bytes.tcp_bytes + bytes.udp_bytes;
    if !clears_min_bytes(total, MIN_BYTES.load(Ordering::Relaxed)) {
        return;
    }
    TCP_BYTES.fetch_add(bytes.tcp_bytes, Ordering::Relaxed);
    UDP_BYTES.fetch_add(bytes.udp_bytes, Ordering::Relaxed);
}

/// Per-connection on-wire byte count, split into payload and headers, standing in for the
/// shared `iris_datatypes::ByteCount` for `MaybeQuic`/`MaybeZoom`/`MaybeIperf3`. `ByteCount`
/// is a single total and is defined to exclude headers (`datatypes/src/conn_fts.rs`), which
/// would put these three rows on a different unit than `EncBytes`/`TransportBytes` above --
/// see "Byte unit" in the module docs.
///
/// There's no handshake bucket here: these are heuristic filters with no `L7EndHdrs` event, so
/// every packet is split as `EncBytes` splits its post-handshake packets.
#[datatype]
struct WireBytes {
    payload_bytes: usize,
    header_bytes: usize,
}

impl WireBytes {
    fn total(&self) -> usize {
        self.payload_bytes + self.header_bytes
    }

    #[datatype_fn("WireBytes,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) {
        let (payload, headers) =
            split_wire_bytes(pdu.mbuf.data_len(), pdu.ctxt.offset, pdu.ctxt.length);
        self.payload_bytes += payload;
        self.header_bytes += headers;
    }
}

impl Tracked for WireBytes {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            payload_bytes: 0,
            header_bytes: 0,
        }
    }

    fn clear(&mut self) {
        self.payload_bytes = 0;
        self.header_bytes = 0;
    }
}

/// `MaybeQuic`/`MaybeZoom` are heuristic filters, not real L7 parsers, so there's no handshake
/// to split out -- the whole connection is accounted as payload plus headers. See the module
/// docs.
///
/// `proto` is checked first: a connection a real parser already claimed (see `enc_totals`) is
/// skipped here, so it isn't double-counted in both its protocol's row and this one.
#[callback("MaybeQuic,level=L4Terminated")]
fn record_maybe_quic_bytes(bytes: &WireBytes, proto: &SessionProto) {
    if enc_totals(proto).is_some() {
        return;
    }
    let total = bytes.total();
    if !clears_min_bytes(total, MIN_BYTES.load(Ordering::Relaxed)) {
        return;
    }
    MAYBE_QUIC_BYTES.add(0, bytes.payload_bytes, bytes.header_bytes);
}

#[callback("MaybeZoom,level=L4Terminated")]
fn record_maybe_zoom_bytes(bytes: &WireBytes, proto: &SessionProto) {
    if enc_totals(proto).is_some() {
        return;
    }
    let total = bytes.total();
    if !clears_min_bytes(total, MIN_BYTES.load(Ordering::Relaxed)) {
        return;
    }
    MAYBE_ZOOM_BYTES.add(0, bytes.payload_bytes, bytes.header_bytes);
}

#[callback("MaybeIperf3,level=L4Terminated")]
fn record_maybe_iperf3_bytes(bytes: &WireBytes) {
    let total = bytes.total();
    if !clears_min_bytes(total, MIN_BYTES.load(Ordering::Relaxed)) {
        return;
    }
    MAYBE_IPERF3_BYTES.add(0, bytes.payload_bytes, bytes.header_bytes);
}

/// Returns `100 * numerator / denominator` as a percentage, or `None` if `denominator` is
/// zero (e.g. a protocol that was never observed in this trace).
fn pct(numerator: usize, denominator: usize) -> Option<f64> {
    if denominator == 0 {
        return None;
    }
    Some(100.0 * numerator as f64 / denominator as f64)
}

fn fmt_pct(p: Option<f64>) -> String {
    match p {
        Some(p) => format!("{:>6.2}%", p),
        None => "   n/a ".to_string(),
    }
}

/// Prints one protocol's handshake/payload/header split and its share of total transport
/// traffic. The three splits are percentages of this protocol's own bytes and sum to 100%.
fn print_proto(name: &str, totals: &ByteTotals, transport_total: usize) {
    let handshake = totals.handshake.load(Ordering::Relaxed);
    let payload = totals.payload.load(Ordering::Relaxed);
    let headers = totals.headers.load(Ordering::Relaxed);
    let total = handshake + payload + headers;
    println!(
        "{:<12} handshake: {}   payload: {}   headers: {}   of total traffic: {}    (raw: {})",
        name,
        fmt_pct(pct(handshake, total)),
        fmt_pct(pct(payload, total)),
        fmt_pct(pct(headers, total)),
        fmt_pct(pct(total, transport_total)),
        total,
    );
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();
    MIN_BYTES.store(args.min_bytes, Ordering::Relaxed);
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    let tcp_bytes = TCP_BYTES.load(Ordering::Relaxed);
    let udp_bytes = UDP_BYTES.load(Ordering::Relaxed);
    let transport_total = tcp_bytes + udp_bytes;

    println!(
        "\n(Byte counts below are on-wire bytes -- full captured frames, Ethernet/IP/TCP/UDP \
         headers included. A protocol's `handshake` is whole frames up to the end of its L7 \
         headers; after that each frame is itemized into its L4 `payload` and the \
         Ethernet/IP/TCP/UDP `headers` carrying it, so the three sum to 100% of that \
         protocol's bytes. Same unit as this runtime's own \"Processed: N pkts, M bytes\" line \
         above (both sum a packet's full `mbuf.data_len()`), though the two totals still won't \
         necessarily match; see the module docs.)"
    );
    if args.min_bytes > 0 {
        println!(
            "\n(Connections with {} or fewer total on-wire bytes are excluded from every \
             count below.)",
            args.min_bytes
        );
    }
    println!(
        "\n=== Encrypted protocol bytes: handshake % vs. payload % vs. header %, \
         and % of total transport traffic ==="
    );
    print_proto("TLS", &TLS_BYTES, transport_total);
    print_proto("SSH", &SSH_BYTES, transport_total);
    print_proto("QUIC", &QUIC_BYTES, transport_total);
    print_proto("WireGuard", &WIREGUARD_BYTES, transport_total);
    print_proto("IKE", &IKE_BYTES, transport_total);
    print_proto("CAPWAP-DTLS", &CAPWAP_BYTES, transport_total);
    print_proto("MaybeQUIC", &MAYBE_QUIC_BYTES, transport_total);
    print_proto("MaybeZoom", &MAYBE_ZOOM_BYTES, transport_total);
    print_proto("MaybeIperf3", &MAYBE_IPERF3_BYTES, transport_total);

    println!("\n=== Total transport-layer traffic ===");
    println!("TCP: {}", fmt_pct(pct(tcp_bytes, transport_total)));
    println!("UDP: {}", fmt_pct(pct(udp_bytes, transport_total)));
}
