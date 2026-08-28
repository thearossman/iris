//! CAPWAP transport/control header parser.
//!
//! [RFC 5415](https://datatracker.ietf.org/doc/rfc5415/) §4.3 defines the transport header
//! shared by both channels; §4.5.1 defines the control header, present only on messages sent
//! on the control channel (UDP port 5246). The data channel (UDP port 5247) carries only the
//! transport header before 802.11/802.3 payload.
//!
//! CAPWAP's plaintext preamble byte is `0x00`, which is far too common in arbitrary UDP
//! payloads for a structural match alone to be [`ProbeResult::Certain`] -- so
//! [`classify_probe`] treats a structurally valid transport header plus a plausible
//! base-spec control header as unambiguous (certain regardless of port), and otherwise falls
//! back to the port as a tiebreaker, in the same spirit as the IKE parser.
//!
//! ## Discovery doesn't finalize a session
//! [RFC 5415] §2.3 guarantees that a connection's Discovery Request/Response messages are
//! always sent in the clear, and that every other control message MUST be DTLS-protected --
//! so a control-channel connection whose first observed message is plaintext Discovery isn't
//! necessarily unencrypted overall; DTLS setup and the encrypted Join/Configuration exchange
//! typically follow right after, on the same connection. [`Capwap::update`] accounts for
//! this: Discovery Request/Response don't finalize the session by themselves ([`is_discovery`]
//! decides), so [`preamble_type`](super::Capwap::preamble_type)/[`is_dtls`](super::Capwap::is_dtls)
//! end up reflecting whatever message actually settles the connection's encryption status,
//! not just whichever one happened to arrive first.

use super::{Capwap, Channel, MsgType};
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::{
    ConnParsable, ParseResult, ParsingState, ProbeResult, Session, SessionData,
};

/// The two standard CAPWAP ports.
const CAPWAP_CONTROL_PORT: u16 = 5246;
const CAPWAP_DATA_PORT: u16 = 5247;

/// Size of the fixed part of the transport header, before the optional Radio MAC Address and
/// Wireless Specific Information fields.
const MIN_TRANSPORT_HEADER_LEN: usize = 8;
/// Minimum valid HLEN (the transport header, in 4-byte words, must cover at least the fixed
/// part above).
const MIN_HLEN: u8 = 2;
/// Size of the fixed control header.
const CONTROL_HEADER_LEN: usize = 8;

/// Base-spec control message types occupy 1..=26; see [`super::MsgType`].
const BASE_SPEC_MSG_TYPE_RANGE: std::ops::RangeInclusive<u32> = 1..=26;

/// Fields decoded from a CAPWAP transport header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransportHeaderFields {
    pub(crate) version: u8,
    pub(crate) preamble_type: u8,
    pub(crate) hlen: u8,
    pub(crate) header_len: usize,
    pub(crate) rid: u8,
    pub(crate) wbid: u8,
    pub(crate) payload_type: u8,
    pub(crate) is_fragment: bool,
    pub(crate) last_fragment: bool,
    pub(crate) keep_alive: bool,
    pub(crate) fragment_id: u16,
    pub(crate) fragment_offset: u16,
    pub(crate) radio_mac: Option<Vec<u8>>,
    pub(crate) wireless_info: Option<Vec<u8>>,
}

/// Fields decoded from a CAPWAP control header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ControlHeaderFields {
    pub(crate) vendor_id: u32,
    pub(crate) msg_type_value: u32,
    pub(crate) msg_type_id: u32,
    pub(crate) seq_num: u8,
    pub(crate) msg_element_length: u16,
    #[allow(dead_code)]
    pub(crate) flags: u8,
}

/// Reads a length-prefixed, 4-byte-padded optional field (Radio MAC Address or Wireless
/// Specific Information) starting at `pos`. Returns the field's value and the offset of the
/// next field, or `None` if the field's length byte, value, or padding would run past `pos`
/// itself being out of range, `data`, or `header_len`.
fn read_optional_field(data: &[u8], pos: usize, header_len: usize) -> Option<(Vec<u8>, usize)> {
    if pos >= header_len || pos >= data.len() {
        return None;
    }
    let len = data[pos] as usize;
    let value_start = pos + 1;
    let value_end = value_start + len;
    if value_end > header_len || value_end > data.len() {
        return None;
    }
    let consumed = 1 + len;
    let padded = consumed.div_ceil(4) * 4;
    let next = pos + padded;
    if next > header_len {
        return None;
    }
    Some((data[value_start..value_end].to_vec(), next))
}

/// Parses `data` as a CAPWAP transport header. Returns `None` if `data` is too short, the
/// version is not 0, the preamble type is not 0 (plaintext) or 1 (DTLS), `HLEN` is less than
/// the minimum, the header (per `HLEN`) extends past `data`, any reserved bit is set, or an
/// optional Radio MAC / Wireless Specific Information field is malformed or runs past the
/// header.
pub(crate) fn parse_transport_header(data: &[u8]) -> Option<TransportHeaderFields> {
    if data.len() < MIN_TRANSPORT_HEADER_LEN {
        return None;
    }

    let version = data[0] >> 4;
    if version != 0 {
        return None;
    }
    let preamble_type = data[0] & 0x0F;
    if preamble_type > 1 {
        return None;
    }

    let hlen = data[1] >> 3;
    if hlen < MIN_HLEN {
        return None;
    }
    let header_len = hlen as usize * 4;
    if header_len > data.len() {
        return None;
    }

    let rid = ((data[1] & 0x07) << 2) | (data[2] >> 6);
    let wbid = (data[2] >> 1) & 0x1F;
    let payload_type = data[2] & 0x01;

    let flags = data[3];
    if flags & 0x07 != 0 {
        return None;
    }
    let is_fragment = flags & 0x80 != 0;
    let last_fragment = flags & 0x40 != 0;
    let wireless_info_flag = flags & 0x20 != 0;
    let radio_mac_flag = flags & 0x10 != 0;
    let keep_alive = flags & 0x08 != 0;

    let fragment_id = u16::from_be_bytes([data[4], data[5]]);
    let frag_raw = u16::from_be_bytes([data[6], data[7]]);
    if frag_raw & 0x07 != 0 {
        return None;
    }
    let fragment_offset = frag_raw >> 3;

    let mut pos = MIN_TRANSPORT_HEADER_LEN;
    let mut radio_mac = None;
    if radio_mac_flag {
        let (value, next) = read_optional_field(data, pos, header_len)?;
        radio_mac = Some(value);
        pos = next;
    }
    let mut wireless_info = None;
    if wireless_info_flag {
        let (value, _next) = read_optional_field(data, pos, header_len)?;
        wireless_info = Some(value);
    }

    Some(TransportHeaderFields {
        version,
        preamble_type,
        hlen,
        header_len,
        rid,
        wbid,
        payload_type,
        is_fragment,
        last_fragment,
        keep_alive,
        fragment_id,
        fragment_offset,
        radio_mac,
        wireless_info,
    })
}

/// Parses `data` as a fixed CAPWAP control header. Only checks that enough bytes are present;
/// callers that need to know whether the *contents* are plausible (as opposed to merely
/// present) should use [`parse_base_spec_control_header`].
pub(crate) fn parse_control_header(data: &[u8]) -> Option<ControlHeaderFields> {
    if data.len() < CONTROL_HEADER_LEN {
        return None;
    }
    let msg_type_value = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    Some(ControlHeaderFields {
        vendor_id: msg_type_value >> 8,
        msg_type_value,
        msg_type_id: msg_type_value & 0xFF,
        seq_num: data[4],
        msg_element_length: u16::from_be_bytes([data[5], data[6]]),
        flags: data[7],
    })
}

/// Parses `data` (everything after the transport header) as a control header and returns it
/// only if it looks like an unambiguous base-spec control message: enterprise number 0,
/// a message type in the base-spec range, and a Message Element Length consistent with the
/// bytes actually remaining after the header.
fn parse_base_spec_control_header(data: &[u8]) -> Option<ControlHeaderFields> {
    let fields = parse_control_header(data)?;
    let remaining = data.len() - CONTROL_HEADER_LEN;
    if fields.vendor_id == 0
        && BASE_SPEC_MSG_TYPE_RANGE.contains(&fields.msg_type_id)
        && (fields.msg_element_length as usize) <= remaining
    {
        Some(fields)
    } else {
        None
    }
}

/// Returns `true` if `data` starts with a plausible DTLS record header: a content type in
/// 20..=25 followed by DTLS's `0xFE 0xFD` (1.2) or `0xFE 0xFF` (1.0) version bytes.
fn looks_like_dtls_record(data: &[u8]) -> bool {
    data.len() >= 3
        && (20..=25).contains(&data[0])
        && data[1] == 0xFE
        && matches!(data[2], 0xFD | 0xFF)
}

/// Decides the probe result for `data`, given whether it was observed on the standard CAPWAP
/// control port (5246) and/or data port (5247). Structural validity is checked regardless of
/// port; the port is used only to resolve otherwise-ambiguous headers. See the module docs.
pub(crate) fn classify_probe(
    data: &[u8],
    on_control_port: bool,
    on_data_port: bool,
) -> ProbeResult {
    let Some(fields) = parse_transport_header(data) else {
        return ProbeResult::NotForUs;
    };
    let on_known_port = on_control_port || on_data_port;
    let rest = &data[fields.header_len..];

    if fields.preamble_type == 1 {
        return if looks_like_dtls_record(rest) {
            if on_known_port {
                ProbeResult::Certain
            } else {
                ProbeResult::Unsure
            }
        } else {
            ProbeResult::NotForUs
        };
    }

    if parse_base_spec_control_header(rest).is_some() {
        return ProbeResult::Certain;
    }
    if on_known_port {
        ProbeResult::Certain
    } else {
        ProbeResult::Unsure
    }
}

/// Returns `true` if `msg_type_id` is a Discovery Request (1) or Discovery Response (2) --
/// the only two CAPWAP control messages [RFC 5415] guarantees are never DTLS-protected. See
/// [`Capwap::update`] for why that matters.
fn is_discovery(msg_type_id: u32) -> bool {
    matches!(msg_type_id, 1 | 2)
}

impl Capwap {
    /// Parses `data` as a CAPWAP message and folds it into the session summary. `channel_hint`
    /// is the channel implied by the UDP ports the message was observed on (or `Unknown` if
    /// neither matched); see [`Channel`] for how it's used to resolve the channel when a
    /// control header is absent or present unexpectedly.
    ///
    /// Returns `HeadersDone` -- and is not called again on this connection -- for most
    /// messages, since the transport (and, when applicable, control) header carries
    /// everything of interest in this scope. The exception is a plaintext Discovery
    /// Request/Response on the control channel: [RFC 5415] guarantees Discovery is
    /// unencrypted and precedes DTLS setup, so finalizing on it here would permanently and
    /// incorrectly report a connection that's about to go DTLS as unencrypted. For that case
    /// this returns `Continue` instead, so the caller keeps calling `update` on later packets
    /// until one arrives that actually settles the connection's encryption status (most
    /// commonly a DTLS record) or the connection ends -- see [`Capwap`] for what's delivered
    /// in the latter case.
    pub(crate) fn update(&mut self, data: &[u8], channel_hint: Channel) -> ParseResult {
        let Some(fields) = parse_transport_header(data) else {
            return ParseResult::Skipped;
        };

        self.version = fields.version;
        self.preamble_type = fields.preamble_type;
        self.hlen = fields.hlen;
        self.rid = fields.rid;
        self.wbid = fields.wbid;
        self.payload_type = fields.payload_type;
        self.is_fragment = fields.is_fragment;
        self.last_fragment = fields.last_fragment;
        self.keep_alive = fields.keep_alive;
        self.fragment_id = fields.fragment_id;
        self.fragment_offset = fields.fragment_offset;
        self.radio_mac = fields.radio_mac;
        self.wireless_info = fields.wireless_info;

        if fields.preamble_type == 1 {
            // DTLS: the transport header is in the clear, but everything after it is an
            // encrypted DTLS record -- there is no control header to extract. See the
            // module docs.
            self.channel = channel_hint;
            self.msg_type = MsgType::None;
            return ParseResult::HeadersDone(0);
        }

        let rest = &data[fields.header_len..];
        match channel_hint {
            Channel::Data => {
                self.channel = Channel::Data;
                self.msg_type = MsgType::None;
                ParseResult::HeadersDone(0)
            }
            Channel::Control => match parse_control_header(rest) {
                Some(c) => self.apply_control_header_and_decide(c),
                None => {
                    self.channel = Channel::Control;
                    self.msg_type = MsgType::None;
                    ParseResult::HeadersDone(0)
                }
            },
            Channel::Unknown => match parse_base_spec_control_header(rest) {
                Some(c) => self.apply_control_header_and_decide(c),
                None => {
                    self.channel = Channel::Data;
                    self.msg_type = MsgType::None;
                    ParseResult::HeadersDone(0)
                }
            },
        }
    }

    /// Applies a parsed control header to the session and decides whether it finalizes
    /// parsing: a Discovery Request/Response defers (`Continue`) so a later, more decisive
    /// message on the same connection can supersede it; everything else finalizes
    /// (`HeadersDone`) immediately. See [`Capwap::update`] and [`is_discovery`].
    fn apply_control_header_and_decide(&mut self, fields: ControlHeaderFields) -> ParseResult {
        let defer = is_discovery(fields.msg_type_id);
        self.apply_control_header(fields);
        if defer {
            ParseResult::Continue(0)
        } else {
            ParseResult::HeadersDone(0)
        }
    }

    fn apply_control_header(&mut self, fields: ControlHeaderFields) {
        self.vendor_id = fields.vendor_id;
        self.msg_type_value = fields.msg_type_value;
        self.msg_type_id = fields.msg_type_id;
        self.msg_type = MsgType::from_byte(fields.msg_type_id as u8);
        self.seq_num = fields.seq_num;
        self.msg_element_length = fields.msg_element_length;
        self.channel = Channel::Control;
    }
}

/// Returns the CAPWAP channel implied by the UDP ports a message was observed on, or
/// `Unknown` if neither is the standard control or data port.
fn channel_from_ports(dst_port: u16, src_port: u16) -> Channel {
    if dst_port == CAPWAP_CONTROL_PORT || src_port == CAPWAP_CONTROL_PORT {
        Channel::Control
    } else if dst_port == CAPWAP_DATA_PORT || src_port == CAPWAP_DATA_PORT {
        Channel::Data
    } else {
        Channel::Unknown
    }
}

#[derive(Debug)]
pub struct CapwapParser {
    sessions: Vec<Capwap>,
}

impl Default for CapwapParser {
    fn default() -> Self {
        CapwapParser {
            sessions: vec![Capwap::new()],
        }
    }
}

impl ConnParsable for CapwapParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        let channel = channel_from_ports(pdu.ctxt.dst.port(), pdu.ctxt.src.port());

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            if !self.sessions.is_empty() {
                return self.sessions[0].update(data, channel);
            }
            ParseResult::Skipped
        } else {
            log::warn!("Malformed packet on parse");
            ParseResult::Skipped
        }
    }

    fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        let offset = pdu.offset();
        let length = pdu.length();
        if length < MIN_TRANSPORT_HEADER_LEN {
            return ProbeResult::Unsure;
        }

        let dst_port = pdu.ctxt.dst.port();
        let src_port = pdu.ctxt.src.port();
        let on_control_port = dst_port == CAPWAP_CONTROL_PORT || src_port == CAPWAP_CONTROL_PORT;
        let on_data_port = dst_port == CAPWAP_DATA_PORT || src_port == CAPWAP_DATA_PORT;

        if let Ok(data) = (pdu.mbuf).get_data_slice(offset, length) {
            classify_probe(data, on_control_port, on_data_port)
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }

    fn remove_session(&mut self, _session_id: usize) -> Option<Session> {
        self.sessions.pop().map(|capwap| Session {
            data: SessionData::Capwap(Box::new(capwap)),
            id: 0,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain(..)
            .map(|capwap| Session {
                data: SessionData::Capwap(Box::new(capwap)),
                id: 0,
            })
            .collect()
    }

    fn session_parsed_state(&self) -> ParsingState {
        // Exactly one summary is produced per connection, so no further sessions are
        // expected. Reporting `Stop` lets conntrack clear the `Parse` action once the
        // session is delivered, rather than keeping the connection on the parse path for
        // the rest of its life to reach an unimplemented code path.
        ParsingState::Stop
    }

    /// CAPWAP payloads (message elements, 802.11/802.3 frames) are out of scope for this
    /// parser, so there is no application-layer body to offset into.
    fn body_offset(&mut self) -> Option<usize> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a transport header. `flags` is the raw byte for F/L/W/M/K (bits 7..3) with
    /// reserved bits 2..0 left at 0. `fragment_offset` is in 8-byte units (13 bits).
    #[allow(clippy::too_many_arguments)]
    fn build_transport_header(
        preamble_type: u8,
        hlen: u8,
        rid: u8,
        wbid: u8,
        t: u8,
        flags: u8,
        fragment_id: u16,
        fragment_offset: u16,
    ) -> Vec<u8> {
        let b0 = preamble_type & 0x0F; // version 0
        let b1 = (hlen << 3) | ((rid >> 2) & 0x07);
        let b2 = ((rid & 0x03) << 6) | ((wbid & 0x1F) << 1) | (t & 0x01);
        let b3 = flags & 0xF8;
        let frag_raw = (fragment_offset & 0x1FFF) << 3;
        let mut data = vec![b0, b1, b2, b3];
        data.extend_from_slice(&fragment_id.to_be_bytes());
        data.extend_from_slice(&frag_raw.to_be_bytes());
        data
    }

    fn build_control_header(
        vendor_id: u32,
        msg_type_id: u8,
        seq_num: u8,
        msg_element_length: u16,
    ) -> Vec<u8> {
        let msg_type_value = (vendor_id << 8) | msg_type_id as u32;
        let mut data = Vec::with_capacity(CONTROL_HEADER_LEN);
        data.extend_from_slice(&msg_type_value.to_be_bytes());
        data.push(seq_num);
        data.extend_from_slice(&msg_element_length.to_be_bytes());
        data.push(0); // flags
        data
    }

    const F: u8 = 0x80;
    const L: u8 = 0x40;
    const W: u8 = 0x20;
    const M: u8 = 0x10;
    const K: u8 = 0x08;

    fn discovery_request() -> Vec<u8> {
        let mut data = build_transport_header(0, 2, 3, 7, 1, 0, 0x1234, 0);
        data.extend_from_slice(&build_control_header(0, 1, 5, 0));
        data
    }

    fn discovery_response() -> Vec<u8> {
        let mut data = build_transport_header(0, 2, 3, 7, 1, 0, 0x1234, 0);
        data.extend_from_slice(&build_control_header(0, 2, 5, 0));
        data
    }

    /// A Join Request -- like Discovery, a plaintext control-channel message, but (unlike
    /// Discovery) one that finalizes parsing immediately, since [RFC 5415] only exempts
    /// Discovery Request/Response from the DTLS-protection requirement.
    fn join_request() -> Vec<u8> {
        let mut data = build_transport_header(0, 2, 3, 7, 1, 0, 0x1234, 0);
        data.extend_from_slice(&build_control_header(0, 3, 5, 0));
        data
    }

    /// A DTLS Handshake record (ClientHello), DTLS 1.2 -- the message that would normally
    /// follow Discovery once the WTP starts securing the control channel.
    fn dtls_client_hello() -> Vec<u8> {
        let mut data = build_transport_header(1, 2, 3, 7, 1, 0, 0x1234, 0);
        data.extend_from_slice(&[22, 0xFE, 0xFD]);
        data
    }

    #[test]
    fn parses_plaintext_control_channel_join_request() {
        let data = join_request();
        let mut capwap = Capwap::new();
        assert_eq!(
            capwap.update(&data, Channel::Control),
            ParseResult::HeadersDone(0)
        );

        assert_eq!(capwap.version(), 0);
        assert_eq!(capwap.preamble_type(), 0);
        assert!(!capwap.is_dtls());
        assert_eq!(capwap.hlen(), 2);
        assert_eq!(capwap.rid(), 3);
        assert_eq!(capwap.wbid(), 7);
        assert_eq!(capwap.payload_type(), 1);
        assert_eq!(capwap.fragment_id(), 0x1234);
        assert_eq!(capwap.fragment_offset(), 0);
        assert_eq!(capwap.vendor_id(), 0);
        assert_eq!(capwap.msg_type_id(), 3);
        assert_eq!(capwap.msg_type(), MsgType::JoinRequest);
        assert_eq!(capwap.seq_num(), 5);
        assert_eq!(capwap.msg_element_length(), 0);
        assert_eq!(capwap.channel(), Channel::Control);
    }

    #[test]
    fn discovery_request_defers_finalization() {
        let data = discovery_request();
        let mut capwap = Capwap::new();
        assert_eq!(
            capwap.update(&data, Channel::Control),
            ParseResult::Continue(0)
        );
        // Best-effort snapshot: reflects the Discovery message seen so far, even though
        // parsing hasn't finalized.
        assert_eq!(capwap.msg_type(), MsgType::DiscoveryRequest);
        assert_eq!(capwap.channel(), Channel::Control);
    }

    #[test]
    fn discovery_response_also_defers_finalization() {
        let data = discovery_response();
        let mut capwap = Capwap::new();
        assert_eq!(
            capwap.update(&data, Channel::Control),
            ParseResult::Continue(0)
        );
        assert_eq!(capwap.msg_type(), MsgType::DiscoveryResponse);
    }

    #[test]
    fn repeated_discovery_messages_keep_deferring() {
        let mut capwap = Capwap::new();
        assert_eq!(
            capwap.update(&discovery_request(), Channel::Control),
            ParseResult::Continue(0)
        );
        assert_eq!(
            capwap.update(&discovery_request(), Channel::Control),
            ParseResult::Continue(0)
        );
        assert_eq!(capwap.msg_type(), MsgType::DiscoveryRequest);
    }

    #[test]
    fn discovery_then_dtls_finalizes_as_encrypted() {
        let mut capwap = Capwap::new();
        assert_eq!(
            capwap.update(&discovery_request(), Channel::Control),
            ParseResult::Continue(0)
        );
        assert!(!capwap.is_dtls());

        assert_eq!(
            capwap.update(&dtls_client_hello(), Channel::Control),
            ParseResult::HeadersDone(0)
        );
        assert!(capwap.is_dtls());
        assert_eq!(capwap.preamble_type(), 1);
    }

    #[test]
    fn discovery_then_non_discovery_control_message_finalizes() {
        let mut capwap = Capwap::new();
        assert_eq!(
            capwap.update(&discovery_request(), Channel::Control),
            ParseResult::Continue(0)
        );
        assert_eq!(
            capwap.update(&join_request(), Channel::Control),
            ParseResult::HeadersDone(0)
        );
        assert_eq!(capwap.msg_type(), MsgType::JoinRequest);
        assert!(!capwap.is_dtls());
    }

    #[test]
    fn discovery_on_unknown_port_defers_and_marks_control_channel() {
        let data = discovery_request();
        let mut capwap = Capwap::new();
        assert_eq!(
            capwap.update(&data, Channel::Unknown),
            ParseResult::Continue(0)
        );
        // A valid base-spec control header, even a deferred one, is enough to resolve the
        // channel to `Control`.
        assert_eq!(capwap.channel(), Channel::Control);
    }

    #[test]
    fn parses_radio_mac_when_m_flag_set() {
        // Fixed 8 bytes + Radio MAC field (1 length byte + 6-byte MAC, padded to 8) = 16
        // bytes total -> HLEN = 4.
        let mut data = build_transport_header(0, 4, 0, 0, 0, M, 0, 0);
        data.push(6); // Radio MAC length
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        data.push(0); // padding to 4-byte boundary

        let mut capwap = Capwap::new();
        assert_eq!(
            capwap.update(&data, Channel::Data),
            ParseResult::HeadersDone(0)
        );
        assert_eq!(
            capwap.radio_mac(),
            Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF].as_slice())
        );
        assert_eq!(capwap.wireless_info(), None);
    }

    #[test]
    fn parses_radio_mac_and_wireless_info_when_m_and_w_flags_set() {
        // Fixed 8 bytes + Radio MAC (1 + 6 = 7, padded to 8) + Wireless Info (1 + 3 = 4,
        // already aligned) = 8 + 8 + 4 = 20 bytes -> HLEN = 5.
        let mut data = build_transport_header(0, 5, 0, 0, 0, M | W, 0, 0);
        data.push(6); // Radio MAC length
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        data.push(0); // padding to 4-byte boundary
        data.push(3); // Wireless Info length
        data.extend_from_slice(&[0x01, 0x02, 0x03]);

        let mut capwap = Capwap::new();
        assert_eq!(
            capwap.update(&data, Channel::Data),
            ParseResult::HeadersDone(0)
        );
        assert_eq!(
            capwap.radio_mac(),
            Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF].as_slice())
        );
        assert_eq!(capwap.wireless_info(), Some([0x01, 0x02, 0x03].as_slice()));
    }

    #[test]
    fn parses_fragment_flags() {
        let data = build_transport_header(0, 2, 0, 0, 0, F | L, 5, 10);
        let mut capwap = Capwap::new();
        assert_eq!(
            capwap.update(&data, Channel::Data),
            ParseResult::HeadersDone(0)
        );
        assert!(capwap.is_fragment());
        assert!(capwap.last_fragment());
        assert_eq!(capwap.fragment_id(), 5);
        assert_eq!(capwap.fragment_offset(), 10);
    }

    #[test]
    fn parses_data_channel_keep_alive() {
        let data = build_transport_header(0, 2, 0, 0, 0, K, 0, 0);
        let mut capwap = Capwap::new();
        assert_eq!(
            capwap.update(&data, Channel::Data),
            ParseResult::HeadersDone(0)
        );
        assert!(capwap.keep_alive());
        assert_eq!(capwap.msg_type(), MsgType::None);
        assert_eq!(capwap.channel(), Channel::Data);
    }

    #[test]
    fn rejects_radio_mac_field_running_past_hlen() {
        // HLEN=2 (8 bytes -- no room for the M-flagged Radio MAC field at all).
        let mut data = build_transport_header(0, 2, 0, 0, 0, M, 0, 0);
        data.push(6);
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        data.push(0);
        assert_eq!(parse_transport_header(&data), None);
    }

    #[test]
    fn rejects_hlen_below_minimum() {
        let data = build_transport_header(0, 1, 0, 0, 0, 0, 0, 0);
        assert_eq!(parse_transport_header(&data), None);
    }

    #[test]
    fn rejects_hlen_extending_past_data() {
        // HLEN=3 (12 bytes) but only 8 bytes of data.
        let data = build_transport_header(0, 3, 0, 0, 0, 0, 0, 0);
        assert_eq!(parse_transport_header(&data), None);
    }

    #[test]
    fn rejects_nonzero_header_reserved_bits() {
        let mut data = build_transport_header(0, 2, 0, 0, 0, 0, 0, 0);
        data[3] |= 0x01; // set a reserved bit in byte 3
        assert_eq!(parse_transport_header(&data), None);
    }

    #[test]
    fn rejects_nonzero_fragment_reserved_bits() {
        let mut data = build_transport_header(0, 2, 0, 0, 0, 0, 0, 0);
        data[7] |= 0x01; // set a reserved bit in byte 7
        assert_eq!(parse_transport_header(&data), None);
    }

    #[test]
    fn rejects_nonzero_version() {
        let mut data = build_transport_header(0, 2, 0, 0, 0, 0, 0, 0);
        data[0] |= 0x10; // version = 1
        assert_eq!(parse_transport_header(&data), None);
    }

    #[test]
    fn probe_is_certain_off_port_for_valid_control_header() {
        let data = discovery_request();
        assert_eq!(classify_probe(&data, false, false), ProbeResult::Certain);
    }

    #[test]
    fn probe_uses_port_as_tiebreaker_for_bare_data_channel_header() {
        let data = build_transport_header(0, 2, 0, 0, 0, K, 0, 0);
        assert_eq!(classify_probe(&data, false, false), ProbeResult::Unsure);
        assert_eq!(classify_probe(&data, false, true), ProbeResult::Certain);
    }

    #[test]
    fn probe_rejects_structurally_invalid_header_regardless_of_port() {
        let mut data = build_transport_header(0, 2, 0, 0, 0, 0, 0, 0);
        data[0] |= 0x10; // version = 1
        assert_eq!(classify_probe(&data, true, false), ProbeResult::NotForUs);
    }

    #[test]
    fn probe_detects_dtls_encapsulated_capwap_on_control_port() {
        let mut data = build_transport_header(1, 2, 0, 0, 0, 0, 0, 0);
        data.extend_from_slice(&[22, 0xFE, 0xFD]); // DTLS Handshake record, DTLS 1.2
        assert_eq!(classify_probe(&data, true, false), ProbeResult::Certain);
        assert_eq!(classify_probe(&data, false, false), ProbeResult::Unsure);
    }

    #[test]
    fn session_skips_unrecognized_data() {
        let mut capwap = Capwap::new();
        assert_eq!(
            capwap.update(&[0u8; 4], Channel::Unknown),
            ParseResult::Skipped
        );
    }

    #[test]
    fn parser_reports_stop_so_conntrack_can_drop_the_parse_action() {
        let parser = CapwapParser::default();
        assert!(matches!(parser.session_parsed_state(), ParsingState::Stop));
    }
}
