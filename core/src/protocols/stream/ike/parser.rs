//! IKE (ISAKMP) header parser.
//!
//! Parses the fixed 28-byte ISAKMP/IKE header, which is byte-for-byte identical between
//! IKEv1 and IKEv2. All integer fields are big-endian (standard network byte order),
//! unlike WireGuard.
//!
//! IKE has no fixed magic bytes, and while it conventionally runs on UDP ports 500/4500, it
//! is not guaranteed to -- so [`classify_probe`] validates header structure first and only
//! falls back to the port as a tiebreaker for otherwise-ambiguous headers, rather than
//! requiring a specific port.

use super::{Ike, IkeExchangeType};
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::{
    ConnParsable, ParseResult, ParsingState, ProbeResult, Session, SessionData,
};

/// Size of the fixed ISAKMP/IKE header.
const IKE_HEADER_LEN: usize = 28;

/// The two standard IKE ports. UDP 4500 additionally carries a 4-byte "non-ESP marker"
/// prefix before the ISAKMP header, used to distinguish IKE from ESP-in-UDP.
const IKE_PORT: u16 = 500;
const IKE_NAT_T_PORT: u16 = 4500;

const FLAG_INITIATOR: u8 = 0x08;
const FLAG_RESPONSE: u8 = 0x20;

const EXCHANGE_TYPE_MIN: u8 = 34;
const EXCHANGE_TYPE_MAX: u8 = 37;

/// Fields decoded from a fixed ISAKMP/IKE header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IkeHeaderFields {
    pub(crate) initiator_spi: [u8; 8],
    pub(crate) responder_spi: [u8; 8],
    pub(crate) version_major: u8,
    pub(crate) version_minor: u8,
    pub(crate) exchange_type: u8,
    pub(crate) is_initiator: bool,
    pub(crate) is_response: bool,
    pub(crate) message_id: u32,
    pub(crate) length: u32,
}

/// Strips the 4-byte NAT-T "non-ESP marker" prefix from `data`, if `on_nat_t_port` and the
/// prefix is present.
pub(crate) fn strip_non_esp_marker(data: &[u8], on_nat_t_port: bool) -> &[u8] {
    if on_nat_t_port && data.len() >= 4 && data[0..4] == [0, 0, 0, 0] {
        &data[4..]
    } else {
        data
    }
}

/// Parses `data` as a fixed ISAKMP/IKE header. Returns `None` if `data` is too short, the
/// version's major nibble is not 1 or 2, or the header's `length` field is wildly
/// inconsistent with the amount of data available.
pub(crate) fn parse_ike_header(data: &[u8]) -> Option<IkeHeaderFields> {
    if data.len() < IKE_HEADER_LEN {
        return None;
    }

    let version_major = data[17] >> 4;
    let version_minor = data[17] & 0x0F;
    if !(1..=2).contains(&version_major) {
        return None;
    }

    let length = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
    // `length` covers the whole IKE message, which may extend beyond a single UDP
    // datagram; reject only if it's shorter than the header itself or wildly larger than
    // what's plausible given the data actually available.
    if (length as usize) < IKE_HEADER_LEN
        || length > (data.len() as u32).saturating_mul(4).saturating_add(4096)
    {
        return None;
    }

    let flags = data[19];
    let mut initiator_spi = [0u8; 8];
    initiator_spi.copy_from_slice(&data[0..8]);
    let mut responder_spi = [0u8; 8];
    responder_spi.copy_from_slice(&data[8..16]);

    Some(IkeHeaderFields {
        initiator_spi,
        responder_spi,
        version_major,
        version_minor,
        exchange_type: data[18],
        is_initiator: flags & FLAG_INITIATOR != 0,
        is_response: flags & FLAG_RESPONSE != 0,
        message_id: u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
        length,
    })
}

/// Returns `true` if `fields` is an unambiguous IKE header match on its own -- a known
/// IKEv2 exchange type and a `length` field that exactly matches the data available --
/// versus a borderline/ambiguous match that should rely on the port as a tiebreaker.
fn is_unambiguous(fields: &IkeHeaderFields, data_len: usize) -> bool {
    (EXCHANGE_TYPE_MIN..=EXCHANGE_TYPE_MAX).contains(&fields.exchange_type)
        && fields.length as usize == data_len
}

/// Decides the probe result for `data`, given whether it was observed on a known IKE port
/// (500/4500) and whether it was observed on the NAT-T port (4500) specifically. Structural
/// validity is checked regardless of port; the port is used only to resolve otherwise
/// ambiguous headers.
pub(crate) fn classify_probe(data: &[u8], on_known_port: bool, on_nat_t_port: bool) -> ProbeResult {
    let stripped = strip_non_esp_marker(data, on_nat_t_port);
    match parse_ike_header(stripped) {
        Some(fields) if is_unambiguous(&fields, stripped.len()) => ProbeResult::Certain,
        Some(_) if on_known_port => ProbeResult::Certain,
        Some(_) => ProbeResult::Unsure,
        None => ProbeResult::NotForUs,
    }
}

impl Ike {
    /// Parses `data` as an IKE header and populates the session summary. Returns
    /// `HeadersDone` on a successful parse, since the header carries everything of
    /// interest in this scope without needing to assemble a multi-packet body.
    ///
    /// The session is removed and delivered on `HeadersDone`, after which the connection
    /// moves to `LayerState::Payload` and this is not called again -- so the summary
    /// describes the first IKE message only. See [`Ike`] for the implications.
    pub(crate) fn update(&mut self, data: &[u8], on_nat_t_port: bool) -> ParseResult {
        let data = strip_non_esp_marker(data, on_nat_t_port);
        let Some(fields) = parse_ike_header(data) else {
            return ParseResult::Skipped;
        };

        self.initiator_spi = fields.initiator_spi;
        self.responder_spi = fields.responder_spi;
        self.version_major = fields.version_major;
        self.version_minor = fields.version_minor;
        self.exchange_type = Some(IkeExchangeType::from_byte(fields.exchange_type));
        self.is_initiator = fields.is_initiator;
        self.is_response = fields.is_response;
        self.message_id = fields.message_id;

        ParseResult::HeadersDone(0)
    }
}

#[derive(Debug)]
pub struct IkeParser {
    sessions: Vec<Ike>,
}

impl Default for IkeParser {
    fn default() -> Self {
        IkeParser {
            sessions: vec![Ike::new()],
        }
    }
}

impl ConnParsable for IkeParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        let on_nat_t_port =
            pdu.ctxt.dst.port() == IKE_NAT_T_PORT || pdu.ctxt.src.port() == IKE_NAT_T_PORT;

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            if !self.sessions.is_empty() {
                return self.sessions[0].update(data, on_nat_t_port);
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
        if length < IKE_HEADER_LEN {
            return ProbeResult::Unsure;
        }

        let dst_port = pdu.ctxt.dst.port();
        let src_port = pdu.ctxt.src.port();
        let on_known_port = matches!(dst_port, IKE_PORT | IKE_NAT_T_PORT)
            || matches!(src_port, IKE_PORT | IKE_NAT_T_PORT);
        let on_nat_t_port = dst_port == IKE_NAT_T_PORT || src_port == IKE_NAT_T_PORT;

        if let Ok(data) = (pdu.mbuf).get_data_slice(offset, length) {
            classify_probe(data, on_known_port, on_nat_t_port)
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }

    fn remove_session(&mut self, _session_id: usize) -> Option<Session> {
        self.sessions.pop().map(|ike| Session {
            data: SessionData::Ike(Box::new(ike)),
            id: 0,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain(..)
            .map(|ike| Session {
                data: SessionData::Ike(Box::new(ike)),
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

    /// IKE payloads are out of scope for this parser, so there is no application-layer
    /// body to offset into.
    fn body_offset(&mut self) -> Option<usize> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn build_header(
        initiator_spi: [u8; 8],
        responder_spi: [u8; 8],
        version: u8,
        exchange_type: u8,
        flags: u8,
        message_id: u32,
        length: u32,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(IKE_HEADER_LEN);
        data.extend_from_slice(&initiator_spi);
        data.extend_from_slice(&responder_spi);
        data.push(0); // next payload
        data.push(version);
        data.push(exchange_type);
        data.push(flags);
        data.extend_from_slice(&message_id.to_be_bytes());
        data.extend_from_slice(&length.to_be_bytes());
        data
    }

    fn ike_sa_init_header() -> Vec<u8> {
        build_header(
            [1, 2, 3, 4, 5, 6, 7, 8],
            [0; 8],
            0x20,
            34, // IKE_SA_INIT
            FLAG_INITIATOR,
            0,
            IKE_HEADER_LEN as u32,
        )
    }

    #[test]
    fn parses_ike_sa_init_header_fields() {
        let data = ike_sa_init_header();
        let fields = parse_ike_header(&data).expect("valid header");
        assert_eq!(fields.initiator_spi, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(fields.responder_spi, [0; 8]);
        assert_eq!(fields.version_major, 2);
        assert_eq!(fields.version_minor, 0);
        assert_eq!(fields.exchange_type, 34);
        assert!(fields.is_initiator);
        assert!(!fields.is_response);
        assert_eq!(fields.message_id, 0);
        assert_eq!(fields.length, IKE_HEADER_LEN as u32);
    }

    #[test]
    fn rejects_truncated_header() {
        let data = ike_sa_init_header();
        assert_eq!(parse_ike_header(&data[..IKE_HEADER_LEN - 1]), None);
    }

    #[test]
    fn rejects_bad_version_nibble() {
        let data = build_header([0; 8], [0; 8], 0x50, 34, 0, 0, IKE_HEADER_LEN as u32);
        assert_eq!(parse_ike_header(&data), None);
    }

    #[test]
    fn rejects_wildly_inconsistent_length() {
        let data = build_header([0; 8], [0; 8], 0x20, 34, 0, 0, 5);
        assert_eq!(parse_ike_header(&data), None);
    }

    #[test]
    fn strips_non_esp_marker_on_nat_t_port() {
        let mut with_marker = vec![0u8; 4];
        with_marker.extend_from_slice(&ike_sa_init_header());
        let stripped = strip_non_esp_marker(&with_marker, true);
        assert_eq!(stripped, ike_sa_init_header().as_slice());
    }

    #[test]
    fn does_not_strip_marker_off_standard_port() {
        let mut with_marker = vec![0u8; 4];
        with_marker.extend_from_slice(&ike_sa_init_header());
        let stripped = strip_non_esp_marker(&with_marker, false);
        assert_eq!(stripped, with_marker.as_slice());
    }

    #[test]
    fn probe_is_certain_on_nonstandard_port_when_structurally_unambiguous() {
        let data = ike_sa_init_header();
        assert_eq!(
            classify_probe(&data, /* on_known_port */ false, false),
            ProbeResult::Certain
        );
    }

    #[test]
    fn probe_uses_port_as_tiebreaker_for_ambiguous_header() {
        // Exchange type 5 is outside the known IKEv2 range, so this header is a
        // structural match but not "unambiguous" -- port should decide certainty.
        let data = build_header([0; 8], [0; 8], 0x10, 5, 0, 0, IKE_HEADER_LEN as u32);
        assert_eq!(
            classify_probe(&data, /* on_known_port */ true, false),
            ProbeResult::Certain
        );
        assert_eq!(
            classify_probe(&data, /* on_known_port */ false, false),
            ProbeResult::Unsure
        );
    }

    #[test]
    fn probe_rejects_structurally_invalid_header_regardless_of_port() {
        let data = build_header([0; 8], [0; 8], 0x50, 34, 0, 0, IKE_HEADER_LEN as u32);
        assert_eq!(
            classify_probe(&data, /* on_known_port */ true, false),
            ProbeResult::NotForUs
        );
    }

    #[test]
    fn probe_strips_non_esp_marker_before_classifying() {
        let mut with_marker = vec![0u8; 4];
        with_marker.extend_from_slice(&ike_sa_init_header());
        assert_eq!(
            classify_probe(&with_marker, false, /* on_nat_t_port */ true),
            ProbeResult::Certain
        );
    }

    #[test]
    fn session_update_tracks_header_fields() {
        let mut ike = Ike::new();
        let data = ike_sa_init_header();
        assert_eq!(ike.update(&data, false), ParseResult::HeadersDone(0));
        assert_eq!(ike.initiator_spi(), [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(ike.exchange_type(), Some(IkeExchangeType::IkeSaInit));
        assert_eq!(ike.version(), (2, 0));
        assert!(ike.is_initiator());
        assert!(!ike.is_response());
    }

    #[test]
    fn session_skips_unrecognized_data() {
        let mut ike = Ike::new();
        assert_eq!(ike.update(&[0u8; 10], false), ParseResult::Skipped);
    }

    #[test]
    fn parser_reports_stop_so_conntrack_can_drop_the_parse_action() {
        let parser = IkeParser::default();
        assert!(matches!(parser.session_parsed_state(), ParsingState::Stop));
    }
}
