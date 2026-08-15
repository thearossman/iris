//! WireGuard parser.
//!
//! Classifies packets by WireGuard message type per the
//! [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf), §5.4. WireGuard
//! message headers use little-endian integers, unlike most network protocols, and their
//! encrypted fields (keys, MACs, transport payloads) are treated as opaque bytes. Only the
//! message-type byte, the reserved bytes, the overall message length, and (for Transport
//! Data) the high bytes of the counter are inspected.

use super::{WireGuard, WireGuardMessageType};
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::{
    ConnParsable, ParseResult, ParsingState, ProbeResult, Session, SessionData,
};

const MSG_TYPE_HANDSHAKE_INITIATION: u8 = 1;
const MSG_TYPE_HANDSHAKE_RESPONSE: u8 = 2;
const MSG_TYPE_COOKIE_REPLY: u8 = 3;
const MSG_TYPE_TRANSPORT_DATA: u8 = 4;

const HANDSHAKE_INITIATION_LEN: usize = 148;
const HANDSHAKE_RESPONSE_LEN: usize = 92;
const COOKIE_REPLY_LEN: usize = 64;
// 4-byte header + 4-byte receiver_index + 8-byte counter + 16-byte minimum AEAD tag.
const TRANSPORT_DATA_MIN_LEN: usize = 32;

/// Offsets of the top two bytes of the Transport Data message's 64-bit little-endian
/// counter, which sits at offset 8.
const TRANSPORT_COUNTER_HIGH: (usize, usize) = (14, 15);

/// Classifies `data` as a WireGuard message type, based on its message-type byte, zeroed
/// reserved bytes, and exact (types 1-3) or minimum (type 4) length. Returns `None` if
/// `data` does not structurally match any WireGuard message.
pub(crate) fn classify_message(data: &[u8]) -> Option<WireGuardMessageType> {
    if data.len() < 4 || data[1] != 0 || data[2] != 0 || data[3] != 0 {
        return None;
    }
    match data[0] {
        MSG_TYPE_HANDSHAKE_INITIATION if data.len() == HANDSHAKE_INITIATION_LEN => {
            Some(WireGuardMessageType::HandshakeInitiation)
        }
        MSG_TYPE_HANDSHAKE_RESPONSE if data.len() == HANDSHAKE_RESPONSE_LEN => {
            Some(WireGuardMessageType::HandshakeResponse)
        }
        MSG_TYPE_COOKIE_REPLY if data.len() == COOKIE_REPLY_LEN => {
            Some(WireGuardMessageType::CookieReply)
        }
        // Unlike the handshake types, whose exact fixed lengths are a strong signal, a
        // Transport Data message is otherwise only a 4-byte signature over a variable
        // length -- too weak to claim a match on. The 64-bit counter at offset 8 is a
        // per-session nonce that resets on rekey (every 2 minutes, well before 2^48
        // messages), so requiring its top two bytes to be zero adds real structure
        // without rejecting any tunnel that can occur in practice.
        MSG_TYPE_TRANSPORT_DATA
            if data.len() >= TRANSPORT_DATA_MIN_LEN
                && data[TRANSPORT_COUNTER_HIGH.0] == 0
                && data[TRANSPORT_COUNTER_HIGH.1] == 0 =>
        {
            Some(WireGuardMessageType::TransportData)
        }
        _ => None,
    }
}

impl WireGuard {
    /// Classifies `data` and updates the session summary. Returns `HeadersDone` once the
    /// handshake completes (or, absent an observed handshake, on the first Transport Data
    /// message), and `Continue` otherwise.
    ///
    /// The session is removed and delivered on `HeadersDone`, after which the connection
    /// moves to `LayerState::Payload` and this is not called again -- so each field is set
    /// at most once.
    pub(crate) fn update(&mut self, data: &[u8]) -> ParseResult {
        let Some(msg_type) = classify_message(data) else {
            return ParseResult::Skipped;
        };

        match msg_type {
            WireGuardMessageType::HandshakeInitiation => self.handshake_initiation_seen = true,
            WireGuardMessageType::HandshakeResponse => self.handshake_response_seen = true,
            WireGuardMessageType::CookieReply => self.cookie_reply_seen = true,
            WireGuardMessageType::TransportData => self.transport_data_seen = true,
        }
        self.message_type = Some(msg_type);

        if self.handshake_response_seen || msg_type == WireGuardMessageType::TransportData {
            ParseResult::HeadersDone(0)
        } else {
            ParseResult::Continue(0)
        }
    }
}

#[derive(Debug)]
pub struct WireGuardParser {
    sessions: Vec<WireGuard>,
}

impl Default for WireGuardParser {
    fn default() -> Self {
        WireGuardParser {
            sessions: vec![WireGuard::new()],
        }
    }
}

impl ConnParsable for WireGuardParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            if !self.sessions.is_empty() {
                return self.sessions[0].update(data);
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
        if length < 4 {
            return ProbeResult::Unsure;
        }

        if let Ok(data) = (pdu.mbuf).get_data_slice(offset, length) {
            match classify_message(data) {
                Some(_) => ProbeResult::Certain,
                None => ProbeResult::NotForUs,
            }
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }

    fn remove_session(&mut self, _session_id: usize) -> Option<Session> {
        self.sessions.pop().map(|wg| Session {
            data: SessionData::WireGuard(Box::new(wg)),
            id: 0,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain(..)
            .map(|wg| Session {
                data: SessionData::WireGuard(Box::new(wg)),
                id: 0,
            })
            .collect()
    }

    fn session_parsed_state(&self) -> ParsingState {
        // Exactly one summary is produced per connection, so no further sessions are
        // expected. Reporting `Stop` lets conntrack clear the `Parse` action once the
        // session is delivered, which takes bulk tunnel traffic off the parse/reassembly
        // path for the rest of the connection's life.
        ParsingState::Stop
    }

    /// WireGuard payloads are encrypted, so there is no application-layer body to offset
    /// into.
    fn body_offset(&mut self) -> Option<usize> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_message(msg_type: u8, total_len: usize) -> Vec<u8> {
        let mut data: Vec<u8> = vec![msg_type, 0, 0, 0]
            .into_iter()
            .chain(std::iter::repeat_n(0xAB, total_len.saturating_sub(4)))
            .collect();
        // A real Transport Data message's 64-bit LE counter at offset 8 never reaches
        // 2^48, so keep the synthetic ones realistic by zeroing its top two bytes.
        if msg_type == MSG_TYPE_TRANSPORT_DATA && data.len() > TRANSPORT_COUNTER_HIGH.1 {
            data[TRANSPORT_COUNTER_HIGH.0] = 0;
            data[TRANSPORT_COUNTER_HIGH.1] = 0;
        }
        data
    }

    #[test]
    fn classifies_handshake_initiation() {
        let data = build_message(MSG_TYPE_HANDSHAKE_INITIATION, HANDSHAKE_INITIATION_LEN);
        assert_eq!(
            classify_message(&data),
            Some(WireGuardMessageType::HandshakeInitiation)
        );
    }

    #[test]
    fn classifies_handshake_response() {
        let data = build_message(MSG_TYPE_HANDSHAKE_RESPONSE, HANDSHAKE_RESPONSE_LEN);
        assert_eq!(
            classify_message(&data),
            Some(WireGuardMessageType::HandshakeResponse)
        );
    }

    #[test]
    fn classifies_cookie_reply() {
        let data = build_message(MSG_TYPE_COOKIE_REPLY, COOKIE_REPLY_LEN);
        assert_eq!(
            classify_message(&data),
            Some(WireGuardMessageType::CookieReply)
        );
    }

    #[test]
    fn classifies_transport_data_at_minimum_length() {
        let data = build_message(MSG_TYPE_TRANSPORT_DATA, TRANSPORT_DATA_MIN_LEN);
        assert_eq!(
            classify_message(&data),
            Some(WireGuardMessageType::TransportData)
        );
    }

    #[test]
    fn classifies_transport_data_with_larger_payload() {
        let data = build_message(MSG_TYPE_TRANSPORT_DATA, TRANSPORT_DATA_MIN_LEN + 1400);
        assert_eq!(
            classify_message(&data),
            Some(WireGuardMessageType::TransportData)
        );
    }

    #[test]
    fn rejects_wrong_length_for_fixed_size_types() {
        let too_short = build_message(MSG_TYPE_HANDSHAKE_INITIATION, HANDSHAKE_INITIATION_LEN - 1);
        assert_eq!(classify_message(&too_short), None);
        let too_long = build_message(MSG_TYPE_HANDSHAKE_RESPONSE, HANDSHAKE_RESPONSE_LEN + 1);
        assert_eq!(classify_message(&too_long), None);
        let wrong = build_message(MSG_TYPE_COOKIE_REPLY, COOKIE_REPLY_LEN - 1);
        assert_eq!(classify_message(&wrong), None);
    }

    #[test]
    fn rejects_transport_data_below_minimum_length() {
        let data = build_message(MSG_TYPE_TRANSPORT_DATA, TRANSPORT_DATA_MIN_LEN - 1);
        assert_eq!(classify_message(&data), None);
    }

    #[test]
    fn rejects_nonzero_reserved_bytes() {
        let mut data = build_message(MSG_TYPE_HANDSHAKE_INITIATION, HANDSHAKE_INITIATION_LEN);
        data[2] = 1;
        assert_eq!(classify_message(&data), None);
    }

    #[test]
    fn rejects_unknown_type_byte() {
        let data = build_message(5, HANDSHAKE_INITIATION_LEN);
        assert_eq!(classify_message(&data), None);
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(classify_message(&[]), None);
    }

    #[test]
    fn rejects_truncated_input() {
        let data = build_message(MSG_TYPE_HANDSHAKE_INITIATION, 3);
        assert_eq!(classify_message(&data), None);
    }

    #[test]
    fn rejects_transport_data_with_implausible_counter() {
        // Default 0xAB filler leaves the counter's top bytes set, which no real tunnel
        // produces -- this is the structure that keeps the 4-byte signature honest.
        let mut data = build_message(MSG_TYPE_TRANSPORT_DATA, TRANSPORT_DATA_MIN_LEN);
        data[TRANSPORT_COUNTER_HIGH.1] = 0xAB;
        assert_eq!(classify_message(&data), None);
    }

    #[test]
    fn rejects_dns_query_shaped_packet() {
        // A non-recursive DNS query with transaction ID 0x0400 and zero flags starts with
        // the same four bytes as a Transport Data message. Its QNAME bytes land where the
        // counter's high bytes would be, so the counter check rejects it.
        let mut data = vec![0x04, 0x00, 0x00, 0x00]; // txid 0x0400, flags 0x0000
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // QDCOUNT=1, ANCOUNT=0
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT=0, ARCOUNT=0
        data.extend_from_slice(b"\x03www\x07example\x03com\x00"); // QNAME
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        assert!(data.len() >= TRANSPORT_DATA_MIN_LEN);
        assert_eq!(classify_message(&data), None);
    }

    #[test]
    fn session_records_handshake_and_completes_on_response() {
        let mut wg = WireGuard::new();

        let init = build_message(MSG_TYPE_HANDSHAKE_INITIATION, HANDSHAKE_INITIATION_LEN);
        assert_eq!(wg.update(&init), ParseResult::Continue(0));
        assert!(wg.handshake_initiation_seen);
        assert!(!wg.handshake_complete());

        // The response completes headers; the session is delivered here and `update` is
        // not called again for the life of the connection.
        let resp = build_message(MSG_TYPE_HANDSHAKE_RESPONSE, HANDSHAKE_RESPONSE_LEN);
        assert_eq!(wg.update(&resp), ParseResult::HeadersDone(0));
        assert!(wg.handshake_complete());
        assert_eq!(
            wg.message_type(),
            Some(WireGuardMessageType::HandshakeResponse)
        );
        // No transport data is ever parsed on a tunnel observed from its handshake.
        assert!(!wg.transport_data_seen());
    }

    #[test]
    fn session_marks_headers_done_on_first_transport_data_without_handshake() {
        let mut wg = WireGuard::new();
        let data = build_message(MSG_TYPE_TRANSPORT_DATA, TRANSPORT_DATA_MIN_LEN);
        assert_eq!(wg.update(&data), ParseResult::HeadersDone(0));
        assert!(wg.transport_data_seen());
        assert!(!wg.handshake_complete());
    }

    #[test]
    fn session_skips_unrecognized_data() {
        let mut wg = WireGuard::new();
        assert_eq!(wg.update(&[9, 9, 9, 9]), ParseResult::Skipped);
    }

    #[test]
    fn parser_reports_stop_so_conntrack_can_drop_the_parse_action() {
        let parser = WireGuardParser::default();
        assert!(matches!(parser.session_parsed_state(), ParsingState::Stop));
    }
}
