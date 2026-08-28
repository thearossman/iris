//! Quic Header parser
//! Custom Quic Parser with many design choices borrowed from
//! [Wireshark Quic Disector](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-quic.c)
//!
use crate::protocols::stream::quic::crypto::calc_init_keys;
use crate::protocols::stream::quic::frame::QuicFrame;
use crate::protocols::stream::quic::header::{
    LongHeaderPacketType, QuicLongHeader, QuicShortHeader,
};
use crate::protocols::stream::quic::{QuicError, QuicPacket};
use crate::protocols::stream::tls::Tls;
use crate::protocols::stream::{
    ConnParsable, L4Pdu, ParseResult, ParsingState, ProbeResult, Session, SessionData,
};
use byteorder::{BigEndian, ByteOrder};
use std::collections::HashSet;
use tls_parser::parse_tls_message_handshake;

use super::QuicConn;

#[derive(Debug)]
pub struct QuicParser {
    // /// Maps session ID to Quic transaction
    // sessions: HashMap<usize, QuicPacket>,
    // /// Total sessions ever seen (Running session ID)
    // cnt: usize,
    sessions: Vec<QuicConn>,
}

impl Default for QuicParser {
    fn default() -> Self {
        QuicParser {
            sessions: vec![QuicConn::new()],
        }
    }
}

impl ConnParsable for QuicParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            if !self.sessions.is_empty() {
                return self.sessions[0].parse_packet(data, pdu.dir);
            }
            ParseResult::Skipped
        } else {
            log::warn!("Malformed packet on parse");
            ParseResult::Skipped
        }
    }

    fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        if pdu.length() < 5 {
            return ProbeResult::Unsure;
        }

        let offset = pdu.offset();
        let length = pdu.length();

        if let Ok(data) = (pdu.mbuf).get_data_slice(offset, length) {
            if (data[0] & 0x80) != 0 {
                // Potential Long Header. The fixed bit is deliberately not
                // checked: RFC 9287 lets an endpoint grease it, and the 32-bit
                // version field is a much stronger discriminator anyway. The
                // five bytes the version field needs are guaranteed by the
                // length check above.
                // Check if version is known
                let version = ((data[1] as u32) << 24)
                    | ((data[2] as u32) << 16)
                    | ((data[3] as u32) << 8)
                    | (data[4] as u32);
                match QuicVersion::from_u32(version) {
                    QuicVersion::Unknown => ProbeResult::NotForUs,
                    _ => ProbeResult::Certain,
                }
            } else if (data[0] & 0x40) != 0 {
                ProbeResult::Unsure
            } else {
                // Short form with the fixed bit clear. RFC 9287 greasing makes
                // this a possible 1-RTT packet, but greasing requires a
                // negotiated transport parameter, so any connection whose
                // *first* packets look like this is mid-stream -- a population
                // this parser cannot serve regardless (it never returns
                // `Certain` for a short header). Reporting `Unsure` here would
                // keep every DTLS, STUN, and RTP flow on a QUIC port in
                // Discovery forever for no gain. `MaybeQuic` covers mid-stream
                // QUIC, greased or not.
                ProbeResult::NotForUs
            }
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }

    fn remove_session(&mut self, session_id: usize) -> Option<Session> {
        self.sessions.pop().map(|quic| Session {
            data: SessionData::Quic(Box::new(quic)),
            id: session_id,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain(..)
            .map(|quic| Session {
                data: SessionData::Quic(Box::new(quic)),
                id: 0,
            })
            .collect()
    }

    fn session_parsed_state(&self) -> ParsingState {
        ParsingState::Parsing
    }

    // Temporary - not supported for QUIC parser.
    fn body_offset(&mut self) -> Option<usize> {
        None
    }
}

/// Supported Quic Versions
#[derive(Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum QuicVersion {
    ReservedNegotiation = 0x00000000,
    Rfc9000 = 0x00000001, // Quic V1
    Rfc9369 = 0x6b3343cf, // Quic V2
    Draft27 = 0xff00001b, // Quic draft 27
    Draft28 = 0xff00001c, // Quic draft 28
    Draft29 = 0xff00001d, // Quic draft 29
    Draft30 = 0xff00001e, // Quic draft 30
    Draft31 = 0xff00001f, // Quic draft 31
    Draft32 = 0xff000020, // Quic draft 32
    Draft33 = 0xff000021, // Quic draft 33
    Draft34 = 0xff000022, // Quic draft 34
    Mvfst27 = 0xfaceb002, // Facebook Implementation of draft 27
    /// A version matching the `0x?a?a?a?a` pattern RFC 9368 Section 3 reserves
    /// for version greasing. Clients send these deliberately to exercise
    /// version negotiation, so they are QUIC -- but by construction Iris cannot
    /// know the wire format, so only the RFC 8999 invariant fields are parsed.
    Greased,
    Unknown,
}

/// Mask and value identifying the greased versions RFC 9368 Section 3 reserves:
/// every version of the form `0x?a?a?a?a`.
const GREASED_VERSION_MASK: u32 = 0x0f0f0f0f;
const GREASED_VERSION_VALUE: u32 = 0x0a0a0a0a;

/// True if `version` is a QUIC version number Iris recognizes.
///
/// Per RFC 8999 Section 5.1 the 32-bit version field is the only part of a long
/// header whose position is invariant across versions, so an exact match on it
/// is much stronger evidence that a datagram is QUIC than the header-form bit
/// on its own. Used by the `quic` probe and by heuristic filters that need to
/// tell a QUIC long header from any other protocol that happens to set the high
/// bit of its first byte.
///
/// Note that this is broader than "Iris can parse this version's packets": a
/// greased version (RFC 9368) or a Version Negotiation packet is recognized as
/// QUIC even though only the RFC 8999 invariant fields can be read from it.
pub fn is_quic_version(version: u32) -> bool {
    QuicVersion::from_u32(version) != QuicVersion::Unknown
}

impl QuicVersion {
    /// True if the version leaves the long header's type bits undefined, so
    /// that nothing past the connection IDs can be interpreted. Version
    /// Negotiation packets give bits 4-7 of the first byte arbitrary values
    /// (RFC 9000 Section 17.2.1), and a greased version's wire format is
    /// unknown by construction (RFC 9368).
    pub fn is_invariants_only(&self) -> bool {
        matches!(
            self,
            QuicVersion::ReservedNegotiation | QuicVersion::Greased
        )
    }

    pub fn from_u32(version: u32) -> Self {
        match version {
            0x00000000 => QuicVersion::ReservedNegotiation,
            0x00000001 => QuicVersion::Rfc9000,
            0x6b3343cf => QuicVersion::Rfc9369,
            0xff00001b => QuicVersion::Draft27,
            0xff00001c => QuicVersion::Draft28,
            0xff00001d => QuicVersion::Draft29,
            0xff00001e => QuicVersion::Draft30,
            0xff00001f => QuicVersion::Draft31,
            0xff000020 => QuicVersion::Draft32,
            0xff000021 => QuicVersion::Draft33,
            0xff000022 => QuicVersion::Draft34,
            0xfaceb002 => QuicVersion::Mvfst27,
            v if v & GREASED_VERSION_MASK == GREASED_VERSION_VALUE => QuicVersion::Greased,
            _ => QuicVersion::Unknown,
        }
    }
}

impl QuicPacket {
    /// Processes the connection ID bytes array to a hex string
    pub fn vec_u8_to_hex_string(vec: &[u8]) -> String {
        vec.iter()
            .map(|&byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join("")
    }

    // Calculate the length of a variable length encoding
    // See RFC 9000 Section 16 for details
    pub fn get_var_len(a: u8) -> Result<usize, QuicError> {
        let two_msb = a >> 6;
        match two_msb {
            0b00 => Ok(1),
            0b01 => Ok(2),
            0b10 => Ok(4),
            0b11 => Ok(8),
            _ => Err(QuicError::UnsupportedVarLen),
        }
    }

    // Masks variable length encoding and returns u64 value for remainder of field
    pub fn slice_to_u64(data: &[u8]) -> Result<u64, QuicError> {
        if data.len() > 8 {
            return Err(QuicError::UnsupportedVarLen);
        }

        let mut result: u64 = 0;
        for &byte in data {
            result = (result << 8) | u64::from(byte);
        }
        result &= !(0b11 << ((data.len() * 8) - 2)); // Var length encoding mask
        Ok(result)
    }

    pub fn access_data(data: &[u8], start: usize, end: usize) -> Result<&[u8], QuicError> {
        if end < start {
            return Err(QuicError::InvalidDataIndices);
        }
        if data.len() < end {
            return Err(QuicError::PacketTooShort);
        }
        Ok(&data[start..end])
    }

    /// Parses Quic packet from bytes
    pub fn parse_from(
        conn: &mut QuicConn,
        data: &[u8],
        mut offset: usize,
        dir: bool,
    ) -> Result<(QuicPacket, usize), QuicError> {
        let packet_header_byte = QuicPacket::access_data(data, offset, offset + 1)?[0];
        offset += 1;
        // Check the Header form
        if (packet_header_byte & 0x80) != 0 {
            // Long Header. The fixed bit is not checked here -- RFC 9287 lets
            // an endpoint grease it once its peer has advertised
            // `grease_quic_bit`, and the version field below is a far stronger
            // check. Rejecting greased packets here dropped the whole datagram
            // (`parse_packet` stops at the first error), losing the packet and
            // its byte count from an otherwise well-understood connection.
            let type_specific = packet_header_byte & 0x0F; // Remainder of information from header byte, Reserved and protected packet number length
                                                           // Parse version
            let version_bytes = QuicPacket::access_data(data, offset, offset + 4)?;
            let version = ((version_bytes[0] as u32) << 24)
                | ((version_bytes[1] as u32) << 16)
                | ((version_bytes[2] as u32) << 8)
                | (version_bytes[3] as u32);
            let quic_version = QuicVersion::from_u32(version);
            if quic_version == QuicVersion::Unknown {
                return Err(QuicError::UnknownVersion);
            }
            offset += 4;
            // Parse DCID
            let dcid_len = QuicPacket::access_data(data, offset, offset + 1)?[0];
            offset += 1;
            let dcid_bytes = QuicPacket::access_data(data, offset, offset + dcid_len as usize)?;
            let dcid = QuicPacket::vec_u8_to_hex_string(dcid_bytes);
            if dcid_len > 0 && !conn.cids.contains(&dcid) {
                conn.cids.insert(dcid.clone());
            }
            offset += dcid_len as usize;
            // Parse SCID
            let scid_len = QuicPacket::access_data(data, offset, offset + 1)?[0];
            offset += 1;
            let scid_bytes = QuicPacket::access_data(data, offset, offset + scid_len as usize)?;
            let scid = QuicPacket::vec_u8_to_hex_string(scid_bytes);
            if scid_len > 0 && !conn.cids.contains(&scid) {
                conn.cids.insert(scid.clone());
            }
            offset += scid_len as usize;

            // Everything past the connection IDs is version-specific (RFC 8999
            // Section 5.1 fixes only the form bit, version, and the two CIDs).
            // For a Version Negotiation packet the type bits are arbitrary and
            // the remainder is a list of supported versions; for a greased
            // version the layout is unknown by construction. Either way, stop
            // at the invariants rather than parsing the first byte's type bits
            // as Initial/Handshake/Retry and reading whatever follows.
            if quic_version.is_invariants_only() {
                let supported_versions = if quic_version == QuicVersion::ReservedNegotiation {
                    let mut versions = Vec::new();
                    while data.len() >= offset + 4 {
                        let bytes = QuicPacket::access_data(data, offset, offset + 4)?;
                        versions.push(
                            ((bytes[0] as u32) << 24)
                                | ((bytes[1] as u32) << 16)
                                | ((bytes[2] as u32) << 8)
                                | (bytes[3] as u32),
                        );
                        offset += 4;
                    }
                    Some(versions)
                } else {
                    None
                };
                let payload_bytes_count = (data.len() - offset) as u64;
                return Ok((
                    QuicPacket {
                        payload_bytes_count: Some(payload_bytes_count),
                        short_header: None,
                        long_header: Some(QuicLongHeader {
                            packet_type: None,
                            type_specific,
                            version,
                            dcid_len,
                            dcid,
                            scid_len,
                            scid,
                            token_len: None,
                            token: None,
                            retry_tag: None,
                            supported_versions,
                        }),
                        frames: None,
                    },
                    data.len(),
                ));
            }

            // Parse packet type. Two bits, four variants, so this cannot fail.
            let packet_type = LongHeaderPacketType::from_u8((packet_header_byte & 0x30) >> 4)?;

            let token_len;
            let token;
            let packet_len;
            let retry_tag;
            let decrypted_payload;
            // Parse packet type specific fields
            match packet_type {
                LongHeaderPacketType::Initial => {
                    retry_tag = None;
                    // Parse token
                    let token_len_len = QuicPacket::get_var_len(
                        QuicPacket::access_data(data, offset, offset + 1)?[0],
                    )?;
                    let token_len_bytes =
                        QuicPacket::access_data(data, offset, offset + token_len_len)?;
                    token_len = Some(QuicPacket::slice_to_u64(token_len_bytes)?);
                    offset += token_len_len;
                    let token_bytes = QuicPacket::access_data(
                        data,
                        offset,
                        offset + token_len.unwrap() as usize,
                    )?;
                    token = Some(QuicPacket::vec_u8_to_hex_string(token_bytes));
                    offset += token_len.unwrap() as usize;
                    // Parse payload length
                    let packet_len_len = QuicPacket::get_var_len(
                        QuicPacket::access_data(data, offset, offset + 1)?[0],
                    )?;
                    let packet_len_bytes =
                        QuicPacket::access_data(data, offset, offset + packet_len_len)?;
                    packet_len = Some(QuicPacket::slice_to_u64(packet_len_bytes)?);
                    offset += packet_len_len;
                    if conn.client_opener.is_none() {
                        // Derive initial keys
                        let [client_opener, server_opener] = calc_init_keys(dcid_bytes, version)?;
                        conn.client_opener = Some(client_opener);
                        conn.server_opener = Some(server_opener);
                    }
                    // Calculate HP
                    let sample_len = conn.client_opener.as_ref().unwrap().sample_len();
                    let hp_sample =
                        QuicPacket::access_data(data, offset + 4, offset + 4 + sample_len)?;
                    let mask = if dir {
                        conn.client_opener.as_ref().unwrap().new_mask(hp_sample)?
                    } else {
                        conn.server_opener.as_ref().unwrap().new_mask(hp_sample)?
                    };
                    // Remove HP from packet header byte
                    let unprotected_header = packet_header_byte ^ (mask[0] & 0b00001111);
                    if (unprotected_header >> 2) & 0b00000011 != 0 {
                        return Err(QuicError::FailedHeaderProtection);
                    }
                    // Parse packet number
                    let packet_num_len = ((unprotected_header & 0b00000011) + 1) as usize;
                    let packet_number_bytes =
                        QuicPacket::access_data(data, offset, offset + packet_num_len)?;
                    let mut packet_number = vec![0; 4 - packet_num_len];
                    for i in 0..packet_num_len {
                        packet_number.push(packet_number_bytes[i] ^ mask[i + 1]);
                    }

                    let initial_packet_number_bytes = &packet_number[4 - packet_num_len..];
                    let packet_number_int = BigEndian::read_i32(&packet_number);
                    offset += packet_num_len;
                    // Parse the encrypted payload
                    let tag_len = conn.client_opener.as_ref().unwrap().alg().tag_len();
                    if (packet_len.unwrap() as usize) < (tag_len + packet_num_len) {
                        return Err(QuicError::PacketTooShort);
                    }
                    let cipher_text_len = packet_len.unwrap() as usize - tag_len - packet_num_len;
                    let mut encrypted_payload =
                        QuicPacket::access_data(data, offset, offset + cipher_text_len)?.to_vec();
                    offset += cipher_text_len;
                    // Parse auth tag
                    let tag = QuicPacket::access_data(data, offset, offset + tag_len)?;
                    offset += tag_len;
                    // Reconstruct authenticated data
                    let mut ad = Vec::new();
                    ad.append(&mut [unprotected_header].to_vec());
                    ad.append(&mut version_bytes.to_vec());
                    ad.append(&mut [dcid_len].to_vec());
                    ad.append(&mut dcid_bytes.to_vec());
                    ad.append(&mut [scid_len].to_vec());
                    ad.append(&mut scid_bytes.to_vec());
                    ad.append(&mut token_len_bytes.to_vec());
                    ad.append(&mut token_bytes.to_vec());
                    ad.append(&mut packet_len_bytes.to_vec());
                    ad.append(&mut initial_packet_number_bytes.to_vec());
                    // Decrypt payload with proper keys based on traffic direction
                    if dir {
                        decrypted_payload =
                            Some(conn.client_opener.as_ref().unwrap().open_with_u64_counter(
                                packet_number_int as u64,
                                &ad,
                                &mut encrypted_payload,
                                tag,
                            )?);
                    } else {
                        decrypted_payload =
                            Some(conn.server_opener.as_ref().unwrap().open_with_u64_counter(
                                packet_number_int as u64,
                                &ad,
                                &mut encrypted_payload,
                                tag,
                            )?);
                    }
                }
                LongHeaderPacketType::ZeroRTT | LongHeaderPacketType::Handshake => {
                    token_len = None;
                    token = None;
                    retry_tag = None;
                    decrypted_payload = None;
                    // Parse payload length
                    let packet_len_len = QuicPacket::get_var_len(
                        QuicPacket::access_data(data, offset, offset + 1)?[0],
                    )?;
                    packet_len = Some(QuicPacket::slice_to_u64(QuicPacket::access_data(
                        data,
                        offset,
                        offset + packet_len_len,
                    )?)?);
                    offset += packet_len_len;
                    offset += packet_len.unwrap() as usize;
                }
                LongHeaderPacketType::Retry => {
                    packet_len = None;
                    decrypted_payload = None;
                    if data.len() > (offset + 16) {
                        token_len = Some((data.len() - offset - 16) as u64);
                    } else {
                        return Err(QuicError::PacketTooShort);
                    }
                    // Parse retry token
                    let token_bytes = QuicPacket::access_data(
                        data,
                        offset,
                        offset + token_len.unwrap() as usize,
                    )?;
                    token = Some(QuicPacket::vec_u8_to_hex_string(token_bytes));
                    offset += token_len.unwrap() as usize;
                    // Parse retry tag
                    let retry_tag_bytes = QuicPacket::access_data(data, offset, offset + 16)?;
                    retry_tag = Some(QuicPacket::vec_u8_to_hex_string(retry_tag_bytes));
                    offset += 16;
                }
            }

            let mut frames: Option<Vec<QuicFrame>> = None;
            // Grab the proper buffer for CRYPTO frame data
            let crypto_buffer: &mut Vec<u8> = if dir {
                conn.client_buffer.as_mut()
            } else {
                conn.server_buffer.as_mut()
            };
            // If decrypted payload is not None, parse the frames
            if let Some(frame_bytes) = decrypted_payload {
                // Get frames and reassembled CRYPTO data
                // Pass the buffer's current length as starting offset for CRYPTO frames
                let (q_frames, mut crypto_bytes) =
                    QuicFrame::parse_frames(&frame_bytes, crypto_buffer.len())?;
                frames = Some(q_frames);
                if !crypto_bytes.is_empty() {
                    crypto_buffer.append(&mut crypto_bytes);
                    // Attempt to parse CRYPTO buffer
                    // clear on success
                    // NICE-TO-HAVE: This naive buffer will not work for out of order frames
                    // across packets or multiple messages in the same buffer
                    match parse_tls_message_handshake(crypto_buffer) {
                        Ok((_, msg)) => {
                            conn.tls.parse_message_level(&msg, dir);
                            crypto_buffer.clear();
                        }
                        Err(_) => return Err(QuicError::TlsParseFail),
                    }
                }
            }

            Ok((
                QuicPacket {
                    payload_bytes_count: packet_len,
                    short_header: None,
                    long_header: Some(QuicLongHeader {
                        packet_type: Some(packet_type),
                        type_specific,
                        version,
                        dcid_len,
                        dcid,
                        scid_len,
                        scid,
                        token_len,
                        token,
                        retry_tag,
                        supported_versions: None,
                    }),
                    frames,
                },
                offset,
            ))
        } else {
            // Short Header. Unlike a long header there is no version field to
            // corroborate the packet, so the fixed bit stays a hard
            // requirement: it is the only thing separating a 1-RTT packet from
            // the PADDING bytes RFC 9000 Section 12.2 allows after a coalesced
            // packet, and misreading padding as a short-header packet would
            // both invent a packet and fire `HeadersDone`. A *greased* 1-RTT
            // packet (RFC 9287) is therefore still skipped here; telling one
            // from padding needs more than the first byte.
            if (packet_header_byte & 0x40) == 0 {
                return Err(QuicError::FixedBitNotSet);
            }
            let mut dcid_len = 20;
            if data.len() < 1 + dcid_len {
                dcid_len = data.len() - 1;
            }
            // Parse DCID
            let dcid_hex = QuicPacket::vec_u8_to_hex_string(QuicPacket::access_data(
                data,
                offset,
                offset + dcid_len,
            )?);
            let mut dcid = None;
            for cid in &conn.cids {
                if dcid_hex.starts_with(cid) {
                    dcid_len = cid.chars().count() / 2;
                    dcid = Some(cid.clone());
                }
            }
            offset += dcid_len;
            // Counts all bytes remaining
            let payload_bytes_count = (data.len() - offset) as u64;
            offset += payload_bytes_count as usize;
            Ok((
                QuicPacket {
                    short_header: Some(QuicShortHeader { dcid }),
                    long_header: None,
                    payload_bytes_count: Some(payload_bytes_count),
                    frames: None,
                },
                offset,
            ))
        }
    }
}

impl QuicConn {
    pub(crate) fn new() -> QuicConn {
        QuicConn {
            packets: Vec::new(),
            cids: HashSet::new(),
            tls: Tls::new(),
            client_opener: None,
            server_opener: None,
            client_buffer: Vec::new(),
            server_buffer: Vec::new(),
        }
    }

    fn parse_packet(&mut self, data: &[u8], direction: bool) -> ParseResult {
        let mut offset = 0;
        // Iterate over all of the data in the datagram
        // Parse as many QUIC packets as possible
        // NICE-TO-HAVE: identify padding appended to datagram
        while data.len() > offset {
            if let Ok((quic, off)) = QuicPacket::parse_from(self, data, offset, direction) {
                self.packets.push(quic);
                offset = off;
            } else {
                return ParseResult::Skipped;
            }
        }
        if self
            .packets
            .last()
            .is_some_and(|p| p.short_header.is_some())
        {
            return ParseResult::HeadersDone(0);
        }
        ParseResult::Continue(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A long header packet, assembled from its RFC 8999 invariant fields plus
    /// whatever version-specific bytes follow.
    fn long_header(first_byte: u8, version: u32, dcid: &[u8], scid: &[u8], rest: &[u8]) -> Vec<u8> {
        let mut out = vec![first_byte];
        out.extend_from_slice(&version.to_be_bytes());
        out.push(dcid.len() as u8);
        out.extend_from_slice(dcid);
        out.push(scid.len() as u8);
        out.extend_from_slice(scid);
        out.extend_from_slice(rest);
        out
    }

    #[test]
    fn drafts_30_through_34_are_recognized() {
        assert_eq!(QuicVersion::from_u32(0xff00001e), QuicVersion::Draft30);
        assert_eq!(QuicVersion::from_u32(0xff000022), QuicVersion::Draft34);
        // draft-35 was never published.
        assert_eq!(QuicVersion::from_u32(0xff000023), QuicVersion::Unknown);
    }

    #[test]
    fn greased_versions_match_the_reserved_pattern() {
        // RFC 9368 Section 3 reserves every version of the form `0x?a?a?a?a`.
        for v in [0x0a0a0a0au32, 0xdada1a1a, 0x1a2a3a4a, 0xfafafafa] {
            assert_eq!(QuicVersion::from_u32(v), QuicVersion::Greased, "{:#x}", v);
            assert!(is_quic_version(v));
        }
        for v in [0x0a0a0a0bu32, 0x12345678, 0xff000023] {
            assert_eq!(QuicVersion::from_u32(v), QuicVersion::Unknown, "{:#x}", v);
            assert!(!is_quic_version(v));
        }
    }

    #[test]
    fn only_version_negotiation_and_greased_stop_at_the_invariants() {
        assert!(QuicVersion::from_u32(0x00000000).is_invariants_only());
        assert!(QuicVersion::from_u32(0x0a0a0a0a).is_invariants_only());
        assert!(!QuicVersion::from_u32(0x00000001).is_invariants_only());
        assert!(!QuicVersion::from_u32(0xff00001e).is_invariants_only());
    }

    #[test]
    fn version_negotiation_yields_the_offered_versions() {
        let mut supported = Vec::new();
        supported.extend_from_slice(&0x00000001u32.to_be_bytes());
        supported.extend_from_slice(&0x6b3343cfu32.to_be_bytes());
        // Bits 4-7 of the first byte are arbitrary in a Version Negotiation
        // packet; 0xab exercises that they are not read as a packet type.
        let data = long_header(0xab, 0x00000000, &[1, 2, 3, 4], &[5, 6, 7, 8], &supported);

        let mut conn = QuicConn::new();
        let (packet, consumed) = QuicPacket::parse_from(&mut conn, &data, 0, true).unwrap();
        assert_eq!(consumed, data.len());

        let hdr = packet.long_header.as_ref().unwrap();
        assert!(hdr.packet_type.is_none());
        assert_eq!(hdr.version, 0);
        assert_eq!(
            hdr.supported_versions.as_deref(),
            Some(&[0x00000001u32, 0x6b3343cf][..])
        );
        assert!(packet.packet_type().is_err());
        // The invariant fields are still harvested.
        assert!(conn.cids.contains("01020304"));
        assert!(conn.cids.contains("05060708"));
    }

    #[test]
    fn greased_version_parses_its_invariants_instead_of_erroring() {
        let data = long_header(0xc3, 0x0a0a0a0a, &[0xaa; 8], &[], &[0xff; 10]);

        let mut conn = QuicConn::new();
        let (packet, consumed) = QuicPacket::parse_from(&mut conn, &data, 0, true).unwrap();
        assert_eq!(consumed, data.len());

        let hdr = packet.long_header.as_ref().unwrap();
        assert!(hdr.packet_type.is_none());
        assert_eq!(hdr.version, 0x0a0a0a0a);
        // Not a Version Negotiation packet, so there is no version list to read.
        assert!(hdr.supported_versions.is_none());
        assert_eq!(packet.payload_bytes_count(), 10);
        assert!(conn.cids.contains("aaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn a_long_header_with_the_fixed_bit_greased_away_still_parses() {
        // Handshake packet (type bits 0b10), fixed bit clear per RFC 9287, with
        // a one-byte varint payload length of 5. This used to fail outright
        // with `FixedBitNotSet`, which discards every packet in the datagram.
        let data = long_header(0xa0, 0x00000001, &[], &[], &[0x05, 1, 2, 3, 4, 5]);

        let mut conn = QuicConn::new();
        let (packet, consumed) = QuicPacket::parse_from(&mut conn, &data, 0, true).unwrap();
        assert_eq!(consumed, data.len());
        assert!(matches!(
            packet.long_header.as_ref().unwrap().packet_type,
            Some(LongHeaderPacketType::Handshake)
        ));
    }

    #[test]
    fn a_short_header_still_requires_the_fixed_bit() {
        // The fixed bit is the only thing distinguishing a 1-RTT packet from
        // trailing PADDING, so it stays mandatory on the short-header path.
        let data = [0x00u8; 25];
        let mut conn = QuicConn::new();
        assert!(matches!(
            QuicPacket::parse_from(&mut conn, &data, 0, true),
            Err(QuicError::FixedBitNotSet)
        ));
    }

    #[test]
    fn an_unknown_version_is_still_rejected() {
        let data = long_header(0xc3, 0x51303530, &[0xaa; 8], &[], &[0xff; 10]);
        let mut conn = QuicConn::new();
        assert!(matches!(
            QuicPacket::parse_from(&mut conn, &data, 0, true),
            Err(QuicError::UnknownVersion)
        ));
    }
}
