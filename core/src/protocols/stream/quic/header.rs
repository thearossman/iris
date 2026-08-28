//! Quic header types

use serde::Serialize;

use crate::protocols::stream::quic::QuicError;

/// Quic Long Header
#[derive(Debug, Serialize, Clone)]
pub struct QuicLongHeader {
    /// `None` when the version does not define the type bits: a Version
    /// Negotiation packet (RFC 9000 Section 17.2.1 gives them arbitrary values)
    /// or a greased version (RFC 9368), which is unknown by construction.
    pub packet_type: Option<LongHeaderPacketType>,
    pub type_specific: u8,
    pub version: u32,
    pub dcid_len: u8,              // length of dcid in bytes
    pub dcid: String,              // hex string
    pub scid_len: u8,              // length of scid in bytes
    pub scid: String,              // hex string
    pub token_len: Option<u64>,    // length of token in bytes, if packet is of type Init or Retry
    pub token: Option<String>,     // hex string, if packet is of type Init or Retry
    pub retry_tag: Option<String>, // hex string, if packet is of type Retry
    /// Versions offered by the server, if this is a Version Negotiation packet
    /// (RFC 9000 Section 17.2.1).
    pub supported_versions: Option<Vec<u32>>,
}

/// Quic Short Header
#[derive(Debug, Serialize, Clone)]
pub struct QuicShortHeader {
    pub dcid: Option<String>, // optional. If not pre-existing cid then none.
}

// Long Header Packet Types from RFC 9000 Table 5
#[derive(Debug, Clone, Serialize, Copy)]
pub enum LongHeaderPacketType {
    Initial,
    ZeroRTT,
    Handshake,
    Retry,
}

impl LongHeaderPacketType {
    pub fn from_u8(value: u8) -> Result<LongHeaderPacketType, QuicError> {
        match value {
            0x00 => Ok(LongHeaderPacketType::Initial),
            0x01 => Ok(LongHeaderPacketType::ZeroRTT),
            0x02 => Ok(LongHeaderPacketType::Handshake),
            0x03 => Ok(LongHeaderPacketType::Retry),
            _ => Err(QuicError::UnknowLongHeaderPacketType),
        }
    }
}
