//! IKE (Internet Key Exchange) header parsing.
//!
//! Parses the fixed ISAKMP/IKE header shared by IKEv1 ([RFC 2408](https://datatracker.ietf.org/doc/rfc2408/)
//! §3.1) and IKEv2 ([RFC 7296](https://datatracker.ietf.org/doc/rfc7296/) §3.1). Only the
//! header is parsed -- payload contents (SA proposals, key exchange material,
//! identification, etc.) are encrypted or otherwise out of scope and are not extracted.

pub mod parser;

use serde::Serialize;

/// IKEv2 exchange types ([RFC 7296](https://datatracker.ietf.org/doc/rfc7296/) §3.1).
/// IKEv1 exchange-type byte values differ and are reported as `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum IkeExchangeType {
    IkeSaInit,
    IkeAuth,
    CreateChildSa,
    Informational,
    Other(u8),
}

impl IkeExchangeType {
    pub(crate) fn from_byte(b: u8) -> IkeExchangeType {
        match b {
            34 => IkeExchangeType::IkeSaInit,
            35 => IkeExchangeType::IkeAuth,
            36 => IkeExchangeType::CreateChildSa,
            37 => IkeExchangeType::Informational,
            other => IkeExchangeType::Other(other),
        }
    }
}

/// Parsed IKE connection summary.
#[derive(Debug, Default, Serialize)]
pub struct Ike {
    pub initiator_spi: [u8; 8],
    pub responder_spi: [u8; 8],
    pub version_major: u8,
    pub version_minor: u8,
    pub last_exchange_type: Option<IkeExchangeType>,
    pub is_initiator: bool,
    pub is_response: bool,
    pub message_id: u32,
    pub message_count: u32,
    #[serde(skip_serializing)]
    pub(crate) last_body_offset: Option<usize>,
}

impl Ike {
    pub(crate) fn new() -> Ike {
        Ike::default()
    }

    /// Returns the initiator SPI (Security Parameter Index) from the most recent message.
    pub fn initiator_spi(&self) -> [u8; 8] {
        self.initiator_spi
    }

    /// Returns the responder SPI (Security Parameter Index) from the most recent message.
    pub fn responder_spi(&self) -> [u8; 8] {
        self.responder_spi
    }

    /// Returns the (major, minor) IKE protocol version from the most recent message.
    pub fn version(&self) -> (u8, u8) {
        (self.version_major, self.version_minor)
    }

    /// Returns the exchange type of the most recently processed message, if any.
    pub fn exchange_type(&self) -> Option<IkeExchangeType> {
        self.last_exchange_type
    }

    /// Returns `true` if the most recently processed message had the Initiator flag set.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Returns `true` if the most recently processed message had the Response flag set.
    pub fn is_response(&self) -> bool {
        self.is_response
    }

    /// Returns the message ID of the most recently processed message.
    pub fn message_id(&self) -> u32 {
        self.message_id
    }
}
