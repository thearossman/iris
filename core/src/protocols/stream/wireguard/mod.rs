//! WireGuard message-type parsing.
//!
//! WireGuard message payloads are AEAD-encrypted (see the
//! [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf), §5.4), so Iris
//! identifies only the message type of each packet rather than extracting handshake
//! sub-fields (ephemeral keys, MACs, encrypted blobs).

pub mod parser;

use serde::Serialize;

/// The four WireGuard message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum WireGuardMessageType {
    HandshakeInitiation,
    HandshakeResponse,
    CookieReply,
    TransportData,
}

/// Parsed WireGuard connection summary.
#[derive(Debug, Default, Serialize)]
pub struct WireGuard {
    /// `true` if a Handshake Initiation message (type 1) has been observed.
    pub handshake_initiation_seen: bool,
    /// `true` if a Handshake Response message (type 2) has been observed.
    pub handshake_response_seen: bool,
    /// `true` if a Cookie Reply message (type 3) has been observed.
    pub cookie_reply_seen: bool,
    /// Number of Transport Data messages (type 4) observed.
    pub transport_data_count: u32,
    /// Message type of the most recently processed packet.
    pub last_message_type: Option<WireGuardMessageType>,
    #[serde(skip_serializing)]
    pub(crate) last_body_offset: Option<usize>,
}

impl WireGuard {
    pub(crate) fn new() -> WireGuard {
        WireGuard::default()
    }

    /// Returns the message type of the most recently processed packet, if any.
    pub fn message_type(&self) -> Option<WireGuardMessageType> {
        self.last_message_type
    }

    /// Returns `true` if both a Handshake Initiation and a Handshake Response have been
    /// observed on this connection.
    pub fn handshake_complete(&self) -> bool {
        self.handshake_initiation_seen && self.handshake_response_seen
    }

    /// Returns the number of Transport Data messages observed on this connection.
    pub fn transport_data_count(&self) -> u32 {
        self.transport_data_count
    }
}
