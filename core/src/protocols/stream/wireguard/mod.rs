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
///
/// ## Scope
/// These fields describe the *opening* of a tunnel, not its full lifetime. Iris delivers
/// the session as soon as header parsing completes -- on the handshake response, or on the
/// first Transport Data message for a tunnel picked up mid-stream -- and does not parse
/// further packets on the connection. Fields are therefore one-shot observations rather
/// than running tallies.
#[derive(Debug, Default, Serialize)]
pub struct WireGuard {
    /// `true` if a Handshake Initiation message (type 1) was observed.
    pub handshake_initiation_seen: bool,
    /// `true` if a Handshake Response message (type 2) was observed.
    pub handshake_response_seen: bool,
    /// `true` if a Cookie Reply message (type 3) was observed.
    pub cookie_reply_seen: bool,
    /// `true` if a Transport Data message (type 4) was observed. Only set when the tunnel
    /// was picked up mid-stream, since a tunnel observed from its handshake is delivered
    /// before any transport data is parsed.
    pub transport_data_seen: bool,
    /// Message type of the packet that completed header parsing.
    pub message_type: Option<WireGuardMessageType>,
}

impl WireGuard {
    pub(crate) fn new() -> WireGuard {
        WireGuard::default()
    }

    /// Returns the message type of the packet that completed header parsing, if any.
    pub fn message_type(&self) -> Option<WireGuardMessageType> {
        self.message_type
    }

    /// Returns `true` if both a Handshake Initiation and a Handshake Response were
    /// observed on this connection.
    pub fn handshake_complete(&self) -> bool {
        self.handshake_initiation_seen && self.handshake_response_seen
    }

    /// Returns `true` if a Transport Data message was observed. See
    /// [`WireGuard::transport_data_seen`] for why this is only set for mid-stream pickup.
    pub fn transport_data_seen(&self) -> bool {
        self.transport_data_seen
    }
}
