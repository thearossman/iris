//! WireGuard message-type parsing.
//!
//! WireGuard message payloads are AEAD-encrypted (see the
//! [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf), §5.4), so Iris
//! identifies only the message type of each packet rather than extracting handshake
//! sub-fields (ephemeral keys, MACs, encrypted blobs).
//!
//! A connection is identified as WireGuard, and a [`WireGuard`] session delivered, only if
//! a handshake-phase message (Handshake Initiation, Handshake Response, or Cookie Reply)
//! is actually observed on it. A tunnel picked up mid-stream, after its handshake has
//! already gone by and only encrypted Transport Data remains, is left unidentified --
//! Transport Data alone is too weak a signal (a 4-byte type+reserved match over a
//! variable, mostly-encrypted length) to claim with confidence, and claiming it anyway
//! would misreport an already-established tunnel as freshly identified.

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
/// A session is only ever created for a connection on which a handshake-phase message was
/// observed (see the module docs) -- so every delivered `WireGuard` reflects a connection
/// where at least one of `handshake_initiation_seen` and `cookie_reply_seen` is `true`.
/// Fields describe the *opening* of the tunnel, not its full lifetime: Iris delivers the
/// session as soon as header parsing completes and does not parse further packets on the
/// connection, so these are one-shot observations rather than running tallies.
#[derive(Debug, Default, Serialize)]
pub struct WireGuard {
    /// `true` if a Handshake Initiation message (type 1) was observed.
    pub handshake_initiation_seen: bool,
    /// `true` if a Handshake Response message (type 2) was observed.
    pub handshake_response_seen: bool,
    /// `true` if a Cookie Reply message (type 3) was observed.
    pub cookie_reply_seen: bool,
    /// `true` if a Transport Data message (type 4) completed header parsing -- i.e. a
    /// handshake-phase message was observed (see the `Scope` note above), but the
    /// connection's Transport Data began before a Handshake Response was also captured
    /// (e.g. the response was lost, or was not part of the earlier-matched exchange).
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

    /// Returns `true` if a Transport Data message completed header parsing. See
    /// [`WireGuard::transport_data_seen`] for what this does (and does not) imply.
    pub fn transport_data_seen(&self) -> bool {
        self.transport_data_seen
    }
}
