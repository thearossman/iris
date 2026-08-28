//! CAPWAP (Control And Provisioning of Wireless Access Points) header parsing.
//!
//! Parses the fixed CAPWAP transport header ([RFC 5415](https://datatracker.ietf.org/doc/rfc5415/)
//! §4.3), shared by both the control channel (UDP port 5246) and the data channel (UDP port
//! 5247), plus the control header (§4.5.1) when the message is a control message. CAPWAP
//! payloads -- message elements on the control channel, and 802.11/802.3 frames on the data
//! channel -- are out of scope and are not extracted.
//!
//! CAPWAP optionally tunnels its payload inside DTLS ([RFC 5415] §3, preamble type 1). The
//! transport header itself is always sent in the clear even when DTLS is in use, so it is
//! always parsed; the DTLS record that follows it is detected (see [`parser::classify_probe`])
//! but not decrypted, and no control header is extracted from it.

pub mod parser;

use serde::Serialize;

/// Base-spec CAPWAP control message types ([RFC 5415] §5). Message types defined by other
/// enterprises (a nonzero vendor/enterprise number in the message type field), and base-spec
/// values outside the range assigned by the RFC, are reported as `Other`. `None` means no
/// control header was parsed for this message -- e.g. a data-channel message, or a
/// DTLS-encapsulated message whose control header (if any) is encrypted.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MsgType {
    DiscoveryRequest,
    DiscoveryResponse,
    JoinRequest,
    JoinResponse,
    ConfigurationStatusRequest,
    ConfigurationStatusResponse,
    ConfigurationUpdateRequest,
    ConfigurationUpdateResponse,
    WtpEventRequest,
    WtpEventResponse,
    ChangeStateEventRequest,
    ChangeStateEventResponse,
    EchoRequest,
    EchoResponse,
    ImageDataRequest,
    ImageDataResponse,
    ResetRequest,
    ResetResponse,
    PrimaryDiscoveryRequest,
    PrimaryDiscoveryResponse,
    DataTransferRequest,
    DataTransferResponse,
    ClearConfigurationRequest,
    ClearConfigurationResponse,
    StationConfigurationRequest,
    StationConfigurationResponse,
    /// A message type outside the base-spec range 1..=26, or one qualified by a nonzero
    /// enterprise number. Carries the raw low-order message-type byte.
    Other(u8),
    /// No control header was parsed for this message.
    #[default]
    None,
}

impl MsgType {
    /// Maps a base-spec message-type byte (the low 8 bits of the 32-bit message type field)
    /// to its named variant, or `Other` if it falls outside the assigned range.
    pub(crate) fn from_byte(b: u8) -> MsgType {
        match b {
            1 => MsgType::DiscoveryRequest,
            2 => MsgType::DiscoveryResponse,
            3 => MsgType::JoinRequest,
            4 => MsgType::JoinResponse,
            5 => MsgType::ConfigurationStatusRequest,
            6 => MsgType::ConfigurationStatusResponse,
            7 => MsgType::ConfigurationUpdateRequest,
            8 => MsgType::ConfigurationUpdateResponse,
            9 => MsgType::WtpEventRequest,
            10 => MsgType::WtpEventResponse,
            11 => MsgType::ChangeStateEventRequest,
            12 => MsgType::ChangeStateEventResponse,
            13 => MsgType::EchoRequest,
            14 => MsgType::EchoResponse,
            15 => MsgType::ImageDataRequest,
            16 => MsgType::ImageDataResponse,
            17 => MsgType::ResetRequest,
            18 => MsgType::ResetResponse,
            19 => MsgType::PrimaryDiscoveryRequest,
            20 => MsgType::PrimaryDiscoveryResponse,
            21 => MsgType::DataTransferRequest,
            22 => MsgType::DataTransferResponse,
            23 => MsgType::ClearConfigurationRequest,
            24 => MsgType::ClearConfigurationResponse,
            25 => MsgType::StationConfigurationRequest,
            26 => MsgType::StationConfigurationResponse,
            other => MsgType::Other(other),
        }
    }
}

/// Which CAPWAP channel a message was observed on.
///
/// Decided primarily by UDP port (5246 = control, 5247 = data). For traffic on neither
/// standard port, [`parser::Capwap::update`] falls back to whether a valid base-spec control
/// header follows the transport header: present means `Control`, absent means `Data`.
/// `Unknown` is the value before any message has been parsed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Channel {
    Control,
    Data,
    #[default]
    Unknown,
}

/// Parsed CAPWAP connection summary.
///
/// ## Scope
/// Every field describes the message that finalized parsing on the connection -- normally
/// the first one, since Iris delivers the session as soon as the transport header (and, on
/// the control channel, the control header) has been parsed and does not parse further
/// packets on the connection afterward. The one exception is a plaintext Discovery
/// Request/Response on the control channel, which doesn't finalize by itself (see
/// [`Capwap::update`] -- CAPWAP's own spec guarantees Discovery is unencrypted and precedes
/// DTLS setup, so stopping there would make `preamble_type`/`is_dtls` permanently misreport
/// an about-to-be-encrypted connection as unencrypted).
/// Whichever message actually finalizes parsing (or, if the connection ends first, the last
/// Discovery message observed) is what every field reflects; later messages past that point
/// are never seen.
#[derive(Debug, Default, Serialize)]
pub struct Capwap {
    version: u8,
    preamble_type: u8,
    hlen: u8,
    rid: u8,
    wbid: u8,
    payload_type: u8,
    is_fragment: bool,
    last_fragment: bool,
    keep_alive: bool,
    fragment_id: u16,
    fragment_offset: u16,
    radio_mac: Option<Vec<u8>>,
    wireless_info: Option<Vec<u8>>,
    vendor_id: u32,
    msg_type_value: u32,
    msg_type_id: u32,
    msg_type: MsgType,
    seq_num: u8,
    msg_element_length: u16,
    channel: Channel,
}

impl Capwap {
    pub(crate) fn new() -> Capwap {
        Capwap::default()
    }

    /// Returns the CAPWAP protocol version (the top 4 bits of the preamble byte). Always 0
    /// for [RFC 5415] traffic.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns the preamble type (the bottom 4 bits of the preamble byte): 0 for plaintext,
    /// 1 for DTLS-encapsulated.
    pub fn preamble_type(&self) -> u8 {
        self.preamble_type
    }

    /// Returns `true` if the preamble type indicates DTLS encapsulation. The DTLS record is
    /// detected but not decrypted -- see the module docs.
    pub fn is_dtls(&self) -> bool {
        self.preamble_type == 1
    }

    /// Returns HLEN: the transport header length in 4-byte words.
    pub fn hlen(&self) -> u8 {
        self.hlen
    }

    /// Returns the Radio ID.
    pub fn rid(&self) -> u8 {
        self.rid
    }

    /// Returns the Wireless Binding ID.
    pub fn wbid(&self) -> u8 {
        self.wbid
    }

    /// Returns the raw T (payload type) flag from the transport header.
    pub fn payload_type(&self) -> u8 {
        self.payload_type
    }

    /// Returns `true` if the Fragment (F) flag is set -- the payload is a fragment of a
    /// larger CAPWAP packet.
    pub fn is_fragment(&self) -> bool {
        self.is_fragment
    }

    /// Returns `true` if the Last Fragment (L) flag is set.
    pub fn last_fragment(&self) -> bool {
        self.last_fragment
    }

    /// Returns `true` if the Keep-Alive (K) flag is set (data-channel keep-alive).
    pub fn keep_alive(&self) -> bool {
        self.keep_alive
    }

    /// Returns the Fragment ID.
    pub fn fragment_id(&self) -> u16 {
        self.fragment_id
    }

    /// Returns the Fragment Offset (in 8-byte units, per [RFC 5415]).
    pub fn fragment_offset(&self) -> u16 {
        self.fragment_offset
    }

    /// Returns the optional Radio MAC Address field, if the M flag was set.
    pub fn radio_mac(&self) -> Option<&[u8]> {
        self.radio_mac.as_deref()
    }

    /// Returns the optional Wireless Specific Information field, if the W flag was set.
    pub fn wireless_info(&self) -> Option<&[u8]> {
        self.wireless_info.as_deref()
    }

    /// Returns the enterprise (vendor) number from the control header's Message Type field,
    /// or 0 if no control header was parsed.
    pub fn vendor_id(&self) -> u32 {
        self.vendor_id
    }

    /// Returns the raw 32-bit Message Type field from the control header (enterprise number
    /// in the high 24 bits, message type in the low 8), or 0 if no control header was
    /// parsed.
    pub fn msg_type_value(&self) -> u32 {
        self.msg_type_value
    }

    /// Returns the low-order message-type byte from the control header's Message Type field
    /// -- the useful part for base-spec messages -- or 0 if no control header was parsed.
    pub fn msg_type_id(&self) -> u32 {
        self.msg_type_id
    }

    /// Returns the named message type, or [`MsgType::None`] if no control header was parsed
    /// for this message (e.g. a data-channel or DTLS-encapsulated message).
    pub fn msg_type(&self) -> MsgType {
        self.msg_type
    }

    /// Returns the control header's Sequence Number, or 0 if no control header was parsed.
    pub fn seq_num(&self) -> u8 {
        self.seq_num
    }

    /// Returns the control header's Message Element Length, or 0 if no control header was
    /// parsed.
    pub fn msg_element_length(&self) -> u16 {
        self.msg_element_length
    }

    /// Returns the channel (control or data) this message was observed on. See [`Channel`].
    pub fn channel(&self) -> Channel {
        self.channel
    }
}
