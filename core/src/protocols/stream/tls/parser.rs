//! TLS handshake parser.
//!
//! The TLS handshake parser uses a [fork](https://github.com/thegwan/tls-parser) of the
//! [tls-parser](https://docs.rs/tls-parser/latest/tls_parser/) crate to parse the handshake phase
//! of a TLS connection. It maintains TLS state, stores selected parameters, and handles
//! defragmentation.
//!
//! Adapted from [the Rusticata TLS
//! parser](https://github.com/rusticata/rusticata/blob/master/src/tls.rs).

use super::handshake::{
    Certificate, ClientDHParams, ClientECDHParams, ClientHello, ClientKeyExchange, ClientRSAParams,
    KeyShareEntry, ServerDHParams, ServerECDHParams, ServerHello, ServerKeyExchange,
    ServerRSAParams,
};
use super::Tls;
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::{
    ConnParsable, ParseResult, ParsingState, ProbeResult, Session, SessionData,
};

use tls_parser::*;

/// Parses a single TLS handshake per connection.
#[derive(Debug)]
pub struct TlsParser {
    /// Handshakes seen. We expect there to only be one.
    sessions: Vec<Tls>,
}

impl Default for TlsParser {
    fn default() -> Self {
        TlsParser {
            sessions: vec![Tls::new()],
        }
    }
}

impl ConnParsable for TlsParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        log::debug!("Updating parser tls");
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            self.sessions[0].parse_tcp_level(data, pdu.dir)
        } else {
            log::warn!("Malformed packet");
            ParseResult::Skipped
        }
    }

    fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        let offset = pdu.offset();
        let length = pdu.length();
        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            classify_probe(data)
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }

    fn remove_session(&mut self, _session_id: usize) -> Option<Session> {
        self.sessions.pop().map(|tls| Session {
            data: SessionData::Tls(Box::new(tls)),
            id: 0,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain(..)
            .map(|tls| Session {
                data: SessionData::Tls(Box::new(tls)),
                id: 0,
            })
            .collect()
    }

    fn session_parsed_state(&self) -> ParsingState {
        ParsingState::Stop
    }

    fn body_offset(&mut self) -> Option<usize> {
        match self.sessions.last_mut() {
            Some(tls) => std::mem::take(&mut tls.last_body_offset),
            None => None,
        }
    }
}

/// Bytes needed to tell an SSLv2-format ClientHello apart from other traffic whose first byte
/// happens to have the high bit set.
const SSLV2_PROBE_LEN: usize = 5;

/// Classifies the first bytes of a (possibly reassembled) TCP segment as TLS, an SSLv2-format
/// ClientHello, or neither. Factored out of [`TlsParser::probe`] so it can be unit-tested over
/// raw bytes without an `Mbuf`.
pub(crate) fn classify_probe(data: &[u8]) -> ProbeResult {
    match data {
        // TLS/SSLv3 record: content type (0x16 is Handshake), version major, version minor.
        // Does not support versions <= SSLv2 in this form.
        [0x14..=0x17, 0x03, 0..=3, ..] => ProbeResult::Certain,
        // SSLv2-format ClientHello (RFC 5246 Appendix E.2, the backward-compatible hello some
        // clients still send): a 2-byte length header with the high bit set (no padding byte),
        // then msg_type = 1 (CLIENT-HELLO) and a 3.x client version.
        [b0, _, 0x01, 0x03, 0..=3, ..] if b0 & 0x80 != 0 => ProbeResult::Certain,
        // High bit set but too few bytes yet to confirm the SSLv2 form.
        [b0, ..] if b0 & 0x80 != 0 && data.len() < SSLV2_PROBE_LEN => ProbeResult::Unsure,
        // Too few bytes to classify at all.
        _ if data.len() < 3 => ProbeResult::Unsure,
        _ => ProbeResult::NotForUs,
    }
}

/// Errors from [`parse_sslv2_client_hello`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SslV2Error {
    /// Not enough bytes yet to parse the full message.
    Incomplete,
    /// Bytes were present but did not form a valid SSLv2 ClientHello.
    Malformed,
}

/// A parsed SSLv2-format ClientHello (RFC 5246 Appendix E.2).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SslV2ClientHello {
    pub(crate) version: u16,
    /// Each cipher spec is 3 bytes; v3-compatible specs have a leading byte of 0.
    pub(crate) cipher_specs: Vec<u32>,
    pub(crate) session_id: Vec<u8>,
    pub(crate) challenge: Vec<u8>,
}

/// Parses an SSLv2-format ClientHello at the start of `data`. On success, returns the number of
/// bytes consumed (the 2-byte length header plus the message body) along with the parsed hello.
pub(crate) fn parse_sslv2_client_hello(
    data: &[u8],
) -> Result<(usize, SslV2ClientHello), SslV2Error> {
    if data.len() < 2 {
        return Err(SslV2Error::Incomplete);
    }
    let hdr = u16::from_be_bytes([data[0], data[1]]);
    if hdr & 0x8000 == 0 {
        return Err(SslV2Error::Malformed);
    }
    let msg_len = (hdr & 0x7fff) as usize;
    let total_len = 2 + msg_len;
    if data.len() < total_len {
        return Err(SslV2Error::Incomplete);
    }
    let body = &data[2..total_len];
    // msg_type(1) + version(2) + cipher_spec_len(2) + session_id_len(2) + challenge_len(2)
    if body.len() < 9 || body[0] != 0x01 {
        return Err(SslV2Error::Malformed);
    }
    let version = u16::from_be_bytes([body[1], body[2]]);
    let cipher_spec_len = u16::from_be_bytes([body[3], body[4]]) as usize;
    let session_id_len = u16::from_be_bytes([body[5], body[6]]) as usize;
    let challenge_len = u16::from_be_bytes([body[7], body[8]]) as usize;
    if 9 + cipher_spec_len + session_id_len + challenge_len != body.len() {
        return Err(SslV2Error::Malformed);
    }
    if !cipher_spec_len.is_multiple_of(3) {
        return Err(SslV2Error::Malformed);
    }
    let mut off = 9;
    let cipher_specs = body[off..off + cipher_spec_len]
        .chunks_exact(3)
        .map(|c| u32::from_be_bytes([0, c[0], c[1], c[2]]))
        .collect();
    off += cipher_spec_len;
    let session_id = body[off..off + session_id_len].to_vec();
    off += session_id_len;
    let challenge = body[off..off + challenge_len].to_vec();
    Ok((
        total_len,
        SslV2ClientHello {
            version,
            cipher_specs,
            session_id,
            challenge,
        },
    ))
}

// ------------------------------------------------------------

impl Tls {
    /// Allocate a new TLS handshake instance.
    pub(crate) fn new() -> Tls {
        Tls {
            client_hello: None,
            server_hello: None,
            server_certificates: vec![],
            client_certificates: vec![],
            server_key_exchange: None,
            client_key_exchange: None,
            state: TlsState::None,
            tcp_buffer: vec![],
            record_buffer: vec![],
            last_body_offset: None,
        }
    }

    /// Applies a parsed SSLv2-format ClientHello (see [`parse_sslv2_client_hello`]) as this
    /// connection's `ClientHello` and advances the state machine as if a v3 ClientHello had just
    /// been parsed, so the rest of the handshake (ServerHello, ChangeCipherSpec, ...) proceeds
    /// through the normal v3 state machine.
    ///
    /// Extensions, compression methods, and SNI are not part of the SSLv2 wire format, so those
    /// fields are left empty -- `sni()` correctly returns `""` for these handshakes.
    fn parse_sslv2_handshake(&mut self, hello: SslV2ClientHello) {
        self.client_hello = Some(ClientHello {
            version: TlsVersion(hello.version),
            random: hello.challenge,
            session_id: hello.session_id,
            // Only the v3-compatible specs (leading byte 0) have a `TlsCipherSuiteID`;
            // SSLv2-only suites such as SSL2_RC4_128_WITH_MD5 (0x010080) are dropped.
            cipher_suites: hello
                .cipher_specs
                .iter()
                .filter(|c| *c >> 16 == 0)
                .map(|c| TlsCipherSuiteID(*c as u16))
                .collect(),
            ..ClientHello::default()
        });
        self.state = TlsState::ClientHello;
    }

    /// Parse a ClientHello message.
    pub(crate) fn parse_handshake_clienthello(&mut self, content: &TlsClientHelloContents) {
        let mut client_hello = ClientHello {
            version: content.version,
            random: content.random.to_vec(),
            session_id: match content.session_id {
                Some(v) => v.to_vec(),
                None => vec![],
            },
            cipher_suites: content.ciphers.to_vec(),
            compression_algs: content.comp.to_vec(),
            ..ClientHello::default()
        };

        let ext = parse_tls_client_hello_extensions(content.ext.unwrap_or(b""));
        log::trace!("client extensions: {:#?}", ext);
        match &ext {
            Ok((rem, ref ext_lst)) => {
                if !rem.is_empty() {
                    log::debug!("warn: extensions not entirely parsed");
                }
                for extension in ext_lst {
                    client_hello
                        .extension_list
                        .push(TlsExtensionType::from(extension));
                    match *extension {
                        TlsExtension::SNI(ref v) if !v.is_empty() => {
                            let sni = v[0].1;
                            client_hello.server_name = Some(match std::str::from_utf8(sni) {
                                Ok(name) => name.to_string(),
                                Err(_) => format!("<Invalid UTF-8: {}>", hex::encode(sni)),
                            });
                        }
                        TlsExtension::SupportedGroups(ref v) => {
                            client_hello.supported_groups = v.clone();
                        }
                        TlsExtension::EcPointFormats(v) => {
                            client_hello.ec_point_formats = v.to_vec();
                        }
                        TlsExtension::SignatureAlgorithms(ref v) => {
                            client_hello.signature_algs = v.clone();
                        }
                        TlsExtension::ALPN(ref v) => {
                            for proto in v {
                                client_hello.alpn_protocols.push(
                                    match std::str::from_utf8(proto) {
                                        Ok(proto) => proto.to_string(),
                                        Err(_) => {
                                            format!("<Invalid UTF-8: {}>", hex::encode(proto))
                                        }
                                    },
                                );
                            }
                        }
                        TlsExtension::KeyShare(ref v) => {
                            log::debug!("Client Shares: {:?}", v);
                            client_hello.key_shares = v
                                .iter()
                                .map(|k| KeyShareEntry {
                                    group: k.group,
                                    kx_data: k.kx.to_vec(),
                                })
                                .collect();
                        }
                        TlsExtension::SupportedVersions(ref v) => {
                            client_hello.supported_versions = v.clone();
                        }
                        _ => (),
                    }
                }
            }
            e => log::debug!("Could not parse extensions: {:?}", e),
        };
        self.client_hello = Some(client_hello);
    }

    /// Parse a ServerHello message.
    fn parse_handshake_serverhello(&mut self, content: &TlsServerHelloContents) {
        let mut server_hello = ServerHello {
            version: content.version,
            random: content.random.to_vec(),
            session_id: match content.session_id {
                Some(v) => v.to_vec(),
                None => vec![],
            },
            cipher_suite: content.cipher,
            compression_alg: content.compression,
            ..ServerHello::default()
        };

        let ext = parse_tls_server_hello_extensions(content.ext.unwrap_or(b""));
        log::debug!("server_hello extensions: {:#?}", ext);
        match &ext {
            Ok((rem, ref ext_lst)) => {
                if !rem.is_empty() {
                    log::debug!("warn: extensions not entirely parsed");
                }
                for extension in ext_lst {
                    server_hello
                        .extension_list
                        .push(TlsExtensionType::from(extension));
                    match *extension {
                        TlsExtension::EcPointFormats(v) => {
                            server_hello.ec_point_formats = v.to_vec();
                        }
                        TlsExtension::ALPN(ref v) if !v.is_empty() => {
                            server_hello.alpn_protocol = Some(match std::str::from_utf8(v[0]) {
                                Ok(proto) => proto.to_string(),
                                Err(_) => format!("<Invalid UTF-8: {}>", hex::encode(v[0])),
                            });
                        }
                        TlsExtension::KeyShare(ref v) => {
                            log::debug!("Server Share: {:?}", v);
                            if !v.is_empty() {
                                server_hello.key_share = Some(KeyShareEntry {
                                    group: v[0].group,
                                    kx_data: v[0].kx.to_vec(),
                                });
                            }
                        }
                        TlsExtension::SupportedVersions(ref v) if !v.is_empty() => {
                            server_hello.selected_version = Some(v[0]);
                        }
                        _ => (),
                    }
                }
            }
            e => log::debug!("Could not parse extensions: {:?}", e),
        };
        self.server_hello = Some(server_hello);
    }

    /// Parse a Certificate message.
    fn parse_handshake_certificate(&mut self, content: &TlsCertificateContents, direction: bool) {
        log::trace!("cert chain length: {}", content.cert_chain.len());
        if direction {
            // client -> server
            for cert in &content.cert_chain {
                self.client_certificates.push(Certificate {
                    raw: cert.data.to_vec(),
                })
            }
        } else {
            // server -> client
            for cert in &content.cert_chain {
                self.server_certificates.push(Certificate {
                    raw: cert.data.to_vec(),
                })
            }
        }
    }

    /// Parse a ServerKeyExchange message.
    fn parse_handshake_serverkeyexchange(&mut self, content: &TlsServerKeyExchangeContents) {
        log::trace!("SKE: {:?}", content);
        if let Some(cipher) = self.cipher_suite() {
            match &cipher.kx {
                TlsCipherKx::Ecdhe | TlsCipherKx::Ecdh => {
                    if let Ok((_sig, ref parsed)) = parse_server_ecdh_params(content.parameters) {
                        if let ECParametersContent::NamedGroup(curve) =
                            parsed.curve_params.params_content
                        {
                            let ecdh_params = ServerECDHParams {
                                curve,
                                kx_data: parsed.public.point.to_vec(),
                            };
                            self.server_key_exchange = Some(ServerKeyExchange::Ecdh(ecdh_params));
                        };
                    }
                }
                TlsCipherKx::Dhe | TlsCipherKx::Dh => {
                    if let Ok((_sig, ref parsed)) = parse_server_dh_params(content.parameters) {
                        let dh_params = ServerDHParams {
                            prime: parsed.dh_p.to_vec(),
                            generator: parsed.dh_g.to_vec(),
                            kx_data: parsed.dh_ys.to_vec(),
                        };
                        self.server_key_exchange = Some(ServerKeyExchange::Dh(dh_params));
                    }
                }
                TlsCipherKx::Rsa => {
                    if let Ok((_sig, ref parsed)) = parse_server_rsa_params(content.parameters) {
                        let rsa_params = ServerRSAParams {
                            modulus: parsed.modulus.to_vec(),
                            exponent: parsed.exponent.to_vec(),
                        };
                        self.server_key_exchange = Some(ServerKeyExchange::Rsa(rsa_params));
                    }
                }
                _ => {
                    self.server_key_exchange =
                        Some(ServerKeyExchange::Unknown(content.parameters.to_vec()))
                }
            }
        }
    }

    /// Parse a ClientKeyExchange message.
    fn parse_handshake_clientkeyexchange(&mut self, content: &TlsClientKeyExchangeContents) {
        log::trace!("CKE: {:?}", content);
        if let Some(cipher) = self.cipher_suite() {
            match &cipher.kx {
                TlsCipherKx::Ecdhe | TlsCipherKx::Ecdh => {
                    if let Ok((_rem, ref parsed)) = parse_client_ecdh_params(content.parameters) {
                        let ecdh_params = ClientECDHParams {
                            kx_data: parsed.ecdh_yc.point.to_vec(),
                        };
                        self.client_key_exchange = Some(ClientKeyExchange::Ecdh(ecdh_params));
                    }
                }
                TlsCipherKx::Dhe | TlsCipherKx::Dh => {
                    if let Ok((_rem, ref parsed)) = parse_client_dh_params(content.parameters) {
                        let dh_params = ClientDHParams {
                            kx_data: parsed.dh_yc.to_vec(),
                        };
                        self.client_key_exchange = Some(ClientKeyExchange::Dh(dh_params));
                    }
                }
                TlsCipherKx::Rsa => {
                    if let Ok((_rem, ref parsed)) = parse_client_rsa_params(content.parameters) {
                        let rsa_params = ClientRSAParams {
                            encrypted_pms: parsed.data.to_vec(),
                        };
                        self.client_key_exchange = Some(ClientKeyExchange::Rsa(rsa_params));
                    }
                }
                _ => {
                    self.client_key_exchange =
                        Some(ClientKeyExchange::Unknown(content.parameters.to_vec()))
                }
            }
        }
        //self.client_key_exchange = Some(client_key_exchange);
    }

    /// Parse a TLS message.
    pub(crate) fn parse_message_level(&mut self, msg: &TlsMessage, direction: bool) -> ParseResult {
        log::trace!("parse_message_level {:?}", msg);

        // do not parse if session is encrypted
        if self.state == TlsState::ClientChangeCipherSpec {
            log::trace!("TLS session encrypted, activating bypass");
            return ParseResult::HeadersDone(0);
        }

        // update state machine
        //
        // Note: `tls_state_transition` from the `tls-parser` crate
        // doesn't handle the TLS 1.3 middlebox-compatibility ChangeCipherSpec
        // transition (RFC 8446).
        let transition =
            if self.state == TlsState::ServerHello && matches!(msg, TlsMessage::ChangeCipherSpec) {
                Ok(TlsState::ClientChangeCipherSpec)
            } else {
                tls_state_transition(self.state, msg, direction)
            };
        match transition {
            Ok(s) => self.state = s,
            Err(_) => {
                self.state = TlsState::Invalid;
            }
        };
        log::trace!("TLS new state: {:?}", self.state);

        // extract variables
        match *msg {
            TlsMessage::Handshake(ref m) => match *m {
                TlsMessageHandshake::ClientHello(ref content) => {
                    self.parse_handshake_clienthello(content);
                }
                TlsMessageHandshake::ServerHello(ref content) => {
                    self.parse_handshake_serverhello(content);
                }
                TlsMessageHandshake::Certificate(ref content) => {
                    self.parse_handshake_certificate(content, direction);
                }
                TlsMessageHandshake::ServerKeyExchange(ref content) => {
                    self.parse_handshake_serverkeyexchange(content);
                }
                TlsMessageHandshake::ClientKeyExchange(ref content) => {
                    self.parse_handshake_clientkeyexchange(content);
                }

                _ => (),
            },
            TlsMessage::Alert(ref a) if a.severity == TlsAlertSeverity::Fatal => {
                return ParseResult::HeadersDone(0);
            }
            _ => (),
        }

        ParseResult::Continue(0)
    }

    /// Parse a TLS record.
    pub(crate) fn parse_record_level(
        &mut self,
        record: &TlsRawRecord<'_>,
        direction: bool,
        pdu_len: usize,
    ) -> ParseResult {
        let mut v: Vec<u8>;
        let mut status = ParseResult::Continue(0);

        log::trace!("parse_record_level ({} bytes)", record.data.len());
        log::trace!("{:?}", record.hdr);
        // log::trace!("{:?}", record.data);

        // do not parse if session is encrypted
        if self.state == TlsState::ClientChangeCipherSpec {
            log::trace!("TLS session encrypted, activating bypass");
            return ParseResult::HeadersDone(0);
        }

        // only parse some message types (the Content type, first byte of TLS record)
        match record.hdr.record_type {
            TlsRecordType::ChangeCipherSpec => (),
            TlsRecordType::Handshake => (),
            TlsRecordType::Alert => (),
            _ => return ParseResult::Continue(0),
        }

        // Check if a record is being defragmented
        let record_buffer = match self.record_buffer.len() {
            0 => record.data,
            _ => {
                // sanity check vector length to avoid memory exhaustion maximum length may be 2^24
                // (handshake message)
                if self.record_buffer.len() + record.data.len() > 16_777_216 {
                    return ParseResult::Skipped;
                };
                v = self.record_buffer.split_off(0);
                v.extend_from_slice(record.data);
                v.as_slice()
            }
        };

        // NICE-TO-HAVE: record may be compressed Parse record contents as plaintext
        match parse_tls_record_with_header(record_buffer, &record.hdr) {
            Ok((rem, ref msg_list)) => {
                for msg in msg_list {
                    status = self.parse_message_level(msg, direction);
                    if status != ParseResult::Continue(0) {
                        // Handshake done, but data remaining
                        let remaining = rem.len();
                        if matches!(status, ParseResult::HeadersDone(_))
                            && remaining > 0
                            && remaining < pdu_len
                        {
                            self.last_body_offset = Some(pdu_len - remaining - 1);
                        }
                        return status;
                    }
                }
                if !rem.is_empty() {
                    log::debug!("warn: extra bytes in TLS record: {:?}", rem);
                };
            }
            Err(Err::Incomplete(needed)) => {
                log::trace!(
                    "Defragmentation required (TLS record), missing {:?} bytes",
                    needed
                );
                self.record_buffer.extend_from_slice(record.data);
            }
            Err(_e) => {
                log::debug!("warn: parse_tls_record_with_header failed");
                return ParseResult::Skipped;
            }
        };

        status
    }

    /// Parse a TCP segment, handling TCP chunks fragmentation.
    pub(crate) fn parse_tcp_level(&mut self, data: &[u8], direction: bool) -> ParseResult {
        let mut v: Vec<u8>;
        let mut status = ParseResult::Continue(0);
        let pdu_len = data.len(); // new data len
        log::trace!("parse_tcp_level ({} bytes)", data.len());
        log::trace!("defrag buffer size: {}", self.tcp_buffer.len());

        // do not parse if session is encrypted
        if self.state == TlsState::ClientChangeCipherSpec {
            log::trace!("TLS session encrypted, activating bypass");
            return ParseResult::HeadersDone(0);
        };
        // Check if TCP data is being defragmented
        let tcp_buffer = match self.tcp_buffer.len() {
            0 => data,
            _ => {
                // sanity check vector length to avoid memory exhaustion maximum length may be 2^24
                // (handshake message)
                if self.tcp_buffer.len() + data.len() > 16_777_216 {
                    return ParseResult::Skipped;
                };
                v = self.tcp_buffer.split_off(0);
                v.extend_from_slice(data);
                v.as_slice()
            }
        };
        let mut cur_data = tcp_buffer;

        // Before the very first record, check for an SSLv2-format ClientHello (see
        // `classify_probe`/`parse_sslv2_client_hello`) instead of a v3 record. This can only be
        // the first message of a connection, so it is only attempted once, gated on `state`.
        if self.state == TlsState::None {
            match parse_sslv2_client_hello(cur_data) {
                Ok((consumed, hello)) => {
                    self.parse_sslv2_handshake(hello);
                    cur_data = &cur_data[consumed..];
                }
                Err(SslV2Error::Incomplete) => {
                    self.tcp_buffer.extend_from_slice(cur_data);
                    return status;
                }
                Err(SslV2Error::Malformed) => {
                    // Not an SSLv2 hello either (or a corrupt one); fall through to the normal
                    // v3 record parser below.
                }
            }
        }

        while !cur_data.is_empty() {
            // parse each TLS record in the TCP segment (there could be multiple)
            match parse_tls_raw_record(cur_data) {
                Ok((rem, ref record)) => {
                    cur_data = rem;
                    status = self.parse_record_level(record, direction, pdu_len);
                    if status != ParseResult::Continue(0) {
                        return status;
                    }
                }
                Err(Err::Incomplete(needed)) => {
                    log::trace!(
                        "Defragmentation required (TCP level), missing {:?} bytes",
                        needed
                    );
                    self.tcp_buffer.extend_from_slice(cur_data);
                    break;
                }
                Err(_e) => {
                    log::debug!("warn: Parsing raw record failed");
                    break;
                }
            }
        }
        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SSLv2-format ClientHello, captured as frame 4032 of `traces/small_flows.pcap` (stream
    /// 164). 15 cipher specs (9 v3-compatible, 6 SSLv2-only), no session ID, 16-byte challenge.
    const SSLV2_CLIENT_HELLO: &str = "8046010301002d00000010000005000004000\
00a0000090000640000620000080000030000060100800700c00300800600400200800400807cbdca33481976efd43\
5e26b20110ea7";

    /// TLS 1.0 ServerHello record replying to the above, captured as frame 4033 (same stream).
    const SERVER_HELLO_RECORD: &str = "160301004a020000460301401be48602ade029e17774e544b9c99cb4\
31315e02dd779d154a9609ba5da870201ca0e4f64c6351ae2f8e4ee1e6766a0a88d5d8c55cae98c5e481f22a69bf905\
8000500";

    /// A second, distinct SSLv2-format ClientHello, captured as frame 4884 (stream 218).
    const SSLV2_CLIENT_HELLO_2: &str = "804c01030000330000001000000400000500000a0100800700c0030\
08000000906004000006400006200000300000602008004008000001300001200006373d2cf902a02321147358f7b8\
014b688";

    /// A v3 record whose body is entirely empty -- the legitimate 5-byte first segment some
    /// clients send (e.g. streams 176/203/204/209/212/247/284 in `small_flows.pcap`).
    const EMPTY_V3_RECORD: &str = "1603010000";

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn classify_probe_recognizes_v3_records() {
        assert_eq!(classify_probe(&hex(EMPTY_V3_RECORD)), ProbeResult::Certain);
        assert_eq!(
            classify_probe(&hex(SERVER_HELLO_RECORD)),
            ProbeResult::Certain
        );
    }

    #[test]
    fn classify_probe_recognizes_sslv2_client_hello() {
        assert_eq!(
            classify_probe(&hex(SSLV2_CLIENT_HELLO)),
            ProbeResult::Certain
        );
        assert_eq!(
            classify_probe(&hex(SSLV2_CLIENT_HELLO_2)),
            ProbeResult::Certain
        );
    }

    #[test]
    fn classify_probe_unsure_on_short_input() {
        let full = hex(SSLV2_CLIENT_HELLO);
        for n in 0..SSLV2_PROBE_LEN {
            assert_eq!(
                classify_probe(&full[..n]),
                ProbeResult::Unsure,
                "expected Unsure at length {n}"
            );
        }
        assert_eq!(classify_probe(&[]), ProbeResult::Unsure);
        assert_eq!(classify_probe(&[0x16]), ProbeResult::Unsure);
        assert_eq!(classify_probe(&[0x16, 0x03]), ProbeResult::Unsure);
    }

    #[test]
    fn classify_probe_rejects_other_traffic() {
        assert_eq!(classify_probe(b"GET / HTTP/1.1\r\n"), ProbeResult::NotForUs);
        // High bit set, but not the SSLv2 ClientHello shape (msg_type != 1).
        assert_eq!(
            classify_probe(&[0x80, 0x10, 0x02, 0x03, 0x01, 0x00]),
            ProbeResult::NotForUs
        );
        // SSLv2-shaped, but the embedded client version isn't a recognized 3.x.
        assert_eq!(
            classify_probe(&[0x80, 0x10, 0x01, 0x02, 0x00, 0x00]),
            ProbeResult::NotForUs
        );
    }

    #[test]
    fn parse_sslv2_client_hello_decodes_real_capture() {
        let data = hex(SSLV2_CLIENT_HELLO);
        let (consumed, hello) = parse_sslv2_client_hello(&data).expect("should parse");
        assert_eq!(consumed, data.len());
        assert_eq!(consumed, 72);
        assert_eq!(hello.version, 0x0301);
        assert_eq!(hello.cipher_specs.len(), 15);
        assert_eq!(
            hello.cipher_specs.iter().filter(|c| *c >> 16 == 0).count(),
            9,
            "9 of the 15 cipher specs are v3-compatible (leading byte 0)"
        );
        assert!(hello.session_id.is_empty());
        assert_eq!(hello.challenge.len(), 16);
    }

    #[test]
    fn parse_sslv2_client_hello_incomplete() {
        let data = hex(SSLV2_CLIENT_HELLO);
        for n in 1..data.len() {
            assert_eq!(
                parse_sslv2_client_hello(&data[..n]),
                Err(SslV2Error::Incomplete),
                "expected Incomplete at length {n}"
            );
        }
        assert_eq!(parse_sslv2_client_hello(&[]), Err(SslV2Error::Incomplete));
    }

    #[test]
    fn parse_sslv2_client_hello_rejects_malformed() {
        // High bit not set: not this format at all.
        assert_eq!(
            parse_sslv2_client_hello(&[0x00, 0x02, 0x01, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00]),
            Err(SslV2Error::Malformed)
        );
        // High bit set, but msg_type != 1 (CLIENT-HELLO).
        assert_eq!(
            parse_sslv2_client_hello(&[0x80, 0x07, 0x02, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00]),
            Err(SslV2Error::Malformed)
        );
        // Declared sub-lengths (cipher_spec_len=3, session_id_len=0, challenge_len=0) don't add
        // up to the declared message length (9, i.e. just the fixed 9-byte header).
        assert_eq!(
            parse_sslv2_client_hello(&[
                0x80, 0x09, 0x01, 0x03, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00
            ]),
            Err(SslV2Error::Malformed)
        );
    }

    #[test]
    fn sslv2_hello_feeds_normal_v3_state_machine() {
        let mut tls = Tls::new();

        let client_to_server = true;
        let server_to_client = false;

        let status = tls.parse_tcp_level(&hex(SSLV2_CLIENT_HELLO), client_to_server);
        assert_eq!(status, ParseResult::Continue(0));
        assert_eq!(tls.client_version(), 0x0301);
        assert!(!tls.is_invalid());

        let status = tls.parse_tcp_level(&hex(SERVER_HELLO_RECORD), server_to_client);
        assert_eq!(status, ParseResult::Continue(0));
        assert_eq!(tls.server_version(), 0x0301);
        assert!(!tls.is_invalid());
    }
}
