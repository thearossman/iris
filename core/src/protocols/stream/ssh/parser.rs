//! SSH parser.
//!
//! Uses parsing functions from the [Rusticata SSH parser](https://github.com/rusticata/ssh-parser/blob/master/src/ssh.rs).

use super::handshake::*;
use super::Ssh;
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::{
    ConnParsable, ParseResult, ParsingState, ProbeResult, Session, SessionData,
};

use ssh_parser::*;

#[derive(Debug)]
pub struct SshParser {
    sessions: Vec<Ssh>,
}

impl Default for SshParser {
    fn default() -> Self {
        SshParser {
            sessions: vec![Ssh::new()],
        }
    }
}

impl ConnParsable for SshParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        log::debug!("Updating parser ssh");
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            if !self.sessions.is_empty() {
                return self.sessions[0].process(data, pdu.dir);
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
            // check if first 4 bytes match the beginning of a SSH identification string ("SSH-")
            match &data[..4] {
                b"SSH-" => ProbeResult::Certain,
                _ => ProbeResult::NotForUs,
            }
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }

    fn remove_session(&mut self, _session_id: usize) -> Option<Session> {
        self.sessions.pop().map(|ssh| Session {
            data: SessionData::Ssh(Box::new(ssh)),
            id: 0,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain(..)
            .map(|ssh| Session {
                data: SessionData::Ssh(Box::new(ssh)),
                id: 0,
            })
            .collect()
    }

    fn session_parsed_state(&self) -> ParsingState {
        ParsingState::Stop
    }

    fn body_offset(&mut self) -> Option<usize> {
        match self.sessions.last_mut() {
            Some(session) => std::mem::take(&mut session.last_body_offset),
            None => None,
        }
    }
}

impl Ssh {
    /// Allocate a new SSH handshake instance.
    pub(crate) fn new() -> Ssh {
        Ssh {
            client_version_exchange: None,
            server_version_exchange: None,
            key_exchange: None,
            client_dh_key_exchange: None,
            server_dh_key_exchange: None,
            client_new_keys: None,
            server_new_keys: None,
            last_body_offset: None,
        }
    }

    fn byte_to_string(&mut self, b: &[u8]) -> String {
        String::from_utf8(b.to_vec()).unwrap()
    }

    pub(crate) fn parse_version_exchange(&mut self, data: &[u8], dir: bool) {
        let ssh_identifier = b"SSH-";
        if let Some(contains_ssh_identifier) = data
            .windows(ssh_identifier.len())
            .position(|window| window == ssh_identifier)
            .map(|p| &data[p..])
        {
            match ssh_parser::parse_ssh_identification(contains_ssh_identifier) {
                Ok((_, (_, ssh_id_string))) => {
                    let version_exchange = SshVersionExchange {
                        protoversion: Some(self.byte_to_string(ssh_id_string.proto)),
                        softwareversion: Some(self.byte_to_string(ssh_id_string.software)),
                        comments: ssh_id_string.comments.map(|c| self.byte_to_string(c)),
                    };

                    if dir {
                        self.client_version_exchange = Some(version_exchange);
                    } else {
                        self.server_version_exchange = Some(version_exchange);
                    }
                }
                e => log::debug!("Not a valid SSH version exchange message: {:?}", e),
            }
        }
    }

    fn bytes_to_string_vec(&mut self, data: &[u8]) -> Vec<String> {
        data.split(|&b| b == b',')
            .map(|chunk| String::from_utf8(chunk.to_vec()).unwrap())
            .collect()
    }

    pub(crate) fn parse_key_exchange(&mut self, data: &[u8]) {
        match ssh_parser::parse_ssh_packet(data) {
            Ok((_, (pkt, _))) => match pkt {
                SshPacket::KeyExchange(pkt) => {
                    let key_exchange = SshKeyExchange {
                        cookie: pkt.cookie.to_vec(),
                        kex_algs: self.bytes_to_string_vec(pkt.kex_algs),
                        server_host_key_algs: self.bytes_to_string_vec(pkt.server_host_key_algs),
                        encryption_algs_client_to_server: self
                            .bytes_to_string_vec(pkt.encr_algs_client_to_server),
                        encryption_algs_server_to_client: self
                            .bytes_to_string_vec(pkt.encr_algs_server_to_client),
                        mac_algs_client_to_server: self
                            .bytes_to_string_vec(pkt.mac_algs_client_to_server),
                        mac_algs_server_to_client: self
                            .bytes_to_string_vec(pkt.mac_algs_server_to_client),
                        compression_algs_client_to_server: self
                            .bytes_to_string_vec(pkt.comp_algs_client_to_server),
                        compression_algs_server_to_client: self
                            .bytes_to_string_vec(pkt.comp_algs_server_to_client),
                        languages_client_to_server: self
                            .bytes_to_string_vec(pkt.langs_client_to_server),
                        languages_server_to_client: self
                            .bytes_to_string_vec(pkt.langs_server_to_client),
                        first_kex_packet_follows: pkt.first_kex_packet_follows,
                    };

                    self.key_exchange = Some(key_exchange);
                }
                e => log::debug!("Could not parse data as a SSH KeyExchange packet: {:?}", e),
            },
            e => log::debug!("Could not parse data as a SSH packet: {:?}", e),
        }
    }

    pub(crate) fn parse_dh_client_init(&mut self, data: &[u8]) {
        match ssh_parser::parse_ssh_packet(data) {
            Ok((_, (pkt, _))) => match pkt {
                SshPacket::DiffieHellmanInit(pkt) => {
                    let dh_init = SshDhInit { e: pkt.e.to_vec() };

                    self.client_dh_key_exchange = Some(dh_init);
                }
                e => log::debug!(
                    "Could not parse data as a SSH DiffieHellmanInit packet: {:?}",
                    e
                ),
            },
            e => log::debug!("Could not parse data as a SSH packet: {:?}", e),
        }
    }

    pub(crate) fn parse_dh_server_response(&mut self, data: &[u8]) {
        match ssh_parser::parse_ssh_packet(data) {
            Ok((_, (pkt, _))) => match pkt {
                SshPacket::DiffieHellmanReply(pkt) => {
                    let dh_response = SshDhResponse {
                        pubkey_and_certs: pkt.pubkey_and_cert.to_vec(),
                        f: pkt.f.to_vec(),
                        signature: pkt.signature.to_vec(),
                    };

                    self.server_dh_key_exchange = Some(dh_response);
                }
                e => log::debug!(
                    "Could not parse data as a SSH DiffieHellmanReply packet: {:?}",
                    e
                ),
            },
            e => log::debug!("Could not parse data as a SSH packet: {:?}", e),
        }
    }

    /// Parse a new keys packet. Return length of remaining data.
    pub(crate) fn parse_new_keys(&mut self, data: &[u8], dir: bool) -> usize {
        let mut remaining = 0;
        match ssh_parser::parse_ssh_packet(data) {
            Ok((rem, (pkt, _))) => match pkt {
                SshPacket::NewKeys => {
                    let new_keys = SshNewKeys;
                    remaining = rem.len();
                    if dir {
                        self.client_new_keys = Some(new_keys);
                    } else {
                        self.server_new_keys = Some(new_keys);
                    }
                }
                e => log::debug!("Could not parse data as a SSH NewKeys packet: {:?}", e),
            },
            e => log::debug!("Could not parse data as a SSH packet: {:?}", e),
        }
        remaining
    }

    pub(crate) fn process(&mut self, data: &[u8], dir: bool) -> ParseResult {
        log::trace!("process ({} bytes)", data.len());

        let mut rest = data;
        let mut parsed_any = false;

        // The identification string ("SSH-...\r\n") opens the connection, and peers
        // routinely coalesce it with the binary key-exchange packets that follow. Consume
        // it off the front and keep going, rather than treating the whole segment as
        // version data and discarding whatever came with it.
        let ssh_identifier = b"SSH-";
        if let Some(pos) = rest
            .windows(ssh_identifier.len())
            .position(|window| window == ssh_identifier)
        {
            self.parse_version_exchange(&rest[pos..], dir);
            match ssh_parser::parse_ssh_identification(&rest[pos..]) {
                Ok((remaining, _)) => {
                    parsed_any = true;
                    rest = remaining;
                }
                // Identification line is incomplete (split across segments); nothing
                // reliable follows it in this segment.
                Err(e) => {
                    log::debug!("incomplete SSH identification: {:?}", e);
                    return ParseResult::Continue(0);
                }
            }
        }

        // A single TCP segment routinely carries several SSH packets back-to-back -- most
        // importantly a server's final key-exchange packet immediately followed by
        // NEWKEYS. `parse_ssh_packet` consumes only the first packet and returns the rest,
        // so drain the whole segment; inspecting just the first packet would miss the
        // NEWKEYS that ends the cleartext handshake.
        while !rest.is_empty() {
            let (remaining, pkt) = match ssh_parser::parse_ssh_packet(rest) {
                Ok((remaining, (pkt, _))) => (remaining, pkt),
                Err(e) => {
                    log::debug!("parse error: {:?}", e);
                    break;
                }
            };
            parsed_any = true;

            match pkt {
                SshPacket::KeyExchange(_) => self.parse_key_exchange(rest),
                SshPacket::DiffieHellmanInit(_) => self.parse_dh_client_init(rest),
                SshPacket::DiffieHellmanReply(_) => self.parse_dh_server_response(rest),
                SshPacket::NewKeys => {
                    self.parse_new_keys(rest, dir);

                    // Handshake is over once both peers have sent NEWKEYS.
                    if self.client_new_keys.is_some() && self.server_new_keys.is_some() {
                        // Anything trailing NEWKEYS in this segment is encrypted payload.
                        if !remaining.is_empty() {
                            self.last_body_offset = Some(data.len() - remaining.len());
                        }
                        return ParseResult::HeadersDone(0);
                    }
                }
                _ => {}
            }

            rest = remaining;
        }

        if parsed_any {
            ParseResult::Continue(0)
        } else {
            ParseResult::Skipped
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds one SSH binary packet (RFC 4253 §6) wrapping `payload`:
    /// `uint32 packet_length | byte padding_length | payload | padding`,
    /// where `packet_length` covers everything after itself.
    fn ssh_packet(payload: &[u8]) -> Vec<u8> {
        let padding_len: u8 = 8;
        let packet_len = 1 + payload.len() + padding_len as usize;
        let mut out = Vec::new();
        out.extend_from_slice(&(packet_len as u32).to_be_bytes());
        out.push(padding_len);
        out.extend_from_slice(payload);
        out.extend(std::iter::repeat_n(0u8, padding_len as usize));
        out
    }

    /// SSH_MSG_NEWKEYS (21) -- the message that ends the cleartext handshake.
    fn newkeys() -> Vec<u8> {
        ssh_packet(&[21])
    }

    /// SSH_MSG_IGNORE (2) with an empty string payload -- stands in for any
    /// handshake packet that a server may send immediately before NEWKEYS.
    fn ignore_msg() -> Vec<u8> {
        ssh_packet(&[2, 0, 0, 0, 0])
    }

    #[test]
    fn newkeys_alone_in_each_segment_ends_the_handshake() {
        let mut ssh = Ssh::new();
        assert_eq!(ssh.process(&newkeys(), true), ParseResult::Continue(0));
        assert!(ssh.client_new_keys.is_some());
        assert_eq!(ssh.process(&newkeys(), false), ParseResult::HeadersDone(0));
        assert!(ssh.server_new_keys.is_some());
    }

    #[test]
    fn version_string_coalesced_with_binary_packets_does_not_hide_them() {
        let mut ssh = Ssh::new();
        assert_eq!(ssh.process(&newkeys(), true), ParseResult::Continue(0));

        // Server sends its identification line and immediately follows it with binary
        // key-exchange traffic in the same segment.
        let mut segment = b"SSH-2.0-OpenSSH_8.9\r\n".to_vec();
        segment.extend_from_slice(&newkeys());

        assert_eq!(ssh.process(&segment, false), ParseResult::HeadersDone(0));
        assert!(ssh.server_version_exchange.is_some());
        assert!(
            ssh.server_new_keys.is_some(),
            "binary packet coalesced behind the identification string was missed"
        );
    }

    #[test]
    fn trailing_payload_after_newkeys_sets_body_offset() {
        let mut ssh = Ssh::new();
        assert_eq!(ssh.process(&newkeys(), true), ParseResult::Continue(0));

        let mut segment = newkeys();
        let body_start = segment.len();
        segment.extend_from_slice(&[0xAA; 32]); // encrypted payload riding along

        assert_eq!(ssh.process(&segment, false), ParseResult::HeadersDone(0));
        assert_eq!(ssh.last_body_offset, Some(body_start));
    }

    #[test]
    fn non_ssh_data_is_skipped() {
        let mut ssh = Ssh::new();
        assert_eq!(ssh.process(&[0xFF; 24], true), ParseResult::Skipped);
    }

    #[test]
    fn newkeys_coalesced_behind_another_packet_still_ends_the_handshake() {
        let mut ssh = Ssh::new();
        assert_eq!(ssh.process(&newkeys(), true), ParseResult::Continue(0));

        // A real server commonly writes its final key-exchange packet and NEWKEYS
        // back-to-back, so TCP delivers them in one segment.
        let mut segment = ignore_msg();
        segment.extend_from_slice(&newkeys());

        assert_eq!(ssh.process(&segment, false), ParseResult::HeadersDone(0));
        assert!(
            ssh.server_new_keys.is_some(),
            "NEWKEYS coalesced behind another packet in the same segment was missed"
        );
    }
}
