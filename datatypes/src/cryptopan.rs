/// Helper for Prefix-preserving IP address anonymization using CryptoPAN.
///
/// Because this requires a global CryptoPAN variable, we don't expose this
/// directly as a subscribable type. Users can subscribe to five tuples, then
/// manually anonymize them.
///
/// Usage:
///
/// /// Initialize global CryptoPAN variable:
/// static CRYPTOPAN: OnceLock<CryptoPAN> = OnceLock::new();
///
/// /// Anonymize an IP address:
/// fn anonymize(ip: IpAddr) -> IpAddr {
///     CRYPTOPAN
///         .get()
///         .expect("CryptoPAN not initialized")
///         .anonymize(ip)
/// }
///
/// /// Or a five-tuple:
/// fn anonymize_fivetuple(ft: &FiveTuple) -> FiveTuple {
///    CRYPTOPAN
///       .get()
///      .expect("CryptoPAN not initialized")
///      .anonymize_fivetuple(ft)
/// }

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use iris_core::FiveTuple;

pub struct CryptoPAN {
    cipher: Aes128,
    pad: u128,
}

unsafe impl Send for CryptoPAN {}
unsafe impl Sync for CryptoPAN {}

impl CryptoPAN {

    pub fn new(key: &[u8; 32]) -> Self {
        let cipher =
            Aes128::new_from_slice(&key[..16]).expect("16-byte AES key is always valid");

        let mut pad_block = aes::Block::clone_from_slice(&key[16..]);
        cipher.encrypt_block(&mut pad_block);
        let pad = u128::from_be_bytes(pad_block.into());

        Self { cipher, pad }
    }

    pub fn anonymize(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => IpAddr::V4(self.anonymize_ipv4(v4)),
            IpAddr::V6(v6) => IpAddr::V6(self.anonymize_ipv6(v6)),
        }
    }

    pub fn anonymize_fivetuple(self, ft: &FiveTuple) -> FiveTuple {
        let mut ft = ft.clone();
        ft.orig.set_ip(self.anonymize(ft.orig.ip()));
        ft.resp.set_ip(self.anonymize(ft.resp.ip()));
        ft
    }

    fn encrypt_block(&self, input: [u8; 16]) -> [u8; 16] {
        let mut block = aes::Block::clone_from_slice(&input);
        self.cipher.encrypt_block(&mut block);
        block.into()
    }

    /// 128-bit AES input for bit position `i` (0 = MSB).
    fn make_input(&self, result: u128, i: u32) -> [u8; 16] {
        let prefix_msb: u128 = if i == 0 {
            0
        } else {
            result << (128 - i)
        };
        // Mask keeping only bits i+1 … 127 of pad (bit i and above are zeroed).
        let pad_mask: u128 = if i + 1 < 128 {
            u128::MAX >> (i + 1)
        } else {
            0
        };
        (prefix_msb | (self.pad & pad_mask)).to_be_bytes()
    }

    fn anonymize_ipv4(&self, ip: Ipv4Addr) -> Ipv4Addr {
        let ip_bits = u32::from(ip) as u128;
        let mut result = 0u128;

        for i in 0..32u32 {
            let input = self.make_input(result, i);
            let enc = self.encrypt_block(input);
            let f_i = ((enc[0] >> 7) & 1) ^ (((ip_bits >> (31 - i)) & 1) as u8);
            result = (result << 1) | (f_i as u128);
        }

        Ipv4Addr::from(result as u32)
    }

    fn anonymize_ipv6(&self, ip: Ipv6Addr) -> Ipv6Addr {
        let ip_bits = u128::from(ip);
        let mut result = 0u128;

        for i in 0..128u32 {
            let input = self.make_input(result, i);
            let enc = self.encrypt_block(input);
            let f_i = ((enc[0] >> 7) & 1) ^ (((ip_bits >> (127 - i)) & 1) as u8);
            result = (result << 1) | (f_i as u128);
        }

        Ipv6Addr::from(result.to_be_bytes())
    }
}