/// Prefix-preserving IP address anonymization (Xu et al., 2002).
///
/// For each bit position i (MSB=0) of an address, the anonymized bit is:
///   f_i = orig_i XOR MSB(AES_key( anon[0..i-1] || 0 || pad[i+1..127] ))
///
/// The 128-bit AES input has the already-anonymized prefix left-justified at
/// the top, bit i forced to 0, and the fixed pad filling the remaining bits.
/// This construction ensures that two addresses sharing an original k-bit
/// prefix will also share their anonymized k-bit prefix.
///
/// Key setup: the 32-byte input key is split in half. The first 16 bytes are
/// the AES-128 key; the second 16 bytes are encrypted with that key to
/// produce the pad used in every block-cipher input.
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct CryptoPAN {
    cipher: Aes128,
    pad: u128,
}

impl std::fmt::Debug for CryptoPAN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoPAN").finish_non_exhaustive()
    }
}

// SAFETY: Aes128 holds only key schedule data (no raw pointers or non-Send
// state), so it is safe to share across threads.
unsafe impl Send for CryptoPAN {}
unsafe impl Sync for CryptoPAN {}

impl CryptoPAN {
    /// Build a `CryptoPAN` instance from a 32-byte secret key.
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher =
            Aes128::new_from_slice(&key[..16]).expect("16-byte AES key is always valid");

        // Pad = AES_encrypt(key, key[16..32])
        let mut pad_block = aes::Block::clone_from_slice(&key[16..]);
        cipher.encrypt_block(&mut pad_block);
        let pad = u128::from_be_bytes(pad_block.into());

        Self { cipher, pad }
    }

    fn encrypt_block(&self, input: [u8; 16]) -> [u8; 16] {
        let mut block = aes::Block::clone_from_slice(&input);
        self.cipher.encrypt_block(&mut block);
        block.into()
    }

    /// Build the 128-bit AES input for bit position `i` (0 = MSB).
    ///
    /// Layout:
    ///   bits  0..i-1  ← already-anonymized prefix (`result`, MSB-justified)
    ///   bit   i       ← 0
    ///   bits  i+1..127 ← pad
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

    pub fn anonymize_ipv4(&self, ip: Ipv4Addr) -> Ipv4Addr {
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

    pub fn anonymize_ipv6(&self, ip: Ipv6Addr) -> Ipv6Addr {
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

    pub fn anonymize(&self, ip: IpAddr) -> String {
        match ip {
            IpAddr::V4(v4) => self.anonymize_ipv4(v4).to_string(),
            IpAddr::V6(v6) => self.anonymize_ipv6(v6).to_string(),
        }
    }
}
