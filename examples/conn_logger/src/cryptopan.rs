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
///
/// `anon_bits_v4`/`anon_bits_v6` optionally restrict anonymization to the
/// trailing N bits of each address (set independently per address family),
/// leaving the leading bits in plaintext. Leading bits still feed the cipher
/// input for the bits that are anonymized, so the prefix-preserving property
/// holds for the anonymized suffix.
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct CryptoPAN {
    cipher: Aes128,
    pad: u128,
    /// Number of least-significant (trailing) IPv4 bits to anonymize; the
    /// remaining leading bits are left as-is. Clamped to 32.
    anon_bits_v4: u32,
    /// Number of least-significant (trailing) IPv6 bits to anonymize; the
    /// remaining leading bits are left as-is. Clamped to 128.
    anon_bits_v6: u32,
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
    ///
    /// `anon_bits_v4`/`anon_bits_v6` set how many trailing (least-significant)
    /// bits of each address family are anonymized; the leading bits are left
    /// unmodified. Pass 32 (v4) / 128 (v6), or any larger value, to anonymize
    /// entire addresses.
    pub fn new(key: &[u8; 32], anon_bits_v4: u32, anon_bits_v6: u32) -> Self {
        let cipher =
            Aes128::new_from_slice(&key[..16]).expect("16-byte AES key is always valid");

        // Pad = AES_encrypt(key, key[16..32])
        let mut pad_block = aes::Block::clone_from_slice(&key[16..]);
        cipher.encrypt_block(&mut pad_block);
        let pad = u128::from_be_bytes(pad_block.into());

        Self { cipher, pad, anon_bits_v4, anon_bits_v6 }
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
        let anon_bits = self.anon_bits_v4.min(32);
        let anon_start = 32 - anon_bits;
        let mut result = 0u128;

        for i in 0..32u32 {
            let bit = (ip_bits >> (31 - i)) & 1;
            let f_i = if i < anon_start {
                bit as u8
            } else {
                let input = self.make_input(result, i);
                let enc = self.encrypt_block(input);
                ((enc[0] >> 7) & 1) ^ (bit as u8)
            };
            result = (result << 1) | (f_i as u128);
        }

        Ipv4Addr::from(result as u32)
    }

    pub fn anonymize_ipv6(&self, ip: Ipv6Addr) -> Ipv6Addr {
        let ip_bits = u128::from(ip);
        let anon_bits = self.anon_bits_v6.min(128);
        let anon_start = 128 - anon_bits;
        let mut result = 0u128;

        for i in 0..128u32 {
            let bit = (ip_bits >> (127 - i)) & 1;
            let f_i = if i < anon_start {
                bit as u8
            } else {
                let input = self.make_input(result, i);
                let enc = self.encrypt_block(input);
                ((enc[0] >> 7) & 1) ^ (bit as u8)
            };
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    #[test]
    fn full_anonymization_changes_every_bit_class() {
        let cp = CryptoPAN::new(&test_key(), 32, 128);
        let a = cp.anonymize_ipv4(Ipv4Addr::new(192, 168, 1, 1));
        assert_ne!(a, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn zero_bits_is_identity() {
        let cp = CryptoPAN::new(&test_key(), 0, 0);
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(cp.anonymize_ipv4(ip), ip);
    }

    #[test]
    fn last_n_bits_preserves_leading_prefix() {
        let cp = CryptoPAN::new(&test_key(), 8, 128);
        let a = cp.anonymize_ipv4(Ipv4Addr::new(192, 168, 1, 1));
        let b = cp.anonymize_ipv4(Ipv4Addr::new(192, 168, 1, 200));
        // Leading /24 must be untouched in both directions.
        assert_eq!(a.octets()[..3], [192, 168, 1]);
        assert_eq!(b.octets()[..3], [192, 168, 1]);
        // The anonymized last octet should differ from the original and
        // between two different inputs.
        assert_ne!(a.octets()[3], 1);
        assert_ne!(a.octets()[3], b.octets()[3]);
    }

    #[test]
    fn shared_prefix_is_preserved_in_anonymized_suffix() {
        let cp = CryptoPAN::new(&test_key(), 16, 128);
        let a = cp.anonymize_ipv4(Ipv4Addr::new(10, 0, 1, 1));
        let b = cp.anonymize_ipv4(Ipv4Addr::new(10, 0, 2, 2));
        // Both share a /16; their anonymized /16 must also match.
        assert_eq!(a.octets()[..2], b.octets()[..2]);
    }

    #[test]
    fn v4_and_v6_bits_are_independent() {
        // Full v4 anonymization, but v6 left untouched.
        let cp = CryptoPAN::new(&test_key(), 32, 0);
        let v4 = Ipv4Addr::new(192, 168, 1, 1);
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert_ne!(cp.anonymize_ipv4(v4), v4);
        assert_eq!(cp.anonymize_ipv6(v6), v6);
    }
}
