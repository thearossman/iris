/// Prefix-preserving IP address anonymization (Xu et al., 2002).
///
/// For each bit position i (MSB=0) of an address, the anonymized bit is:
///   f_i = orig_i XOR MSB(AES_key( anon[0..i-1] || 0 || pad[i+1..127] ))
///
/// The algorithm is inherently sequential — each anonymized bit feeds the
/// AES input for the next — so true per-address parallelism is not possible.
/// The practical speedup technique is prefix memoization: two IPs sharing a
/// common k-bit original prefix also share their anonymized k-bit prefix.
/// We cache the anonymized prefix per thread (no locking required on DPDK's
/// pinned-core model) so that only the host portion of each new address
/// needs to be recomputed.
///
///   IPv4 /24 cache: 24 AES ops on the first IP in a subnet, 8 thereafter (75% saving).
///   IPv6 /48 cache: 48 AES ops on the first /48 prefix, 80 thereafter (37.5% saving).
///
/// Key setup: the 32-byte input key is split in half.  The first 16 bytes are
/// the AES-128 key; the second 16 bytes are encrypted with that key to produce
/// the pad used in every block-cipher input.
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Bits of the IPv4 address cached per thread (i.e. we cache per /24 subnet).
const IPV4_PREFIX_BITS: u32 = 24;
/// Bits of the IPv6 address cached per thread (i.e. we cache per /48 prefix).
const IPV6_PREFIX_BITS: u32 = 48;

thread_local! {
    // key   = top IPV4_PREFIX_BITS bits of the original address (right-justified)
    // value = top IPV4_PREFIX_BITS bits of the anonymized address (right-justified)
    static V4_CACHE: RefCell<HashMap<u32, u32>> = RefCell::new(HashMap::new());

    // key   = top IPV6_PREFIX_BITS bits of the original address (right-justified)
    // value = top IPV6_PREFIX_BITS bits of the anonymized address (right-justified)
    static V6_CACHE: RefCell<HashMap<u64, u64>> = RefCell::new(HashMap::new());
}

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

    /// Anonymize bits `start_i..end_i` of an address.
    ///
    /// `start_result` must hold the already-anonymized prefix (bits 0..start_i)
    /// right-justified.  `msb_shift` is `addr_bits - 1` (31 for IPv4, 127 for IPv6).
    ///
    /// Returns the accumulated right-justified result after `end_i` bits.
    #[inline]
    fn anonymize_bits(
        &self,
        ip_bits: u128,
        start_result: u128,
        start_i: u32,
        end_i: u32,
        msb_shift: u32,
    ) -> u128 {
        let mut result = start_result;
        for i in start_i..end_i {
            let input = self.make_input(result, i);
            let enc = self.encrypt_block(input);
            let f_i = ((enc[0] >> 7) & 1) ^ (((ip_bits >> (msb_shift - i)) & 1) as u8);
            result = (result << 1) | (f_i as u128);
        }
        result
    }

    pub fn anonymize_ipv4(&self, ip: Ipv4Addr) -> Ipv4Addr {
        let ip_u32 = u32::from(ip);
        let ip_bits = ip_u32 as u128;
        let prefix_key = ip_u32 >> (32 - IPV4_PREFIX_BITS);

        // Look up the cached anonymized /24 prefix for this address.
        let anon_prefix = V4_CACHE.with(|c| {
            if let Some(&v) = c.borrow().get(&prefix_key) {
                return v as u128;
            }
            let v = self.anonymize_bits(ip_bits, 0, 0, IPV4_PREFIX_BITS, 31);
            c.borrow_mut().insert(prefix_key, v as u32);
            v
        });

        // Complete the remaining host bits.
        Ipv4Addr::from(
            self.anonymize_bits(ip_bits, anon_prefix, IPV4_PREFIX_BITS, 32, 31) as u32,
        )
    }

    pub fn anonymize_ipv6(&self, ip: Ipv6Addr) -> Ipv6Addr {
        let ip_bits = u128::from(ip);
        let prefix_key = (ip_bits >> (128 - IPV6_PREFIX_BITS)) as u64;

        // Look up the cached anonymized /48 prefix for this address.
        let anon_prefix = V6_CACHE.with(|c| {
            if let Some(&v) = c.borrow().get(&prefix_key) {
                return v as u128;
            }
            let v = self.anonymize_bits(ip_bits, 0, 0, IPV6_PREFIX_BITS, 127);
            c.borrow_mut().insert(prefix_key, v as u64);
            v
        });

        // Complete the remaining host bits.
        Ipv6Addr::from(
            self.anonymize_bits(ip_bits, anon_prefix, IPV6_PREFIX_BITS, 128, 127)
                .to_be_bytes(),
        )
    }

    pub fn anonymize(&self, ip: IpAddr) -> String {
        match ip {
            IpAddr::V4(v4) => self.anonymize_ipv4(v4).to_string(),
            IpAddr::V6(v6) => self.anonymize_ipv6(v6).to_string(),
        }
    }
}
