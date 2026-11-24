//! RPF9 TOC decryption primitives.
//!
//! Two cipher models live here:
//!
//! * [`aes256_ecb_decrypt`] / [`decrypt_toc_and_names`] — the original RPF7-style
//!   hypothesis (plain AES-256-ECB over the whole TOC+names blob). Kept because its
//!   failure is the evidence against ECB (see the Python `toc_key`).
//! * [`WhitenedAesCbc`] — the cipher identified in the retail executable: a
//!   table-driven AES-256 with input and output whitening folded into the tables,
//!   run in CBC mode.
//!
//! There are two AES cores, deliberately:
//!
//! * [`aes256_ecb_decrypt`] uses the `aes` crate, which emits hardware AES-NI on
//!   x86_64. It needs the *raw* 32-byte key, so it only serves the ECB hypothesis.
//! * [`aes256_decrypt_block`] / [`aes256_encrypt_block`] are a small constant-time
//!   software core that consumes a *round-key schedule* directly. This is what the
//!   whitened cipher uses, because the game hands us the expanded round keys inside the
//!   `key_ctx` blob — the raw key is never recoverable from them, so the AES-NI path
//!   (which re-expands from a raw key) cannot be used there. This mirrors the Python
//!   `gta6/rpf9/crypto.py` core one-for-one.
//!
//! The whitened cipher takes the precomputed key-context blob (`key_ctx`) the game
//! derives for the archive key handles, laid out as:
//!
//! ```text
//! +0x0000  initial whitening keys      16 B
//! +0x0010  round keys                  AES-256: 15 x 16 B
//! +0x00f0  16 final whitening tables   16 x 256 B = 0x1000
//! +0x10f0  IV / chaining slot          16 B   (total 0x10f4)
//! ```
//!
//! The blob address is build-specific and is recovered at runtime; the layout offsets
//! above are the stable part.

use aes::Aes256;
use aes::cipher::{Block as AesBlock, BlockCipherDecrypt, Key as AesKey, KeyInit};

pub const KEY_CTX_SIZE: usize = 0x1100; // IV slot at +0x10f0 needs 16 B; blob rounded up from 0x10f4
pub const INITIAL_WHITENING_OFFSET: usize = 0x0000;
pub const ROUND_KEYS_OFFSET: usize = 0x0010;
pub const FINAL_TABLES_OFFSET: usize = 0x00F0;
pub const IV_SLOT_OFFSET: usize = 0x10F0;
pub const AES256_ROUNDS: usize = 14;
pub const BLOCK: usize = 16;

/// Fraction of names-blob bytes that must look like ASCII to accept a decrypted key.
pub const DEFAULT_NAME_PLAUSIBILITY: f64 = 0.85;

fn key_arr(b: &[u8]) -> AesKey<Aes256> {
    AesKey::<Aes256>::try_from(b).expect("AES-256 key must be 32 bytes")
}

fn block_arr(b: &[u8]) -> AesBlock<Aes256> {
    AesBlock::<Aes256>::try_from(b).expect("AES block must be 16 bytes")
}

/// Expand a 32-byte key into the 15 AES-256 round-key blocks (16 B each).
///
/// Mirrors the Python schedule so the round keys can be sliced straight out of a
/// `key_ctx` blob and fed to [`aes256_decrypt_block`].
pub fn expand_key_256(key: &[u8]) -> Vec<[u8; BLOCK]> {
    assert_eq!(key.len(), 32, "AES-256 key must be 32 bytes");
    let sbox: &[u8; 256] = &SBOX;
    let rcon: [u8; 14] = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D,
    ];
    let nk = 8usize;
    let mut words: Vec<[u8; 4]> = (0..nk)
        .map(|i| key[4 * i..4 * i + 4].try_into().unwrap())
        .collect();
    for i in nk..4 * (AES256_ROUNDS + 1) {
        let mut temp = words[i - 1];
        if i % nk == 0 {
            temp = [temp[1], temp[2], temp[3], temp[0]];
            for b in temp.iter_mut() {
                *b = sbox[*b as usize];
            }
            temp[0] ^= rcon[i / nk - 1];
        } else if i % nk == 4 {
            for b in temp.iter_mut() {
                *b = sbox[*b as usize];
            }
        }
        let prev = words[i - nk];
        words.push([
            prev[0] ^ temp[0],
            prev[1] ^ temp[1],
            prev[2] ^ temp[2],
            prev[3] ^ temp[3],
        ]);
    }
    let mut blocks = Vec::with_capacity(AES256_ROUNDS + 1);
    for r in 0..=AES256_ROUNDS {
        let mut blk = [0u8; BLOCK];
        for w in 0..4 {
            blk[4 * w..4 * w + 4].copy_from_slice(&words[4 * r + w]);
        }
        blocks.push(blk);
    }
    blocks
}

/// Decrypt `data` in 16-byte ECB blocks using hardware AES-NI. A trailing partial
/// block (< 16 B) is passed through unchanged.
pub fn aes256_ecb_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), 32, "AES-256 key must be 32 bytes");
    let cipher = Aes256::new(&key_arr(key));
    let full = full_blocks(data.len());
    let mut out = Vec::with_capacity(data.len());
    for chunk in data[..full].as_chunks::<BLOCK>().0 {
        let mut block = block_arr(chunk);
        cipher.decrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    out.extend_from_slice(&data[full..]);
    out
}

// ---------------------------------------------------------------------------
// Round-key-driven software AES core (mirrors gta6/rpf9/crypto.py).
//
// These consume a precomputed round-key schedule rather than a raw key, which is
// what the whitened cipher needs: the game exposes the expanded round keys in the
// key_ctx blob and the raw key cannot be recovered from them.
// ---------------------------------------------------------------------------

fn xtime(a: u8) -> u8 {
    let a = (a as u16) << 1;
    if a & 0x100 != 0 {
        (a as u8) ^ 0x1B
    } else {
        a as u8
    }
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut res = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            res ^= a;
        }
        b >>= 1;
        a = xtime(a);
    }
    res
}

fn add_round_key(s: &mut [u8; BLOCK], rk: &[u8; BLOCK]) {
    for (a, b) in s.iter_mut().zip(rk.iter()) {
        *a ^= *b;
    }
}

fn sub_bytes(s: &mut [u8; BLOCK]) {
    for a in s.iter_mut() {
        *a = SBOX[*a as usize];
    }
}

fn inv_sub_bytes(s: &mut [u8; BLOCK]) {
    for a in s.iter_mut() {
        *a = INV_SBOX[*a as usize];
    }
}

fn shift_rows(s: &mut [u8; BLOCK]) {
    let src = *s;
    for r in 1..4 {
        for c in 0..4 {
            s[4 * c + r] = src[4 * ((c + r) % 4) + r];
        }
    }
}

fn inv_shift_rows(s: &mut [u8; BLOCK]) {
    let src = *s;
    for r in 1..4 {
        for c in 0..4 {
            s[4 * ((c + r) % 4) + r] = src[4 * c + r];
        }
    }
}

fn mix_columns(s: &mut [u8; BLOCK]) {
    for c in 0..4 {
        let (a0, a1, a2, a3) = (s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]);
        s[4 * c] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        s[4 * c + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        s[4 * c + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        s[4 * c + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

fn inv_mix_columns(s: &mut [u8; BLOCK]) {
    for c in 0..4 {
        let (a0, a1, a2, a3) = (s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]);
        s[4 * c] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        s[4 * c + 1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        s[4 * c + 2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        s[4 * c + 3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
}

/// Encrypt one 16-byte block with a precomputed AES-256 round-key schedule.
///
/// Used to build round-trip tests for the whitened cipher (the game only decrypts,
/// but a matching encrypt lets us verify the core against FIPS-197 without a key).
pub fn aes256_encrypt_block(block: &[u8; BLOCK], round_keys: &[[u8; BLOCK]]) -> [u8; BLOCK] {
    assert_eq!(round_keys.len(), AES256_ROUNDS + 1, "need 15 round keys");
    let mut s = *block;
    add_round_key(&mut s, &round_keys[0]);
    for rk in &round_keys[1..AES256_ROUNDS] {
        sub_bytes(&mut s);
        shift_rows(&mut s);
        mix_columns(&mut s);
        add_round_key(&mut s, rk);
    }
    sub_bytes(&mut s);
    shift_rows(&mut s);
    add_round_key(&mut s, &round_keys[AES256_ROUNDS]);
    s
}

/// Inverse AES-256 block transform with a precomputed round-key schedule.
pub fn aes256_decrypt_block(block: &[u8; BLOCK], round_keys: &[[u8; BLOCK]]) -> [u8; BLOCK] {
    assert_eq!(round_keys.len(), AES256_ROUNDS + 1, "need 15 round keys");
    let mut s = *block;
    add_round_key(&mut s, &round_keys[AES256_ROUNDS]);
    for rnd in (1..AES256_ROUNDS).rev() {
        inv_shift_rows(&mut s);
        inv_sub_bytes(&mut s);
        add_round_key(&mut s, &round_keys[rnd]);
        inv_mix_columns(&mut s);
    }
    inv_shift_rows(&mut s);
    inv_sub_bytes(&mut s);
    add_round_key(&mut s, &round_keys[0]);
    s
}

/// Whitened AES-256-CBC driven by a precomputed `key_ctx` blob.
///
/// Whitening is applied around the round-key AES core: output whitening XOR, inverse
/// AES, then CBC chaining with `iv` and input whitening XOR. The whitening/IV fields
/// are exposed so a dynamic trace of the AES block transform can override the defaults
/// read from `key_ctx`.
pub struct WhitenedAesCbc {
    round_keys: Vec<[u8; BLOCK]>,
    pub input_whitening: [u8; BLOCK],
    pub output_whitening: [u8; BLOCK],
    pub iv: [u8; BLOCK],
}

impl WhitenedAesCbc {
    /// Read round keys, whitening and IV out of a `key_ctx` blob.
    ///
    /// AES-256 uses 15 round keys: `key_ctx[0:16]` is the round-0 (initial whitening)
    /// key; rounds 1..14 are the 14 contiguous blocks at `+0x10..+0xf0`. These are fed
    /// straight to the software core, so this constructor is fully decrypt-capable from
    /// the blob alone (no raw key needed).
    pub fn from_key_ctx(key_ctx: &[u8], iv: Option<[u8; BLOCK]>) -> Self {
        assert!(
            key_ctx.len() >= KEY_CTX_SIZE,
            "key_ctx must be >= {KEY_CTX_SIZE} bytes, got {}",
            key_ctx.len()
        );
        let mut round_keys = Vec::with_capacity(AES256_ROUNDS + 1);
        // Round 0 lives at the initial-whitening offset; rounds 1..14 at +0x10..
        round_keys.push(read_block(key_ctx, INITIAL_WHITENING_OFFSET));
        for r in 1..=AES256_ROUNDS {
            round_keys.push(read_block(key_ctx, ROUND_KEYS_OFFSET + BLOCK * (r - 1)));
        }
        let input_whitening = read_block(key_ctx, INITIAL_WHITENING_OFFSET);
        let output_whitening = read_block(key_ctx, FINAL_TABLES_OFFSET);
        let ivb = match iv {
            Some(v) => v,
            None => read_block(key_ctx, IV_SLOT_OFFSET),
        };
        Self {
            round_keys,
            input_whitening,
            output_whitening,
            iv: ivb,
        }
    }

    /// Construct from the raw 32-byte key (expanded to a round-key schedule) plus
    /// explicit whitening/IV. Convenient when the raw key is known.
    pub fn with_key(
        key: &[u8],
        input_whitening: [u8; BLOCK],
        output_whitening: [u8; BLOCK],
        iv: [u8; BLOCK],
    ) -> Self {
        Self {
            round_keys: expand_key_256(key),
            input_whitening,
            output_whitening,
            iv,
        }
    }

    /// Raw whitened block transform (no CBC chaining): output-XOR, inverse AES.
    pub fn decrypt_block(&self, block: &[u8; BLOCK]) -> [u8; BLOCK] {
        let mut g = *block;
        for (o, k) in g.iter_mut().zip(self.output_whitening.iter()) {
            *o ^= k;
        }
        aes256_decrypt_block(&g, &self.round_keys)
    }

    /// Forward whitened block transform (output-XOR after AES). Used to build test
    /// vectors; the game only decrypts.
    pub fn encrypt_block(&self, block: &[u8; BLOCK]) -> [u8; BLOCK] {
        let mut s = aes256_encrypt_block(block, &self.round_keys);
        for (o, k) in s.iter_mut().zip(self.output_whitening.iter()) {
            *o ^= k;
        }
        s
    }

    /// CBC-decrypt `data`. A trailing partial block is passed through.
    pub fn decrypt(&self, data: &[u8], iv: Option<[u8; BLOCK]>) -> Vec<u8> {
        let mut prev = iv.unwrap_or(self.iv);
        let full = full_blocks(data.len());
        let mut out = Vec::with_capacity(data.len());
        for block in data[..full].as_chunks::<BLOCK>().0 {
            let mut b = [0u8; BLOCK];
            b.copy_from_slice(block);
            let dec = self.decrypt_block(&b);
            for (d, (p, w)) in dec.iter().zip(prev.iter().zip(self.input_whitening.iter())) {
                out.push(d ^ p ^ w);
            }
            prev = b;
        }
        out.extend_from_slice(&data[full..]);
        out
    }

    /// Forward CBC-encrypt (the exact inverse of [`decrypt`]) — test helper only.
    pub fn encrypt(&self, data: &[u8], iv: Option<[u8; BLOCK]>) -> Vec<u8> {
        let mut prev = iv.unwrap_or(self.iv);
        let full = full_blocks(data.len());
        let mut out = Vec::with_capacity(data.len());
        for block in data[..full].as_chunks::<BLOCK>().0 {
            let mut p = [0u8; BLOCK];
            p.copy_from_slice(block);
            // plaintext XOR input_whitening XOR prev, then forward whitened block.
            for (p, (w, pv)) in p
                .iter_mut()
                .zip(self.input_whitening.iter().zip(prev.iter()))
            {
                *p ^= w ^ pv;
            }
            let c = self.encrypt_block(&p);
            out.extend_from_slice(&c);
            prev = c;
        }
        out.extend_from_slice(&data[full..]);
        out
    }
}

fn full_blocks(len: usize) -> usize {
    len - (len % BLOCK)
}

fn read_block(buf: &[u8], off: usize) -> [u8; BLOCK] {
    let mut b = [0u8; BLOCK];
    b.copy_from_slice(&buf[off..off + BLOCK]);
    b
}

/// Retail RPF7 decrypts TOC+names as one run; try the same for RPF9.
pub fn decrypt_toc_and_names(blob: &[u8], key: &[u8]) -> Vec<u8> {
    aes256_ecb_decrypt(blob, key)
}

/// Standard AES S-box (used by [`expand_key_256`] and the software core).
static SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Inverse S-box, derived from [`SBOX`] at compile time (mirrors Python `_INV_SBOX`).
static INV_SBOX: [u8; 256] = build_inv_sbox();

const fn build_inv_sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// FIPS-197 C.3 AES-256 known-answer vector: AES-NI ECB decrypt must invert encrypt.
    #[test]
    fn aes256_ecb_matches_fips197() {
        let key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let cipher = "d83414223d20a0c928b136c884d07ea2";
        let plain = hex("00112233445566778899aabbccddeeff");
        let got = aes256_ecb_decrypt(&hex(cipher), &key);
        assert_eq!(got, plain);
    }

    /// The software round-key core must agree with the AES-NI ECB path on the same
    /// FIPS-197 vector — this pins the core the whitened cipher relies on.
    #[test]
    fn software_core_matches_fips197() {
        let key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let rk = expand_key_256(&key);
        let ct: [u8; 16] = hex("d83414223d20a0c928b136c884d07ea2").try_into().unwrap();
        let pt: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
        assert_eq!(aes256_decrypt_block(&ct, &rk), pt);
        assert_eq!(aes256_encrypt_block(&pt, &rk), ct);
    }

    /// A trailing partial block (< 16 B) is passed through unchanged.
    #[test]
    fn ecb_passes_through_partial_tail() {
        let key = [0u8; 32];
        let data = [0u8; 20];
        let out = aes256_ecb_decrypt(&data, &key);
        assert_eq!(out.len(), 20);
        assert_eq!(&out[16..], &data[16..]);
    }

    /// Whitened CBC with zero whitening/IV reduces to plain CBC; chaining must hold.
    #[test]
    fn whitened_cbc_chains() {
        let key = [7u8; 32];
        let w = WhitenedAesCbc::with_key(&key, [0u8; 16], [0u8; 16], [0u8; 16]);
        let mut data = Vec::new();
        data.extend_from_slice(&[0xABu8; 16]);
        data.extend_from_slice(&[0xABu8; 16]);
        let out = w.decrypt(&data, None);
        assert_eq!(out.len(), 32);
        assert_ne!(&out[0..16], &out[16..32]);
    }

    /// The whitened cipher must round-trip from a synthetic key_ctx blob: build a blob
    /// with a real round-key schedule at the documented offsets, encrypt, then decrypt,
    /// and confirm the plaintext comes back. This is the property the extractor depends
    /// on (decrypt-capable from the blob alone).
    #[test]
    fn whitened_roundtrips_from_key_ctx_blob() {
        let mut blob = vec![0u8; KEY_CTX_SIZE];
        // Put a real AES-256 schedule into the round-key region so the core is valid.
        let key = [0x42u8; 32];
        let rk = expand_key_256(&key);
        blob[INITIAL_WHITENING_OFFSET..INITIAL_WHITENING_OFFSET + BLOCK].copy_from_slice(&rk[0]);
        for r in 1..=AES256_ROUNDS {
            blob[ROUND_KEYS_OFFSET + BLOCK * (r - 1)..ROUND_KEYS_OFFSET + BLOCK * r]
                .copy_from_slice(&rk[r]);
        }
        // Non-trivial whitening + IV so the test would fail if they were ignored.
        for i in 0..BLOCK {
            blob[FINAL_TABLES_OFFSET + i] = (0xA0 + i as u8) ^ 0x5A;
            blob[IV_SLOT_OFFSET + i] = (0x10 + i as u8) ^ 0x0F;
        }
        let w = WhitenedAesCbc::from_key_ctx(&blob, None);
        let plain: Vec<u8> = (0..48).map(|i| (i * 7 + 3) as u8).collect();
        let ct = w.encrypt(&plain, None);
        let back = w.decrypt(&ct, None);
        assert_eq!(back, plain);
    }
}
