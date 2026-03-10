//! GF(2^128) (Polyval field) and GF(2^256) helpers.

// ---------------------------------------------------------------------------
// GF(2^256) doubling with modulus x^256 + x^10 + x^5 + x^2 + 1, mask = 1061
// Matches the reference byte-swap + shift construction.

#[inline]
pub fn gf256_double(inp: &[u8; 32]) -> [u8; 32] {
    // Load as four u64s in memory order, then swap to big-endian.
    let mut w = [0u64; 4];
    for i in 0..4 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&inp[8 * i..8 * i + 8]);
        w[i] = u64::from_le_bytes(buf).swap_bytes();
    }
    let mask: u64 = 1061;
    let tmp = w[0] >> 63;
    w[0] = (w[0] << 1) ^ (w[1] >> 63);
    w[1] = (w[1] << 1) ^ (w[2] >> 63);
    w[2] = (w[2] << 1) ^ (w[3] >> 63);
    w[3] = (w[3] << 1) ^ (mask & tmp.wrapping_neg());
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[8 * i..8 * i + 8].copy_from_slice(&w[i].swap_bytes().to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Polyval "dot" over GF(2^128) with modulus x^128 + x^127 + x^126 + x^121 + 1.
//
// dot(a,b) = a * b * x^{-128}   (see RFC 8452 §3)
//
// Portable software implementation based on Gueron/Langley/Lindell's
// AES-GCM-SIV reference (gfmul_int). A CLMUL-accelerated path could be added
// for x86_64 but OCH only calls this a handful of times per seal so it is
// not on the hot path.

/// 64x64 -> 128 carryless multiply. Returns (lo, hi).
fn clmul64(a: u64, b: u64) -> (u64, u64) {
    // Straightforward shift-and-xor. Not constant-time vs bit values but this
    // is reference code; the OCH paper uses Polyval as AXU only (adversary
    // never sees its output directly).
    let mut lo: u64 = 0;
    let mut hi: u64 = 0;
    let mut aa = a;
    let mut i = 0;
    while i < 64 {
        // mask = all-ones iff bit i of b is set
        let mask = 0u64.wrapping_sub((b >> i) & 1);
        lo ^= aa & mask;
        // high part: bits of `a << i` that overflow out of 64 bits
        if i > 0 {
            hi ^= (a >> (64 - i)) & mask;
        }
        aa <<= 1;
        i += 1;
    }
    (lo, hi)
}

fn vclmul(src1: &[u64; 2], src2: &[u64; 2], imm: u8) -> [u64; 2] {
    let (a, b) = match imm {
        0x00 => (src1[0], src2[0]),
        0x01 => (src1[1], src2[0]),
        0x10 => (src1[0], src2[1]),
        0x11 => (src1[1], src2[1]),
        _ => unreachable!(),
    };
    let (lo, hi) = clmul64(a, b);
    [lo, hi]
}

/// Computes a <- dot(a, b).
/// a, b are little-endian 128-bit values (2 u64 words, word[0] = low half).
pub fn gf128_dot(a: &mut [u64; 2], b: &[u64; 2]) {
    // Direct port of gfmul_int() from the AES-GCM-SIV reference.
    let xmmmask: [u64; 2] = [0x1, 0xc200_0000_0000_0000];

    let mut tmp1 = vclmul(a, b, 0x00);
    let mut tmp2 = vclmul(a, b, 0x01);
    let tmp3_ = vclmul(a, b, 0x10);
    let mut tmp4 = vclmul(a, b, 0x11);

    tmp2[0] ^= tmp3_[0];
    tmp2[1] ^= tmp3_[1];

    let mut tmp3 = [0u64, tmp2[0]];
    tmp2 = [tmp2[1], 0];

    tmp1[0] ^= tmp3[0];
    tmp1[1] ^= tmp3[1];
    tmp4[0] ^= tmp2[0];
    tmp4[1] ^= tmp2[1];

    // First reduction step
    tmp2 = vclmul(&xmmmask, &tmp1, 0x01);
    // Swap 64-bit halves of tmp1 into tmp3 (the 32-bit rewiring in the
    // reference is just a 64-bit lane swap when you unpack it)
    tmp3 = [tmp1[1], tmp1[0]];
    tmp1 = [tmp2[0] ^ tmp3[0], tmp2[1] ^ tmp3[1]];

    // Second reduction step
    tmp2 = vclmul(&xmmmask, &tmp1, 0x01);
    tmp3 = [tmp1[1], tmp1[0]];
    tmp1 = [tmp2[0] ^ tmp3[0], tmp2[1] ^ tmp3[1]];

    a[0] = tmp4[0] ^ tmp1[0];
    a[1] = tmp4[1] ^ tmp1[1];
}

// ---------------------------------------------------------------------------
// X2Polyval AXU hash.
//
// NOTE: the reference C code has a bug where `_polyval_key_init` is called
// twice on &key0 (second call with raw_key+16) and key1 is never set. The
// effect is: key0 = powers of H where H = raw_key[16..32], and key1 = all
// zeros (from memset). We **reproduce this bug** so that the published KAT
// vectors validate.

pub struct X2PolyvalKey {
    h0: [u64; 2], // actual H used for state0 (= raw_key[16..32] due to bug)
    h1: [u64; 2], // actual H used for state1 (= 0 due to bug)
}

impl X2PolyvalKey {
    pub fn new(raw_key: &[u8; 32]) -> Self {
        // Reproduce reference bug: two init calls on key0.
        // First: key0 <- raw_key[0..16]  (overwritten)
        // Second: key0 <- raw_key[16..32]
        // key1 stays zero.
        let mut h0 = [0u64; 2];
        h0[0] = u64::from_le_bytes(raw_key[16..24].try_into().unwrap());
        h0[1] = u64::from_le_bytes(raw_key[24..32].try_into().unwrap());
        let h1 = [0u64; 2];
        X2PolyvalKey { h0, h1 }
    }

    /// Compute Polyval(key0, in) || Polyval(key1, in) over 16-byte blocks.
    /// `input.len()` must be a multiple of 16.
    pub fn hash(&self, input: &[u8]) -> [u8; 32] {
        assert!(input.len() % 16 == 0);
        let mut s0 = [0u64; 2];
        let mut s1 = [0u64; 2];
        for chunk in input.chunks_exact(16) {
            let x0 = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let x1 = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
            s0[0] ^= x0;
            s0[1] ^= x1;
            s1[0] ^= x0;
            s1[1] ^= x1;
            gf128_dot(&mut s0, &self.h0);
            gf128_dot(&mut s1, &self.h1);
        }
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&s0[0].to_le_bytes());
        out[8..16].copy_from_slice(&s0[1].to_le_bytes());
        out[16..24].copy_from_slice(&s1[0].to_le_bytes());
        out[24..32].copy_from_slice(&s1[1].to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polyval_rfc8452() {
        // RFC 8452 Appendix A: POLYVAL test vector.
        // H = 25629347589242761d31f826ba4b757b
        // X_1 = 4f4f95668c83dfb6401762bb2d01a262
        // X_2 = d1a24ddd2721d006bbe45f20d3c9f362
        // result = f7a3b47b846119fae5b7866cf5e5b77e
        let h = [
            0x61_27_24_89_75_34_62_25u64.swap_bytes(),
            0x7b_75_4b_ba_26_f8_31_1du64.swap_bytes(),
        ];
        // Easier: read as LE bytes
        let h_bytes: [u8; 16] = [
            0x25, 0x62, 0x93, 0x47, 0x58, 0x92, 0x42, 0x76, 0x1d, 0x31, 0xf8, 0x26, 0xba, 0x4b,
            0x75, 0x7b,
        ];
        let hw = [
            u64::from_le_bytes(h_bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(h_bytes[8..16].try_into().unwrap()),
        ];
        let _ = h;

        let x1: [u8; 16] = [
            0x4f, 0x4f, 0x95, 0x66, 0x8c, 0x83, 0xdf, 0xb6, 0x40, 0x17, 0x62, 0xbb, 0x2d, 0x01,
            0xa2, 0x62,
        ];
        let x2: [u8; 16] = [
            0xd1, 0xa2, 0x4d, 0xdd, 0x27, 0x21, 0xd0, 0x06, 0xbb, 0xe4, 0x5f, 0x20, 0xd3, 0xc9,
            0xf3, 0x62,
        ];
        let mut s = [0u64; 2];
        for blk in [&x1, &x2] {
            s[0] ^= u64::from_le_bytes(blk[0..8].try_into().unwrap());
            s[1] ^= u64::from_le_bytes(blk[8..16].try_into().unwrap());
            gf128_dot(&mut s, &hw);
        }
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&s[0].to_le_bytes());
        out[8..16].copy_from_slice(&s[1].to_le_bytes());
        assert_eq!(
            out,
            [
                0xf7, 0xa3, 0xb4, 0x7b, 0x84, 0x61, 0x19, 0xfa, 0xe5, 0xb7, 0x86, 0x6c, 0xf5,
                0xe5, 0xb7, 0x7e
            ]
        );
    }
}
