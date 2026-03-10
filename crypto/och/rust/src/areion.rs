//! Areion256 / Areion512 permutations (eprint.iacr.org/2023/794).
//!
//! Built from AES round functions. On x86_64 with AES-NI the hardware path is
//! used; otherwise a software fallback.

#[allow(unused_imports)]
use crate::aes_soft;

pub type U128 = [u8; 16];

// Round constants: digits of π. RC[i] is packed as 4 little-endian u32s,
// matching `_mm_setr_epi32(RC[i][0], RC[i][1], RC[i][2], RC[i][3])`.
static RC: [[u32; 4]; 24] = [
    [0x03707344, 0x13198a2e, 0x85a308d3, 0x243f6a88],
    [0xec4e6c89, 0x082efa98, 0x299f31d0, 0xa4093822],
    [0x34e90c6c, 0xbe5466cf, 0x38d01377, 0x452821e6],
    [0xb5470917, 0x3f84d5b5, 0xc97c50dd, 0xc0ac29b7],
    [0x98dfb5ac, 0xd1310ba6, 0x8979fb1b, 0x9216d5d9],
    [0x6a267e96, 0xb8e1afed, 0xd01adfb7, 0x2ffd72db],
    [0xb3916cf7, 0x24a19947, 0xf12c7f99, 0xba7c9045],
    [0x1574e690, 0x36920d87, 0x58efc166, 0x801f2e28],
    [0x728eb658, 0x0d95748f, 0xf4933d7e, 0xa458fea3],
    [0xc25a59b5, 0x7b54a41d, 0x82154aee, 0x718bcd58],
    [0x286085f0, 0xc5d1b023, 0x2af26013, 0x9c30d539],
    [0x603a180e, 0x8e79dcb0, 0xb8db38ef, 0xca417918],
    [0xbd314b27, 0xd71577c1, 0xb01e8a3e, 0x6c9e0e8b],
    [0xaa55ab94, 0xe65525f3, 0x55605c60, 0x78af2fda],
    [0x2aab10b6, 0x55ca396a, 0x63e81440, 0x57489862],
    [0x7c72e993, 0xa15486af, 0x1141e8ce, 0xb4cc5c34],
    [0x741831f6, 0x2ba9c55d, 0x636fbc2a, 0xb3ee1411],
    [0x6c24cf5c, 0xafd6ba33, 0x9b87931e, 0xce5c3e16],
    [0x6b4bb9af, 0x3b8f4898, 0x28958677, 0x7a325381],
    [0xfb21a991, 0x61d809cc, 0x66282193, 0xc4bfe81b],
    [0xe98575b1, 0xef845d5d, 0x5dec8032, 0x487cac60],
    [0xd396acc5, 0x23893e81, 0xeb651b88, 0xdc262302],
    [0x48420040, 0xe0b4482a, 0x3f442392, 0xf6d6ff38],
    [0xf6e96c9a, 0x21c66842, 0x9e1f9b5e, 0x69c8f04a],
];

#[inline(always)]
fn rc0(i: usize) -> U128 {
    let r = RC[i];
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&r[0].to_le_bytes());
    out[4..8].copy_from_slice(&r[1].to_le_bytes());
    out[8..12].copy_from_slice(&r[2].to_le_bytes());
    out[12..16].copy_from_slice(&r[3].to_le_bytes());
    out
}

const RC1: U128 = [0u8; 16];

// ---------------------------------------------------------------------------
// Hardware path (x86_64 AES-NI)

#[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
mod hw {
    use super::{rc0, RC1};
    use core::arch::x86_64::*;

    #[inline(always)]
    unsafe fn load(b: &[u8; 16]) -> __m128i {
        _mm_loadu_si128(b.as_ptr() as *const __m128i)
    }
    #[inline(always)]
    unsafe fn store(b: &mut [u8; 16], x: __m128i) {
        _mm_storeu_si128(b.as_mut_ptr() as *mut __m128i, x);
    }

    #[inline(always)]
    unsafe fn round256(x0: &mut __m128i, x1: &mut __m128i, i: usize) {
        let rk0 = load(&rc0(i));
        let rk1 = load(&RC1);
        *x1 = _mm_aesenc_si128(_mm_aesenc_si128(*x0, rk0), *x1);
        *x0 = _mm_aesenclast_si128(*x0, rk1);
    }

    #[inline(always)]
    unsafe fn inv_round256(x0: &mut __m128i, x1: &mut __m128i, i: usize) {
        let rk0 = load(&rc0(i));
        let rk1 = load(&RC1);
        *x0 = _mm_aesdeclast_si128(*x0, rk1);
        *x1 = _mm_aesenc_si128(_mm_aesenc_si128(*x0, rk0), *x1);
    }

    #[inline(always)]
    unsafe fn round512(x0: &mut __m128i, x1: &mut __m128i, x2: &mut __m128i, x3: &mut __m128i, i: usize) {
        let rk0 = load(&rc0(i));
        let rk1 = load(&RC1);
        *x1 = _mm_aesenc_si128(*x0, *x1);
        *x3 = _mm_aesenc_si128(*x2, *x3);
        *x0 = _mm_aesenclast_si128(*x0, rk1);
        *x2 = _mm_aesenc_si128(_mm_aesenclast_si128(*x2, rk0), rk1);
    }

    pub fn areion256_fwd(x0: &mut [u8; 16], x1: &mut [u8; 16]) {
        unsafe {
            let mut a = load(x0);
            let mut b = load(x1);
            round256(&mut a, &mut b, 0);
            round256(&mut b, &mut a, 1);
            round256(&mut a, &mut b, 2);
            round256(&mut b, &mut a, 3);
            round256(&mut a, &mut b, 4);
            round256(&mut b, &mut a, 5);
            round256(&mut a, &mut b, 6);
            round256(&mut b, &mut a, 7);
            round256(&mut a, &mut b, 8);
            round256(&mut b, &mut a, 9);
            store(x0, a);
            store(x1, b);
        }
    }

    pub fn areion256_bwd(x0: &mut [u8; 16], x1: &mut [u8; 16]) {
        unsafe {
            let mut a = load(x0);
            let mut b = load(x1);
            inv_round256(&mut b, &mut a, 9);
            inv_round256(&mut a, &mut b, 8);
            inv_round256(&mut b, &mut a, 7);
            inv_round256(&mut a, &mut b, 6);
            inv_round256(&mut b, &mut a, 5);
            inv_round256(&mut a, &mut b, 4);
            inv_round256(&mut b, &mut a, 3);
            inv_round256(&mut a, &mut b, 2);
            inv_round256(&mut b, &mut a, 1);
            inv_round256(&mut a, &mut b, 0);
            store(x0, a);
            store(x1, b);
        }
    }

    pub fn areion512_fwd(s: &mut [[u8; 16]; 4]) {
        unsafe {
            let mut x0 = load(&s[0]);
            let mut x1 = load(&s[1]);
            let mut x2 = load(&s[2]);
            let mut x3 = load(&s[3]);
            // 15 rounds, rotating the argument order each time
            round512(&mut x0, &mut x1, &mut x2, &mut x3, 0);
            round512(&mut x1, &mut x2, &mut x3, &mut x0, 1);
            round512(&mut x2, &mut x3, &mut x0, &mut x1, 2);
            round512(&mut x3, &mut x0, &mut x1, &mut x2, 3);
            round512(&mut x0, &mut x1, &mut x2, &mut x3, 4);
            round512(&mut x1, &mut x2, &mut x3, &mut x0, 5);
            round512(&mut x2, &mut x3, &mut x0, &mut x1, 6);
            round512(&mut x3, &mut x0, &mut x1, &mut x2, 7);
            round512(&mut x0, &mut x1, &mut x2, &mut x3, 8);
            round512(&mut x1, &mut x2, &mut x3, &mut x0, 9);
            round512(&mut x2, &mut x3, &mut x0, &mut x1, 10);
            round512(&mut x3, &mut x0, &mut x1, &mut x2, 11);
            round512(&mut x0, &mut x1, &mut x2, &mut x3, 12);
            round512(&mut x1, &mut x2, &mut x3, &mut x0, 13);
            round512(&mut x2, &mut x3, &mut x0, &mut x1, 14);
            store(&mut s[0], x0);
            store(&mut s[1], x1);
            store(&mut s[2], x2);
            store(&mut s[3], x3);
        }
    }
}

// ---------------------------------------------------------------------------
// Software fallback path

#[cfg_attr(all(target_arch = "x86_64", target_feature = "aes"), allow(dead_code))]
mod sw {
    use super::{aes_soft, rc0, RC1, U128};

    #[inline(always)]
    fn round256(x0: &mut U128, x1: &mut U128, i: usize) {
        let rk0 = rc0(i);
        *x1 = aes_soft::aes_enc(&aes_soft::aes_enc(x0, &rk0), x1);
        *x0 = aes_soft::aes_enc_last(x0, &RC1);
    }

    #[inline(always)]
    fn inv_round256(x0: &mut U128, x1: &mut U128, i: usize) {
        let rk0 = rc0(i);
        *x0 = aes_soft::aes_dec_last(x0, &RC1);
        *x1 = aes_soft::aes_enc(&aes_soft::aes_enc(x0, &rk0), x1);
    }

    /// round512 applied to s[a],s[b],s[c],s[d] where a,b,c,d are a permutation
    /// of {0,1,2,3}. Works by local copies to sidestep the borrow checker.
    #[inline(always)]
    fn round512(s: &mut [[u8; 16]; 4], a: usize, b: usize, c: usize, d: usize, i: usize) {
        let rk0 = rc0(i);
        let x0 = s[a];
        let x2 = s[c];
        s[b] = aes_soft::aes_enc(&x0, &s[b]);
        s[d] = aes_soft::aes_enc(&x2, &s[d]);
        s[a] = aes_soft::aes_enc_last(&x0, &RC1);
        s[c] = aes_soft::aes_enc(&aes_soft::aes_enc_last(&x2, &rk0), &RC1);
    }

    pub fn areion256_fwd(x0: &mut U128, x1: &mut U128) {
        round256(x0, x1, 0);
        round256(x1, x0, 1);
        round256(x0, x1, 2);
        round256(x1, x0, 3);
        round256(x0, x1, 4);
        round256(x1, x0, 5);
        round256(x0, x1, 6);
        round256(x1, x0, 7);
        round256(x0, x1, 8);
        round256(x1, x0, 9);
    }

    pub fn areion256_bwd(x0: &mut U128, x1: &mut U128) {
        inv_round256(x1, x0, 9);
        inv_round256(x0, x1, 8);
        inv_round256(x1, x0, 7);
        inv_round256(x0, x1, 6);
        inv_round256(x1, x0, 5);
        inv_round256(x0, x1, 4);
        inv_round256(x1, x0, 3);
        inv_round256(x0, x1, 2);
        inv_round256(x1, x0, 1);
        inv_round256(x0, x1, 0);
    }

    pub fn areion512_fwd(s: &mut [[u8; 16]; 4]) {
        round512(s, 0, 1, 2, 3, 0);
        round512(s, 1, 2, 3, 0, 1);
        round512(s, 2, 3, 0, 1, 2);
        round512(s, 3, 0, 1, 2, 3);
        round512(s, 0, 1, 2, 3, 4);
        round512(s, 1, 2, 3, 0, 5);
        round512(s, 2, 3, 0, 1, 6);
        round512(s, 3, 0, 1, 2, 7);
        round512(s, 0, 1, 2, 3, 8);
        round512(s, 1, 2, 3, 0, 9);
        round512(s, 2, 3, 0, 1, 10);
        round512(s, 3, 0, 1, 2, 11);
        round512(s, 0, 1, 2, 3, 12);
        round512(s, 1, 2, 3, 0, 13);
        round512(s, 2, 3, 0, 1, 14);
    }
}

// ---------------------------------------------------------------------------
// Public API — dispatches to hw or sw.

#[inline]
pub fn areion256_forward(state: &mut [u8; 32]) {
    let (a, b) = state.split_at_mut(16);
    let x0: &mut [u8; 16] = a.try_into().unwrap();
    let x1: &mut [u8; 16] = b.try_into().unwrap();
    #[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
    {
        hw::areion256_fwd(x0, x1);
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "aes")))]
    {
        sw::areion256_fwd(x0, x1);
    }
}

#[inline]
pub fn areion256_backward(state: &mut [u8; 32]) {
    let (a, b) = state.split_at_mut(16);
    let x0: &mut [u8; 16] = a.try_into().unwrap();
    let x1: &mut [u8; 16] = b.try_into().unwrap();
    #[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
    {
        hw::areion256_bwd(x0, x1);
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "aes")))]
    {
        sw::areion256_bwd(x0, x1);
    }
}

#[inline]
pub fn areion512_forward(state: &mut [u8; 64]) {
    // View as 4 x [u8; 16]
    let mut s = [[0u8; 16]; 4];
    for i in 0..4 {
        s[i].copy_from_slice(&state[16 * i..16 * i + 16]);
    }
    #[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
    {
        hw::areion512_fwd(&mut s);
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "aes")))]
    {
        sw::areion512_fwd(&mut s);
    }
    for i in 0..4 {
        state[16 * i..16 * i + 16].copy_from_slice(&s[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn areion256_kat() {
        // Appendix B of eprint.iacr.org/2023/794
        let mut s = [0u8; 32];
        areion256_forward(&mut s);
        assert_eq!(
            hex(&s),
            "2812a72465b26e9fca7583f6e4123aa1490e35e7d5203e4ba2e927b0482f4db8"
        );
        areion256_backward(&mut s);
        assert_eq!(hex(&s), "00".repeat(32));

        let mut s = [0u8; 32];
        for i in 0..32u8 {
            s[i as usize] = i;
        }
        areion256_forward(&mut s);
        assert_eq!(
            hex(&s),
            "68845f132ee4616066c702d942a3b2c3a377f65b13bb05c7cd1fb29c89afa185"
        );
    }

    #[test]
    fn areion512_kat() {
        // From OCH reference test suite (differs from paper Appendix B
        // in output word order — this is what the reference C code produces)
        let mut s = [0u8; 64];
        areion512_forward(&mut s);
        assert_eq!(
            hex(&s),
            "78cf3ee4b73c6a543fe6dc85779102e7e3f5501016ceed1dd2c48d0bc212fb07ad168794bd96cff35909cdd8e2274928b2adb04fa91f901559367122cb3c96a9"
        );

        let mut s = [0u8; 64];
        for i in 0..64u8 {
            s[i as usize] = i;
        }
        areion512_forward(&mut s);
        assert_eq!(
            hex(&s),
            "135e9ac5fc3dc9b647a43f4daa8da7a4e0afbdd8e6e255c24527736b298bd61de460bab9ea7915c6d6ddbe05fe8dde40b690b88297ec470b07dda92b91959cff"
        );
    }
}
