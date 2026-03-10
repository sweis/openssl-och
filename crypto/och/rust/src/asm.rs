//! Bindings to the Perl-generated x86_64 Areion-256 kernels.
//!
//! Compiled only when `build.rs` sets `cfg(och_asm)` (i.e. on x86_64 where
//! the perlasm step succeeded). The pure-Rust path remains the fallback.
//!
//! Safety: every wrapper takes fixed-size array references, so the slice
//! widths passed across the FFI boundary are proven at the type level.

#![cfg(och_asm)]
// The x1/x4 raw-permutation wrappers are used only by tests; the production
// code path goes straight to em_{enc,dec}_x4. Suppress dead-code on release.
#![cfg_attr(not(test), allow(dead_code))]

extern "C" {
    fn och_asm_areion256_x1(state: *mut u8);
    fn och_asm_areion256_inv_x1(state: *mut u8);
    fn och_asm_areion256_x4(state: *mut u8);
    fn och_asm_areion256_inv_x4(state: *mut u8);
    fn och_asm_em_enc_x4(blk: *mut u8, off: *const u8);
    fn och_asm_em_dec_x4(blk: *mut u8, off: *const u8);
    // Full bulk loop — offsets, checksum, EM, stride all in-ASM.
    fn och_asm_em_enc_bulk(
        dst: *mut u8,
        src: *const u8,
        nblocks: usize,
        l_table: *const u8,
        off: *mut u8,
        i: *mut u32,
        checksum: *mut u8,
    );
    fn och_asm_em_dec_bulk(
        dst: *mut u8,
        src: *const u8,
        nblocks: usize,
        l_table: *const u8,
        off: *mut u8,
        i: *mut u32,
        checksum: *mut u8,
    );
}

#[inline]
pub fn areion256_x1(s: &mut [u8; 32]) {
    unsafe { och_asm_areion256_x1(s.as_mut_ptr()) }
}

#[inline]
pub fn areion256_inv_x1(s: &mut [u8; 32]) {
    unsafe { och_asm_areion256_inv_x1(s.as_mut_ptr()) }
}

#[inline]
pub fn areion256_x4(s: &mut [[u8; 32]; 4]) {
    unsafe { och_asm_areion256_x4(s.as_mut_ptr().cast()) }
}

#[inline]
pub fn areion256_inv_x4(s: &mut [[u8; 32]; 4]) {
    unsafe { och_asm_areion256_inv_x4(s.as_mut_ptr().cast()) }
}

/// Even-Mansour encrypt ×4:
///   for each i: blk[i] ^= off[i]; Areion256(blk[i]); blk[i] ^= off[i]
#[inline]
pub fn em_enc_x4(blk: &mut [[u8; 32]; 4], off: &[[u8; 32]; 4]) {
    unsafe { och_asm_em_enc_x4(blk.as_mut_ptr().cast(), off.as_ptr().cast()) }
}

#[inline]
pub fn em_dec_x4(blk: &mut [[u8; 32]; 4], off: &[[u8; 32]; 4]) {
    unsafe { och_asm_em_dec_x4(blk.as_mut_ptr().cast(), off.as_ptr().cast()) }
}

/// Full bulk EM encrypt loop — processes `n4` blocks (multiple of 4, >= 4).
/// Does the complete inner-loop work in ASM: offset chain (OCB-style
/// `off ^= L[ntz(i)]`), checksum accumulation, and the 4-way interleaved
/// Areion-EM kernel. One FFI call per message, not per 4-block stride.
///
/// `src` and `dst` must not overlap (Rust's `&[u8]` / `&mut [u8]` already
/// forbid this). `i` must be >= 1 on entry.
#[inline]
pub fn em_enc_bulk(
    dst: &mut [u8],
    src: &[u8],
    n4: usize,
    l_table: &[[u8; 32]],
    off: &mut [u8; 32],
    i: &mut u32,
    checksum: &mut [u8; 16],
) {
    debug_assert!(n4 >= 4 && n4 % 4 == 0);
    debug_assert!(src.len() >= 32 * n4 && dst.len() >= 32 * n4);
    debug_assert!(*i >= 1);
    unsafe {
        och_asm_em_enc_bulk(
            dst.as_mut_ptr(),
            src.as_ptr(),
            n4,
            l_table.as_ptr().cast(),
            off.as_mut_ptr(),
            i,
            checksum.as_mut_ptr(),
        )
    }
}

#[inline]
pub fn em_dec_bulk(
    dst: &mut [u8],
    src: &[u8],
    n4: usize,
    l_table: &[[u8; 32]],
    off: &mut [u8; 32],
    i: &mut u32,
    checksum: &mut [u8; 16],
) {
    debug_assert!(n4 >= 4 && n4 % 4 == 0);
    debug_assert!(src.len() >= 32 * n4 && dst.len() >= 32 * n4);
    debug_assert!(*i >= 1);
    unsafe {
        och_asm_em_dec_bulk(
            dst.as_mut_ptr(),
            src.as_ptr(),
            n4,
            l_table.as_ptr().cast(),
            off.as_mut_ptr(),
            i,
            checksum.as_mut_ptr(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::areion::{areion256_backward, areion256_forward};

    fn rand32(seed: &mut u32) -> [u8; 32] {
        let mut b = [0u8; 32];
        for v in &mut b {
            *seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            *v = (*seed >> 16) as u8;
        }
        b
    }

    #[test]
    fn x1_matches_rust_fwd() {
        let mut seed = 0xcafed00d;
        for _ in 0..64 {
            let mut a = rand32(&mut seed);
            let mut r = a;
            areion256_x1(&mut a);
            areion256_forward(&mut r);
            assert_eq!(a, r);
        }
    }

    #[test]
    fn x1_inv_roundtrip() {
        let mut seed = 0x12345678;
        for _ in 0..64 {
            let orig = rand32(&mut seed);
            let mut s = orig;
            areion256_x1(&mut s);
            areion256_inv_x1(&mut s);
            assert_eq!(s, orig);
            let mut s = orig;
            areion256_inv_x1(&mut s);
            areion256_x1(&mut s);
            assert_eq!(s, orig);
        }
        // Also cross-check inv against Rust backward.
        let mut s = rand32(&mut seed);
        let mut r = s;
        areion256_inv_x1(&mut s);
        areion256_backward(&mut r);
        assert_eq!(s, r);
    }

    #[test]
    fn x4_matches_x1_per_lane() {
        let mut seed = 0xf005ba11;
        for _ in 0..32 {
            let mut s4: [[u8; 32]; 4] = [
                rand32(&mut seed),
                rand32(&mut seed),
                rand32(&mut seed),
                rand32(&mut seed),
            ];
            let mut want = s4;
            for lane in &mut want {
                areion256_x1(lane);
            }
            areion256_x4(&mut s4);
            assert_eq!(s4, want);
            // inverse recovers original
            let orig = want; // s4 is already fwd'd from above? No — use want's origin.
            // Simpler: inv_x4(fwd_x4(x)) == x
            let mut y: [[u8; 32]; 4] = [
                rand32(&mut seed),
                rand32(&mut seed),
                rand32(&mut seed),
                rand32(&mut seed),
            ];
            let y0 = y;
            areion256_x4(&mut y);
            areion256_inv_x4(&mut y);
            assert_eq!(y, y0);
            let _ = orig; // silence
        }
    }

    #[test]
    fn em_x4_matches_scalar() {
        let mut seed = 0x0badc0de;
        for _ in 0..32 {
            let blk_in: [[u8; 32]; 4] = [
                rand32(&mut seed),
                rand32(&mut seed),
                rand32(&mut seed),
                rand32(&mut seed),
            ];
            let off: [[u8; 32]; 4] = [
                rand32(&mut seed),
                rand32(&mut seed),
                rand32(&mut seed),
                rand32(&mut seed),
            ];
            // kernel
            let mut blk = blk_in;
            em_enc_x4(&mut blk, &off);
            // reference: xor, Areion fwd, xor
            let mut ref_blk = blk_in;
            for b in 0..4 {
                for i in 0..32 {
                    ref_blk[b][i] ^= off[b][i];
                }
                areion256_forward(&mut ref_blk[b]);
                for i in 0..32 {
                    ref_blk[b][i] ^= off[b][i];
                }
            }
            assert_eq!(blk, ref_blk);
            // dec inverts enc
            em_dec_x4(&mut blk, &off);
            assert_eq!(blk, blk_in);
        }
    }

    /// Reference scalar bulk: mirrors och.rs em_encrypt_blocks scalar path.
    fn ref_enc_bulk(
        l: &[[u8; 32]; 16],
        off: &mut [u8; 32],
        i: &mut u32,
        chk: &mut [u8; 16],
        src: &[u8],
        dst: &mut [u8],
        n: usize,
    ) {
        for k in 0..n {
            let mut pi = [0u8; 32];
            pi.copy_from_slice(&src[32 * k..32 * k + 32]);
            for j in 0..16 {
                chk[j] ^= pi[j];
            }
            let idx = i.trailing_zeros() as usize;
            for j in 0..32 {
                off[j] ^= l[idx][j];
            }
            let mut c = pi;
            for j in 0..32 {
                c[j] ^= off[j];
            }
            areion256_forward(&mut c);
            for j in 0..32 {
                c[j] ^= off[j];
            }
            dst[32 * k..32 * k + 32].copy_from_slice(&c);
            *i += 1;
        }
    }

    #[test]
    fn bulk_matches_scalar() {
        let mut seed = 0xdeadbeefu32;
        let mut l = [[0u8; 32]; 16];
        for row in &mut l {
            *row = rand32(&mut seed);
        }
        for &n in &[4usize, 8, 12, 16, 64] {
            let mut src = vec![0u8; 32 * n];
            for b in src.iter_mut() {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                *b = (seed >> 16) as u8;
            }
            let off0 = rand32(&mut seed);
            let i0 = 1u32 + (seed % 7); // >= 1

            // ASM path
            let mut dst_a = vec![0u8; 32 * n];
            let (mut off_a, mut i_a, mut chk_a) = (off0, i0, [0u8; 16]);
            em_enc_bulk(&mut dst_a, &src, n, &l, &mut off_a, &mut i_a, &mut chk_a);

            // Reference path
            let mut dst_r = vec![0u8; 32 * n];
            let (mut off_r, mut i_r, mut chk_r) = (off0, i0, [0u8; 16]);
            ref_enc_bulk(&l, &mut off_r, &mut i_r, &mut chk_r, &src, &mut dst_r, n);

            assert_eq!(dst_a, dst_r, "ciphertext mismatch at n={n}");
            assert_eq!(off_a, off_r, "offset mismatch at n={n}");
            assert_eq!(i_a, i_r, "counter mismatch at n={n}");
            assert_eq!(chk_a, chk_r, "checksum mismatch at n={n}");

            // dec inverts enc, restores state
            let mut dst_d = vec![0u8; 32 * n];
            let (mut off_d, mut i_d, mut chk_d) = (off0, i0, [0u8; 16]);
            em_dec_bulk(
                &mut dst_d, &dst_a, n, &l, &mut off_d, &mut i_d, &mut chk_d,
            );
            assert_eq!(dst_d, src, "dec roundtrip at n={n}");
            assert_eq!(off_d, off_r, "dec offset at n={n}");
            assert_eq!(chk_d, chk_r, "dec checksum at n={n}");
        }
    }
}
