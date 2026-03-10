//! OCH (Offset Codebook with Hashing) authenticated encryption — Rust impl.
//!
//! Areion-based instantiation of the OCH-256 mode from:
//!   Menda, Bellare, Hoang, Len, Ristenpart,
//!   "OCH: Fast, Committing AEAD from a Tweakable Block Cipher",
//!   ACM CCS 2025 / eprint 2026/439.
//!
//! This is a reference-faithful port of the authors' C code, reproducing
//! its known bugs so that published KAT vectors match. See och.rs for
//! details.
//!
//! Exported C ABI for OpenSSL integration:
//!   OCH_areion_p_init / OCH_areion_s_init
//!   OCH_areion_seal / OCH_areion_open
//!   OCH_areion256_permute (for benchmarking)

#![allow(clippy::needless_range_loop, clippy::manual_memcpy)]

mod aes_soft;
mod areion;
#[cfg(och_asm)]
mod asm;
mod gf;
mod och;
mod sponge;

pub use areion::{areion256_backward, areion256_forward, areion512_forward};
pub use och::{open, seal, OchCtx, KEY_LEN, NONCE_LEN, P_OVERHEAD, S_OVERHEAD, TAG_LEN};

// ---------------------------------------------------------------------------
// C FFI
//
// The opaque context is heap-allocated so OpenSSL's C side can hold a pointer
// without knowing Rust's struct layout. C callers must pair *_init with
// *_free.

use core::ptr;
use core::slice;

/// Opaque handle given to C. Actually a Box<OchCtx>.
pub type OchCtxHandle = *mut OchCtx;

#[no_mangle]
pub extern "C" fn OCH_areion_p_init(key: *const u8) -> OchCtxHandle {
    if key.is_null() {
        return ptr::null_mut();
    }
    let k: &[u8; 32] = unsafe { &*(key as *const [u8; 32]) };
    let ctx = Box::new(OchCtx::new_p(k));
    Box::into_raw(ctx)
}

#[no_mangle]
pub extern "C" fn OCH_areion_s_init(key: *const u8) -> OchCtxHandle {
    if key.is_null() {
        return ptr::null_mut();
    }
    let k: &[u8; 32] = unsafe { &*(key as *const [u8; 32]) };
    let ctx = Box::new(OchCtx::new_s(k));
    Box::into_raw(ctx)
}

#[no_mangle]
pub extern "C" fn OCH_areion_free(ctx: OchCtxHandle) {
    if !ctx.is_null() {
        unsafe {
            drop(Box::from_raw(ctx));
        }
    }
}

/// Returns ciphertext length (>=0) on success, -1 on error.
///
/// Layout on success:
///   OCH-P: ct = enc(msg) || tag           (ct_len = msg_len + 32)
///   OCH-S: ct = enc(sn) || enc(msg) || tag (ct_len = msg_len + 64)
///
/// For OCH-P, pass `secnonce = NULL, secnonce_len = 0`.
/// For OCH-S, pass `pubnonce = NULL, pubnonce_len = 0`.
/// The caller must size `ct` accordingly.
#[no_mangle]
pub extern "C" fn OCH_areion_seal(
    ctx: OchCtxHandle,
    ct: *mut u8,
    ct_cap: usize,
    msg: *const u8,
    msg_len: usize,
    ad: *const u8,
    ad_len: usize,
    pubnonce: *const u8,
    pubnonce_len: usize,
    secnonce: *const u8,
    secnonce_len: usize,
) -> isize {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    let ct = unsafe { slice::from_raw_parts_mut(ct, ct_cap) };
    let msg = if msg_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(msg, msg_len) }
    };
    let ad = if ad_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(ad, ad_len) }
    };
    let pubnonce = if pubnonce_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(pubnonce, pubnonce_len) }
    };
    let secnonce = if secnonce_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(secnonce, secnonce_len) }
    };
    match seal(ctx, ct, msg, ad, pubnonce, secnonce) {
        Some(n) => n as isize,
        None => -1,
    }
}

/// Returns plaintext length (>=0) on success, -1 on auth failure or error.
/// Output buffers are NOT wiped on failure; caller must discard.
#[no_mangle]
pub extern "C" fn OCH_areion_open(
    ctx: OchCtxHandle,
    msg: *mut u8,
    msg_cap: usize,
    secnonce_out: *mut u8,
    secnonce_out_len: usize,
    ct: *const u8,
    ct_len: usize,
    ad: *const u8,
    ad_len: usize,
    pubnonce: *const u8,
    pubnonce_len: usize,
) -> isize {
    if ctx.is_null() || ct.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    let msg = if msg_cap == 0 {
        &mut [][..]
    } else {
        unsafe { slice::from_raw_parts_mut(msg, msg_cap) }
    };
    let secnonce_out = if secnonce_out_len == 0 {
        &mut [][..]
    } else {
        unsafe { slice::from_raw_parts_mut(secnonce_out, secnonce_out_len) }
    };
    let ct = unsafe { slice::from_raw_parts(ct, ct_len) };
    let ad = if ad_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(ad, ad_len) }
    };
    let pubnonce = if pubnonce_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(pubnonce, pubnonce_len) }
    };
    match open(ctx, msg, secnonce_out, ct, ad, pubnonce) {
        Some(n) => n as isize,
        None => -1,
    }
}

/// Raw Areion256 forward permutation (32 bytes in-place). For benchmarking.
#[no_mangle]
pub extern "C" fn OCH_areion256_permute(state: *mut u8) {
    let s: &mut [u8; 32] = unsafe { &mut *(state as *mut [u8; 32]) };
    areion256_forward(s);
}

/// Raw Areion256 ×4 forward permutation (4×32 bytes in-place).
/// Uses the Perl-asm kernel when available; otherwise four scalar calls.
/// Exposed purely for benchmarking the interleaved throughput.
#[no_mangle]
pub extern "C" fn OCH_areion256_permute_x4(state: *mut u8) {
    #[cfg(och_asm)]
    {
        let s: &mut [[u8; 32]; 4] = unsafe { &mut *(state as *mut [[u8; 32]; 4]) };
        crate::asm::areion256_x4(s);
    }
    #[cfg(not(och_asm))]
    {
        for b in 0..4 {
            let s: &mut [u8; 32] =
                unsafe { &mut *(state.add(32 * b) as *mut [u8; 32]) };
            areion256_forward(s);
        }
    }
}

// ---------------------------------------------------------------------------
// KAT tests

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn kat_areion_och_p_0() {
        // AreionOCH_P_0 from reference aead_test.cc
        let key = [0u8; 32];
        let pubnonce = [0u8; 32];
        let ad = [0u8; 32];
        let msg = [0u8; 32];
        let expected_ct =
            "94fb76019c4cc1bb2b8c745d749ccf0261e4c99041349b80a8e6c70e3cf9837e\
             bd367f85091b4989ae1d9276f918edc58412e61d451918ed96d89104dfc0d282";

        let mut ctx = OchCtx::new_p(&key);
        let mut ct = [0u8; 64];
        let n = seal(&mut ctx, &mut ct, &msg, &ad, &pubnonce, &[]).unwrap();
        assert_eq!(n, 64);
        assert_eq!(hex(&ct), expected_ct);

        // Round-trip
        let mut dec = [0xffu8; 32];
        let m = open(&mut ctx, &mut dec, &mut [], &ct, &ad, &pubnonce).unwrap();
        assert_eq!(m, 32);
        assert_eq!(dec, msg);

        // Tamper detection
        let mut bad = ct;
        bad[63] ^= 1;
        assert!(open(&mut ctx, &mut dec, &mut [], &bad, &ad, &pubnonce).is_none());
    }

    #[test]
    fn kat_areion_och_s_0() {
        let key = [0u8; 32];
        let secnonce = [0u8; 32];
        let ad = [0u8; 32];
        let msg = [0u8; 32];
        let expected_ct =
            "94fb76019c4cc1bb2b8c745d749ccf0261e4c99041349b80a8e6c70e3cf9837e\
             69f7a06a96353e5c3010ebd8db1d20c8cc5bd43eae6df364a10c2062b3f818e3\
             c85ab5e5c9ca43e66bca16dbb5b5c240e86fa59167f895926775550583a250b8";

        let mut ctx = OchCtx::new_s(&key);
        let mut ct = [0u8; 96];
        let n = seal(&mut ctx, &mut ct, &msg, &ad, &[], &secnonce).unwrap();
        assert_eq!(n, 96);
        assert_eq!(hex(&ct), expected_ct);

        let mut dec = [0xffu8; 32];
        let mut dec_sn = [0xffu8; 32];
        let m = open(&mut ctx, &mut dec, &mut dec_sn, &ct, &ad, &[]).unwrap();
        assert_eq!(m, 32);
        assert_eq!(dec, msg);
        assert_eq!(dec_sn, secnonce);
    }

    #[test]
    fn roundtrip_many_lengths() {
        let key = [0x42u8; 32];
        let pubnonce = [0x42u8; 32];
        let ad = [0x42u8; 128];
        // Include sizes that exercise the 4-way ASM stride (>= 5 full blocks
        // after the first = 160+ bytes) and misaligned tails.
        for mlen in [
            0, 2, 8, 16, 31, 32, 48, 64, 80, 108, 128, 144, 160, 191, 192, 256,
            304, 512, 513, 1024, 1025, 4096, 4097,
        ] {
            let msg: Vec<u8> = (0..mlen).map(|i| (i * 7 + 3) as u8).collect();
            let mut ctx = OchCtx::new_p(&key);
            let mut ct = vec![0u8; mlen + P_OVERHEAD];
            let n = seal(&mut ctx, &mut ct, &msg, &ad, &pubnonce, &[]).unwrap();
            assert_eq!(n, ct.len());

            let mut dec = vec![0xaau8; mlen];
            let m = open(&mut ctx, &mut dec, &mut [], &ct, &ad, &pubnonce).unwrap();
            assert_eq!(m, mlen);
            assert_eq!(dec, msg);

            // Tamper: flip a tag bit.
            let mut bad = ct.clone();
            let last = bad.len() - 1;
            bad[last] ^= 0x80;
            assert!(open(&mut ctx, &mut dec, &mut [], &bad, &ad, &pubnonce).is_none());
        }
    }
}
