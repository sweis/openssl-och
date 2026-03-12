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
pub use och::{
    open, seal, OchCtx, KEY_LEN, MAX_MSG_LEN, NONCE_LEN, P_OVERHEAD, S_OVERHEAD, TAG_LEN,
};

// ---------------------------------------------------------------------------
// C FFI
//
// The opaque context is heap-allocated so OpenSSL's C side can hold a pointer
// without knowing Rust's struct layout. C callers must pair *_init with
// *_free.

use core::ptr;
use core::slice;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Build a `&[u8]` from a C pointer/length. Returns `None` if the pointer is
/// NULL while length > 0 (which would be UB via `slice::from_raw_parts`).
#[inline]
unsafe fn c_slice<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if p.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(p, len))
    }
}

#[inline]
unsafe fn c_slice_mut<'a>(p: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 {
        Some(&mut [])
    } else if p.is_null() {
        None
    } else {
        Some(slice::from_raw_parts_mut(p, len))
    }
}

/// Opaque handle given to C. Actually a Box<OchCtx>.
pub type OchCtxHandle = *mut OchCtx;

#[no_mangle]
pub extern "C" fn OCH_areion_p_init(key: *const u8) -> OchCtxHandle {
    if key.is_null() {
        return ptr::null_mut();
    }
    let k: &[u8; 32] = unsafe { &*(key as *const [u8; 32]) };
    catch_unwind(|| Box::into_raw(Box::new(OchCtx::new_p(k))))
        .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn OCH_areion_s_init(key: *const u8) -> OchCtxHandle {
    if key.is_null() {
        return ptr::null_mut();
    }
    let k: &[u8; 32] = unsafe { &*(key as *const [u8; 32]) };
    catch_unwind(|| Box::into_raw(Box::new(OchCtx::new_s(k))))
        .unwrap_or(ptr::null_mut())
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
    let (ct, msg, ad, pubnonce, secnonce) = unsafe {
        match (
            c_slice_mut(ct, ct_cap),
            c_slice(msg, msg_len),
            c_slice(ad, ad_len),
            c_slice(pubnonce, pubnonce_len),
            c_slice(secnonce, secnonce_len),
        ) {
            (Some(a), Some(b), Some(c), Some(d), Some(e)) => (a, b, c, d, e),
            _ => return -1,
        }
    };
    let ctx = unsafe { &mut *ctx };
    catch_unwind(AssertUnwindSafe(|| seal(ctx, ct, msg, ad, pubnonce, secnonce)))
        .ok()
        .flatten()
        .map_or(-1, |n| n as isize)
}

/// Returns plaintext length (>=0) on success, -1 on auth failure or error.
/// On auth failure, any unverified plaintext already written to `msg` /
/// `secnonce_out` is wiped before returning.
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
    if ctx.is_null() {
        return -1;
    }
    let (msg, secnonce_out, ct, ad, pubnonce) = unsafe {
        match (
            c_slice_mut(msg, msg_cap),
            c_slice_mut(secnonce_out, secnonce_out_len),
            c_slice(ct, ct_len),
            c_slice(ad, ad_len),
            c_slice(pubnonce, pubnonce_len),
        ) {
            (Some(a), Some(b), Some(c), Some(d), Some(e)) => (a, b, c, d, e),
            _ => return -1,
        }
    };
    let ctx = unsafe { &mut *ctx };
    catch_unwind(AssertUnwindSafe(|| open(ctx, msg, secnonce_out, ct, ad, pubnonce)))
        .ok()
        .flatten()
        .map_or(-1, |n| n as isize)
}

/// Raw Areion256 forward permutation (32 bytes in-place). For benchmarking.
#[no_mangle]
pub extern "C" fn OCH_areion256_permute(state: *mut u8) {
    if state.is_null() {
        return;
    }
    let s: &mut [u8; 32] = unsafe { &mut *(state as *mut [u8; 32]) };
    let _ = catch_unwind(AssertUnwindSafe(|| areion256_forward(s)));
}

/// Raw Areion256 ×4 forward permutation (4×32 bytes in-place).
/// Uses the Perl-asm kernel when available; otherwise four scalar calls.
/// Exposed purely for benchmarking the interleaved throughput.
#[no_mangle]
pub extern "C" fn OCH_areion256_permute_x4(state: *mut u8) {
    if state.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
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
    }));
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

    #[test]
    fn large_message_roundtrip() {
        // Regression test for L-table OOB at ~2 MiB. With L_TABLE_SIZE=16
        // the block counter i=65536 yielded ntz=16, panicking on l[16].
        // Now L_TABLE_SIZE=32 covers the full u32 counter range.
        let key = [0x99u8; 32];
        let pubnonce = [0x77u8; 32];
        let mlen: usize = 32 + 65536 * 32; // 2 MiB + 32 bytes
        let msg: Vec<u8> = (0..mlen).map(|i| (i * 13 + 5) as u8).collect();
        let mut ctx = OchCtx::new_p(&key);
        let mut ct = vec![0u8; mlen + P_OVERHEAD];
        let n = seal(&mut ctx, &mut ct, &msg, &[], &pubnonce, &[]).unwrap();
        assert_eq!(n, ct.len());

        let mut dec = vec![0u8; mlen];
        let m = open(&mut ctx, &mut dec, &mut [], &ct, &[], &pubnonce).unwrap();
        assert_eq!(m, mlen);
        assert_eq!(dec, msg);
    }

    #[test]
    fn wipes_output_on_auth_failure() {
        let key = [0x11u8; 32];
        let pubnonce = [0x22u8; 32];
        let msg = [0x33u8; 128];
        let mut ctx = OchCtx::new_p(&key);
        let mut ct = [0u8; 128 + P_OVERHEAD];
        seal(&mut ctx, &mut ct, &msg, &[], &pubnonce, &[]).unwrap();

        // Tamper with the tag.
        let last = ct.len() - 1;
        ct[last] ^= 1;

        let mut dec = [0xffu8; 128];
        assert!(open(&mut ctx, &mut dec, &mut [], &ct, &[], &pubnonce).is_none());
        // Unverified plaintext must not leak.
        assert_eq!(dec, [0u8; 128]);
    }

    #[test]
    fn ffi_null_safety() {
        use core::ptr;
        // NULL ct buffer with nonzero length must return -1, not UB.
        let key = [0u8; 32];
        let ctx = OCH_areion_p_init(key.as_ptr());
        assert!(!ctx.is_null());
        let nonce = [0u8; 32];
        let r = OCH_areion_seal(
            ctx, ptr::null_mut(), 64, ptr::null(), 0, ptr::null(), 0,
            nonce.as_ptr(), 32, ptr::null(), 0,
        );
        assert_eq!(r, -1);
        // NULL key rejected by init.
        assert!(OCH_areion_p_init(ptr::null()).is_null());
        // NULL state to permute is a no-op, not a crash.
        OCH_areion256_permute(ptr::null_mut());
        OCH_areion_free(ctx);
    }
}
