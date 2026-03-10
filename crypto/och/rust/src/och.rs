//! OCH-256 AEAD (Areion instantiation).
//!
//! Reference-faithful port of the OCH reference implementation from
//! https://eprint.iacr.org/2026/439. Reproduces all known reference-code
//! quirks so that published KAT vectors validate:
//!
//!   * `tbc_key` is never set (stays zero) — Even-Mansour offset for the L
//!     table and KTop is always the all-zero block.
//!   * X2Polyval's second key is never initialised (stays zero) so the upper
//!     16 bytes of the AXU output are always zero.
//!   * `shiftleft256` is lane-wise (each u64 shifted independently, matching
//!     `_mm256_slli_epi64`).
//!   * XtH's ad_len>=itag_len branch omits the 0xff separator.

use crate::areion::{areion256_backward, areion256_forward};
use crate::gf::{gf256_double, X2PolyvalKey};
use crate::sponge::{keyed_hash, Sponge512};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;
pub const TAG_LEN: usize = 32;
pub const P_OVERHEAD: usize = TAG_LEN; // pubnonce variant
pub const S_OVERHEAD: usize = NONCE_LEN + TAG_LEN; // secret-nonce variant

const L_TABLE_SIZE: usize = 16;

const LABEL_KG_TBC: u8 = 0xf0;
const LABEL_KG_AXU: u8 = 0xf1;
const LABEL_TINY: u8 = 0xf2;
const LABEL_CORE_NO_PARTIAL: u8 = 0xf3;
const LABEL_CORE_WITH_PARTIAL: u8 = 0xf4;

type U256 = [u8; 32];

#[inline]
fn xor256(a: &U256, b: &U256) -> U256 {
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = a[i] ^ b[i];
    }
    o
}

#[inline]
fn xor256_into(a: &mut U256, b: &U256) {
    for i in 0..32 {
        a[i] ^= b[i];
    }
}

/// Lane-wise left shift of a 256-bit value (4 independent u64 lanes).
/// Matches `_mm256_slli_epi64` as used by the reference on x86.
#[inline]
fn shiftleft256_lanewise(a: &U256, bits: u8) -> U256 {
    let mut o = [0u8; 32];
    for lane in 0..4 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&a[8 * lane..8 * lane + 8]);
        let w = u64::from_le_bytes(b) << (bits as u32);
        o[8 * lane..8 * lane + 8].copy_from_slice(&w.to_le_bytes());
    }
    o
}

/// Even-Mansour encrypt:  out = Areion256(in XOR offset) XOR offset
#[inline]
fn em_encrypt(offset: &U256, block: &mut U256) {
    xor256_into(block, offset);
    areion256_forward(block);
    xor256_into(block, offset);
}

#[inline]
fn em_decrypt(offset: &U256, block: &mut U256) {
    xor256_into(block, offset);
    areion256_backward(block);
    xor256_into(block, offset);
}

#[inline]
fn ntz(x: u32) -> usize {
    x.trailing_zeros() as usize
}

// ---------------------------------------------------------------------------
// OCT-256 precomputed state (OCB3-style L table)

struct OctState {
    // tbc_key stays all-zeros in the reference (bug), but we keep the slot
    // for clarity.
    tbc_key: U256,
    lstar: U256,
    #[allow(dead_code)]
    ldollar: U256,
    l: [U256; L_TABLE_SIZE],
    cached_top: U256,
    cached_ktop: U256,
}

impl OctState {
    fn new(_raw_tbc_key: &[u8; 32]) -> Self {
        // Reference bug: raw_tbc_key is never copied to ctx->tbc_key, which
        // was memset-zeroed by the caller. So all EM calls below use a zero
        // offset. We MUST replicate this for KAT compatibility.
        let tbc_key = [0u8; 32];

        let mut lstar = [0u8; 32];
        em_encrypt(&tbc_key, &mut lstar); // = Areion256(0)

        let ldollar = gf256_double(&lstar);
        let mut l = [[0u8; 32]; L_TABLE_SIZE];
        l[0] = gf256_double(&ldollar);
        for i in 1..L_TABLE_SIZE {
            l[i] = gf256_double(&l[i - 1]);
        }

        // Pre-cache KTop for all-zero Top.
        let cached_top = [0u8; 32];
        let mut cached_ktop = [0u8; 32];
        em_encrypt(&tbc_key, &mut cached_ktop);

        OctState {
            tbc_key,
            lstar,
            ldollar,
            l,
            cached_top,
            cached_ktop,
        }
    }

    fn init_offset(&mut self, n: &U256) -> U256 {
        // Bottom = low 6 bits of last byte; Top = N with those bits cleared.
        let bottom = n[31] & 0b00111111;
        let mut top = *n;
        top[31] &= 0b11000000;

        let ktop = if top == self.cached_top {
            self.cached_ktop
        } else {
            let mut k = top;
            em_encrypt(&self.tbc_key, &mut k);
            self.cached_top = top;
            self.cached_ktop = k;
            k
        };

        // RN = KTop << Bottom (lane-wise on x86 — see reference quirk)
        shiftleft256_lanewise(&ktop, bottom)
    }
}

// ---------------------------------------------------------------------------
// OCH context

pub struct OchCtx {
    pubnonce_len: usize,
    secnonce_len: usize,
    // pre-keyed sponge state (crhash_ctx)
    crhash_ctx: Sponge512,
    // X2Polyval key (with reference bug applied)
    axu_key: X2PolyvalKey,
    oct: OctState,
}

impl OchCtx {
    fn new(key: &[u8; 32], pubnonce_len: usize, secnonce_len: usize) -> Self {
        // precompute keyed-hash state
        let crhash_ctx = Sponge512::new_keyed(key);

        // derive subkeys via keyed hash of a single label byte
        let raw_tbc_key = keyed_hash(key, &[LABEL_KG_TBC]);
        let raw_axu_key = keyed_hash(key, &[LABEL_KG_AXU]);

        let oct = OctState::new(&raw_tbc_key);
        let axu_key = X2PolyvalKey::new(&raw_axu_key);

        OchCtx {
            pubnonce_len,
            secnonce_len,
            crhash_ctx,
            axu_key,
            oct,
        }
    }

    pub fn new_p(key: &[u8; 32]) -> Self {
        Self::new(key, 32, 0)
    }
    pub fn new_s(key: &[u8; 32]) -> Self {
        Self::new(key, 0, 32)
    }

    pub fn overhead(&self) -> usize {
        self.secnonce_len + TAG_LEN
    }
}

// ---------------------------------------------------------------------------
// XtH transform (reference-faithful, including missing-0xff quirk)

fn hash_xth_tag(
    crhash_ctx: &Sponge512,
    ad: &[u8],
    pubnonce: &[u8],
    inner_tag: &[u8; 32],
) -> [u8; 32] {
    let itag_len = 32usize;
    let mut ctx = crhash_ctx.clone();

    if ad.len() < itag_len {
        // sponge_in[i] = itag[i]^ad[i] for i<adlen, sponge_in[adlen]^=0xff,
        // rest stays ZERO (ref bug: not itag[i]).
        let mut sponge_in = [0u8; 32];
        for i in 0..ad.len() {
            sponge_in[i] = inner_tag[i] ^ ad[i];
        }
        sponge_in[ad.len()] ^= 0xff;
        ctx.update(&sponge_in);
    } else {
        // sponge_in = itag ^ ad[..32], then ad[32..]. No 0xff separator
        // (ref bug vs. spec comment).
        let mut sponge_in = [0u8; 32];
        for i in 0..32 {
            sponge_in[i] = inner_tag[i] ^ ad[i];
        }
        ctx.update(&sponge_in);
        if ad.len() > 32 {
            ctx.update(&ad[32..]);
        }
    }

    if !pubnonce.is_empty() {
        ctx.update(pubnonce);
    }
    ctx.finalize()
}

// ---------------------------------------------------------------------------
// Tag computation helpers

fn compute_tag_tiny(
    ctx: &OchCtx,
    p: &[u8],
    ad: &[u8],
    pubnonce: &[u8],
    _secret_nonce: &[u8],
) -> [u8; 32] {
    debug_assert!(p.len() <= 31);
    // axu_in = P || LABEL_TINY, zero-padded to 32
    let mut axu_in = [0u8; 32];
    axu_in[..p.len()].copy_from_slice(p);
    axu_in[p.len()] = LABEL_TINY;
    let axu_out = ctx.axu_key.hash(&axu_in);
    hash_xth_tag(&ctx.crhash_ctx, ad, pubnonce, &axu_out)
}

fn compute_tag_no_partial(
    ctx: &OchCtx,
    msg_len: usize,
    ad: &[u8],
    pubnonce: &[u8],
    secret_nonce: &[u8],
    checksum: &[u8; 16],
) -> [u8; 32] {
    let num_blocks = (msg_len >> 5) as u64;
    let mlen: u64 = num_blocks << 1; // is_partial = 0

    let axu_out = if !secret_nonce.is_empty() {
        // sn || checksum(16) || mlen(8) || label, zero-padded to 64
        let snl = secret_nonce.len();
        let unpadded = snl + 16 + 8;
        let mut axu_in = [0u8; 64];
        axu_in[..snl].copy_from_slice(secret_nonce);
        axu_in[snl..snl + 16].copy_from_slice(checksum);
        axu_in[snl + 16..snl + 24].copy_from_slice(&mlen.to_le_bytes());
        axu_in[unpadded] = LABEL_CORE_NO_PARTIAL;
        ctx.axu_key.hash(&axu_in)
    } else {
        // checksum(16) || mlen(8) || label, zero-padded to 32
        let mut axu_in = [0u8; 32];
        axu_in[..16].copy_from_slice(checksum);
        axu_in[16..24].copy_from_slice(&mlen.to_le_bytes());
        axu_in[24] = LABEL_CORE_NO_PARTIAL;
        ctx.axu_key.hash(&axu_in)
    };
    hash_xth_tag(&ctx.crhash_ctx, ad, pubnonce, &axu_out)
}

fn compute_tag_with_partial(
    ctx: &OchCtx,
    msg_len: usize,
    ad: &[u8],
    pubnonce: &[u8],
    secret_nonce: &[u8],
    ext_chk: &[u8],
) -> [u8; 32] {
    let num_blocks = (msg_len >> 5) as u64;
    let mlen: u64 = (num_blocks << 1) | 1;

    let axu_out = if !secret_nonce.is_empty() {
        // sn || ext_chk || mlen || label, padded to 80
        let snl = secret_nonce.len();
        let ecl = ext_chk.len();
        let unpadded = snl + ecl + 8;
        let mut axu_in = [0u8; 80];
        axu_in[..snl].copy_from_slice(secret_nonce);
        axu_in[snl..snl + ecl].copy_from_slice(ext_chk);
        axu_in[snl + ecl..snl + ecl + 8].copy_from_slice(&mlen.to_le_bytes());
        axu_in[unpadded] = LABEL_CORE_WITH_PARTIAL;
        ctx.axu_key.hash(&axu_in)
    } else {
        // ext_chk || mlen || label, padded to 48
        let ecl = ext_chk.len();
        let unpadded = ecl + 8;
        let mut axu_in = [0u8; 48];
        axu_in[..ecl].copy_from_slice(ext_chk);
        axu_in[ecl..ecl + 8].copy_from_slice(&mlen.to_le_bytes());
        axu_in[unpadded] = LABEL_CORE_WITH_PARTIAL;
        ctx.axu_key.hash(&axu_in)
    };
    hash_xth_tag(&ctx.crhash_ctx, ad, pubnonce, &axu_out)
}

// ---------------------------------------------------------------------------
// Seal / Open

/// Generic seal (works for OCH-P with pubnonce=Some, secnonce=None,
/// and OCH-S with the reverse).
///
/// Output layout: [enc_secnonce (if any)] || [enc_msg] || [tag(32)]
/// Returns the ciphertext length on success.
pub fn seal(
    ctx: &mut OchCtx,
    ct: &mut [u8],
    msg: &[u8],
    ad: &[u8],
    pubnonce: &[u8],
    secnonce: &[u8],
) -> Option<usize> {
    let snl = ctx.secnonce_len;
    let pnl = ctx.pubnonce_len;
    if pubnonce.len() != pnl || secnonce.len() != snl {
        return None;
    }
    let ct_len = snl + msg.len() + TAG_LEN;
    if ct.len() < ct_len {
        return None;
    }

    // Derive n0_offset from public nonce only.
    let n0: U256 = if pnl == 32 {
        let mut n = [0u8; 32];
        n.copy_from_slice(pubnonce);
        n
    } else {
        [0u8; 32]
    };
    let mut n0_offset = ctx.oct.init_offset(&n0);

    // OCH-Tiny: |snl + msg_len| < 32
    if snl + msg.len() < 32 {
        // reference only supports snl==0 here
        debug_assert!(snl == 0);
        let tag = compute_tag_tiny(ctx, msg, ad, pubnonce, secnonce);
        // offset = n0_offset ^ L[ntz(1)] ^ Lstar
        let mut off = xor256(&n0_offset, &ctx.oct.l[0]); // ntz(1)=0
        off = xor256(&off, &ctx.oct.lstar);
        let mut pad = tag;
        em_encrypt(&off, &mut pad);
        for i in 0..msg.len() {
            ct[i] = pad[i] ^ msg[i];
        }
        ct[snl + msg.len()..ct_len].copy_from_slice(&tag);
        return Some(ct_len);
    }

    // Checksum is first 128 bits of each plaintext block, XORed.
    let mut checksum = [0u8; 16];
    let mut i: u32 = 1; // block counter

    // Encrypt first block with n0_offset.
    let p1: U256;
    let mut msg_off = 0usize;
    let mut ct_off = 0usize;
    if pnl == 0 && snl == 32 {
        let mut b = [0u8; 32];
        b.copy_from_slice(secnonce);
        p1 = b;
    } else {
        let mut b = [0u8; 32];
        b.copy_from_slice(&msg[..32]);
        msg_off = 32;
        p1 = b;
    }
    for j in 0..16 {
        checksum[j] ^= p1[j];
    }
    n0_offset = xor256(&n0_offset, &ctx.oct.l[0]); // ntz(1)=0
    let mut c1 = p1;
    em_encrypt(&n0_offset, &mut c1);
    i += 1;

    // Derive n_offset from full nonce.
    let nfull: U256 = if pnl == 0 && snl == 32 {
        let mut n = [0u8; 32];
        n.copy_from_slice(secnonce);
        n
    } else {
        let mut n = [0u8; 32];
        n.copy_from_slice(pubnonce);
        n
    };
    let mut n_offset = ctx.oct.init_offset(&nfull);
    n_offset = xor256(&n_offset, &ctx.oct.l[0]);

    // Write first ciphertext block (look-ahead pattern from reference).
    let mut pending_ci = c1;

    // Process full blocks.
    while msg_off + 32 <= msg.len() {
        let mut pi = [0u8; 32];
        pi.copy_from_slice(&msg[msg_off..msg_off + 32]);
        // flush pending
        ct[ct_off..ct_off + 32].copy_from_slice(&pending_ci);
        ct_off += 32;
        msg_off += 32;

        for j in 0..16 {
            checksum[j] ^= pi[j];
        }
        n_offset = xor256(&n_offset, &ctx.oct.l[ntz(i)]);
        let mut ci = pi;
        em_encrypt(&n_offset, &mut ci);
        pending_ci = ci;
        i += 1;
    }

    // No partial block?
    if msg_off == msg.len() {
        ct[ct_off..ct_off + 32].copy_from_slice(&pending_ci);
        ct_off += 32;
        let tag = compute_tag_no_partial(
            ctx,
            msg.len(),
            ad,
            pubnonce,
            secnonce,
            &checksum,
        );
        ct[ct_off..ct_off + 32].copy_from_slice(&tag);
        return Some(ct_len);
    }

    // Partial block.
    let pstar_len = msg.len() - msg_off;
    let mut ext_chk = [0u8; 32];
    ext_chk[..16].copy_from_slice(&checksum);
    let ext_chk_len = if pstar_len > 16 { pstar_len } else { 16 };

    // flush last full ciphertext block
    ct[ct_off..ct_off + 32].copy_from_slice(&pending_ci);
    ct_off += 32;

    // Pad encryption
    n_offset = xor256(&n_offset, &ctx.oct.lstar);
    let mut pad = [0u8; 32];
    em_encrypt(&n_offset, &mut pad);
    for j in 0..pstar_len {
        ext_chk[j] ^= msg[msg_off + j];
        ct[ct_off + j] = pad[j] ^ msg[msg_off + j];
    }
    ct_off += pstar_len;

    let tag = compute_tag_with_partial(
        ctx,
        msg.len(),
        ad,
        pubnonce,
        secnonce,
        &ext_chk[..ext_chk_len],
    );
    ct[ct_off..ct_off + 32].copy_from_slice(&tag);
    Some(ct_len)
}

/// Generic open. On success, plaintext is written to `msg` and (for OCH-S)
/// the recovered secret nonce to `secnonce_out`. Returns the plaintext length.
/// On auth failure, returns None and **does not** zero the output buffer
/// (caller must discard it).
pub fn open(
    ctx: &mut OchCtx,
    msg: &mut [u8],
    secnonce_out: &mut [u8],
    ct: &[u8],
    ad: &[u8],
    pubnonce: &[u8],
) -> Option<usize> {
    let snl = ctx.secnonce_len;
    let pnl = ctx.pubnonce_len;
    if pubnonce.len() != pnl || secnonce_out.len() != snl {
        return None;
    }
    if ct.len() < snl + TAG_LEN {
        return None;
    }
    let ctcore_len = ct.len() - TAG_LEN;
    let msg_len = ctcore_len - snl;
    if msg.len() < msg_len {
        return None;
    }
    let given_tag: &[u8; 32] = ct[ctcore_len..].try_into().unwrap();

    let n0: U256 = if pnl == 32 {
        let mut n = [0u8; 32];
        n.copy_from_slice(pubnonce);
        n
    } else {
        [0u8; 32]
    };
    let mut n0_offset = ctx.oct.init_offset(&n0);

    // OCH-Tiny
    if snl + msg_len < 32 {
        debug_assert!(snl == 0);
        let mut off = xor256(&n0_offset, &ctx.oct.l[0]);
        off = xor256(&off, &ctx.oct.lstar);
        let mut pad = *given_tag;
        em_encrypt(&off, &mut pad);
        for j in 0..msg_len {
            msg[j] = pad[j] ^ ct[j];
        }
        let expected = compute_tag_tiny(ctx, &msg[..msg_len], ad, pubnonce, &[]);
        return if ct_eq(&expected, given_tag) {
            Some(msg_len)
        } else {
            None
        };
    }

    let mut checksum = [0u8; 16];
    let mut i: u32 = 1;
    let mut ct_off = 0usize;
    let mut msg_off = 0usize;

    // Decrypt first block
    let mut c1 = [0u8; 32];
    c1.copy_from_slice(&ct[..32]);
    ct_off += 32;
    n0_offset = xor256(&n0_offset, &ctx.oct.l[0]);
    let mut p1 = c1;
    em_decrypt(&n0_offset, &mut p1);
    for j in 0..16 {
        checksum[j] ^= p1[j];
    }
    i += 1;

    let mut sn_buf = [0u8; 32];
    if pnl == 0 && snl == 32 {
        sn_buf.copy_from_slice(&p1);
        secnonce_out.copy_from_slice(&sn_buf);
    } else {
        msg[..32].copy_from_slice(&p1);
        msg_off = 32;
    }
    let secret_nonce: &[u8] = if snl == 32 { &sn_buf } else { &[] };

    let nfull: U256 = if pnl == 0 && snl == 32 {
        sn_buf
    } else {
        let mut n = [0u8; 32];
        n.copy_from_slice(pubnonce);
        n
    };
    let mut n_offset = ctx.oct.init_offset(&nfull);
    n_offset = xor256(&n_offset, &ctx.oct.l[0]);

    while ct_off + 32 <= ctcore_len {
        let mut ci = [0u8; 32];
        ci.copy_from_slice(&ct[ct_off..ct_off + 32]);
        ct_off += 32;
        n_offset = xor256(&n_offset, &ctx.oct.l[ntz(i)]);
        let mut pi = ci;
        em_decrypt(&n_offset, &mut pi);
        for j in 0..16 {
            checksum[j] ^= pi[j];
        }
        i += 1;
        msg[msg_off..msg_off + 32].copy_from_slice(&pi);
        msg_off += 32;
    }

    if ct_off == ctcore_len {
        let expected = compute_tag_no_partial(
            ctx,
            msg_len,
            ad,
            pubnonce,
            secret_nonce,
            &checksum,
        );
        return if ct_eq(&expected, given_tag) {
            Some(msg_len)
        } else {
            None
        };
    }

    // Partial
    let pstar_len = ctcore_len - ct_off;
    let mut ext_chk = [0u8; 32];
    ext_chk[..16].copy_from_slice(&checksum);
    let ext_chk_len = if pstar_len > 16 { pstar_len } else { 16 };

    n_offset = xor256(&n_offset, &ctx.oct.lstar);
    let mut pad = [0u8; 32];
    em_encrypt(&n_offset, &mut pad);
    for j in 0..pstar_len {
        msg[msg_off + j] = pad[j] ^ ct[ct_off + j];
        ext_chk[j] ^= msg[msg_off + j];
    }

    let expected = compute_tag_with_partial(
        ctx,
        msg_len,
        ad,
        pubnonce,
        secret_nonce,
        &ext_chk[..ext_chk_len],
    );
    if ct_eq(&expected, given_tag) {
        Some(msg_len)
    } else {
        None
    }
}

#[inline]
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut d = 0u8;
    for i in 0..32 {
        d |= a[i] ^ b[i];
    }
    d == 0
}
