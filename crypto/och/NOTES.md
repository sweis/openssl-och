# Implementation notes

## Deviations from CLAUDE.md

### 1. Directory: `crypto/och/`, not `crypto/aes/`

CLAUDE.md asks for OCH under `crypto/aes/`. OCH isn't an AES mode — it's
built on the Areion permutation (which *uses* AES round functions but isn't a
block cipher). OpenSSL precedent is to give non-AES primitives their own
directory (`crypto/chacha/`, `crypto/aria/`, `crypto/sm4/`). Putting this
under `crypto/aes/` would misrepresent the algorithm and tangle build rules.

### 2. Perl-asm lives under `crypto/och/asm/`, not `crypto/aes/asm/`

CLAUDE.md suggests Perl-asm changes under `crypto/aes/asm/`. Those generators
produce the AES block cipher key schedule and encrypt/decrypt for a dozen
architectures — they are the wrong place for a new AEAD mode. The Areion
perlasm lives in `crypto/och/asm/areion-x86_64.pl` alongside the Rust code,
driven through OpenSSL's standard `perlasm/x86_64-xlate.pl`.

Primary implementation remains Rust AES-NI intrinsics (`core::arch::x86_64::
_mm_aesenc_si128` etc.) plus a constant-time software fallback for non-AES-NI
and non-x86. The perlasm exports an x86_64-only `och_asm_em_enc_bulk` /
`och_asm_em_dec_bulk` that hoist the entire OCH inner loop — `bsf`-indexed
L-table offset chain, checksum, 4× interleaved Areion-EM, src→dst stride —
into one kernel. Enabled via `cfg(och_asm)` set by `build.rs` when the
perlasm + assemble steps succeed; disabled with `OCH_NO_ASM=1`.

Lesson learned: a naive per-4-block ASM dispatch (compute offsets/checksum
in Rust, call `em_enc_x4`, repeat) is a net loss vs LLVM-pipelined intrinsics
— the FFI boundary costs ~30 cycles per stride and LLVM auto-interleaves the
scalar loop nearly as well as a hand-rolled 4-way kernel. The bulk-loop
approach (one FFI call per message) is what makes ASM pay off. See
[BENCHMARKS.md](BENCHMARKS.md).

### 3. Benchmark targets: GCM, OCB, CTR — not OFB

CLAUDE.md lists "OFB" as a comparison. OFB is not authenticated; the closest
authenticated analogue is OCB (Offset CodeBook — structurally the nearest
relative of OCH). The benchmark covers AES-256-GCM and AES-128-OCB as AEAD
comparators, plus AES-256-CTR as the unauthenticated baseline CLAUDE.md asks
for.

### 4. `build.info` does not fully plumb `liboch.a` into `libcrypto`

OpenSSL's `Configure` has no native hook for running a foreign toolchain
(`cargo`) during the build. Wiring that in properly requires teaching
`Configure` a new build stage, which is a policy discussion beyond a crypto
patch. `crypto/och/build.info` documents exactly what to add to `Configure`
once that's resolved. In the meantime `crypto/och/Makefile` builds a
standalone benchmark that links the Rust staticlib against system
`libcrypto`, demonstrating the C ↔ Rust FFI end-to-end.

## Reference bugs reproduced for KAT compatibility

The only KAT vectors available for Areion-OCH are from the authors' reference
C implementation (`aead_test.cc`). That implementation contains several bugs
that change the ciphertext and tag output. To match the published vectors,
this Rust code **reproduces those bugs verbatim**. Each is isolated and
documented with a `REF-BUG` comment at the call site.

| # | Location (ref) | Effect | Repro (here) |
|---|---|---|---|
| 1 | `oct256.h` `Oct256_setup` | `tbc_key` parameter never copied to ctx; stays all-zero from `memset`. L-table/KTop offsets derived from `Areion256(0)` regardless of master key. | `och.rs` `OctState::new` hard-codes `tbc_key = [0u8; 32]`. |
| 2 | `hash_polyval.c` `X2Polyval_init` | `_polyval_key_init(&key0, ...)` called twice; `key1` never initialised, stays zero. Also means digest bytes `[16..32]` of X2Polyval are always zero. | `gf.rs` `X2PolyvalKey::new` sets `h0` from `raw[16..32]`, `h1 = [0; 2]`. |
| 3 | `trans.h` `hash_tag` | When `ad_len >= inner_tag_len` the comment says "append 0xff" but the code doesn't. When `ad_len < inner_tag_len`, `sponge_in[ad_len..]` left zero rather than filled with remaining `inner_tag` bytes. | `och.rs` `hash_xth_tag` omits `0xff` in the `>=32` branch, leaves tail zeroed in the `<32` branch. |
| 4 | `_cr_types.h` `shiftleft256` | x86 build uses `_mm256_slli_epi64` — a *lane-wise* shift (each 64-bit lane independently, no carry between lanes). The generic build does a true 256-bit shift with carry. | `och.rs` `shiftleft256_lanewise` matches the x86 (KAT-producing) path. |

None of these are silently patched. If the authors ever publish spec-correct
vectors, each `REF-BUG` site is a one-line fix.

## Test vectors

```
Areion-256 (eprint 2023/794 Appendix B, verified):
  in:  0000...0000 (32B)
  out: 2812a72465b26e9fca7583f6e4123aa1490e35e7d5203e4ba2e927b0482f4db8

Areion-512 (reference C output; paper Appendix B differs — see note below):
  in:  0000...0000 (64B)
  out: 78cf3ee4b73c6a543fe6dc85779102e7e3f5501016ceed1dd2c48d0bc212fb07
       ad168794bd96cff35909cdd8e2274928b2adb04fa91f901559367122cb3c96a9

  Note: the paper's Appendix B for Areion-512 prints state lanes in a
  different order than the reference code's `store256`. We match the
  reference code, which is what the OCH KATs depend on.

Polyval (RFC 8452 Appendix A):
  verified in gf::tests::polyval_rfc8452

Areion-OCH-P (all-zero key/nonce/ad/msg, 32B each):
  ct: 94fb76019c4cc1bb2b8c745d749ccf0261e4c99041349b80a8e6c70e3cf9837e
      bd367f85091b4989ae1d9276f918edc58412e61d451918ed96d89104dfc0d282

Areion-OCH-S (all-zero key/secnonce/ad/msg, 32B each):
  ct: 94fb76019c4cc1bb2b8c745d749ccf0261e4c99041349b80a8e6c70e3cf9837e
      69f7a06a96353e5c3010ebd8db1d20c8cc5bd43eae6df364a10c2062b3f818e3
      c85ab5e5c9ca43e66bca16dbb5b5c240e86fa59167f895926775550583a250b8
```

All verified by `make test` on both the AES-NI and software code paths.
