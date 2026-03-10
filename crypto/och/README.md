# OCH authenticated encryption for OpenSSL

Rust-backed implementation of the **OCH** committing AEAD mode from

> Menda, Bellare, Hoang, Len, Ristenpart,
> *"OCH: Fast, Committing AEAD from a Tweakable Block Cipher"*,
> ACM CCS 2025 (Distinguished Paper) / [eprint 2026/439].

OCH is an OCB3-style single-pass AEAD built over a 256-bit permutation.
This directory instantiates it with **Areion-256/512** [eprint 2023/794],
a permutation constructed from AES round functions (so AES-NI accelerates
it directly). The design is nonce-misuse-resistant and *key-committing*
(CMT-4), unlike GCM, OCB, or ChaCha20-Poly1305.

Two variants are provided:

| Variant | Overhead | Nonce | Use case |
|---------|----------|-------|----------|
| **OCH-P** | +32 B | 32 B public | drop-in AEAD replacement |
| **OCH-S** | +64 B | 32 B *secret* | nonce-hiding (e.g. encrypted counters) |

## Layout

```
crypto/och/
├── rust/               # Rust crate — Areion, GF(2^128/256), Sponge, OCH
│   ├── src/aes_soft.rs # constant-time software AES round functions
│   ├── src/areion.rs   # Areion-256/512 (AES-NI + software fallback)
│   ├── src/gf.rs       # GF(2^256) doubling, Polyval dot, X2Polyval
│   ├── src/sponge.rs   # Areion512-based sponge hash
│   ├── src/och.rs      # OCH seal/open core
│   ├── src/asm.rs      # FFI bindings to perlasm kernels (x86_64)
│   ├── src/lib.rs      # C FFI exports + KAT tests
│   └── build.rs        # perlasm codegen + link (sets cfg(och_asm))
├── asm/
│   ├── areion-x86_64.pl# OpenSSL-style perlasm: 4× Areion + bulk EM loop
│   └── asm_test.c      # ASM-vs-Rust cross-check harness
├── och.h               # C API (links against liboch.a)
├── bench.c             # OCH vs OpenSSL GCM/OCB/CTR benchmark
├── build.info          # OpenSSL build stanza (see NOTES.md for wiring)
├── Makefile            # standalone build + test + bench + valgrind
├── tests/ffi_test.c    # C-side seal/open sweep for valgrind
├── BENCHMARKS.md       # measured results: Rust vs ASM vs OpenSSL
└── NOTES.md            # design notes, deviations from CLAUDE.md, ref-bugs
```

## Build and test

Requires a Rust toolchain and system `libcrypto` (OpenSSL ≥ 3.0).

```sh
make            # builds rust/target/release/liboch.a + bench + test binaries
make test       # 11 tests: Areion KATs, Polyval RFC 8452, OCH-P/S KATs,
                #   multi-length roundtrip, ASM-vs-Rust cross-check
make bench      # throughput sweep vs AES-256-GCM / AES-128-OCB / AES-256-CTR
make valgrind   # leak + memory-error check of full C-FFI seal/open path
```

The Rust build defaults to `RUSTFLAGS="-C target-feature=+aes,+sse2,+ssse3"`
for the AES-NI code path. Without `+aes` the software fallback is used (and
tests still pass against the same KAT vectors). Set `OCH_NO_ASM=1` to
disable the perlasm kernels and use the pure-Rust path.

## C API

```c
#include "och.h"

OCH_CTX ctx = OCH_areion_p_init(key32);     /* or _s_init for nonce-hiding */
ptrdiff_t ctlen = OCH_areion_seal(ctx, ct, sizeof ct,
                                  msg, msglen, ad, adlen,
                                  pubnonce, 32, /*secnonce*/NULL, 0);
ptrdiff_t ptlen = OCH_areion_open(ctx, pt, sizeof pt, /*sn_out*/NULL, 0,
                                  ct, ctlen, ad, adlen, pubnonce, 32);
OCH_areion_free(ctx);
```

`open` returns `-1` on authentication failure; the caller must discard any
partial plaintext in that case.

## Performance

Seal throughput, **Intel Xeon @ 2.80 GHz**, AES-NI enabled, single thread.
OCH uses the bulk-loop perlasm kernel; GCM/OCB/CTR are system OpenSSL
3.0.13's hand-tuned assembly. Full tables and Rust-vs-ASM comparison in
[BENCHMARKS.md](BENCHMARKS.md).

| Bytes | OCH-P (cpb) | OCH-S (cpb) | GCM-256 | OCB-128 | CTR-256 |
|------:|------:|------:|------:|------:|------:|
|   1 K |  6.96 | 12.49 |  1.62 |  1.31 |  1.08 |
|   4 K |  2.39 |  3.76 |  0.96 |  0.73 |  0.83 |
|  16 K |  1.23 |  1.59 |  0.80 |  0.58 |  0.76 |
|  64 K |  0.94 |  1.06 |  0.76 |  0.54 |  0.75 |
|   1 M |  **0.87** |  **0.90** |  0.76 |  0.54 |  0.75 |

At 1 MiB: **OCH-P = 3079 MB/s**, GCM-256 = 3518 MB/s, OCB-128 = 4935 MB/s,
CTR-256 = 3543 MB/s.

The raw Areion-256 permutation clocks at **~72 cycles / 32 B block** single-
block (latency-bound on the 2-deep `aesenc` chain), **~0.86 cpb** with 4-way
interleaving. The bulk ASM kernel achieves essentially zero mode overhead at
1 Mi — the seal rate matches the raw permutation rate because offset/checksum
work is fully hidden behind AES-NI latency.

OCB-128 remains ~1.6× ahead: it processes 128-bit blocks (half Areion's
state) and needs no separate AXU MAC pass. Short-message cost is dominated
by the fixed XtH tag pass (≈3 Areion-512 calls) — inherent to committing
AEAD, not the implementation.

[eprint 2026/439]: https://eprint.iacr.org/2026/439
[eprint 2023/794]: https://eprint.iacr.org/2023/794
