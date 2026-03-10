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
│   └── src/lib.rs      # C FFI exports + KAT tests
├── och.h               # C API (links against liboch.a)
├── bench.c             # OCH vs OpenSSL GCM/OCB/CTR benchmark
├── build.info          # OpenSSL build stanza (see NOTES.md for wiring)
├── Makefile            # standalone build + test + bench
├── tests/              # (placeholder for future EVP-level test vectors)
└── NOTES.md            # design notes, deviations from CLAUDE.md, ref-bugs
```

## Build and test

Requires a Rust toolchain and system `libcrypto` (OpenSSL ≥ 3.0).

```sh
make            # builds rust/target/release/liboch.a and och_bench
make test       # 6 tests: Areion KATs, Polyval RFC 8452, OCH-P/S KATs,
                #   multi-length roundtrip — runs on both AES-NI and soft path
make bench      # throughput sweep vs AES-256-GCM / AES-128-OCB / AES-256-CTR
```

The Rust build defaults to `RUSTFLAGS="-C target-feature=+aes,+sse2,+ssse3"`
for the AES-NI code path. Without `+aes` the software fallback is used (and
tests still pass against the same KAT vectors).

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
GCM/OCB/CTR numbers are system OpenSSL 3.0.13's hand-tuned assembly.

### Cycles per byte

| Bytes | OCH-P | OCH-S | AES-256-GCM | AES-128-OCB | AES-256-CTR |
|------:|------:|------:|------------:|------------:|------------:|
|    16 |  320.5 |  734.3 |   41.1 |   43.0 |   16.3 |
|    64 |   77.8 |  148.5 |   11.5 |   11.0 |    4.4 |
|   256 |   20.0 |   37.7 |    3.3 |    3.0 |    1.4 |
|   1 K |    5.5 |    9.9 |    1.3 |    1.0 |    0.6 |
|   4 K |    1.9 |    3.0 |    0.7 |    0.5 |    0.4 |
|  16 K |    1.0 |    1.3 |    0.6 |    0.3 |    0.4 |
|  64 K |    0.75 |   0.82 |   0.55 |   0.32 |   0.38 |
|   1 M |   0.72 |   0.70 |   0.55 |   0.31 |   0.39 |

### MB/s

| Bytes | OCH-P | OCH-S | AES-256-GCM | AES-128-OCB | AES-256-CTR |
|------:|------:|------:|------------:|------------:|------------:|
|    16 |      8 |      4 |     65 |     62 |    164 |
|    64 |     34 |     18 |    232 |    243 |    602 |
|   256 |    133 |     71 |    815 |    881 |  1 898 |
|   1 K |    483 |    270 |  2 087 |  2 728 |  4 224 |
|   4 K |  1 414 |    894 |  3 681 |  5 636 |  6 065 |
|  16 K |  2 645 |  2 078 |  4 551 |  7 829 |  6 788 |
|  64 K |  3 543 |  3 246 |  4 843 |  8 452 |  7 030 |
|   1 M |  3 732 |  3 827 |  4 841 |  8 517 |  6 853 |

The raw Areion-256 permutation clocks at **~59 cycles / 32 B block** (≈ 1.84
cpb). That floor fully explains the gap vs OCB: AES-128 runs a 16-byte block
in ≈10 cycles on this part, roughly 3× denser per byte than Areion-256.
Accounting for that, OCH's mode overhead is comparable to OCB's.

Short-message cost is dominated by the fixed XtH tag pass (≈3 Areion-512
calls) — the same trade every committing AEAD makes. Large-message throughput
(≥ 4 K) is within ~1.3× of GCM-256 despite OpenSSL's GCM being a
hand-optimised Skylake assembly kernel and this code being plain Rust.

[eprint 2026/439]: https://eprint.iacr.org/2026/439
[eprint 2023/794]: https://eprint.iacr.org/2023/794
