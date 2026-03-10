# Areion-OCH — Benchmark Results

Measured seal throughput (encrypt + authenticate) for the Areion-OCH AEAD
against OpenSSL EVP ciphers.

- **CPU**: Intel Xeon @ 2.80 GHz (Cascade Lake class)
- **OpenSSL**: 3.0.13 (system `libcrypto`)
- **Build**: `rustc` release, `-C target-feature=+aes,+sse2,+ssse3`; C linked with `-O3 -march=native`
- **Metric**: cycles-per-byte via `rdtsc`, MB/s via `CLOCK_MONOTONIC`
- **Driver**: `crypto/och/bench.c` — timed loop, min 0.25 s + 64 iters per size

All ciphers were measured in the same `./och_bench` invocation to control
for machine noise; numbers are stable within ~2% across runs.

---

## Raw Areion-256 permutation

One 256-bit Areion permutation = 10 rounds, 30 AES-NI ops on one block
(3 per round). The 2-deep `aesenc` chain for the `x1` lane bounds single-
block throughput by latency (~8 cyc/round on Skylake-era cores).

| Path | cyc/block | cyc/byte | Speedup |
|---|---|---|---|
| Rust intrinsic, scalar | 65.5 | 2.05 | 1.00× |
| Perl-asm, 4-way interleaved kernel | 78.0 / 4 | **0.61** | 3.36× |

The ASM kernel achieves near the issue-port limit for `aesenc` (~1 per
cycle on Cascade Lake), and the seal rate below matches it — i.e.
essentially zero mode overhead at large sizes.

---

## Seal at 1 MiB — full cipher set

Grouped by key size for direct comparison. Areion-OCH uses a 256-bit
key; compare against the AES-256 column for the fairest apples-to-apples.

### 128-bit keys

| Cipher | cpb | MB/s |
|---|---:|---:|
| AES-128-GCM (OpenSSL) | 0.47 | 5646 |
| AES-128-OCB (OpenSSL) | 0.32 | 8440 |
| AES-128-CTR (OpenSSL, unauth) | 0.30 | 8902 |

### 256-bit keys

| Cipher | cpb | MB/s |
|---|---:|---:|
| **Areion-OCH-P** | **0.59** | **4533** |
| **Areion-OCH-S** | **0.60** | **4456** |
| AES-256-GCM (OpenSSL) | 0.56 | 4756 |
| AES-256-CTR (OpenSSL, unauth) | 0.39 | 6830 |

**Key observation**: OCH-P at 0.59 cpb is **within 5 %** of AES-256-GCM
(0.56 cpb), and within 2× of unauthenticated AES-256-CTR — while providing
key-commitment (CMT-4), which GCM, OCB, and ChaCha20-Poly1305 do not.

---

## OCH-P / OCH-S seal — per-size sweep, three builds

**Rust** — pure Rust intrinsics, scalar EM loop, `-C target-feature=+aes`.
**ASM v1** — per-4-block FFI: Rust computes offsets + checksum, dispatches to `och_asm_em_enc_x4` every 4 blocks.
**ASM v2** — full bulk-loop kernel: one FFI call per message, offset chain (`bsf`-indexed L-table XOR), checksum, and 4-way EM entirely in ASM.

Comparison columns are grouped by key size.

### OCH-P (public-nonce) — cycles/byte

| Size | Rust | ASM v1 | **ASM v2** | GCM-128 | OCB-128 | CTR-128 | GCM-256 | CTR-256 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 16 | 440.0 | 392.6 | **323.6** | 40.4 | 44.0 | 16.5 | 41.0 | 17.3 |
| 64 | 114.5 | 97.8 | **79.3** | 11.5 | 11.7 | 4.5 | 11.5 | 4.6 |
| 256 | 28.4 | 25.4 | **20.9** | 3.24 | 3.09 | 1.36 | 3.31 | 1.46 |
| 1 Ki | 7.56 | 7.20 | **5.56** | 1.24 | 1.01 | 0.55 | 1.30 | 0.65 |
| 4 Ki | 2.60 | 2.59 | **1.81** | 0.66 | 0.49 | 0.36 | 0.75 | 0.45 |
| 16 Ki | 1.34 | 1.45 | **0.88** | 0.51 | 0.35 | 0.30 | 0.59 | 0.40 |
| 64 Ki | 1.02 | 1.19 | **0.65** | 0.47 | 0.32 | 0.29 | 0.55 | 0.38 |
| 1 Mi | 0.94 | 1.25 | **0.59** | 0.47 | 0.32 | 0.30 | 0.56 | 0.39 |

### OCH-S (nonce-hiding) — cycles/byte

| Size | Rust | ASM v1 | **ASM v2** | GCM-128 | OCB-128 | CTR-128 | GCM-256 | CTR-256 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 Ki | 4.10 | 3.99 | **2.93** | 0.66 | 0.49 | 0.36 | 0.75 | 0.45 |
| 16 Ki | 1.74 | 1.81 | **1.17** | 0.51 | 0.35 | 0.30 | 0.59 | 0.40 |
| 64 Ki | 1.26 | 1.30 | **0.73** | 0.47 | 0.32 | 0.29 | 0.55 | 0.38 |
| 1 Mi | 0.98 | 1.26 | **0.60** | 0.47 | 0.32 | 0.30 | 0.56 | 0.39 |

---

## vs the paper

[eprint 2026/439] reports peak seal speed on Intel Raptor Lake for four
schemes. Below: paper numbers alongside our own measurements on an older
Cascade Lake Xeon (same harness — `./och_bench`).

| Cipher | Paper (Raptor Lake) | This impl (Cascade Lake) | Ratio¹ |
|---|---:|---:|---:|
| **Areion-OCH** | 0.62 cpb | **0.59 cpb** | 0.95× |
| AES-128-GCM | 0.38 cpb | 0.47 cpb | 1.24× |
| ChaCha20-Poly1305 | 1.63 cpb | — ² | — |
| TurboSHAKE128-Wrap | 3.52 cpb | — ² | — |
| **OCH / GCM-128** | **1.63×** | **1.26×** | |

¹ our cpb ÷ paper cpb — values >1 mean our older core is slower.
² not in this bench harness; OpenSSL ships ChaCha20-Poly1305 but TurboSHAKE-Wrap is not in any OpenSSL release.

Our OCH is **faster** than the paper's peak despite running on an older
core — the bulk-loop kernel (offset chain + checksum fully hoisted into
ASM) is more aggressive than the authors' ~1 kLOC reference C and hides
all mode overhead behind AES-NI latency. Raptor Lake's hardware
advantage (lower AES-NI latency, VAES 256-bit lanes) shows up in the
GCM number — our core pays ~24 % more for GCM — but not in OCH,
tightening the OCH/GCM ratio from 1.63× to 1.26×.

---

## Analysis

**ASM v1 is a net loss vs pure Rust.** The 4-way kernel (0.61 cpb) is
itself fine, but each 4-block stride pays ~30 cycles of FFI overhead
(call/ret + register spills for the `&mut U256` offset, checksum, and
counter arguments) plus a 128-byte offset-buffer fill. At ~0.3 cpb of
overhead on a ~0.6 cpb kernel, the result (1.25 cpb @ 1 Mi) loses badly
to LLVM's fully-inlined scalar loop (0.94 cpb), which the compiler
pipelines across iterations on its own.

**ASM v2 recovers the gain.** Hoisting the entire inner loop — `bsf`
offset chain, 16-byte checksum XOR, src load, 10-round 4-way Areion,
dst store — into one kernel reduces FFI to *one* call per message. At
1 Mi the overhead vanishes: OCH-P achieves **0.59 cpb**, matching the
raw 4-way permutation rate (0.61 cpb). The offset/checksum work is
fully hidden behind AES-NI latency.

**vs OpenSSL AEADs.** At 1 Mi, OCH-P is within 5 % of AES-256-GCM and
1.5× slower than unauthenticated AES-256-CTR. Against 128-bit ciphers
OCH pays the expected cost: OCB-128 is 1.8× faster (128-bit blocks,
single-key, no separate AXU MAC pass), and CTR-128 is 2.0× faster
(unauthenticated). OCH's fixed per-message overhead (sponge-based key
schedule, Polyval-derived tag) dominates at small sizes; this is
inherent to the design, not the implementation.

---

## Reproducing

```sh
cd crypto/och
make                 # builds liboch.a (ASM enabled) + och_bench
./och_bench

OCH_NO_ASM=1 make    # pure-Rust build for comparison
./och_bench
```
