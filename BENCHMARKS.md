# AES-NI Performance: VAES CTR Mode Optimization

## Test Environment

- CPU: Intel Xeon @ 2.10GHz (Sapphire Rapids class)
- Features: AES-NI, AVX-512F/DQ/BW/VL, VAES, VPCLMULQDQ
- OpenSSL: 4.0.0-dev, linux-x86_64, gcc -O3
- Benchmark: `openssl speed -evp aes-<mode>` (3 seconds per data point)

## Baseline (before changes)

| Cipher       | 16 B   | 64 B    | 256 B   | 1024 B   | 8192 B    | 16384 B   |
|--------------|--------|---------|---------|----------|-----------|-----------|
| AES-128-CTR  | 851.3k | 2701.1k | 5293.0k | 7148.4k  |  7784.0k  |  7831.2k  |
| AES-128-OCB  |  56.7k |  221.8k |  824.3k | 2217.3k  |  5938.8k  |  6948.2k  |
| AES-128-GCM  | 111.0k |  440.6k | 1643.5k | 4441.0k  | 11120.7k  | 12526.4k  |
| AES-192-CTR  | 780.7k | 2512.9k | 4907.0k | 6282.6k  |  6840.0k  |  6803.8k  |
| AES-256-CTR  | 705.6k | 2261.6k | 4498.8k | 5532.2k  |  5944.5k  |  5940.3k  |

Numbers are in 1000s of bytes/second.

### Root cause of CTR/OCB underperformance

- **GCM** dispatches to `ossl_aes_gcm_encrypt_avx512` (aes-gcm-avx512.pl)
  which uses VAES on ZMM registers — 16 blocks per iteration.
- **CTR** dispatches to `aesni_ctr32_encrypt_blocks` (aesni-x86_64.pl)
  which uses AES-NI on XMM registers — 8 blocks per iteration.
  4× narrower registers, 2× shallower unroll.
- **OCB** dispatches to `aesni_ocb_encrypt` (aesni-x86_64.pl)
  which uses AES-NI on XMM — only 6 blocks per iteration
  (register-pressure limited by the 6 offset registers).

CTR and OCB have no VAES code path in the tree. XTS, GCM, and CFB already do.

## Change: VAES CTR kernel

Added `crypto/aes/asm/aes-ctr-avx512.pl`:

- `ossl_aes_ctr32_encrypt_blocks_vaes()` — drop-in `ctr128_f` replacement.
- 16 blocks/iteration main loop on 4 ZMM registers; 4-block and 1-block tails.
- All 15 round keys pre-broadcast into `zmm17..zmm31` (EVEX-only, no callee save).
- 32-bit BE counter tracked in byte-swapped form so `vpaddd` can increment it.
  The caller (`CRYPTO_ctr128_encrypt_ctr32`) already guarantees no wrap.
- `ossl_aes_ctr32_vaes_eligible()` — runtime check for AVX512F/DQ/BW + VAES.

Dispatch: `providers/implementations/ciphers/cipher_aes_hw_aesni.inc` selects
the VAES path at key-init time on x86-64 when eligible.

## Results (after changes)

| Cipher       | 16 B   | 64 B    | 256 B   | 1024 B   | 8192 B    | 16384 B   | vs base |
|--------------|--------|---------|---------|----------|-----------|-----------|---------|
| AES-128-CTR  | 786.6k | 2969.4k | 8579.0k | 14531.8k | 17642.0k  | 17888.5k  | **2.28×** |
| AES-192-CTR  | 717.9k | 2763.5k | 8300.8k | 12548.9k | 14780.5k  | 14959.9k  | **2.20×** |
| AES-256-CTR  | 648.2k | 2483.8k | 7572.8k | 11022.8k | 12628.7k  | 12684.5k  | **2.14×** |
| AES-128-GCM  |   —    |    —    |    —    |    —     |    —      | 12603.7k  | unchanged |
| AES-128-OCB  |   —    |    —    |    —    |    —     |    —      |  6968.9k  | unchanged |

The ~8% regression at 16 B is the cost of broadcasting 15 round keys into ZMM
for a single-block payload. Crossover to net gain is at 64 B. This matches the
behaviour of the existing XTS and CFB AVX-512 implementations which make the
same trade-off.

AES-128-CTR now runs 43% faster than AES-128-GCM at 16 KiB, which is the
expected margin since GCM = CTR + GHASH.

## Correctness

- `30-test_evp.t`: 111 tests pass
- Differential test vs. `aesni_ctr32_encrypt_blocks` (reference):
  28 sizes × 3 key lengths × 3 IVs (including counter values near 2³²) = 252 cases, all identical
- VAES enc → legacy dec round-trip: pass
