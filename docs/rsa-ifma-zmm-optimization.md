# RSA IFMA ZMM Optimization

Two commits adding 512-bit (ZMM) AVX-512 IFMA kernels for the dual modular
exponentiation used by RSA-CRT private-key operations.

## Results

| Benchmark | Before (YMM) | After (ZMM) | Speedup |
|-----------|-------------:|------------:|--------:|
| `rsa2048 sign` | 3052 /s | 3163 /s | **+3.6%** |
| `rsa2048 decrypt` | 2988 /s | 3072 /s | +2.8% |
| `rsa4096 sign` | 529 /s | 552 /s | **+4.3%** |
| `rsa4096 decrypt` | 513 /s | 541 /s | +5.4% |

Verify/encrypt unaffected (public-key path uses small exponent, different code).
All 133+ tests pass (`test_rsa`, `test_bn`, `test_exp`, `test_evp`, `test_rsapss`,
`test_rsaoaep`).

## Background

RSA-CRT splits one n-bit private-key operation into two n/2-bit modular
exponentiations that run in parallel. OpenSSL's existing IFMA kernel
(`rsaz-*k-avx512.pl`, Intel 2020) stores each number in 52-bit redundant
radix across YMM lanes and computes both exponentiations together in one
function. The inner loop is an Almost Montgomery Multiplication: 20 (or 40)
iterations of broadcast, IFMA multiply-accumulate, shift, extract.

## Why ZMM helps

On Sapphire Rapids, YMM `vpmadd52` dispatches to **ports 0, 1, and 5** at
~3/cycle. ZMM `vpmadd52` uses a narrower port set at ~2/cycle.

The YMM dual kernel runs both numbers through the same loop, doubling the
IFMA op count. Those ops spread across all three ports — including port 5,
which also handles every `valignq` (the 64-bit lane shift) and
`vpbroadcastq`. Port 5 saturates.

ZMM holds twice as many lanes per register, so the same work needs half as
many IFMA instructions and half as many shifts. More importantly, ZMM IFMA
pulls off port 5 entirely, leaving it free for the shifts.

### Cycle-level: `amm52x40_x2` (RSA-4096 primes)

| | IFMA ops | `valignq` | Port-5 total | cyc/iter |
|---|---:|---:|---:|---:|
| YMM (10 regs × 2) | 80 | 20 | ~27 IFMA + 20 shift = **47** | 47.9 |
| ZMM (5 regs × 2) | 40 | 10 | 10 shift + ~4 bcast = 14 | 43.7 |

The ZMM loop doesn't reach the 19-cycle dependency-chain floor because the
~500-byte loop body overruns the µop cache; but halving the instruction
count still nets a win. The single-number `x1` kernel at 253 bytes does hit
the floor (~24 cyc/iter).

## Implementation notes

### 1024-bit (commit `079efba`)

20 digits → 3 ZMM (24 lanes, top 4 padding). Padding lanes must stay zero:
the per-iteration `valignq $1` shifts lane 20 into lane 19, so any garbage
there would corrupt the next call's input. Normalization explicitly zeros
lanes 20–23 after the carry-add step (lane-19's carry otherwise leaks into
lane 20).

C side: `regs_capacity` and `red_digits` bumped to 24 for the 1024-bit
AVX-512 case. `to_words52()` already zero-pads; the `coeff_red` memset was
widened to cover the full capacity.

### 2048-bit (commit `9e5d25e`)

40 digits → 5 ZMM (40 lanes **exact**, no padding). Same memory layout as
YMM — the only C change is two function-pointer array entries.

Normalization carry mask is 5×8 = 40 bits, assembled into one 64-bit GPR
with shift+or, propagated with add+xor (ripple through saturated lanes),
then sliced back into five kmask registers.

## Non-findings

- **Instruction reordering** (hoist luq before scalar, A/B interleave):
  ~0% — the OoO engine already overlaps independent chains.
- **Critical-path bypass** (extract lane 1 early + scalar m[1]·yi): ~0% —
  the R-register chain (luq→luq→shift→huq→huq = 19 cyc) is equally binding.
- **ZMM lane-interleave** (A in lanes 0–3, B in 4–7): the Yi-combine step
  adds latency and B's extract needs vextracti64x4; net loss.
- **Separated luq/huq accumulators**: doubles `valignq` → port-5 bound again.

## Platform caveat

Cloud hypervisors may mask the AVX512_IFMA CPUID bit (leaf 7 EBX bit 21)
for live-migration portability, even when the hardware supports the
instruction. OpenSSL's eligibility check reads CPUID, so the IFMA path
silently skips and falls back to the 2×-slower AVX2 kernel.

Test actual hardware support directly:
```c
signal(SIGILL, handler);
if (!setjmp(jb)) { _mm256_madd52lo_epu64(a, b, c); /* supported */ }
```

Force-enable for benchmarking:
```sh
OPENSSL_ia32cap=":0x00000804d1bf2ffb" openssl speed rsa2048
```
(Sets bits 31/21/17/16 of capability word 2: AVX512VL / IFMA / DQ / F.)

## Files

- `crypto/bn/asm/rsaz-2k-avx512.pl` — `ossl_rsaz_amm52x20_x{1,2}_ifma512`,
  `ossl_extract_multiplier_2x20_win5_zmm`
- `crypto/bn/asm/rsaz-4k-avx512.pl` — `ossl_rsaz_amm52x40_x{1,2}_ifma512`
- `crypto/bn/rsaz_exp_x2.c` — dispatch + 24-qword layout for 1024-bit
