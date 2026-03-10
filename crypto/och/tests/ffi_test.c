/*
 * C-FFI correctness + leak test for OCH.
 *
 * Exercises OCH_areion_{p,s}_{init,seal,open,free} across a sweep of
 * message / AD sizes, including the 4-way ASM stride. Built without
 * aggressive -march so valgrind can fully emulate every instruction.
 *
 * Catches:
 *   - use-after-free / double-free on the opaque ctx handle
 *   - buffer over-reads / over-writes in seal/open
 *   - memory leaks from init without free
 *   - correctness regressions (seal→open roundtrip) under valgrind's
 *     perturbation of uninit memory
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../och.h"

static int fails = 0;

static void check(const char *what, int cond) {
    if (!cond) { fails++; fprintf(stderr, "FAIL: %s\n", what); }
}

static void fill(uint8_t *p, size_t n, uint32_t *seed) {
    for (size_t i = 0; i < n; i++) {
        *seed = *seed * 1103515245u + 12345u;
        p[i] = (uint8_t)(*seed >> 16);
    }
}

/* Exercise the KAT vector so valgrind sees the published data path too. */
static void test_kat_p(void) {
    static const uint8_t expect[64] = {
        0x94,0xfb,0x76,0x01,0x9c,0x4c,0xc1,0xbb,0x2b,0x8c,0x74,0x5d,0x74,0x9c,0xcf,0x02,
        0x61,0xe4,0xc9,0x90,0x41,0x34,0x9b,0x80,0xa8,0xe6,0xc7,0x0e,0x3c,0xf9,0x83,0x7e,
        0xbd,0x36,0x7f,0x85,0x09,0x1b,0x49,0x89,0xae,0x1d,0x92,0x76,0xf9,0x18,0xed,0xc5,
        0x84,0x12,0xe6,0x1d,0x45,0x19,0x18,0xed,0x96,0xd8,0x91,0x04,0xdf,0xc0,0xd2,0x82,
    };
    uint8_t key[32] = {0}, nonce[32] = {0}, ad[32] = {0}, msg[32] = {0};
    uint8_t ct[64];
    OCH_CTX ctx = OCH_areion_p_init(key);
    check("kat: init", ctx != NULL);
    ptrdiff_t n = OCH_areion_seal(ctx, ct, sizeof ct, msg, 32, ad, 32, nonce, 32, NULL, 0);
    check("kat: seal len", n == 64);
    check("kat: ct match", memcmp(ct, expect, 64) == 0);
    OCH_areion_free(ctx);
}

static void test_roundtrip_p(size_t mlen, size_t adlen, uint32_t *seed) {
    uint8_t key[32], nonce[32];
    fill(key, 32, seed); fill(nonce, 32, seed);
    uint8_t *ad  = malloc(adlen ? adlen : 1);
    uint8_t *msg = malloc(mlen ? mlen : 1);
    uint8_t *ct  = malloc(mlen + OCH_P_OVERHEAD);
    uint8_t *dec = malloc(mlen ? mlen : 1);
    fill(ad, adlen, seed); fill(msg, mlen, seed);
    memset(dec, 0xaa, mlen);

    OCH_CTX ctx = OCH_areion_p_init(key);
    check("p: init", ctx != NULL);

    ptrdiff_t n = OCH_areion_seal(ctx, ct, mlen + OCH_P_OVERHEAD,
                                  msg, mlen, ad, adlen, nonce, 32, NULL, 0);
    check("p: seal len", n == (ptrdiff_t)(mlen + OCH_P_OVERHEAD));

    ptrdiff_t m = OCH_areion_open(ctx, dec, mlen, NULL, 0,
                                  ct, (size_t)n, ad, adlen, nonce, 32);
    check("p: open len", m == (ptrdiff_t)mlen);
    check("p: roundtrip", mlen == 0 || memcmp(dec, msg, mlen) == 0);

    /* Tamper → auth failure */
    ct[(size_t)n - 1] ^= 0x01;
    m = OCH_areion_open(ctx, dec, mlen, NULL, 0, ct, (size_t)n, ad, adlen, nonce, 32);
    check("p: tamper rejected", m < 0);

    OCH_areion_free(ctx);
    free(ad); free(msg); free(ct); free(dec);
}

static void test_roundtrip_s(size_t mlen, size_t adlen, uint32_t *seed) {
    uint8_t key[32], snonce[32], snonce_out[32];
    fill(key, 32, seed); fill(snonce, 32, seed);
    uint8_t *ad  = malloc(adlen ? adlen : 1);
    uint8_t *msg = malloc(mlen ? mlen : 1);
    uint8_t *ct  = malloc(mlen + OCH_S_OVERHEAD);
    uint8_t *dec = malloc(mlen ? mlen : 1);
    fill(ad, adlen, seed); fill(msg, mlen, seed);
    memset(dec, 0x55, mlen);

    OCH_CTX ctx = OCH_areion_s_init(key);
    check("s: init", ctx != NULL);

    ptrdiff_t n = OCH_areion_seal(ctx, ct, mlen + OCH_S_OVERHEAD,
                                  msg, mlen, ad, adlen, NULL, 0, snonce, 32);
    check("s: seal len", n == (ptrdiff_t)(mlen + OCH_S_OVERHEAD));

    ptrdiff_t m = OCH_areion_open(ctx, dec, mlen, snonce_out, 32,
                                  ct, (size_t)n, ad, adlen, NULL, 0);
    check("s: open len", m == (ptrdiff_t)mlen);
    check("s: roundtrip", mlen == 0 || memcmp(dec, msg, mlen) == 0);
    check("s: snonce recovered", memcmp(snonce_out, snonce, 32) == 0);

    OCH_areion_free(ctx);
    free(ad); free(msg); free(ct); free(dec);
}

int main(void) {
    test_kat_p();

    /* Sweep sizes — lengths chosen to exercise: tiny path, single block,
     * partial-tail, 4x-ASM stride, and large (multi-MB) buffers. */
    static const size_t mlens[] = {
        0, 1, 16, 31, 32, 33, 63, 64, 128, 160, 191, 192, 256,
        512, 1024, 4096, 65536,
    };
    static const size_t adlens[] = { 0, 1, 31, 32, 33, 128 };
    uint32_t seed = 0x1badb002u;

    for (size_t i = 0; i < sizeof mlens / sizeof mlens[0]; i++) {
        for (size_t j = 0; j < sizeof adlens / sizeof adlens[0]; j++) {
            test_roundtrip_p(mlens[i], adlens[j], &seed);
            test_roundtrip_s(mlens[i], adlens[j], &seed);
        }
    }

    /* One deliberately large buffer so valgrind walks a long ASM stride. */
    test_roundtrip_p(1 << 18, 0, &seed);

    if (fails) {
        printf("%d checks FAILED\n", fails);
        return 1;
    }
    printf("All C-FFI checks passed.\n");
    return 0;
}
