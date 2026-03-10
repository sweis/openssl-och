/*
 * Correctness harness for crypto/och/asm/areion-x86_64.s.
 *
 * Cross-checks every ASM kernel against the Rust reference exports
 * (OCH_areion256_permute + direct round-trip), and sanity-checks the
 * published Areion-256 KATs. Run under valgrind to catch OOB/UB.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* --- ASM kernels (areion-x86_64.o) -------------------------------------- */
void och_asm_areion256_x1     (uint8_t s[32]);
void och_asm_areion256_inv_x1 (uint8_t s[32]);
void och_asm_areion256_x4     (uint8_t s[4][32]);
void och_asm_areion256_inv_x4 (uint8_t s[4][32]);
void och_asm_em_enc_x4        (uint8_t blk[4][32], const uint8_t off[4][32]);
void och_asm_em_dec_x4        (uint8_t blk[4][32], const uint8_t off[4][32]);

/* --- Rust reference (liboch.a) ------------------------------------------ */
void OCH_areion256_permute(uint8_t state[32]);

/* ------------------------------------------------------------------------ */

static int fails = 0;

static void hexdump(const char *tag, const uint8_t *b, size_t n) {
    fprintf(stderr, "%s: ", tag);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", b[i]);
    fprintf(stderr, "\n");
}

static void check(const char *what, const uint8_t *a, const uint8_t *b, size_t n) {
    if (memcmp(a, b, n) != 0) {
        fails++;
        fprintf(stderr, "FAIL %s\n", what);
        hexdump("  got", a, n);
        hexdump("  want", b, n);
    }
}

static void fill(uint8_t *p, size_t n, uint32_t *seed) {
    for (size_t i = 0; i < n; i++) {
        *seed = *seed * 1664525u + 1013904223u;
        p[i] = (uint8_t)(*seed >> 16);
    }
}

/* --- KATs (eprint 2023/794 Appendix B) ---------------------------------- */

static const uint8_t KAT0_IN[32] = {0};
static const uint8_t KAT0_OUT[32] = {
    0x28,0x12,0xa7,0x24,0x65,0xb2,0x6e,0x9f,0xca,0x75,0x83,0xf6,0xe4,0x12,0x3a,0xa1,
    0x49,0x0e,0x35,0xe7,0xd5,0x20,0x3e,0x4b,0xa2,0xe9,0x27,0xb0,0x48,0x2f,0x4d,0xb8,
};
static const uint8_t KAT1_IN[32] = {
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
    16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
};
static const uint8_t KAT1_OUT[32] = {
    0x68,0x84,0x5f,0x13,0x2e,0xe4,0x61,0x60,0x66,0xc7,0x02,0xd9,0x42,0xa3,0xb2,0xc3,
    0xa3,0x77,0xf6,0x5b,0x13,0xbb,0x05,0xc7,0xcd,0x1f,0xb2,0x9c,0x89,0xaf,0xa1,0x85,
};

/* ------------------------------------------------------------------------ */

int main(void) {
    /* 1. KAT: ASM x1 vs known outputs. */
    {
        uint8_t s[32];
        memcpy(s, KAT0_IN, 32); och_asm_areion256_x1(s);
        check("x1 KAT0", s, KAT0_OUT, 32);
        memcpy(s, KAT1_IN, 32); och_asm_areion256_x1(s);
        check("x1 KAT1", s, KAT1_OUT, 32);
    }

    /* 2. ASM x1 matches Rust permutation on 256 random inputs. */
    {
        uint32_t seed = 0xcafed00d;
        for (int t = 0; t < 256; t++) {
            uint8_t a[32], r[32];
            fill(a, 32, &seed);
            memcpy(r, a, 32);
            och_asm_areion256_x1(a);
            OCH_areion256_permute(r);
            check("x1 == Rust", a, r, 32);
        }
    }

    /* 3. x1 inverse: inv(fwd(s)) == s and fwd(inv(s)) == s. */
    {
        uint32_t seed = 0x1234abcd;
        for (int t = 0; t < 256; t++) {
            uint8_t orig[32], s[32];
            fill(orig, 32, &seed);
            memcpy(s, orig, 32); och_asm_areion256_x1(s); och_asm_areion256_inv_x1(s);
            check("inv∘fwd == id", s, orig, 32);
            memcpy(s, orig, 32); och_asm_areion256_inv_x1(s); och_asm_areion256_x1(s);
            check("fwd∘inv == id", s, orig, 32);
        }
    }

    /* 4. x4 fwd == x1 fwd, lane by lane (random). */
    {
        uint32_t seed = 0xf005ba11;
        for (int t = 0; t < 64; t++) {
            uint8_t s4[4][32], ref[4][32];
            fill((uint8_t*)s4, sizeof s4, &seed);
            memcpy(ref, s4, sizeof s4);
            och_asm_areion256_x4(s4);
            for (int b = 0; b < 4; b++) {
                och_asm_areion256_x1(ref[b]);
                check("x4 fwd lane", s4[b], ref[b], 32);
            }
        }
    }

    /* 5. x4 inv is inverse of x4 fwd. */
    {
        uint32_t seed = 0xdeadbeef;
        for (int t = 0; t < 64; t++) {
            uint8_t orig[4][32], s[4][32];
            fill((uint8_t*)orig, sizeof orig, &seed);
            memcpy(s, orig, sizeof s);
            och_asm_areion256_x4(s);
            och_asm_areion256_inv_x4(s);
            check("x4 inv∘fwd", (uint8_t*)s, (uint8_t*)orig, 128);
        }
    }

    /* 6. em_enc_x4: blk ^= off; Areion256(blk); blk ^= off — vs x1 manual. */
    {
        uint32_t seed = 0x0badc0de;
        for (int t = 0; t < 64; t++) {
            uint8_t blk[4][32], off[4][32], ref[4][32];
            fill((uint8_t*)blk, sizeof blk, &seed);
            fill((uint8_t*)off, sizeof off, &seed);
            memcpy(ref, blk, sizeof blk);
            /* reference */
            for (int b = 0; b < 4; b++) {
                for (int i = 0; i < 32; i++) ref[b][i] ^= off[b][i];
                och_asm_areion256_x1(ref[b]);
                for (int i = 0; i < 32; i++) ref[b][i] ^= off[b][i];
            }
            /* kernel */
            och_asm_em_enc_x4(blk, off);
            check("em_enc_x4", (uint8_t*)blk, (uint8_t*)ref, 128);
        }
    }

    /* 7. em_dec_x4 inverts em_enc_x4. */
    {
        uint32_t seed = 0xfeedface;
        for (int t = 0; t < 64; t++) {
            uint8_t orig[4][32], blk[4][32], off[4][32];
            fill((uint8_t*)orig, sizeof orig, &seed);
            fill((uint8_t*)off,  sizeof off,  &seed);
            memcpy(blk, orig, sizeof blk);
            och_asm_em_enc_x4(blk, off);
            och_asm_em_dec_x4(blk, off);
            check("em_dec inverts em_enc", (uint8_t*)blk, (uint8_t*)orig, 128);
        }
    }

    if (fails) {
        printf("%d checks FAILED\n", fails);
        return 1;
    }
    printf("All ASM-vs-reference checks passed.\n");
    return 0;
}
