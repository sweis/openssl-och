/*
 * Benchmark: Areion-OCH vs OpenSSL AEADs.
 *
 * Measures seal/encrypt throughput across a sweep of message sizes for:
 *   - Areion-OCH-P   (this work, via Rust liboch.a)
 *   - Areion-OCH-S   (this work, nonce-hiding)
 *   - AES-256-GCM    (OpenSSL EVP)
 *   - AES-128-OCB    (OpenSSL EVP; 128-bit key is what OpenSSL ships)
 *   - AES-256-CTR    (OpenSSL EVP; unauthenticated baseline)
 *
 * Also clocks the raw Areion256 permutation (cycles/byte) for context.
 *
 * Build via the adjacent Makefile; links against system libcrypto.
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "och.h"

/* ------------------------------------------------------------------------- */

static inline uint64_t rdtsc(void) {
#if defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
#endif
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

/* ------------------------------------------------------------------------- */
/* Timing driver — runs `fn` until >= min_sec elapsed and >= min_iters done. */

typedef void (*bench_fn)(void *udata, size_t mlen);

typedef struct {
    double  cpb;   /* cycles per byte   */
    double  mbps;  /* megabytes per sec */
    size_t  iters;
} bench_result;

static bench_result run_bench(bench_fn fn, void *udata,
                              size_t mlen,
                              double min_sec, size_t min_iters)
{
    /* Warm up. */
    for (size_t i = 0; i < 4; i++) fn(udata, mlen);

    size_t iters = 0;
    uint64_t tsc0 = rdtsc();
    double t0 = now_sec();
    do {
        size_t batch = (iters < 64) ? 8 : (iters < 1024) ? 64 : 512;
        for (size_t i = 0; i < batch; i++) fn(udata, mlen);
        iters += batch;
    } while (now_sec() - t0 < min_sec || iters < min_iters);
    double dt = now_sec() - t0;
    uint64_t dtsc = rdtsc() - tsc0;

    bench_result r;
    double bytes = (double)mlen * (double)iters;
    r.cpb = (double)dtsc / bytes;
    r.mbps = bytes / (1024.0 * 1024.0) / dt;
    r.iters = iters;
    return r;
}

/* ------------------------------------------------------------------------- */
/* OCH runners                                                               */

typedef struct {
    OCH_CTX ctx;
    uint8_t *msg;
    uint8_t *ct;
    uint8_t *ad;
    uint8_t  pubnonce[OCH_NONCE_LEN];
    uint8_t  secnonce[OCH_NONCE_LEN];
} och_bench;

static void och_p_seal(void *udata, size_t mlen) {
    och_bench *b = udata;
    ptrdiff_t n = OCH_areion_seal(b->ctx,
        b->ct, mlen + OCH_P_OVERHEAD,
        b->msg, mlen,
        b->ad, 32,
        b->pubnonce, OCH_NONCE_LEN,
        NULL, 0);
    if (n < 0) die("OCH-P seal failed");
    b->pubnonce[0]++;   /* vary nonce */
}

static void och_s_seal(void *udata, size_t mlen) {
    och_bench *b = udata;
    ptrdiff_t n = OCH_areion_seal(b->ctx,
        b->ct, mlen + OCH_S_OVERHEAD,
        b->msg, mlen,
        b->ad, 32,
        NULL, 0,
        b->secnonce, OCH_NONCE_LEN);
    if (n < 0) die("OCH-S seal failed");
    b->secnonce[0]++;
}

/* ------------------------------------------------------------------------- */
/* EVP runners                                                               */

typedef struct {
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    uint8_t *msg;
    uint8_t *ct;
    uint8_t *ad;
    uint8_t  key[32];
    uint8_t  iv[16];
    int      is_aead;   /* AEAD needs tag finalisation */
} evp_bench;

static void evp_seal(void *udata, size_t mlen) {
    evp_bench *b = udata;
    int outl, tmp;

    /* Re-key each iteration to match realistic use (EVP reset-via-NULL). */
    if (EVP_EncryptInit_ex(b->ctx, NULL, NULL, NULL, b->iv) != 1)
        die("evp init iv");
    if (b->is_aead) {
        if (EVP_EncryptUpdate(b->ctx, NULL, &outl, b->ad, 32) != 1)
            die("evp aad");
    }
    if (EVP_EncryptUpdate(b->ctx, b->ct, &outl, b->msg, (int)mlen) != 1)
        die("evp update");
    if (EVP_EncryptFinal_ex(b->ctx, b->ct + outl, &tmp) != 1)
        die("evp final");
    if (b->is_aead) {
        uint8_t tag[16];
        if (EVP_CIPHER_CTX_ctrl(b->ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1)
            die("evp get tag");
    }
    b->iv[0]++;
}

static evp_bench *evp_bench_new(const char *name, size_t max_mlen,
                                int is_aead) {
    evp_bench *b = calloc(1, sizeof *b);
    b->cipher = EVP_CIPHER_fetch(NULL, name, NULL);
    if (!b->cipher) die("no such cipher");
    b->ctx = EVP_CIPHER_CTX_new();
    b->msg = malloc(max_mlen);
    b->ct  = malloc(max_mlen + 32);
    b->ad  = calloc(1, 32);
    b->is_aead = is_aead;
    for (size_t i = 0; i < max_mlen; i++) b->msg[i] = (uint8_t)(i * 7u);
    memset(b->key, 0x11, sizeof b->key);
    memset(b->iv, 0x22, sizeof b->iv);

    int ivlen = EVP_CIPHER_get_iv_length(b->cipher);
    if (EVP_EncryptInit_ex(b->ctx, b->cipher, NULL, NULL, NULL) != 1)
        die("evp init cipher");
    if (is_aead) {
        if (EVP_CIPHER_CTX_ctrl(b->ctx, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL) != 1)
            die("evp set ivlen");
    }
    if (EVP_EncryptInit_ex(b->ctx, NULL, NULL, b->key, b->iv) != 1)
        die("evp init key");
    return b;
}

static void evp_bench_free(evp_bench *b) {
    EVP_CIPHER_CTX_free(b->ctx);
    EVP_CIPHER_free((EVP_CIPHER *)b->cipher);
    free(b->msg); free(b->ct); free(b->ad);
    free(b);
}

/* ------------------------------------------------------------------------- */

static const size_t SIZES[] = { 16, 64, 256, 1024, 4096, 16384, 65536, 1048576 };
static const size_t NSIZES  = sizeof SIZES / sizeof SIZES[0];

int main(void) {
    printf("Areion-OCH benchmark — seal throughput\n");
    printf("(cycles/byte via rdtsc; MB/s via CLOCK_MONOTONIC)\n\n");

    size_t max_mlen = SIZES[NSIZES - 1];

    /* OCH-P */
    uint8_t key[OCH_KEY_LEN]; memset(key, 0x33, sizeof key);
    och_bench op = {0};
    op.ctx = OCH_areion_p_init(key);
    op.msg = malloc(max_mlen);
    op.ct  = malloc(max_mlen + OCH_S_OVERHEAD);
    op.ad  = calloc(1, 32);
    for (size_t i = 0; i < max_mlen; i++) op.msg[i] = (uint8_t)(i * 7u);

    /* OCH-S */
    och_bench os = op;
    os.ctx = OCH_areion_s_init(key);

    /* EVP. AES-128-GCM is the paper's primary reference point (0.38 cpb on
     * Raptor Lake); 256-bit variants show the key-length overhead. */
    evp_bench *eg1 = evp_bench_new("AES-128-GCM", max_mlen, 1);
    evp_bench *eg2 = evp_bench_new("AES-256-GCM", max_mlen, 1);
    evp_bench *eo  = evp_bench_new("AES-128-OCB", max_mlen, 1);
    evp_bench *ec1 = evp_bench_new("AES-128-CTR", max_mlen, 0);
    evp_bench *ec2 = evp_bench_new("AES-256-CTR", max_mlen, 0);

    /* ----- Areion256 raw permutation (1x vs 4x interleave) ----- */
    {
        const size_t iters = 1 << 20;
        uint8_t s[32] = {0};
        uint64_t t0 = rdtsc();
        for (size_t i = 0; i < iters; i++) OCH_areion256_permute(s);
        uint64_t dt1 = rdtsc() - t0;
        double cpb1 = (double)dt1 / iters / 32.0;

        uint8_t s4[128] = {0};
        t0 = rdtsc();
        for (size_t i = 0; i < iters; i++) OCH_areion256_permute_x4(s4);
        uint64_t dt4 = rdtsc() - t0;
        double cpb4 = (double)dt4 / iters / 128.0;

        printf("Areion256 permutation:   1x %.2f cyc/blk  (= %.3f cpb)\n",
               (double)dt1 / iters, cpb1);
        printf("                         4x %.2f cyc/4blk (= %.3f cpb) -- %.2fx\n\n",
               (double)dt4 / iters, cpb4, cpb1 / cpb4);
    }

    /* ----- Main sweep ----- */
    const char *hdr[] = {"OCH-P","OCH-S","GCM-128","GCM-256","OCB-128","CTR-128","CTR-256"};
    printf("%-9s", "size");
    for (int c = 0; c < 7; c++) printf(" %8s", hdr[c]);
    printf("  |  ");
    for (int c = 0; c < 7; c++) printf(" %8s", hdr[c]);
    printf("\n%-9s", "(bytes)");
    for (int c = 0; c < 7; c++) printf(" %8s", "(cpb)");
    printf("  |  ");
    for (int c = 0; c < 7; c++) printf(" %8s", "(MB/s)");
    printf("\n");

    double min_sec = 0.25;
    size_t min_iters = 64;

    for (size_t i = 0; i < NSIZES; i++) {
        size_t m = SIZES[i];
        bench_result r[7] = {
            run_bench(och_p_seal, &op, m, min_sec, min_iters),
            run_bench(och_s_seal, &os, m, min_sec, min_iters),
            run_bench(evp_seal, eg1, m, min_sec, min_iters),
            run_bench(evp_seal, eg2, m, min_sec, min_iters),
            run_bench(evp_seal, eo,  m, min_sec, min_iters),
            run_bench(evp_seal, ec1, m, min_sec, min_iters),
            run_bench(evp_seal, ec2, m, min_sec, min_iters),
        };
        printf("%-9zu", m);
        for (int c = 0; c < 7; c++) printf(" %8.2f", r[c].cpb);
        printf("  |  ");
        for (int c = 0; c < 7; c++) printf(" %8.1f", r[c].mbps);
        printf("\n");
    }

    /* Clean up. */
    OCH_areion_free(op.ctx);
    OCH_areion_free(os.ctx);
    free(op.msg); free(op.ct); free(op.ad);
    evp_bench_free(eg1); evp_bench_free(eg2);
    evp_bench_free(eo);
    evp_bench_free(ec1); evp_bench_free(ec2);
    return 0;
}
