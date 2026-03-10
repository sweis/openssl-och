/*
 * OCH authenticated encryption — C API for the Rust-backed implementation.
 *
 * Areion-based instantiation of OCH-256 from:
 *   Menda, Bellare, Hoang, Len, Ristenpart,
 *   "OCH: Fast, Committing AEAD from a Tweakable Block Cipher",
 *   ACM CCS 2025 / eprint 2026/439.
 *
 * The implementation lives in crypto/och/rust/ and is built as a
 * static library (liboch.a) that exports the symbols below.
 */

#ifndef OSSL_CRYPTO_OCH_H
# define OSSL_CRYPTO_OCH_H

# include <stddef.h>
# include <stdint.h>

# ifdef __cplusplus
extern "C" {
# endif

/* Sizes (bytes). */
# define OCH_KEY_LEN     32
# define OCH_NONCE_LEN   32
# define OCH_TAG_LEN     32
# define OCH_P_OVERHEAD  32   /* ct_len = msg_len + 32                  */
# define OCH_S_OVERHEAD  64   /* ct_len = msg_len + 64 (enc_sn || tag)  */

/* Opaque context handle. Must be freed with OCH_areion_free. */
typedef struct OchCtx *OCH_CTX;

/* ------------------------------------------------------------------------- */
/* Setup                                                                     */

/*
 * Allocate and key an OCH-P context (public 32-byte nonce variant).
 * Returns NULL on error.
 */
OCH_CTX OCH_areion_p_init(const uint8_t key[OCH_KEY_LEN]);

/*
 * Allocate and key an OCH-S context (secret nonce-hiding variant).
 * Returns NULL on error.
 */
OCH_CTX OCH_areion_s_init(const uint8_t key[OCH_KEY_LEN]);

void OCH_areion_free(OCH_CTX ctx);

/* ------------------------------------------------------------------------- */
/* AEAD                                                                      */

/*
 * Encrypt + authenticate.
 *
 *   OCH-P: ct = enc(msg) || tag              ct_cap >= msg_len + 32
 *          pass secnonce=NULL, secnonce_len=0, pubnonce_len=32.
 *   OCH-S: ct = enc(sn) || enc(msg) || tag   ct_cap >= msg_len + 64
 *          pass pubnonce=NULL, pubnonce_len=0, secnonce_len=32.
 *
 * Returns ciphertext length (>=0) on success, -1 on error.
 */
ptrdiff_t OCH_areion_seal(OCH_CTX ctx,
                          uint8_t *ct, size_t ct_cap,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *ad, size_t ad_len,
                          const uint8_t *pubnonce, size_t pubnonce_len,
                          const uint8_t *secnonce, size_t secnonce_len);

/*
 * Verify + decrypt.
 *
 *   OCH-P: pass secnonce_out=NULL, secnonce_out_len=0, pubnonce_len=32.
 *   OCH-S: pass pubnonce=NULL, pubnonce_len=0, secnonce_out_len=32.
 *
 * Returns plaintext length (>=0) on success, -1 on authentication failure
 * or error. Output buffers are NOT wiped on failure; caller must discard.
 */
ptrdiff_t OCH_areion_open(OCH_CTX ctx,
                          uint8_t *msg, size_t msg_cap,
                          uint8_t *secnonce_out, size_t secnonce_out_len,
                          const uint8_t *ct, size_t ct_len,
                          const uint8_t *ad, size_t ad_len,
                          const uint8_t *pubnonce, size_t pubnonce_len);

/* Raw Areion256 forward permutation (32 bytes in-place). For benchmarking. */
void OCH_areion256_permute(uint8_t state[32]);

# ifdef __cplusplus
}
# endif

#endif  /* OSSL_CRYPTO_OCH_H */
