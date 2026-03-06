/*
 * ts_crypto.h — Noise_IK crypto layer for Tailscale TS2021 control protocol
 *
 * Implements:
 *   - Noise_IK_25519_ChaChaPoly_BLAKE2s handshake (initiator side)
 *   - ChaCha20-Poly1305 transport encryption with Big-Endian nonce
 *   - HMAC-BLAKE2s and HKDF key derivation
 *   - Curve25519 key generation
 *   - Hex encoding/decoding for key formatting
 *
 * Reuses Phase 1 crypto from component/wireguard/crypto/refc/
 */

#ifndef TS_CRYPTO_H
#define TS_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define TS_KEY_LEN          32
#define TS_HASH_LEN         32
#define TS_AEAD_TAG_LEN     16
#define TS_BLAKE2S_BLOCK    64

/* Noise_IK message sizes */
#define TS_NOISE_MSG1_BASE  96  /* e(32) + enc_s(48) + enc_empty_payload(16) */
#define TS_NOISE_MSG1_LEN   96  /* kept for backwards compat (empty payload) */
#define TS_NOISE_MSG2_LEN   48  /* e(32) + enc_payload(16) */

/* ------------------------------------------------------------------ */
/*  Noise_IK Handshake                                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    /* Noise symmetric state */
    uint8_t  ck[TS_HASH_LEN];       /* chaining key */
    uint8_t  h[TS_HASH_LEN];        /* handshake hash */

    /* Local static keypair (= machine key) */
    uint8_t  s_priv[TS_KEY_LEN];
    uint8_t  s_pub[TS_KEY_LEN];

    /* Local ephemeral keypair (generated per handshake) */
    uint8_t  e_priv[TS_KEY_LEN];
    uint8_t  e_pub[TS_KEY_LEN];

    /* Remote static public key (= control server key) */
    uint8_t  rs[TS_KEY_LEN];

    /* Derived transport keys (after split) */
    uint8_t  send_key[TS_KEY_LEN];
    uint8_t  recv_key[TS_KEY_LEN];
    uint64_t send_nonce;
    uint64_t recv_nonce;

    bool     handshake_complete;
} ts_noise_ik_t;

/*
 * Initialize a Noise_IK handshake.
 *
 * @param state         Handshake state to initialize
 * @param static_priv   Local machine key (private, 32 bytes)
 * @param static_pub    Local machine key (public, 32 bytes)
 * @param remote_static Control server public key (32 bytes)
 */
void ts_noise_ik_init(ts_noise_ik_t *state,
                      const uint8_t *static_priv,
                      const uint8_t *static_pub,
                      const uint8_t *remote_static);

/*
 * Generate Noise_IK Message 1 (initiator -> responder).
 * Pattern: -> e, es, s, ss [payload]
 *
 * @param state       Initialized handshake state
 * @param out         Output buffer (must be >= 80 + payload_len + 16 bytes)
 * @param payload     Early payload to encrypt (NULL for empty)
 * @param payload_len Length of payload (0 for empty)
 * @return            Number of bytes written (96 + payload_len), or -1
 */
int ts_noise_ik_write_msg1(ts_noise_ik_t *state, uint8_t *out,
                            const uint8_t *payload, size_t payload_len);

/*
 * Process Noise_IK Message 2 (responder -> initiator).
 * Pattern: <- e, ee, se
 *
 * @param state   Handshake state (after write_msg1)
 * @param msg     Incoming message (TS_NOISE_MSG2_LEN bytes)
 * @param msg_len Length of incoming message
 * @return        0 on success, -1 on MAC verification failure
 */
int ts_noise_ik_read_msg2(ts_noise_ik_t *state,
                          const uint8_t *msg, size_t msg_len);

/*
 * Derive transport keys from completed handshake.
 * Must be called after successful read_msg2.
 * Sets state->send_key, state->recv_key, resets nonces to 0.
 *
 * @param state   Completed handshake state
 * @return        0 on success, -1 if handshake not complete
 */
int ts_noise_ik_split(ts_noise_ik_t *state);

/* ------------------------------------------------------------------ */
/*  Noise Transport Encryption (Big-Endian nonce)                      */
/* ------------------------------------------------------------------ */

/*
 * Encrypt data using ChaCha20-Poly1305 with Big-Endian nonce.
 * Used for Noise transport messages after handshake.
 * Increments state->send_nonce after each call.
 *
 * @param state    Noise state with send_key
 * @param dst      Output: ciphertext + 16-byte tag (src_len + 16 bytes)
 * @param src      Plaintext to encrypt
 * @param src_len  Length of plaintext
 * @return         Total output length (src_len + 16)
 */
int ts_noise_encrypt(ts_noise_ik_t *state,
                     uint8_t *dst, const uint8_t *src, size_t src_len);

/*
 * Decrypt data using ChaCha20-Poly1305 with Big-Endian nonce.
 * Increments state->recv_nonce after each call.
 *
 * @param state    Noise state with recv_key
 * @param dst      Output: plaintext (src_len - 16 bytes)
 * @param src      Ciphertext + tag
 * @param src_len  Length of ciphertext + tag (must be >= 16)
 * @return         Plaintext length, or -1 on MAC failure
 */
int ts_noise_decrypt(ts_noise_ik_t *state,
                     uint8_t *dst, const uint8_t *src, size_t src_len);

/* ------------------------------------------------------------------ */
/*  Low-level crypto utilities                                         */
/* ------------------------------------------------------------------ */

/* HMAC-BLAKE2s */
void ts_hmac_blake2s(uint8_t *digest,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *text, size_t text_len);

/* HKDF-BLAKE2s: derive 1 output key */
void ts_hkdf1(uint8_t *out1,
              const uint8_t *ck, const uint8_t *input, size_t input_len);

/* HKDF-BLAKE2s: derive 2 output keys */
void ts_hkdf2(uint8_t *out1, uint8_t *out2,
              const uint8_t *ck, const uint8_t *input, size_t input_len);

/* Generate a Curve25519 keypair from random bytes */
void ts_keygen(uint8_t *priv, uint8_t *pub);

/* ChaCha20-Poly1305 with Big-Endian nonce (standalone, no state) */
void ts_aead_encrypt_be(uint8_t *dst, const uint8_t *src, size_t src_len,
                        const uint8_t *ad, size_t ad_len,
                        uint64_t nonce, const uint8_t *key);
bool ts_aead_decrypt_be(uint8_t *dst, const uint8_t *src, size_t src_len,
                        const uint8_t *ad, size_t ad_len,
                        uint64_t nonce, const uint8_t *key);

/* ------------------------------------------------------------------ */
/*  Hex/Key encoding utilities                                         */
/* ------------------------------------------------------------------ */

/* Encode 32-byte key to hex string (64 chars + null) */
void ts_key_to_hex(char *hex_out, const uint8_t *key);

/* Decode hex string (64 chars) to 32-byte key */
int ts_hex_to_key(uint8_t *key_out, const char *hex, size_t hex_len);

#ifdef __cplusplus
}
#endif

#endif /* TS_CRYPTO_H */
