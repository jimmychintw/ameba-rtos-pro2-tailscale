/*
 * ts_crypto.c — Noise_IK crypto layer for Tailscale TS2021 control protocol
 *
 * Implements Noise_IK_25519_ChaChaPoly_BLAKE2s (initiator side)
 * with Big-Endian nonce for transport encryption.
 *
 * Reuses Phase 1 crypto primitives from component/wireguard/.
 */

#include "ts_crypto.h"

#include <string.h>
#include <stdio.h>

/* Phase 1 crypto (Curve25519, ChaCha20-Poly1305, BLAKE2s) */
#include "../wireguard/crypto.h"
#include "../wireguard/wireguard-platform.h"  /* wireguard_random_bytes */

/* ------------------------------------------------------------------ */
/*  Internal constants                                                 */
/* ------------------------------------------------------------------ */

/* Noise protocol name: determines initial hash/chaining key */
static const char NOISE_PROTOCOL_NAME[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/* Tailscale control protocol prologue */
static const char TS_PROLOGUE[] = "Tailscale Control Protocol v1";

/* ------------------------------------------------------------------ */
/*  Byte-swap for Big-Endian nonce                                     */
/* ------------------------------------------------------------------ */

static inline uint64_t bswap64(uint64_t x)
{
    return ((x & 0xFF00000000000000ULL) >> 56) |
           ((x & 0x00FF000000000000ULL) >> 40) |
           ((x & 0x0000FF0000000000ULL) >> 24) |
           ((x & 0x000000FF00000000ULL) >>  8) |
           ((x & 0x00000000FF000000ULL) <<  8) |
           ((x & 0x0000000000FF0000ULL) << 24) |
           ((x & 0x000000000000FF00ULL) << 40) |
           ((x & 0x00000000000000FFULL) << 56);
}

/* ------------------------------------------------------------------ */
/*  HMAC-BLAKE2s                                                       */
/* ------------------------------------------------------------------ */

void ts_hmac_blake2s(uint8_t *digest,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *text, size_t text_len)
{
    blake2s_ctx ctx;
    uint8_t k_ipad[TS_BLAKE2S_BLOCK];
    uint8_t k_opad[TS_BLAKE2S_BLOCK];
    uint8_t tk[TS_HASH_LEN];
    int i;

    if (key_len > TS_BLAKE2S_BLOCK) {
        blake2s_init(&ctx, TS_HASH_LEN, NULL, 0);
        blake2s_update(&ctx, key, key_len);
        blake2s_final(&ctx, tk);
        key = tk;
        key_len = TS_HASH_LEN;
    }

    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    for (i = 0; i < TS_BLAKE2S_BLOCK; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    /* Inner hash */
    blake2s_init(&ctx, TS_HASH_LEN, NULL, 0);
    blake2s_update(&ctx, k_ipad, TS_BLAKE2S_BLOCK);
    blake2s_update(&ctx, text, text_len);
    blake2s_final(&ctx, digest);

    /* Outer hash */
    blake2s_init(&ctx, TS_HASH_LEN, NULL, 0);
    blake2s_update(&ctx, k_opad, TS_BLAKE2S_BLOCK);
    blake2s_update(&ctx, digest, TS_HASH_LEN);
    blake2s_final(&ctx, digest);

    crypto_zero(k_ipad, sizeof(k_ipad));
    crypto_zero(k_opad, sizeof(k_opad));
    crypto_zero(tk, sizeof(tk));
}

/* ------------------------------------------------------------------ */
/*  HKDF-BLAKE2s                                                       */
/* ------------------------------------------------------------------ */

void ts_hkdf1(uint8_t *out1,
              const uint8_t *ck, const uint8_t *input, size_t input_len)
{
    uint8_t tau0[TS_HASH_LEN];
    uint8_t buf[TS_HASH_LEN + 1];

    ts_hmac_blake2s(tau0, ck, TS_HASH_LEN, input, input_len);

    buf[0] = 1;
    ts_hmac_blake2s(buf, tau0, TS_HASH_LEN, buf, 1);
    memcpy(out1, buf, TS_HASH_LEN);

    crypto_zero(tau0, sizeof(tau0));
    crypto_zero(buf, sizeof(buf));
}

void ts_hkdf2(uint8_t *out1, uint8_t *out2,
              const uint8_t *ck, const uint8_t *input, size_t input_len)
{
    uint8_t tau0[TS_HASH_LEN];
    uint8_t buf[TS_HASH_LEN + 1];

    ts_hmac_blake2s(tau0, ck, TS_HASH_LEN, input, input_len);

    /* out1 = HMAC(tau0, 0x01) */
    buf[0] = 1;
    ts_hmac_blake2s(buf, tau0, TS_HASH_LEN, buf, 1);
    memcpy(out1, buf, TS_HASH_LEN);

    /* out2 = HMAC(tau0, out1 || 0x02) */
    buf[TS_HASH_LEN] = 2;
    ts_hmac_blake2s(buf, tau0, TS_HASH_LEN, buf, TS_HASH_LEN + 1);
    memcpy(out2, buf, TS_HASH_LEN);

    crypto_zero(tau0, sizeof(tau0));
    crypto_zero(buf, sizeof(buf));
}

/* ------------------------------------------------------------------ */
/*  Noise helpers                                                      */
/* ------------------------------------------------------------------ */

static void mix_hash(uint8_t *h, const uint8_t *data, size_t data_len)
{
    blake2s_ctx ctx;
    blake2s_init(&ctx, TS_HASH_LEN, NULL, 0);
    blake2s_update(&ctx, h, TS_HASH_LEN);
    blake2s_update(&ctx, data, data_len);
    blake2s_final(&ctx, h);
}

/* ------------------------------------------------------------------ */
/*  ChaCha20-Poly1305 with Big-Endian nonce                            */
/* ------------------------------------------------------------------ */

void ts_aead_encrypt_be(uint8_t *dst, const uint8_t *src, size_t src_len,
                        const uint8_t *ad, size_t ad_len,
                        uint64_t nonce, const uint8_t *key)
{
    /* Byte-swap nonce: Go uses BE, our chacha20 implementation uses LE */
    uint64_t nonce_swapped = bswap64(nonce);
    chacha20poly1305_encrypt(dst, src, src_len, ad, ad_len, nonce_swapped, key);
}

bool ts_aead_decrypt_be(uint8_t *dst, const uint8_t *src, size_t src_len,
                        const uint8_t *ad, size_t ad_len,
                        uint64_t nonce, const uint8_t *key)
{
    uint64_t nonce_swapped = bswap64(nonce);
    return chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len,
                                   nonce_swapped, key);
}

/* ------------------------------------------------------------------ */
/*  Key generation                                                     */
/* ------------------------------------------------------------------ */

void ts_keygen(uint8_t *priv, uint8_t *pub)
{
    wireguard_random_bytes(priv, TS_KEY_LEN);
    /* Clamp private key for Curve25519 */
    priv[0]  &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
    /* Derive public key: pub = priv * basepoint */
    x25519_base(pub, priv, 1);
}

/* ------------------------------------------------------------------ */
/*  Hex utilities                                                      */
/* ------------------------------------------------------------------ */

void ts_key_to_hex(char *hex_out, const uint8_t *key)
{
    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < TS_KEY_LEN; i++) {
        hex_out[i * 2]     = hex_chars[(key[i] >> 4) & 0x0F];
        hex_out[i * 2 + 1] = hex_chars[key[i] & 0x0F];
    }
    hex_out[TS_KEY_LEN * 2] = '\0';
}

int ts_hex_to_key(uint8_t *key_out, const char *hex, size_t hex_len)
{
    if (hex_len != TS_KEY_LEN * 2)
        return -1;

    for (size_t i = 0; i < TS_KEY_LEN; i++) {
        uint8_t hi, lo;
        char ch = hex[i * 2];
        if      (ch >= '0' && ch <= '9') hi = ch - '0';
        else if (ch >= 'a' && ch <= 'f') hi = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') hi = ch - 'A' + 10;
        else return -1;

        ch = hex[i * 2 + 1];
        if      (ch >= '0' && ch <= '9') lo = ch - '0';
        else if (ch >= 'a' && ch <= 'f') lo = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') lo = ch - 'A' + 10;
        else return -1;

        key_out[i] = (hi << 4) | lo;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Noise_IK Handshake Implementation                                  */
/* ------------------------------------------------------------------ */

void ts_noise_ik_init(ts_noise_ik_t *state,
                      const uint8_t *static_priv,
                      const uint8_t *static_pub,
                      const uint8_t *remote_static)
{
    memset(state, 0, sizeof(*state));

    /* Copy keys */
    memcpy(state->s_priv, static_priv, TS_KEY_LEN);
    memcpy(state->s_pub, static_pub, TS_KEY_LEN);
    memcpy(state->rs, remote_static, TS_KEY_LEN);

    /*
     * Initialize symmetric state:
     *   h = HASH(protocol_name)
     *   ck = h
     *
     * If protocol_name.len <= HASH_LEN, pad with zeros.
     * If protocol_name.len > HASH_LEN, h = HASH(protocol_name).
     * "Noise_IK_25519_ChaChaPoly_BLAKE2s" = 34 bytes > 32, so we hash it.
     */
    blake2s(state->h, TS_HASH_LEN, NULL, 0,
            NOISE_PROTOCOL_NAME, strlen(NOISE_PROTOCOL_NAME));
    memcpy(state->ck, state->h, TS_HASH_LEN);

    /* Mix in prologue: h = HASH(h || prologue) */
    mix_hash(state->h, (const uint8_t *)TS_PROLOGUE, strlen(TS_PROLOGUE));

    /* Pre-message pattern: <- s (responder's static is known) */
    /* h = HASH(h || rs) */
    mix_hash(state->h, state->rs, TS_KEY_LEN);
}

int ts_noise_ik_write_msg1(ts_noise_ik_t *state, uint8_t *out,
                            const uint8_t *payload, size_t payload_len)
{
    uint8_t dh_result[TS_KEY_LEN];
    uint8_t k[TS_KEY_LEN];
    uint8_t *p = out;

    /* -> e: Generate ephemeral keypair */
    ts_keygen(state->e_priv, state->e_pub);

    /* Write ephemeral public key (32 bytes, plaintext) */
    memcpy(p, state->e_pub, TS_KEY_LEN);
    mix_hash(state->h, state->e_pub, TS_KEY_LEN);
    p += TS_KEY_LEN;

    /* -> es: DH(e, rs) */
    x25519(dh_result, state->e_priv, state->rs, 1);
    ts_hkdf2(state->ck, k, state->ck, dh_result, TS_KEY_LEN);

    /* -> s: Encrypt our static public key (32 + 16 MAC = 48 bytes) */
    ts_aead_encrypt_be(p, state->s_pub, TS_KEY_LEN,
                       state->h, TS_HASH_LEN, 0, k);
    mix_hash(state->h, p, TS_KEY_LEN + TS_AEAD_TAG_LEN);
    p += TS_KEY_LEN + TS_AEAD_TAG_LEN;

    /* -> ss: DH(s, rs) */
    x25519(dh_result, state->s_priv, state->rs, 1);
    ts_hkdf2(state->ck, k, state->ck, dh_result, TS_KEY_LEN);

    /* Encrypt payload (payload_len + 16 MAC bytes) */
    ts_aead_encrypt_be(p, payload, payload_len,
                       state->h, TS_HASH_LEN, 0, k);
    mix_hash(state->h, p, payload_len + TS_AEAD_TAG_LEN);
    p += payload_len + TS_AEAD_TAG_LEN;

    /* Cleanup */
    crypto_zero(dh_result, sizeof(dh_result));
    crypto_zero(k, sizeof(k));

    return (int)(p - out); /* 96 + payload_len */
}

int ts_noise_ik_read_msg2(ts_noise_ik_t *state,
                          const uint8_t *msg, size_t msg_len)
{
    uint8_t dh_result[TS_KEY_LEN];
    uint8_t k[TS_KEY_LEN];
    uint8_t re[TS_KEY_LEN];
    const uint8_t *p = msg;

    if (msg_len < TS_NOISE_MSG2_LEN)
        return -1;

    /* <- e: Read responder's ephemeral public key (32 bytes) */
    memcpy(re, p, TS_KEY_LEN);
    mix_hash(state->h, re, TS_KEY_LEN);
    p += TS_KEY_LEN;

    /* <- ee: DH(e_init, e_resp) */
    x25519(dh_result, state->e_priv, re, 1);
    ts_hkdf2(state->ck, k, state->ck, dh_result, TS_KEY_LEN);

    /* <- se: DH(s_init, e_resp) */
    x25519(dh_result, state->s_priv, re, 1);
    ts_hkdf2(state->ck, k, state->ck, dh_result, TS_KEY_LEN);

    /* Decrypt empty payload (16-byte ciphertext = 0 plaintext + MAC) */
    /* Verify MAC to confirm handshake integrity */
    if (!ts_aead_decrypt_be(NULL, p, TS_AEAD_TAG_LEN,
                            state->h, TS_HASH_LEN, 0, k)) {
        crypto_zero(dh_result, sizeof(dh_result));
        crypto_zero(k, sizeof(k));
        return -1;
    }
    mix_hash(state->h, p, TS_AEAD_TAG_LEN);

    state->handshake_complete = true;

    /* Cleanup */
    crypto_zero(dh_result, sizeof(dh_result));
    crypto_zero(k, sizeof(k));
    crypto_zero(re, sizeof(re));

    return 0;
}

int ts_noise_ik_split(ts_noise_ik_t *state)
{
    if (!state->handshake_complete)
        return -1;

    /* Derive transport keys:
     * k1, k2 = HKDF2(ck, empty)
     * Initiator: send = k1, recv = k2
     */
    ts_hkdf2(state->send_key, state->recv_key,
             state->ck, NULL, 0);

    state->send_nonce = 0;
    state->recv_nonce = 0;

    /* Clear sensitive handshake state */
    crypto_zero(state->ck, sizeof(state->ck));
    crypto_zero(state->h, sizeof(state->h));
    crypto_zero(state->e_priv, sizeof(state->e_priv));

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Noise Transport Encryption                                         */
/* ------------------------------------------------------------------ */

int ts_noise_encrypt(ts_noise_ik_t *state,
                     uint8_t *dst, const uint8_t *src, size_t src_len)
{
    ts_aead_encrypt_be(dst, src, src_len, NULL, 0,
                       state->send_nonce, state->send_key);
    state->send_nonce++;
    return (int)(src_len + TS_AEAD_TAG_LEN);
}

int ts_noise_decrypt(ts_noise_ik_t *state,
                     uint8_t *dst, const uint8_t *src, size_t src_len)
{
    if (src_len < TS_AEAD_TAG_LEN)
        return -1;

    if (!ts_aead_decrypt_be(dst, src, src_len, NULL, 0,
                            state->recv_nonce, state->recv_key)) {
        return -1;
    }
    state->recv_nonce++;
    return (int)(src_len - TS_AEAD_TAG_LEN);
}
