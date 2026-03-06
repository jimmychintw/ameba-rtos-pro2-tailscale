/*
 * ts_nacl.c — NaCl crypto_box (X25519 + XSalsa20-Poly1305)
 *
 * New code: HSalsa20, Salsa20 core
 * Reused:   X25519 (wireguard), Poly1305 (poly1305-donna)
 */

#include "ts_nacl.h"
#include <string.h>
#include "x25519.h"
#include "poly1305-donna.h"

/* ------------------------------------------------------------------ */
/*  Endian helpers                                                     */
/* ------------------------------------------------------------------ */

static inline uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* ------------------------------------------------------------------ */
/*  Salsa20 core                                                       */
/* ------------------------------------------------------------------ */

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

/* Salsa20 sigma: "expand 32-byte k" */
static const uint32_t SIGMA[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

/*
 * Salsa20 double round on state x[16].
 * 10 double rounds = 20 rounds total.
 */
static void salsa20_rounds(uint32_t x[16])
{
    for (int i = 0; i < 10; i++) {
        /* Column round */
        x[ 4] ^= ROTL32(x[ 0]+x[12],  7);
        x[ 8] ^= ROTL32(x[ 4]+x[ 0],  9);
        x[12] ^= ROTL32(x[ 8]+x[ 4], 13);
        x[ 0] ^= ROTL32(x[12]+x[ 8], 18);
        x[ 9] ^= ROTL32(x[ 5]+x[ 1],  7);
        x[13] ^= ROTL32(x[ 9]+x[ 5],  9);
        x[ 1] ^= ROTL32(x[13]+x[ 9], 13);
        x[ 5] ^= ROTL32(x[ 1]+x[13], 18);
        x[14] ^= ROTL32(x[10]+x[ 6],  7);
        x[ 2] ^= ROTL32(x[14]+x[10],  9);
        x[ 6] ^= ROTL32(x[ 2]+x[14], 13);
        x[10] ^= ROTL32(x[ 6]+x[ 2], 18);
        x[ 3] ^= ROTL32(x[15]+x[11],  7);
        x[ 7] ^= ROTL32(x[ 3]+x[15],  9);
        x[11] ^= ROTL32(x[ 7]+x[ 3], 13);
        x[15] ^= ROTL32(x[11]+x[ 7], 18);
        /* Row round */
        x[ 1] ^= ROTL32(x[ 0]+x[ 3],  7);
        x[ 2] ^= ROTL32(x[ 1]+x[ 0],  9);
        x[ 3] ^= ROTL32(x[ 2]+x[ 1], 13);
        x[ 0] ^= ROTL32(x[ 3]+x[ 2], 18);
        x[ 6] ^= ROTL32(x[ 5]+x[ 4],  7);
        x[ 7] ^= ROTL32(x[ 6]+x[ 5],  9);
        x[ 4] ^= ROTL32(x[ 7]+x[ 6], 13);
        x[ 5] ^= ROTL32(x[ 4]+x[ 7], 18);
        x[11] ^= ROTL32(x[10]+x[ 9],  7);
        x[ 8] ^= ROTL32(x[11]+x[10],  9);
        x[ 9] ^= ROTL32(x[ 8]+x[11], 13);
        x[10] ^= ROTL32(x[ 9]+x[ 8], 18);
        x[12] ^= ROTL32(x[15]+x[14],  7);
        x[13] ^= ROTL32(x[12]+x[15],  9);
        x[14] ^= ROTL32(x[13]+x[12], 13);
        x[15] ^= ROTL32(x[14]+x[13], 18);
    }
}

/*
 * HSalsa20: derive 32-byte subkey from 32-byte key + 16-byte nonce.
 * Output = state[0,5,10,15,6,7,8,9] after 20 rounds (no final add).
 */
static void hsalsa20(uint8_t out[32], const uint8_t nonce[16],
                     const uint8_t key[32])
{
    uint32_t x[16];
    x[ 0] = SIGMA[0];
    x[ 1] = load32_le(key +  0);
    x[ 2] = load32_le(key +  4);
    x[ 3] = load32_le(key +  8);
    x[ 4] = load32_le(key + 12);
    x[ 5] = SIGMA[1];
    x[ 6] = load32_le(nonce +  0);
    x[ 7] = load32_le(nonce +  4);
    x[ 8] = load32_le(nonce +  8);
    x[ 9] = load32_le(nonce + 12);
    x[10] = SIGMA[2];
    x[11] = load32_le(key + 16);
    x[12] = load32_le(key + 20);
    x[13] = load32_le(key + 24);
    x[14] = load32_le(key + 28);
    x[15] = SIGMA[3];

    salsa20_rounds(x);

    store32_le(out +  0, x[ 0]);
    store32_le(out +  4, x[ 5]);
    store32_le(out +  8, x[10]);
    store32_le(out + 12, x[15]);
    store32_le(out + 16, x[ 6]);
    store32_le(out + 20, x[ 7]);
    store32_le(out + 24, x[ 8]);
    store32_le(out + 28, x[ 9]);
}

/*
 * Salsa20 block: generate 64-byte keystream block.
 * key=32 bytes, nonce=8 bytes, counter=block number.
 */
static void salsa20_block(uint8_t out[64], const uint8_t key[32],
                           const uint8_t nonce[8], uint64_t counter)
{
    uint32_t s[16], x[16];
    s[ 0] = SIGMA[0];
    s[ 1] = load32_le(key +  0);
    s[ 2] = load32_le(key +  4);
    s[ 3] = load32_le(key +  8);
    s[ 4] = load32_le(key + 12);
    s[ 5] = SIGMA[1];
    s[ 6] = load32_le(nonce + 0);
    s[ 7] = load32_le(nonce + 4);
    s[ 8] = (uint32_t)counter;
    s[ 9] = (uint32_t)(counter >> 32);
    s[10] = SIGMA[2];
    s[11] = load32_le(key + 16);
    s[12] = load32_le(key + 20);
    s[13] = load32_le(key + 24);
    s[14] = load32_le(key + 28);
    s[15] = SIGMA[3];

    memcpy(x, s, 64);
    salsa20_rounds(x);

    /* Add initial state (Salsa20, not HSalsa20) */
    for (int i = 0; i < 16; i++)
        store32_le(out + i * 4, x[i] + s[i]);
}

/* ------------------------------------------------------------------ */
/*  XSalsa20-Poly1305                                                  */
/* ------------------------------------------------------------------ */

/*
 * XSalsa20-Poly1305 encrypt (secretbox_easy format).
 * Output: mac(16) || ciphertext(ptlen).
 */
static int xsalsa20poly1305_encrypt(uint8_t *ct, const uint8_t *pt,
                                     size_t ptlen, const uint8_t nonce[24],
                                     const uint8_t key[32])
{
    /* Derive XSalsa20 subkey */
    uint8_t subkey[32];
    hsalsa20(subkey, nonce, key);

    /* Generate block 0 for Poly1305 key + first 32 bytes of stream */
    uint8_t block0[64];
    salsa20_block(block0, subkey, nonce + 16, 0);

    /* XOR plaintext with keystream (starting at byte 32 of block 0) */
    uint8_t *ctext = ct + NACL_BOX_MACBYTES;
    size_t pos = 0;
    size_t avail = 32;  /* bytes 32-63 of block0 */
    size_t use = (ptlen < avail) ? ptlen : avail;
    for (size_t i = 0; i < use; i++)
        ctext[i] = pt[i] ^ block0[32 + i];
    pos = use;

    uint64_t counter = 1;
    while (pos < ptlen) {
        uint8_t block[64];
        salsa20_block(block, subkey, nonce + 16, counter++);
        avail = 64;
        use = ((ptlen - pos) < avail) ? (ptlen - pos) : avail;
        for (size_t i = 0; i < use; i++)
            ctext[pos + i] = pt[pos + i] ^ block[i];
        pos += use;
    }

    /* Poly1305 MAC over ciphertext, key = block0[0:32] */
    poly1305_context poly;
    poly1305_init(&poly, block0);
    poly1305_update(&poly, ctext, ptlen);
    poly1305_finish(&poly, ct);  /* MAC goes at front */

    memset(subkey, 0, 32);
    memset(block0, 0, 64);
    return 0;
}

/*
 * XSalsa20-Poly1305 decrypt (secretbox_open_easy format).
 * Input: mac(16) || ciphertext.
 */
static int xsalsa20poly1305_decrypt(uint8_t *pt, const uint8_t *ct,
                                     size_t ctlen, const uint8_t nonce[24],
                                     const uint8_t key[32])
{
    if (ctlen < NACL_BOX_MACBYTES) return -1;

    size_t ptlen = ctlen - NACL_BOX_MACBYTES;
    const uint8_t *mac = ct;
    const uint8_t *ctext = ct + NACL_BOX_MACBYTES;

    /* Derive subkey + block0 */
    uint8_t subkey[32];
    hsalsa20(subkey, nonce, key);

    uint8_t block0[64];
    salsa20_block(block0, subkey, nonce + 16, 0);

    /* Verify MAC */
    uint8_t computed_mac[16];
    poly1305_context poly;
    poly1305_init(&poly, block0);
    poly1305_update(&poly, ctext, ptlen);
    poly1305_finish(&poly, computed_mac);

    int diff = 0;
    for (int i = 0; i < 16; i++)
        diff |= mac[i] ^ computed_mac[i];
    if (diff != 0) {
        memset(subkey, 0, 32);
        memset(block0, 0, 64);
        return -1;
    }

    /* Decrypt: XOR ciphertext with keystream */
    size_t pos = 0;
    size_t avail = 32;
    size_t use = (ptlen < avail) ? ptlen : avail;
    for (size_t i = 0; i < use; i++)
        pt[i] = ctext[i] ^ block0[32 + i];
    pos = use;

    uint64_t counter = 1;
    while (pos < ptlen) {
        uint8_t block[64];
        salsa20_block(block, subkey, nonce + 16, counter++);
        avail = 64;
        use = ((ptlen - pos) < avail) ? (ptlen - pos) : avail;
        for (size_t i = 0; i < use; i++)
            pt[pos + i] = ctext[pos + i] ^ block[i];
        pos += use;
    }

    memset(subkey, 0, 32);
    memset(block0, 0, 64);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public API: NaCl box                                               */
/* ------------------------------------------------------------------ */

void nacl_box_beforenm(uint8_t shared[32],
                        const uint8_t pk[32], const uint8_t sk[32])
{
    uint8_t s[32];
    x25519(s, sk, pk, 1);  /* ECDH with clamping */

    /* HSalsa20(shared_secret, zeros16) → box key */
    uint8_t zero16[16];
    memset(zero16, 0, 16);
    hsalsa20(shared, zero16, s);
    memset(s, 0, 32);
}

int nacl_box_easy_afternm(uint8_t *ct, const uint8_t *pt, size_t ptlen,
                           const uint8_t nonce[24], const uint8_t shared[32])
{
    return xsalsa20poly1305_encrypt(ct, pt, ptlen, nonce, shared);
}

int nacl_box_open_easy_afternm(uint8_t *pt, const uint8_t *ct, size_t ctlen,
                                const uint8_t nonce[24],
                                const uint8_t shared[32])
{
    return xsalsa20poly1305_decrypt(pt, ct, ctlen, nonce, shared);
}

int nacl_box_easy(uint8_t *ct, const uint8_t *pt, size_t ptlen,
                   const uint8_t nonce[24],
                   const uint8_t pk[32], const uint8_t sk[32])
{
    uint8_t shared[32];
    nacl_box_beforenm(shared, pk, sk);
    int ret = nacl_box_easy_afternm(ct, pt, ptlen, nonce, shared);
    memset(shared, 0, 32);
    return ret;
}

int nacl_box_open_easy(uint8_t *pt, const uint8_t *ct, size_t ctlen,
                        const uint8_t nonce[24],
                        const uint8_t pk[32], const uint8_t sk[32])
{
    uint8_t shared[32];
    nacl_box_beforenm(shared, pk, sk);
    int ret = nacl_box_open_easy_afternm(pt, ct, ctlen, nonce, shared);
    memset(shared, 0, 32);
    return ret;
}
