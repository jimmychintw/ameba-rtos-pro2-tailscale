/*
 * ts_nacl.h — NaCl crypto_box for DISCO protocol
 *
 * Implements X25519 + XSalsa20-Poly1305 (NaCl box) using
 * existing WireGuard crypto primitives (x25519, poly1305-donna).
 * Only HSalsa20 + Salsa20 are new implementations.
 */

#ifndef TS_NACL_H
#define TS_NACL_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NACL_BOX_MACBYTES   16
#define NACL_BOX_NONCEBYTES 24
#define NACL_BOX_KEYBYTES   32

/*
 * Compute shared key: out = HSalsa20(X25519(sk, pk), zero16).
 * Call once per peer, cache result.
 */
void nacl_box_beforenm(uint8_t shared[32],
                        const uint8_t pk[32], const uint8_t sk[32]);

/*
 * Encrypt with pre-computed shared key.
 * ct must have room for ptlen + 16 bytes (MAC || ciphertext).
 * Returns 0 on success.
 */
int nacl_box_easy_afternm(uint8_t *ct, const uint8_t *pt, size_t ptlen,
                           const uint8_t nonce[24], const uint8_t shared[32]);

/*
 * Decrypt with pre-computed shared key.
 * ctlen must be >= 16. pt receives ctlen - 16 bytes.
 * Returns 0 on success, -1 on MAC failure.
 */
int nacl_box_open_easy_afternm(uint8_t *pt, const uint8_t *ct, size_t ctlen,
                                const uint8_t nonce[24],
                                const uint8_t shared[32]);

/* All-in-one encrypt */
int nacl_box_easy(uint8_t *ct, const uint8_t *pt, size_t ptlen,
                   const uint8_t nonce[24],
                   const uint8_t pk[32], const uint8_t sk[32]);

/* All-in-one decrypt */
int nacl_box_open_easy(uint8_t *pt, const uint8_t *ct, size_t ctlen,
                        const uint8_t nonce[24],
                        const uint8_t pk[32], const uint8_t sk[32]);

#ifdef __cplusplus
}
#endif

#endif /* TS_NACL_H */
