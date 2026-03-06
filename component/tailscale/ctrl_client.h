/*
 * ctrl_client.h — Tailscale control plane client
 *
 * Handles:
 *   - GET /key?v=130 to fetch server public key
 *   - WebSocket upgrade with Noise_IK handshake
 *   - Noise transport (encrypt/decrypt) over Controlbase + WebSocket
 *
 * Usage:
 *   ctrl_client_t c;
 *   ctrl_client_init(&c);
 *   ctrl_client_set_machine_key(&c, priv, pub);
 *   ctrl_client_fetch_key(&c, "headscale.example.com", 8080);
 *   ctrl_client_connect(&c, "headscale.example.com", 8080);
 *   // Now send/recv through Noise transport
 *   ctrl_client_send(&c, data, len);
 *   ctrl_client_recv(&c, buf, sizeof(buf), 5000);
 *   ctrl_client_close(&c);
 */

#ifndef CTRL_CLIENT_H
#define CTRL_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "ts_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

/* Controlbase message types */
#define CB_MSG_INIT      0x01
#define CB_MSG_RESPONSE  0x02
#define CB_MSG_ERROR     0x03
#define CB_MSG_RECORD    0x04

/* Controlbase version */
#define CB_VERSION       0x0001

/* Controlbase header sizes */
#define CB_CLIENT_HDR_LEN  5   /* version(2) + type(1) + length(2) — init only */
#define CB_SERVER_HDR_LEN  3   /* type(1) + length(2)                          */

/* Buffer sizes — must hold a full HTTP/2 frame (up to 16384 payload) after
 * Noise encryption (16 tag) + Controlbase header (3) + WebSocket framing (~6) */
#define CTRL_RECV_BUF_SIZE   20480
#define CTRL_MAX_SEND_PT     4608  /* 4096 HTTP/2 payload + 9 header + overhead */

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    /* TCP socket file descriptor (-1 if not connected) */
    int sock_fd;

    /* Noise handshake / transport state */
    ts_noise_ik_t noise;

    /* Server public key (from GET /key?v=130) */
    uint8_t server_key[TS_KEY_LEN];
    bool    server_key_valid;

    /* Machine key pair */
    uint8_t machine_priv[TS_KEY_LEN];
    uint8_t machine_pub[TS_KEY_LEN];

    /* Node public key (for early payload in Noise handshake) */
    uint8_t node_pub[TS_KEY_LEN];

    /* Connection state flags */
    bool connected;    /* WebSocket upgraded */
    bool noise_ready;  /* Noise transport active */

    /* TLS (for official Tailscale servers over HTTPS) */
    bool  use_tls;     /* true → wrap TCP in TLS */
    void *tls_ctx;     /* opaque tls_state_t* (heap) */

    /* Server host/port (saved for HTTP Host header) */
    char     host[128];
    uint16_t port;

    /* Receive buffer (accumulates partial WebSocket frames) */
    uint8_t recv_buf[CTRL_RECV_BUF_SIZE];
    size_t  recv_buf_len;
} ctrl_client_t;

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

/*
 * Initialize a control client (zero state).
 */
void ctrl_client_init(ctrl_client_t *c);

/*
 * Set machine key pair (call before connect).
 */
void ctrl_client_set_machine_key(ctrl_client_t *c,
                                  const uint8_t *priv,
                                  const uint8_t *pub);

/*
 * Set node public key (for Noise handshake early payload).
 */
void ctrl_client_set_node_key(ctrl_client_t *c, const uint8_t *pub);

/*
 * Fetch server public key via GET /key?v=130.
 * Opens a TCP connection, sends request, parses JSON, closes connection.
 * Result stored in c->server_key.
 *
 * @return 0 on success, -1 on error
 */
int ctrl_client_fetch_key(ctrl_client_t *c,
                           const char *host, uint16_t port);

/*
 * Connect to control server and complete Noise handshake:
 *   1. TCP connect
 *   2. WebSocket upgrade (Noise init in X-Tailscale-Handshake query param)
 *   3. Receive and verify Noise response
 *   4. Derive transport keys (split)
 *
 * Must call set_machine_key() and fetch_key() first.
 *
 * @return 0 on success, -1 on error
 */
int ctrl_client_connect(ctrl_client_t *c,
                         const char *host, uint16_t port);

/*
 * Send plaintext through Noise-encrypted transport.
 * Pipeline: plaintext → Noise encrypt → Controlbase record → WS binary → TCP
 *
 * @return plaintext bytes sent, or -1 on error
 */
int ctrl_client_send(ctrl_client_t *c,
                      const uint8_t *data, size_t len);

/*
 * Receive and decrypt from Noise transport.
 * Pipeline: TCP → WS frame → Controlbase record → Noise decrypt → plaintext
 *
 * @return plaintext bytes received, 0 on timeout, -1 on error
 */
int ctrl_client_recv(ctrl_client_t *c,
                      uint8_t *buf, size_t buf_len,
                      int timeout_ms);

/*
 * Enable TLS for this client (call before fetch_key/connect).
 * Required for official Tailscale servers (controlplane.tailscale.com:443).
 */
void ctrl_client_enable_tls(ctrl_client_t *c);

/*
 * Close connection and zero sensitive state.
 */
void ctrl_client_close(ctrl_client_t *c);

/* ------------------------------------------------------------------ */
/*  Shared TLS/TCP helpers (used by ctrl_client and ts_derp)           */
/* ------------------------------------------------------------------ */

/* TCP connect with DNS resolution. Returns socket fd, or -1 on error. */
int ts_tcp_connect(const char *host, uint16_t port);

/* Create TLS state and perform handshake. Returns opaque tls ptr, or NULL. */
void *ts_tls_handshake(int fd, const char *hostname);

/* Send all bytes through TLS. Returns bytes sent, or -1 on error. */
int ts_tls_send(void *tls, const uint8_t *buf, size_t len);

/* Receive from TLS (matches recv() semantics). Returns bytes, 0 on close, -1 on error. */
int ts_tls_recv(void *tls, uint8_t *buf, size_t len);

/* Close TLS and free state. */
void ts_tls_close(void *tls);

/* Set socket receive timeout. */
void ts_tcp_set_timeout(int fd, int timeout_ms);

/*
 * Non-blocking TLS recv — distinguishes timeout from error.
 * Returns: >0 bytes read, 0 connection closed, -1 error, -2 timeout/WANT_READ.
 */
int ts_tls_recv_nonblock(void *tls, uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CTRL_CLIENT_H */
