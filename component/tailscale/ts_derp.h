/*
 * ts_derp.h — DERP relay client for Tailscale
 *
 * Connects to a DERP relay server (TLS + HTTP upgrade) and provides
 * bidirectional WireGuard packet relay for NAT traversal.
 *
 * Thread safety: All TLS I/O is done exclusively in the recv task.
 * derp_send_packet() queues requests that the recv task processes.
 */

#ifndef TS_DERP_H
#define TS_DERP_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DERP frame types */
#define DERP_FRAME_SERVER_KEY     0x01
#define DERP_FRAME_CLIENT_INFO    0x02
#define DERP_FRAME_SERVER_INFO    0x03
#define DERP_FRAME_SEND_PACKET    0x04
#define DERP_FRAME_RECV_PACKET    0x05
#define DERP_FRAME_KEEP_ALIVE     0x06
#define DERP_FRAME_NOTE_PREFERRED 0x07
#define DERP_FRAME_PEER_GONE      0x08
#define DERP_FRAME_PING           0x12
#define DERP_FRAME_PONG           0x13

/* DERP magic (8 bytes) in ServerKey frame */
#define DERP_MAGIC  "DERP\xf0\x9f\x94\x91"
#define DERP_MAGIC_LEN 8

/* Send queue depth */
#define DERP_SEND_QUEUE_DEPTH  8

/* Receive callback: called from recv task with src_key (32B) + WG packet */
typedef void (*derp_recv_cb_t)(const uint8_t *src_key,
                                const uint8_t *pkt, size_t pkt_len,
                                void *ctx);

typedef struct {
    /* TLS connection state */
    int        sock_fd;
    void      *tls;           /* tls_state_t* (opaque) */

    /* Keys */
    uint8_t    node_priv[32]; /* our node private key (for NaCl box) */
    uint8_t    node_pub[32];  /* our node public key */
    uint8_t    server_pub[32]; /* DERP server public key (from ServerKey frame) */

    /* Connection info */
    int        region_id;
    char       hostname[64];
    uint16_t   port;
    bool       connected;
    bool       ready;

    /* Receive callback */
    derp_recv_cb_t recv_cb;
    void          *recv_ctx;

    /* Recv task + send queue */
    void      *task_handle;   /* TaskHandle_t */
    void      *send_queue;    /* QueueHandle_t — queue of derp_send_req_t* */
    bool       running;

    /* Reconnect state */
    uint32_t   backoff_ms;
    int        consecutive_failures;
} derp_client_t;

/* Initialize DERP client (zeros state) */
void derp_init(derp_client_t *dc);

/*
 * Connect to DERP server and complete handshake.
 * TCP + TLS + HTTP upgrade + ServerKey/ClientInfo/ServerInfo exchange.
 * @return 0 on success, -1 on error
 */
int derp_connect(derp_client_t *dc, const char *hostname, uint16_t port);

/*
 * Queue a WireGuard packet for sending to a peer via DERP relay.
 * Thread-safe: can be called from any context (ISR-safe with zero timeout).
 * @param dst_key  32-byte destination node public key
 * @param pkt      WireGuard packet data (copied internally)
 * @param pkt_len  WireGuard packet length
 * @return 0 on success (queued), -1 on error (queue full or not ready)
 */
int derp_send_packet(derp_client_t *dc, const uint8_t *dst_key,
                      const uint8_t *pkt, size_t pkt_len);

/* Start background recv task (reads frames, dispatches callbacks) */
void derp_start(derp_client_t *dc);

/* Signal recv task to stop */
void derp_stop(derp_client_t *dc);

/* Close connection and free resources */
void derp_close(derp_client_t *dc);

#ifdef __cplusplus
}
#endif

#endif /* TS_DERP_H */
