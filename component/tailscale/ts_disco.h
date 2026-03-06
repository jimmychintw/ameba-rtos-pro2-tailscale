/*
 * ts_disco.h — Tailscale DISCO protocol + STUN endpoint discovery
 *
 * DISCO: NaCl-box encrypted Ping/Pong over UDP for NAT traversal.
 * STUN:  RFC 8489 Binding Request to discover public IP:port.
 *
 * Packet format:
 *   [0-5]   Magic "TS💬" (6 bytes)
 *   [6-37]  Sender disco public key (32 bytes)
 *   [38-61] NaCl nonce (24 bytes)
 *   [62+]   NaCl box ciphertext (MAC(16) + encrypted payload)
 */

#ifndef TS_DISCO_H
#define TS_DISCO_H

#include <stdint.h>
#include <stdbool.h>
#include "peer_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

/* DISCO magic: "TS" + UTF-8 💬 */
#define DISCO_MAGIC_LEN  6
extern const uint8_t DISCO_MAGIC[DISCO_MAGIC_LEN];

/* DISCO header: magic(6) + disco_pub(32) + nonce(24) = 62 */
#define DISCO_HDR_LEN    62

/* Message types */
#define DISCO_TYPE_PING          0x01
#define DISCO_TYPE_PONG          0x02
#define DISCO_TYPE_CALLMEMAYBE   0x03

/* Ping TxID length */
#define DISCO_TXID_LEN   12

/* Max DISCO packet size */
#define DISCO_MAX_PKT    256

/* STUN constants */
#define STUN_MAGIC_COOKIE  0x2112A442
#define STUN_HDR_LEN       20
#define STUN_TXID_LEN      12
#define STUN_DEFAULT_PORT  3478

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

/* Callback for non-DISCO packets received on DISCO socket (WG direct) */
typedef void (*disco_raw_rx_cb_t)(const uint8_t *pkt, size_t pkt_len,
                                    uint32_t src_ip_be, uint16_t src_port,
                                    void *ctx);

/* Discovered endpoint (from STUN or DISCO Pong) */
typedef struct {
    char     ip[PM_MAX_IP_LEN];
    uint16_t port;
    bool     valid;
    uint32_t rtt_ms;    /* Round-trip time in ms */
} disco_endpoint_t;

/* DISCO session state */
typedef struct {
    peer_manager_t *pm;           /* Peer manager (not owned) */

    /* UDP socket for DISCO/STUN */
    int sock_fd;

    /* Our public endpoint (discovered via STUN) */
    disco_endpoint_t self_endpoint;

    /* Pending ping tracking */
    uint8_t  pending_txid[DISCO_TXID_LEN];
    int      pending_peer_idx;     /* Which peer we pinged */
    uint32_t pending_send_ms;      /* Tick when ping was sent */
    bool     pending_valid;

    /* STUN state */
    uint8_t  stun_txid[STUN_TXID_LEN];
    bool     stun_pending;

    /* DERP relay for sending DISCO via DERP (set by disco_set_derp) */
    void    *derp_client;          /* derp_client_t* (opaque) */

    /* WG packet injection callback (for direct WG packets on DISCO socket) */
    disco_raw_rx_cb_t raw_rx_cb;
    void             *raw_rx_ctx;

    /* Direct-send queue: output hook (tcpip_thread) enqueues WG packets;
     * DISCO task drains and sends via DISCO socket.  Avoids deadlock
     * from calling BSD sendto() inside tcpip_thread. */
    void    *send_queue;           /* FreeRTOS QueueHandle_t */

    /* Task handle */
    void    *task_handle;          /* FreeRTOS task */
    bool     running;
} disco_state_t;

/* Max WG packet in direct-send queue */
#define DISCO_DIRECT_PKT_MAX  1500

/* Queue item for direct WG send */
typedef struct {
    uint32_t dst_ip_be;            /* Network byte order */
    uint16_t dst_port;             /* Host byte order */
    uint16_t len;
    uint8_t  data[DISCO_DIRECT_PKT_MAX];
} disco_direct_send_t;

/*
 * Queue a WG packet for sending via the DISCO socket.
 * Safe to call from any thread (including tcpip_thread).
 * @return 0 on success, -1 if queue full
 */
int disco_queue_direct_send(disco_state_t *ds,
                             uint32_t dst_ip_be, uint16_t dst_port,
                             const uint8_t *data, uint16_t len);

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

/*
 * Initialize DISCO state.
 */
void disco_init(disco_state_t *ds, peer_manager_t *pm);

/*
 * Set DERP client for DISCO relay (dual-path: direct UDP + DERP).
 * Must be called after DERP is connected.
 */
void disco_set_derp(disco_state_t *ds, void *derp_client);

/*
 * Set callback for non-DISCO packets (WG direct path).
 * Called when the DISCO socket receives a packet that isn't DISCO or STUN.
 */
void disco_set_raw_rx(disco_state_t *ds, disco_raw_rx_cb_t cb, void *ctx);

/*
 * Check if a UDP packet is a DISCO packet (starts with magic).
 */
bool disco_is_disco_packet(const uint8_t *data, size_t len);

/*
 * Send a DISCO Ping to a peer.
 * @param peer_idx  Index in pm->peers[]
 * @param dst_ip    Destination IP string
 * @param dst_port  Destination UDP port
 * @return 0 on success, -1 on error
 */
int disco_send_ping(disco_state_t *ds, int peer_idx,
                     const char *dst_ip, uint16_t dst_port);

/*
 * Handle an incoming DISCO packet (decrypt + dispatch).
 * If it's a Ping, sends a Pong automatically.
 * If it's a Pong, updates peer endpoint via peer_manager.
 * @return 0 on success, -1 on error
 */
int disco_handle_packet(disco_state_t *ds,
                         const uint8_t *pkt, size_t pkt_len,
                         const char *src_ip, uint16_t src_port);

/*
 * Handle a DISCO packet received via DERP relay.
 * If it's a Ping, builds a Pong and writes it to resp_out.
 * @param src_node_key  32B node key of the sender (from DERP RecvPacket)
 * @param pkt           Raw DISCO packet (magic + disco_pub + nonce + box)
 * @param pkt_len       Length of DISCO packet
 * @param resp_out      Buffer for response DISCO packet (must be >= DISCO_MAX_PKT)
 * @param resp_len      Output: length of response packet (0 if no response needed)
 * @return 0 on success, -1 on error
 */
int disco_handle_derp_packet(disco_state_t *ds,
                              const uint8_t *src_node_key,
                              const uint8_t *pkt, size_t pkt_len,
                              uint8_t *resp_out, size_t *resp_len);

/*
 * Send a STUN Binding Request to discover our public endpoint.
 * @param stun_host  STUN server IP string
 * @param stun_port  STUN server port (typically 3478)
 * @return 0 on success, -1 on error
 */
int disco_send_stun(disco_state_t *ds,
                     const char *stun_host, uint16_t stun_port);

/*
 * Parse a STUN Binding Response.
 * Updates ds->self_endpoint on success.
 * @return 0 on success, -1 on error
 */
int disco_parse_stun_response(disco_state_t *ds,
                                const uint8_t *data, size_t len);

/*
 * Start the DISCO/STUN background task.
 * Runs STUN discovery, then sends DISCO pings to all peers.
 * @param stun_host  STUN server IP (NULL to skip STUN)
 * @return 0 on success
 */
int disco_start(disco_state_t *ds, const char *stun_host);

/*
 * Stop the DISCO task and close socket.
 */
void disco_stop(disco_state_t *ds);

#ifdef __cplusplus
}
#endif

#endif /* TS_DISCO_H */
