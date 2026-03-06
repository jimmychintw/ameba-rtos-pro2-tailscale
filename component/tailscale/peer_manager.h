/*
 * peer_manager.h — Tailscale peer management + WireGuard integration
 *
 * Manages:
 *   - Key generation (machine, node, disco)
 *   - RegisterRequest / MapRequest JSON construction
 *   - MapResponse parsing (self IP, peers, endpoints)
 *   - WireGuard interface setup and peer configuration
 */

#ifndef PEER_MANAGER_H
#define PEER_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "ts_crypto.h"
#include "lwip/ip_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define PM_MAX_PEERS         4
#define PM_MAX_IP_LEN       20   /* "100.64.0.xxx" + null */
#define PM_MAX_ENDPOINT_LEN 48   /* "xxx.xxx.xxx.xxx:65535" + null */
#define PM_MAX_HOSTNAME_LEN 32
#define PM_MAX_AUTHKEY_LEN  128
#define DERP_MAX_NODES       32

/* Tailscale capability version (Headscale minimum) */
#define TS_CAP_VERSION      49   /* Match ESP32 — server processes all fields with Stream=true */

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

/* Single DERP region node */
typedef struct {
    int      region_id;
    char     hostname[64];
    char     ipv4[16];
    uint16_t derp_port;    /* default 443 */
    uint16_t stun_port;    /* default 3478 */
} derp_node_t;

/* DERP server map (from MapResponse) */
typedef struct {
    derp_node_t nodes[DERP_MAX_NODES];
    int count;
} derp_map_t;

/* Discovered endpoint with latency (for bestAddr selection) */
#define TS_MAX_EP_PER_PEER 8
typedef struct {
    ip_addr_t addr;
    uint16_t  port;
    uint32_t  latency_ms;      /* From DISCO pong RTT */
    uint32_t  last_pong_tick;  /* xTaskGetTickCount when last pong received */
} ts_endpoint_t;

/* Single Tailscale peer (parsed from MapResponse) */
typedef struct {
    uint8_t  node_key[TS_KEY_LEN];      /* WireGuard public key (binary) */
    uint8_t  disco_key[TS_KEY_LEN];     /* Disco public key (binary) */
    char     ip[PM_MAX_IP_LEN];         /* Tailscale IP "100.64.0.x" */
    char     endpoint[PM_MAX_ENDPOINT_LEN]; /* "IP:port" string */
    uint16_t endpoint_port;
    char     hostname[PM_MAX_HOSTNAME_LEN];
    bool     valid;
    uint8_t  wg_peer_idx;               /* WG peer index (0xFF = not added) */
    int      derp_region;               /* DERP region ID (0 = none) */

    /* Direct path (learned from receiving WG packets on DISCO socket) */
    ip_addr_t direct_addr;              /* Peer's real LAN IP */
    uint16_t  direct_port;              /* Peer's real port */
    bool      direct_valid;             /* true if we've received direct WG traffic */
    uint32_t  direct_last_rx_tick;      /* xTaskGetTickCount of last direct WG rx */

    /* Discovered endpoints (from CallMeMaybe / DISCO pong) */
    ts_endpoint_t eps[TS_MAX_EP_PER_PEER];
    int      ep_count;
    int      best_ep_idx;               /* -1 = DERP, >=0 = direct endpoint index */
} ts_peer_t;

/* Peer manager state */
typedef struct {
    /* === Key pairs (Curve25519) === */
    uint8_t machine_priv[TS_KEY_LEN];
    uint8_t machine_pub[TS_KEY_LEN];
    uint8_t node_priv[TS_KEY_LEN];   /* = WireGuard private key */
    uint8_t node_pub[TS_KEY_LEN];    /* = WireGuard public key */
    uint8_t disco_priv[TS_KEY_LEN];
    uint8_t disco_pub[TS_KEY_LEN];

    /* === Device config === */
    char     hostname[PM_MAX_HOSTNAME_LEN];
    char     auth_key[PM_MAX_AUTHKEY_LEN];  /* Headscale pre-auth key */
    uint16_t wg_listen_port;                /* Default 41641 */

    /* === Self info === */
    char     self_ip[PM_MAX_IP_LEN];        /* Our Tailscale IP (from MapResponse) */
    char     lan_ip[PM_MAX_IP_LEN];         /* Our LAN IP (from DHCP) */
    char     public_ip[PM_MAX_IP_LEN];      /* Our public IP (from STUN) */
    uint16_t public_port;                   /* Our public port (from STUN) */
    bool     registered;

    /* === Peers (from MapResponse) === */
    ts_peer_t peers[PM_MAX_PEERS];
    int       peer_count;

    /* === DERP map (from MapResponse) === */
    derp_map_t derp_map;
    int        preferred_derp;          /* Our preferred DERP region ID */

    /* === WireGuard state === */
    void    *wg_ctx;      /* Opaque: ameba_wg_ctx_t* (avoids header dep) */
    bool     wg_up;
} peer_manager_t;

/* ------------------------------------------------------------------ */
/*  API: Initialization                                                */
/* ------------------------------------------------------------------ */

/* Initialize peer manager (zeros everything) */
void pm_init(peer_manager_t *pm);

/* Generate all three key pairs (machine, node, disco) */
void pm_generate_keys(peer_manager_t *pm);

/* Set device config */
void pm_set_hostname(peer_manager_t *pm, const char *hostname);
void pm_set_auth_key(peer_manager_t *pm, const char *auth_key);
void pm_set_lan_ip(peer_manager_t *pm, const char *ip);
void pm_set_public_endpoint(peer_manager_t *pm, const char *ip, uint16_t port);

/* ------------------------------------------------------------------ */
/*  API: JSON builders (returns length, or -1 on error)                */
/* ------------------------------------------------------------------ */

/*
 * Build RegisterRequest JSON.
 * Requires: keys generated, hostname set, auth_key set.
 */
int pm_build_register_json(peer_manager_t *pm, char *buf, size_t buf_len);

/*
 * Build MapRequest JSON.
 * @param streaming  true → Stream=true (long-poll, server ignores Hostinfo/Endpoints for v>=68)
 *                   false → Stream=false (update push, includes Hostinfo/Endpoints/DiscoKey)
 */
int pm_build_map_json(peer_manager_t *pm, char *buf, size_t buf_len);

/*
 * Build keepalive MapRequest JSON.
 * Includes KeepAlive=true, OmitPeers=true, Stream=true, and Endpoints.
 */
int pm_build_keepalive_json(peer_manager_t *pm, char *buf, size_t buf_len);

/* ------------------------------------------------------------------ */
/*  API: Response parsing                                              */
/* ------------------------------------------------------------------ */

/*
 * Parse RegisterResponse JSON.
 * Checks for errors, stores registration state.
 * @return 0 on success, -1 on error (check pm->registered)
 */
int pm_parse_register_response(peer_manager_t *pm,
                                const char *json, size_t json_len);

/*
 * Parse MapResponse JSON.
 * Extracts self IP and peer list.
 * @return number of peers parsed, or -1 on error
 */
int pm_parse_map_response(peer_manager_t *pm,
                           const char *json, size_t json_len);

/* ------------------------------------------------------------------ */
/*  API: WireGuard integration                                         */
/* ------------------------------------------------------------------ */

/*
 * Initialize WireGuard interface using parsed MapResponse data.
 * Sets our Tailscale IP and adds first peer.
 * Must call pm_parse_map_response() first.
 *
 * @return 0 on success, -1 on error
 */
int pm_setup_wireguard(peer_manager_t *pm);

/*
 * Update a peer's WireGuard endpoint (e.g., after DISCO discovery).
 * @param peer_idx  Index in pm->peers[]
 * @param ip        New endpoint IP string
 * @param port      New endpoint port
 * @return 0 on success, -1 on error
 */
int pm_update_peer_endpoint(peer_manager_t *pm, int peer_idx,
                             const char *ip, uint16_t port);

/*
 * Check if WireGuard tunnel to a peer is established.
 * @return true if handshake complete and tunnel active
 */
bool pm_peer_is_up(peer_manager_t *pm, int peer_idx);

/*
 * Tear down WireGuard interface.
 */
void pm_teardown_wireguard(peer_manager_t *pm);

/*
 * Update endpoint latency for a peer (called when DISCO pong received).
 */
void pm_update_endpoint_latency(peer_manager_t *pm, int peer_idx,
                                 const ip_addr_t *addr, uint16_t port,
                                 uint32_t rtt_ms);

/*
 * Evaluate and select the best endpoint for a peer.
 * Returns index into eps[] or -1 for DERP fallback.
 */
int pm_evaluate_best_endpoint(peer_manager_t *pm, int peer_idx);

#ifdef __cplusplus
}
#endif

#endif /* PEER_MANAGER_H */
