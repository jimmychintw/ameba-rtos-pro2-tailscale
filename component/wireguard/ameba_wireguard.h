/*
 * WireGuard VPN client for AMB82-MINI (RTL8735B)
 *
 * Simplified API wrapping wireguard-lwip for the Ameba platform.
 *
 * Usage:
 *   1. Connect to WiFi and initialize SNTP for time sync
 *   2. Call ameba_wg_init() with your WireGuard config
 *   3. Call ameba_wg_connect() to establish the tunnel
 *   4. Route traffic through the WireGuard netif
 *   5. Call ameba_wg_disconnect() when done
 */

#ifndef _AMEBA_WIREGUARD_H_
#define _AMEBA_WIREGUARD_H_

#include <stdint.h>
#include <stdbool.h>
#include "lwip/netif.h"
#include "lwip/ip_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define AMEBA_WG_OK          0
#define AMEBA_WG_ERR_PARAM  -1
#define AMEBA_WG_ERR_INIT   -2
#define AMEBA_WG_ERR_NETIF  -3
#define AMEBA_WG_ERR_PEER   -4

/* WireGuard configuration */
typedef struct {
	/* Local interface */
	const char *private_key;       /* Base64 private key (required) */
	uint16_t listen_port;          /* UDP listen port (default 51820) */
	ip_addr_t ip;                  /* Tunnel IP address */
	ip_addr_t netmask;             /* Tunnel netmask */
	ip_addr_t gateway;             /* Tunnel gateway (usually same as ip) */

	/* Remote peer */
	const char *peer_public_key;   /* Base64 public key (required) */
	const uint8_t *preshared_key;  /* 32-byte PSK (NULL to disable) */
	const char *endpoint;          /* Peer endpoint IP address string */
	uint16_t endpoint_port;        /* Peer endpoint port */
	ip_addr_t allowed_ip;          /* Allowed IP (e.g., 0.0.0.0 for all) */
	ip_addr_t allowed_mask;        /* Allowed mask */
	uint16_t persistent_keepalive; /* Keepalive interval in seconds (0 = disabled) */
} ameba_wg_config_t;

/* WireGuard context (opaque to user) */
typedef struct {
	ameba_wg_config_t config;
	struct netif netif;
	uint8_t peer_index;
	bool initialized;
	bool connected;
} ameba_wg_ctx_t;

/*
 * Initialize WireGuard interface.
 * Must be called after WiFi is connected.
 * Returns AMEBA_WG_OK on success.
 */
int ameba_wg_init(ameba_wg_config_t *config, ameba_wg_ctx_t *ctx);

/*
 * Start WireGuard tunnel connection.
 * Initiates handshake with the configured peer.
 * Returns AMEBA_WG_OK on success.
 */
int ameba_wg_connect(ameba_wg_ctx_t *ctx);

/*
 * Check if the WireGuard tunnel is up (handshake completed).
 * Returns true if the tunnel has an active session.
 */
bool ameba_wg_is_up(ameba_wg_ctx_t *ctx);

/*
 * Set the WireGuard interface as the default route.
 * All outbound traffic will go through the tunnel.
 */
int ameba_wg_set_default(ameba_wg_ctx_t *ctx);

/*
 * Disconnect and clean up WireGuard tunnel.
 */
int ameba_wg_disconnect(ameba_wg_ctx_t *ctx);

/*
 * Add an additional WG peer (for multi-peer Tailscale use).
 * Returns AMEBA_WG_OK on success, sets *out_peer_index.
 */
int ameba_wg_add_peer(ameba_wg_ctx_t *ctx,
                      const char *pub_key_b64,
                      const ip_addr_t *allowed_ip,
                      const ip_addr_t *allowed_mask,
                      const ip_addr_t *endpoint_ip,
                      uint16_t endpoint_port,
                      uint16_t keepalive,
                      uint8_t *out_peer_index);

/*
 * Get the WireGuard netif pointer (for advanced usage).
 */
struct netif *ameba_wg_get_netif(ameba_wg_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _AMEBA_WIREGUARD_H_ */
