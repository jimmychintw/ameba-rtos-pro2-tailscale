/*
 * WireGuard VPN client for AMB82-MINI (RTL8735B)
 *
 * Wraps wireguard-lwip into a simple init/connect/disconnect API.
 */

#include "ameba_wireguard.h"

#include <string.h>
#include <stdio.h>

#include "lwip/ip.h"
#include "lwip/netif.h"

#include "wireguardif.h"
#include "wireguard-platform.h"
#include "basic_types.h"

int ameba_wg_init(ameba_wg_config_t *config, ameba_wg_ctx_t *ctx)
{
	struct wireguardif_init_data wg_init;
	int ret;

	if (!config || !ctx) {
		return AMEBA_WG_ERR_PARAM;
	}
	if (!config->private_key || !config->peer_public_key) {
		return AMEBA_WG_ERR_PARAM;
	}

	memset(ctx, 0, sizeof(*ctx));
	memcpy(&ctx->config, config, sizeof(*config));
	ctx->peer_index = WIREGUARDIF_INVALID_INDEX;

	/* Initialize platform (RNG, entropy) */
	ret = wireguard_platform_init();
	if (ret != 0) {
		return AMEBA_WG_ERR_INIT;
	}

	/* Setup WireGuard interface */
	memset(&wg_init, 0, sizeof(wg_init));
	wg_init.private_key = config->private_key;
	wg_init.listen_port = config->listen_port ? config->listen_port : 51820;
	wg_init.bind_netif = NULL; /* Use routing table */

	/* Create the WireGuard netif */
	memset(&ctx->netif, 0, sizeof(ctx->netif));
	if (!netif_add(
		&ctx->netif,
		ip_2_ip4(&config->ip),
		ip_2_ip4(&config->netmask),
		ip_2_ip4(&config->gateway),
		&wg_init,
		&wireguardif_init,
		&ip_input)) {
		return AMEBA_WG_ERR_NETIF;
	}

	netif_set_up(&ctx->netif);
	ctx->initialized = true;

	/* Add peer */
	struct wireguardif_peer peer;
	wireguardif_peer_init(&peer);

	peer.public_key = config->peer_public_key;
	peer.preshared_key = config->preshared_key;
	peer.allowed_ip = config->allowed_ip;
	peer.allowed_mask = config->allowed_mask;

	/* Resolve endpoint IP */
	if (config->endpoint) {
		ip_addr_t endpoint_ip;
		if (ipaddr_aton(config->endpoint, &endpoint_ip)) {
			peer.endpoint_ip = endpoint_ip;
		}
	}
	peer.endport_port = config->endpoint_port;

	if (config->persistent_keepalive > 0) {
		peer.keep_alive = config->persistent_keepalive;
	}

	if (wireguardif_add_peer(&ctx->netif, &peer, &ctx->peer_index) != ERR_OK) {
		netif_remove(&ctx->netif);
		ctx->initialized = false;
		return AMEBA_WG_ERR_PEER;
	}

	return AMEBA_WG_OK;
}

int ameba_wg_connect(ameba_wg_ctx_t *ctx)
{
	if (!ctx || !ctx->initialized) {
		return AMEBA_WG_ERR_PARAM;
	}
	if (ctx->peer_index == WIREGUARDIF_INVALID_INDEX) {
		return AMEBA_WG_ERR_PEER;
	}

	if (wireguardif_connect(&ctx->netif, ctx->peer_index) != ERR_OK) {
		return AMEBA_WG_ERR_PEER;
	}

	ctx->connected = true;
	return AMEBA_WG_OK;
}

bool ameba_wg_is_up(ameba_wg_ctx_t *ctx)
{
	if (!ctx || !ctx->initialized) {
		return false;
	}
	if (ctx->peer_index == WIREGUARDIF_INVALID_INDEX) {
		return false;
	}

	ip_addr_t current_ip = IPADDR4_INIT(0);
	uint16_t current_port = 0;
	return (wireguardif_peer_is_up(&ctx->netif, ctx->peer_index,
		&current_ip, &current_port) == ERR_OK);
}

int ameba_wg_set_default(ameba_wg_ctx_t *ctx)
{
	if (!ctx || !ctx->initialized) {
		return AMEBA_WG_ERR_PARAM;
	}

	netif_set_default(&ctx->netif);
	return AMEBA_WG_OK;
}

int ameba_wg_disconnect(ameba_wg_ctx_t *ctx)
{
	if (!ctx || !ctx->initialized) {
		return AMEBA_WG_ERR_PARAM;
	}

	if (ctx->peer_index != WIREGUARDIF_INVALID_INDEX) {
		wireguardif_disconnect(&ctx->netif, ctx->peer_index);
		wireguardif_remove_peer(&ctx->netif, ctx->peer_index);
		ctx->peer_index = WIREGUARDIF_INVALID_INDEX;
	}

	/* Check if default route points to our netif */
	if (netif_default == &ctx->netif) {
		netif_set_default(NULL);
	}

	netif_set_down(&ctx->netif);
	wireguardif_fini(&ctx->netif);  /* Clean up UDP/timer/device before netif_remove */
	netif_remove(&ctx->netif);

	ctx->initialized = false;
	ctx->connected = false;
	return AMEBA_WG_OK;
}

int ameba_wg_add_peer(ameba_wg_ctx_t *ctx,
                      const char *pub_key_b64,
                      const ip_addr_t *allowed_ip,
                      const ip_addr_t *allowed_mask,
                      const ip_addr_t *endpoint_ip,
                      uint16_t endpoint_port,
                      uint16_t keepalive,
                      uint8_t *out_peer_index)
{
	if (!ctx || !ctx->initialized || !pub_key_b64) {
		return AMEBA_WG_ERR_PARAM;
	}

	struct wireguardif_peer peer;
	wireguardif_peer_init(&peer);
	peer.public_key = pub_key_b64;
	peer.preshared_key = NULL;
	if (allowed_ip) peer.allowed_ip = *allowed_ip;
	if (allowed_mask) peer.allowed_mask = *allowed_mask;
	if (endpoint_ip) peer.endpoint_ip = *endpoint_ip;
	peer.endport_port = endpoint_port;
	peer.keep_alive = keepalive;

	uint8_t idx = WIREGUARDIF_INVALID_INDEX;
	if (wireguardif_add_peer(&ctx->netif, &peer, &idx) != ERR_OK) {
		return AMEBA_WG_ERR_PEER;
	}
	if (out_peer_index) *out_peer_index = idx;
	return AMEBA_WG_OK;
}

struct netif *ameba_wg_get_netif(ameba_wg_ctx_t *ctx)
{
	if (!ctx || !ctx->initialized) {
		return NULL;
	}
	return &ctx->netif;
}
