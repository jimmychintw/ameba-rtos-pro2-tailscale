/*
 * ts_disco.c — Tailscale DISCO + STUN implementation
 */

#include "ts_disco.h"
#include "ts_log.h"
#include "ts_nacl.h"
#include "ts_crypto.h"
#include "ts_derp.h"
#include <string.h>
#include <stdio.h>
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/sys.h"
#include "wireguard-platform.h"
#include "FreeRTOS.h"
#include "queue.h"

#define LOG_TAG "[DISCO] "
#define DS_LOG(fmt, ...) printf(LOG_TAG fmt "\r\n", ##__VA_ARGS__)
#define DS_ERR(fmt, ...) printf(LOG_TAG "ERROR: " fmt "\r\n", ##__VA_ARGS__)
#define DS_DBG(fmt, ...) TS_DBG(LOG_TAG fmt "\r\n", ##__VA_ARGS__)

/* DISCO magic: "TS" + UTF-8 💬 (U+1F4AC) */
const uint8_t DISCO_MAGIC[DISCO_MAGIC_LEN] = {
    0x54, 0x53, 0xF0, 0x9F, 0x92, 0xAC
};

/* ------------------------------------------------------------------ */
/*  Internal: find peer by disco public key                            */
/* ------------------------------------------------------------------ */

static int find_peer_by_disco_key(peer_manager_t *pm,
                                   const uint8_t disco_pub[32])
{
    for (int i = 0; i < pm->peer_count; i++) {
        if (pm->peers[i].valid &&
            memcmp(pm->peers[i].disco_key, disco_pub, 32) == 0)
            return i;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Internal: encode Pong src address (18 bytes)                       */
/* ------------------------------------------------------------------ */

static void encode_addr(uint8_t out[18], const char *ip, uint16_t port)
{
    memset(out, 0, 18);
    out[2] = 0x01;  /* IPv4 */
    out[3] = (uint8_t)(port >> 8);
    out[4] = (uint8_t)(port & 0xFF);

    /* Parse IPv4 dotted-decimal */
    unsigned a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        out[5] = (uint8_t)a;
        out[6] = (uint8_t)b;
        out[7] = (uint8_t)c;
        out[8] = (uint8_t)d;
    }
}

/* Decode Pong src address (18 bytes) → IP string + port */
static int decode_addr(const uint8_t src[18], char *ip, size_t ip_len,
                        uint16_t *port)
{
    if (src[2] != 0x01) return -1;  /* Only IPv4 supported */
    *port = ((uint16_t)src[3] << 8) | src[4];
    snprintf(ip, ip_len, "%u.%u.%u.%u", src[5], src[6], src[7], src[8]);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public: init                                                       */
/* ------------------------------------------------------------------ */

void disco_init(disco_state_t *ds, peer_manager_t *pm)
{
    memset(ds, 0, sizeof(*ds));
    ds->pm = pm;
    ds->sock_fd = -1;
    ds->pending_peer_idx = -1;
}

void disco_set_derp(disco_state_t *ds, void *derp_client)
{
    ds->derp_client = derp_client;
    DS_LOG("DERP client set for dual-path DISCO");
}

void disco_set_raw_rx(disco_state_t *ds, disco_raw_rx_cb_t cb, void *ctx)
{
    ds->raw_rx_cb = cb;
    ds->raw_rx_ctx = ctx;
    DS_LOG("WG direct rx callback set");
}

int disco_queue_direct_send(disco_state_t *ds,
                             uint32_t dst_ip_be, uint16_t dst_port,
                             const uint8_t *data, uint16_t len)
{
    if (!ds->send_queue || len > DISCO_DIRECT_PKT_MAX) return -1;
    /* Static item to avoid large stack allocation in tcpip_thread */
    static disco_direct_send_t item;
    item.dst_ip_be = dst_ip_be;
    item.dst_port  = dst_port;
    item.len       = len;
    memcpy(item.data, data, len);
    if (xQueueSend((QueueHandle_t)ds->send_queue, &item, 0) != pdTRUE) {
        DS_ERR("direct send queue full");
        return -1;
    }
    return 0;
}

bool disco_is_disco_packet(const uint8_t *data, size_t len)
{
    return (len >= DISCO_HDR_LEN + NACL_BOX_MACBYTES + 2 &&
            memcmp(data, DISCO_MAGIC, DISCO_MAGIC_LEN) == 0);
}

/* ------------------------------------------------------------------ */
/*  Public: send DISCO Ping                                            */
/* ------------------------------------------------------------------ */

int disco_send_ping(disco_state_t *ds, int peer_idx,
                     const char *dst_ip, uint16_t dst_port)
{
    peer_manager_t *pm = ds->pm;
    if (peer_idx < 0 || peer_idx >= pm->peer_count) return -1;
    if (ds->sock_fd < 0) return -1;

    ts_peer_t *peer = &pm->peers[peer_idx];

    /* Build plaintext: type(1) + version(1) + txid(12) + nodekey(32) = 46 */
    uint8_t plain[46];
    plain[0] = DISCO_TYPE_PING;
    plain[1] = 0x00;  /* version */
    wireguard_random_bytes(plain + 2, DISCO_TXID_LEN);
    memcpy(plain + 14, pm->node_pub, 32);

    /* Build packet: magic(6) + disco_pub(32) + nonce(24) + box(16+46) */
    uint8_t pkt[DISCO_MAX_PKT];
    memcpy(pkt, DISCO_MAGIC, DISCO_MAGIC_LEN);
    memcpy(pkt + 6, pm->disco_pub, 32);

    uint8_t nonce[24];
    wireguard_random_bytes(nonce, 24);
    memcpy(pkt + 38, nonce, 24);

    /* NaCl box encrypt */
    int ret = nacl_box_easy(pkt + DISCO_HDR_LEN, plain, sizeof(plain),
                             nonce, peer->disco_key, pm->disco_priv);
    if (ret < 0) {
        DS_ERR("nacl_box_easy failed");
        return -1;
    }

    size_t pkt_len = DISCO_HDR_LEN + NACL_BOX_MACBYTES + sizeof(plain);

    /* Path A: direct UDP (may be blocked by NAT, but try) */
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    inet_aton(dst_ip, &dst.sin_addr);

    int sent = sendto(ds->sock_fd, pkt, pkt_len, 0,
                       (struct sockaddr *)&dst, sizeof(dst));

    /* Path B: via DERP relay (if available) */
    bool derp_sent = false;
    if (ds->derp_client) {
        derp_client_t *dc = (derp_client_t *)ds->derp_client;
        if (dc->ready) {
            int dret = derp_send_packet(dc, peer->node_key, pkt, pkt_len);
            derp_sent = (dret == 0);
        }
    }

    if (sent < 0 && !derp_sent) {
        DS_ERR("Ping failed (both paths)");
        return -1;
    }

    /* Track pending ping */
    memcpy(ds->pending_txid, plain + 2, DISCO_TXID_LEN);
    ds->pending_peer_idx = peer_idx;
    ds->pending_send_ms = sys_now();
    ds->pending_valid = true;

    DS_DBG("Ping → peer %d %s:%u (udp=%s derp=%s)",
           peer_idx, dst_ip, dst_port,
           sent >= 0 ? "ok" : "fail",
           derp_sent ? "ok" : "skip");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public: handle incoming DISCO packet                               */
/* ------------------------------------------------------------------ */

int disco_handle_packet(disco_state_t *ds,
                         const uint8_t *pkt, size_t pkt_len,
                         const char *src_ip, uint16_t src_port)
{
    peer_manager_t *pm = ds->pm;

    if (!disco_is_disco_packet(pkt, pkt_len)) return -1;

    /* Extract sender disco public key and nonce */
    const uint8_t *sender_pub = pkt + 6;
    const uint8_t *nonce = pkt + 38;
    const uint8_t *box = pkt + DISCO_HDR_LEN;
    size_t box_len = pkt_len - DISCO_HDR_LEN;

    if (box_len < NACL_BOX_MACBYTES + 2) return -1;

    /* Find peer by disco key */
    int pidx = find_peer_by_disco_key(pm, sender_pub);
    if (pidx < 0) {
        DS_ERR("Unknown disco key");
        return -1;
    }

    /* Decrypt NaCl box */
    uint8_t plain[DISCO_MAX_PKT];
    size_t plain_len = box_len - NACL_BOX_MACBYTES;
    if (plain_len > sizeof(plain)) return -1;

    int ret = nacl_box_open_easy(plain, box, box_len,
                                  nonce, sender_pub, pm->disco_priv);
    if (ret < 0) {
        DS_ERR("Decrypt failed (peer %d)", pidx);
        return -1;
    }

    uint8_t msg_type = plain[0];

    switch (msg_type) {
    case DISCO_TYPE_PING: {
        DS_DBG("Ping ← peer %d (%s:%u)", pidx, src_ip, src_port);

        /* Build Pong: type(1) + version(1) + txid(12) + src(18) = 32 */
        uint8_t pong[32];
        pong[0] = DISCO_TYPE_PONG;
        pong[1] = 0x00;
        memcpy(pong + 2, plain + 2, DISCO_TXID_LEN);  /* echo TxID */
        encode_addr(pong + 14, src_ip, src_port);

        /* Build DISCO packet */
        uint8_t resp[DISCO_MAX_PKT];
        memcpy(resp, DISCO_MAGIC, DISCO_MAGIC_LEN);
        memcpy(resp + 6, pm->disco_pub, 32);

        uint8_t resp_nonce[24];
        wireguard_random_bytes(resp_nonce, 24);
        memcpy(resp + 38, resp_nonce, 24);

        ts_peer_t *peer = &pm->peers[pidx];
        nacl_box_easy(resp + DISCO_HDR_LEN, pong, sizeof(pong),
                       resp_nonce, peer->disco_key, pm->disco_priv);

        size_t resp_len = DISCO_HDR_LEN + NACL_BOX_MACBYTES + sizeof(pong);

        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(src_port);
        inet_aton(src_ip, &dst.sin_addr);

        sendto(ds->sock_fd, resp, resp_len, 0,
               (struct sockaddr *)&dst, sizeof(dst));
        DS_DBG("Pong → %s:%u", src_ip, src_port);
        break;
    }

    case DISCO_TYPE_PONG: {
        if (plain_len < 32) break;

        /* Extract source address from Pong */
        char obs_ip[PM_MAX_IP_LEN];
        uint16_t obs_port;
        if (decode_addr(plain + 14, obs_ip, sizeof(obs_ip), &obs_port) < 0)
            break;

        /* Check TxID match */
        if (ds->pending_valid &&
            memcmp(ds->pending_txid, plain + 2, DISCO_TXID_LEN) == 0) {

            uint32_t rtt = sys_now() - ds->pending_send_ms;
            DS_DBG("Pong ← peer %d: our addr=%s:%u rtt=%ums",
                   pidx, obs_ip, obs_port, rtt);

            /* Update peer endpoint to the source of this Pong */
            pm_update_peer_endpoint(pm, pidx, src_ip, src_port);

            /* Update endpoint latency and re-evaluate bestAddr */
            ip_addr_t pong_addr;
            ipaddr_aton(src_ip, &pong_addr);
            pm_update_endpoint_latency(pm, pidx, &pong_addr, src_port, rtt);
            int best = pm_evaluate_best_endpoint(pm, pidx);
            if (best >= 0) {
                DS_DBG("peer[%d] bestAddr: direct ep[%d] (%ums)",
                       pidx, best, pm->peers[pidx].eps[best].latency_ms);
            }

            ds->pending_valid = false;
        }
        break;
    }

    default:
        DS_LOG("Unknown msg type 0x%02x from peer %d", msg_type, pidx);
        break;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public: handle DISCO from DERP relay                               */
/* ------------------------------------------------------------------ */

int disco_handle_derp_packet(disco_state_t *ds,
                              const uint8_t *src_node_key,
                              const uint8_t *pkt, size_t pkt_len,
                              uint8_t *resp_out, size_t *resp_len)
{
    (void)src_node_key;
    peer_manager_t *pm = ds->pm;
    *resp_len = 0;

    if (!disco_is_disco_packet(pkt, pkt_len)) return -1;

    /* Extract sender disco public key and nonce */
    const uint8_t *sender_pub = pkt + 6;
    const uint8_t *nonce = pkt + 38;
    const uint8_t *box = pkt + DISCO_HDR_LEN;
    size_t box_len = pkt_len - DISCO_HDR_LEN;

    if (box_len < NACL_BOX_MACBYTES + 2) return -1;

    /* Find peer by disco key */
    int pidx = find_peer_by_disco_key(pm, sender_pub);
    if (pidx < 0) {
        DS_ERR("DERP DISCO: unknown disco key");
        return -1;
    }

    /* Decrypt NaCl box */
    uint8_t plain[DISCO_MAX_PKT];
    size_t plain_len = box_len - NACL_BOX_MACBYTES;
    if (plain_len > sizeof(plain)) return -1;

    int ret = nacl_box_open_easy(plain, box, box_len,
                                  nonce, sender_pub, pm->disco_priv);
    if (ret < 0) {
        DS_ERR("DERP DISCO: decrypt failed (peer %d)", pidx);
        return -1;
    }

    uint8_t msg_type = plain[0];

    switch (msg_type) {
    case DISCO_TYPE_PING: {
        DS_DBG("DERP Ping ← peer %d [%s]", pidx, pm->peers[pidx].hostname);

        /* Build Pong: type(1) + version(1) + txid(12) + src(18) = 32 */
        uint8_t pong[32];
        pong[0] = DISCO_TYPE_PONG;
        pong[1] = 0x00;
        memcpy(pong + 2, plain + 2, DISCO_TXID_LEN);  /* echo TxID */
        /* Src = DERP magic addr 127.3.3.40:0 (came via DERP, no real src addr) */
        memset(pong + 14, 0, 18);

        /* Build DISCO response packet */
        memcpy(resp_out, DISCO_MAGIC, DISCO_MAGIC_LEN);
        memcpy(resp_out + 6, pm->disco_pub, 32);

        uint8_t resp_nonce[24];
        wireguard_random_bytes(resp_nonce, 24);
        memcpy(resp_out + 38, resp_nonce, 24);

        ts_peer_t *peer = &pm->peers[pidx];
        nacl_box_easy(resp_out + DISCO_HDR_LEN, pong, sizeof(pong),
                       resp_nonce, peer->disco_key, pm->disco_priv);

        *resp_len = DISCO_HDR_LEN + NACL_BOX_MACBYTES + sizeof(pong);
        DS_DBG("DERP Pong → peer %d via DERP", pidx);
        break;
    }

    case DISCO_TYPE_PONG: {
        if (plain_len < 32) break;

        /* Check TxID match against our pending ping */
        if (ds->pending_valid &&
            memcmp(ds->pending_txid, plain + 2, DISCO_TXID_LEN) == 0) {

            uint32_t rtt = sys_now() - ds->pending_send_ms;
            DS_DBG("DERP Pong ← peer %d rtt=%ums", pidx, rtt);
            ds->pending_valid = false;
        } else {
            DS_DBG("DERP Pong ← peer %d (no matching txid)", pidx);
        }
        break;
    }

    case DISCO_TYPE_CALLMEMAYBE: {
        /* CallMeMaybe payload: N * 18 bytes (16B IPv6-mapped IP + 2B BE port) */
        size_t cmm_payload_len = plain_len - 2;  /* skip type + version */
        const uint8_t *cmm_data = plain + 2;
        int ep_count = (int)(cmm_payload_len / 18);

        DS_LOG("DERP CallMeMaybe ← peer %d: %d endpoints", pidx, ep_count);

        ts_peer_t *cmm_peer = &pm->peers[pidx];

        /* Parse endpoints and send DISCO pings to each */
        for (int ei = 0; ei < ep_count && ei < 8; ei++) {
            const uint8_t *ep = cmm_data + ei * 18;

            /* Check if IPv4-mapped IPv6: first 10 bytes 0x00, bytes 10-11 = 0xFF 0xFF */
            bool is_v4 = true;
            for (int j = 0; j < 10; j++) {
                if (ep[j] != 0x00) { is_v4 = false; break; }
            }
            if (is_v4 && (ep[10] != 0xFF || ep[11] != 0xFF)) is_v4 = false;

            if (!is_v4) {
                DS_DBG("  CMM ep[%d]: skip non-IPv4", ei);
                continue;
            }

            uint32_t ipv4 = ((uint32_t)ep[12] << 24) | ((uint32_t)ep[13] << 16) |
                            ((uint32_t)ep[14] << 8) | ep[15];
            uint16_t cmm_port = ((uint16_t)ep[16] << 8) | ep[17];

            /* Skip link-local (169.254.x.x) */
            if ((ipv4 >> 16) == 0xA9FE) continue;

            char ep_ip[PM_MAX_IP_LEN];
            snprintf(ep_ip, sizeof(ep_ip), "%u.%u.%u.%u",
                     (ipv4 >> 24) & 0xFF, (ipv4 >> 16) & 0xFF,
                     (ipv4 >> 8) & 0xFF, ipv4 & 0xFF);

            DS_DBG("  CMM ep[%d]: %s:%u", ei, ep_ip, cmm_port);

            /* Store in peer's endpoint list */
            if (cmm_peer->ep_count < TS_MAX_EP_PER_PEER) {
                ts_endpoint_t *tep = &cmm_peer->eps[cmm_peer->ep_count];
                IP4_ADDR(ip_2_ip4(&tep->addr), (ipv4 >> 24) & 0xFF,
                         (ipv4 >> 16) & 0xFF, (ipv4 >> 8) & 0xFF,
                         ipv4 & 0xFF);
                tep->port = cmm_port;
                tep->latency_ms = 0;
                tep->last_pong_tick = 0;
                cmm_peer->ep_count++;
            }

            /* Send DISCO ping to this endpoint */
            if (ds->sock_fd >= 0) {
                disco_send_ping(ds, pidx, ep_ip, cmm_port);
            }
        }
        break;
    }

    default:
        DS_LOG("DERP DISCO: unknown type 0x%02x from peer %d", msg_type, pidx);
        break;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public: STUN                                                       */
/* ------------------------------------------------------------------ */

int disco_send_stun(disco_state_t *ds,
                     const char *stun_host, uint16_t stun_port)
{
    if (ds->sock_fd < 0) return -1;

    /* STUN Binding Request: type(2) + length(2) + cookie(4) + txid(12) */
    uint8_t req[STUN_HDR_LEN];
    req[0] = 0x00; req[1] = 0x01;  /* Binding Request */
    req[2] = 0x00; req[3] = 0x00;  /* Length = 0 */
    req[4] = 0x21; req[5] = 0x12;  /* Magic cookie */
    req[6] = 0xA4; req[7] = 0x42;
    wireguard_random_bytes(req + 8, STUN_TXID_LEN);

    memcpy(ds->stun_txid, req + 8, STUN_TXID_LEN);
    ds->stun_pending = true;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(stun_port);
    inet_aton(stun_host, &dst.sin_addr);

    int sent = sendto(ds->sock_fd, req, STUN_HDR_LEN, 0,
                       (struct sockaddr *)&dst, sizeof(dst));
    if (sent < 0) {
        DS_ERR("STUN sendto failed");
        return -1;
    }

    DS_LOG("STUN → %s:%u", stun_host, stun_port);
    return 0;
}

int disco_parse_stun_response(disco_state_t *ds,
                                const uint8_t *data, size_t len)
{
    if (len < STUN_HDR_LEN) return -1;

    /* Verify Binding Response (0x0101) */
    uint16_t msg_type = ((uint16_t)data[0] << 8) | data[1];
    if (msg_type != 0x0101) return -1;

    /* Verify magic cookie */
    uint32_t cookie = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
                      ((uint32_t)data[6] << 8) | data[7];
    if (cookie != STUN_MAGIC_COOKIE) return -1;

    /* Verify TxID */
    if (!ds->stun_pending ||
        memcmp(data + 8, ds->stun_txid, STUN_TXID_LEN) != 0)
        return -1;

    /* Parse attributes looking for XOR-MAPPED-ADDRESS (0x0020) */
    uint16_t attr_len = ((uint16_t)data[2] << 8) | data[3];
    size_t pos = STUN_HDR_LEN;
    size_t end = STUN_HDR_LEN + attr_len;
    if (end > len) end = len;

    while (pos + 4 <= end) {
        uint16_t atype = ((uint16_t)data[pos] << 8) | data[pos + 1];
        uint16_t alen = ((uint16_t)data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        if (pos + alen > end) break;

        /* XOR-MAPPED-ADDRESS = 0x0020, MAPPED-ADDRESS = 0x0001 */
        if ((atype == 0x0020 || atype == 0x0001) && alen >= 8) {
            uint8_t family = data[pos + 1];
            if (family != 0x01) { pos += alen; continue; }  /* IPv4 only */

            uint16_t port = ((uint16_t)data[pos + 2] << 8) | data[pos + 3];
            uint32_t ip = ((uint32_t)data[pos + 4] << 24) |
                          ((uint32_t)data[pos + 5] << 16) |
                          ((uint32_t)data[pos + 6] << 8) | data[pos + 7];

            if (atype == 0x0020) {
                /* XOR decode */
                port ^= 0x2112;
                ip ^= STUN_MAGIC_COOKIE;
            }

            snprintf(ds->self_endpoint.ip, sizeof(ds->self_endpoint.ip),
                     "%u.%u.%u.%u",
                     (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                     (ip >> 8) & 0xFF, ip & 0xFF);
            ds->self_endpoint.port = port;
            ds->self_endpoint.valid = true;
            ds->stun_pending = false;

            DS_LOG("STUN: our public addr = %s:%u",
                   ds->self_endpoint.ip, ds->self_endpoint.port);
            return 0;
        }

        /* Pad to 4-byte boundary */
        pos += alen;
        if (alen % 4) pos += 4 - (alen % 4);
    }

    return -1;
}

/* ------------------------------------------------------------------ */
/*  DISCO task (FreeRTOS)                                              */
/* ------------------------------------------------------------------ */

/* Drain direct-send queue: send queued WG packets via DISCO socket */
static void disco_drain_direct_queue(disco_state_t *ds)
{
    if (!ds->send_queue) return;
    disco_direct_send_t item;
    while (xQueueReceive((QueueHandle_t)ds->send_queue, &item, 0) == pdTRUE) {
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(item.dst_port);
        dest.sin_addr.s_addr = item.dst_ip_be;
        sendto(ds->sock_fd, item.data, item.len, 0,
               (struct sockaddr *)&dest, sizeof(dest));
    }
}

static void disco_task_fn(void *arg)
{
    disco_state_t *ds = (disco_state_t *)arg;
    peer_manager_t *pm = ds->pm;

    /* Create direct-send queue (depth 4, ~6KB) */
    ds->send_queue = (void *)xQueueCreate(4, sizeof(disco_direct_send_t));

    /* Create UDP socket */
    ds->sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ds->sock_fd < 0) {
        DS_ERR("socket failed");
        ds->running = false;
        vTaskDelete(NULL);
        return;
    }

    /* Bind to ephemeral port */
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind(ds->sock_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr));

    /* Set receive timeout */
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(ds->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    DS_LOG("Task started, sock=%d", ds->sock_fd);

    uint32_t ping_interval_ms = 5000;
    uint32_t last_ping_ms = 0;

    while (ds->running) {
        /* Drain direct-send queue (WG packets from output hook) */
        disco_drain_direct_queue(ds);

        uint32_t now = sys_now();

        /* Periodic: send DISCO pings to all peers with known endpoints */
        if (now - last_ping_ms >= ping_interval_ms) {
            for (int i = 0; i < pm->peer_count; i++) {
                ts_peer_t *p = &pm->peers[i];
                if (!p->valid || !p->endpoint[0]) continue;

                char ep_ip[PM_MAX_IP_LEN];
                uint16_t ep_port;
                const char *colon = strrchr(p->endpoint, ':');
                if (!colon) continue;
                size_t ipsz = (size_t)(colon - p->endpoint);
                if (ipsz >= sizeof(ep_ip)) continue;
                memcpy(ep_ip, p->endpoint, ipsz);
                ep_ip[ipsz] = '\0';
                ep_port = (uint16_t)atoi(colon + 1);

                disco_send_ping(ds, i, ep_ip, ep_port);
            }
            last_ping_ms = now;
        }

        /* Receive loop */
        uint8_t buf[DISCO_MAX_PKT];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);

        int n = recvfrom(ds->sock_fd, buf, sizeof(buf), 0,
                          (struct sockaddr *)&from, &fromlen);
        if (n <= 0) continue;

        char from_ip[PM_MAX_IP_LEN];
        uint16_t from_port = ntohs(from.sin_port);
        snprintf(from_ip, sizeof(from_ip), "%s",
                 inet_ntoa(from.sin_addr));

        /* Check if STUN response */
        if (n >= STUN_HDR_LEN && ds->stun_pending) {
            uint16_t mt = ((uint16_t)buf[0] << 8) | buf[1];
            if (mt == 0x0101) {
                disco_parse_stun_response(ds, buf, n);
                continue;
            }
        }

        /* Check if DISCO packet */
        if (disco_is_disco_packet(buf, n)) {
            disco_handle_packet(ds, buf, n, from_ip, from_port);
        } else if (ds->raw_rx_cb) {
            /* Non-DISCO packet (likely WG direct) → forward to WG */
            ds->raw_rx_cb(buf, n, from.sin_addr.s_addr, from_port,
                           ds->raw_rx_ctx);
        }
    }

    close(ds->sock_fd);
    ds->sock_fd = -1;
    DS_LOG("Task stopped");
    vTaskDelete(NULL);
}

/* ------------------------------------------------------------------ */
/*  Public: start / stop                                               */
/* ------------------------------------------------------------------ */

int disco_start(disco_state_t *ds, const char *stun_host)
{
    if (ds->running) return 0;
    ds->running = true;

    BaseType_t ret = xTaskCreate(disco_task_fn, "disco",
                                  4096, ds, tskIDLE_PRIORITY + 2,
                                  (TaskHandle_t *)&ds->task_handle);
    if (ret != pdPASS) {
        DS_ERR("xTaskCreate failed");
        ds->running = false;
        return -1;
    }

    /* Send initial STUN request after socket is ready (with small delay) */
    if (stun_host) {
        vTaskDelay(pdMS_TO_TICKS(500));
        disco_send_stun(ds, stun_host, STUN_DEFAULT_PORT);
    }

    return 0;
}

void disco_stop(disco_state_t *ds)
{
    ds->running = false;
    /* Task will exit on next recv timeout and delete itself */
    ds->task_handle = NULL;
}
