/*
 * ts_main.c — Tailscale client state machine for AMB82-MINI
 *
 * Flow:
 *   WiFi → SNTP → Fetch server key → Noise connect →
 *   HTTP/2 start → Register → Map → WireGuard → DISCO → Monitor
 *
 * Reconnects automatically on control connection failure.
 *
 * Build: added via scenario.cmake
 */

#include "FreeRTOS.h"
#include "task.h"

#include <stdio.h>
#include <string.h>

#include "FreeRTOS_POSIX/time.h"
#include "wifi_conf.h"
#include "lwip_netconf.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "sntp/sntp.h"
#include "basic_types.h"

#include "peer_manager.h"
#include "ts_log.h"
#include "ctrl_client.h"
#include "ts_http2.h"
#include "ts_disco.h"
#include "ts_derp.h"
#include "ota_server.h"
#include "wireguardif.h"
#include "wireguard.h"
#include "ameba_wireguard.h"
#include "lwip/udp.h"
#include "lwip/sockets.h"
#include "lwip/pbuf.h"

/* ================================================================== */
/*  Configuration — EDIT THESE FOR YOUR SETUP                         */
/* ================================================================== */

/* WiFi */
#define WIFI_SSID           "YOUR_WIFI_SSID"
#define WIFI_PASSWORD       "YOUR_WIFI_PASSWORD"

/* Tailscale control server (HTTPS + TLS) */
#define TS_CONTROL_HOST     "controlplane.tailscale.com"
#define TS_CONTROL_PORT     443
#define TS_USE_TLS          1   /* 1 for official Tailscale, 0 for Headscale HTTP */

/* Pre-auth key (generate at: https://login.tailscale.com/admin/settings/keys) */
#define TS_AUTH_KEY          "tskey-auth-YOUR_PREAUTH_KEY_HERE"

/* Device identity */
#define TS_HOSTNAME         "amb82-mini"

/* STUN server — Google STUN (stun.l.google.com), port 3478 */
#define STUN_SERVER         "74.125.250.129"

/* Reconnect delay on failure */
#define RETRY_DELAY_MS      10000

/* OTA protection: heap safety valve and reconnect limits */
#define HEAP_SAFETY_MIN     50000   /* 50KB minimum free heap to attempt reconnect */
#define MAX_RECONNECT_FAILS 5       /* Enter OTA-only mode after this many failures */

/* ================================================================== */

#define TS_TASK_STACK       (16 * 1024)
#define TS_TASK_PRIO        (tskIDLE_PRIORITY + 2)

#define LOG_TAG "[TS_MAIN] "
#define TS_LOG(fmt, ...) printf(LOG_TAG fmt "\r\n", ##__VA_ARGS__)
#define TS_ERR(fmt, ...) printf(LOG_TAG "ERROR: " fmt "\r\n", ##__VA_ARGS__)
#define TS_MAIN_DBG(fmt, ...) TS_DBG(LOG_TAG fmt "\r\n", ##__VA_ARGS__)

extern struct netif xnetif[];

/* ------------------------------------------------------------------ */
/*  State — static globals to avoid stack overflow                     */
/* ------------------------------------------------------------------ */

static peer_manager_t  s_pm;
static ctrl_client_t   s_ctrl;
static ts_http2_t      s_h2;
static disco_state_t   s_disco;
static derp_client_t   s_derp;

/* JSON / response buffers */
#define JSON_BUF_SIZE  2048
#define RESP_BUF_SIZE  (48 * 1024)  /* 48KB — MapResponse includes DERPMap (10-40KB) */

static char    s_json_buf[JSON_BUF_SIZE];
static uint8_t s_resp_buf[RESP_BUF_SIZE];
static uint32_t s_map_stream_id = 0;  /* persistent map stream */

/* ------------------------------------------------------------------ */
/*  WiFi connect (same pattern as wg_test.c)                           */
/* ------------------------------------------------------------------ */

static int wifi_do_connect(void)
{
    rtw_network_info_t param = {0};

    TS_LOG("Connecting WiFi '%s'...", WIFI_SSID);

    memcpy(param.ssid.val, WIFI_SSID, strlen(WIFI_SSID));
    param.ssid.len = strlen(WIFI_SSID);
    param.password = (unsigned char *)WIFI_PASSWORD;
    param.password_len = strlen(WIFI_PASSWORD);
    param.security_type = RTW_SECURITY_WPA2_AES_PSK;

    if (wifi_connect(&param, 1) != RTW_SUCCESS) {
        TS_ERR("wifi_connect failed");
        return -1;
    }

    TS_LOG("WiFi associated, DHCP...");
    LwIP_DHCP(0, DHCP_START);

    for (int i = 0; i < 20; i++) {
        if (*(u32 *)LwIP_GetIP(0) != IP_ADDR_INVALID) {
            uint8_t *ip = LwIP_GetIP(0);
            TS_LOG("WiFi IP: %d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
            return 0;
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    TS_ERR("DHCP timeout");
    return -1;
}

/* ------------------------------------------------------------------ */
/*  SNTP time sync                                                     */
/* ------------------------------------------------------------------ */

static void sntp_wait_sync(uint32_t timeout_ms)
{
    TS_LOG("SNTP sync...");
    sntp_init();

    uint32_t waited = 0;
    while (waited < timeout_ms) {
        time_t now = time(NULL);
        if (now > 1704067200) { /* > 2024-01-01 */
            struct tm *t = localtime(&now);
            TS_LOG("Time: %04d-%02d-%02d %02d:%02d:%02d UTC",
                   t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                   t->tm_hour, t->tm_min, t->tm_sec);
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
        waited += 1000;
    }
    TS_LOG("SNTP timeout — continuing");
}

/* ------------------------------------------------------------------ */
/*  Control plane: connect + register + map                            */
/* ------------------------------------------------------------------ */

static int ctrl_connect_and_register(void)
{
    int ret;

    /* --- Fetch server key --- */
    TS_LOG("Fetching server key from %s:%d...", TS_CONTROL_HOST, TS_CONTROL_PORT);
    ctrl_client_init(&s_ctrl);
    ctrl_client_set_machine_key(&s_ctrl, s_pm.machine_priv, s_pm.machine_pub);
    ctrl_client_set_node_key(&s_ctrl, s_pm.node_pub);
#if TS_USE_TLS
    ctrl_client_enable_tls(&s_ctrl);
#endif

    ret = ctrl_client_fetch_key(&s_ctrl, TS_CONTROL_HOST, TS_CONTROL_PORT);
    if (ret < 0) {
        TS_ERR("Failed to fetch server key");
        return -1;
    }
    TS_LOG("Server key fetched");

    /* --- Noise connect (WebSocket + handshake) --- */
    TS_LOG("Connecting control plane...");
    ret = ctrl_client_connect(&s_ctrl, TS_CONTROL_HOST, TS_CONTROL_PORT);
    if (ret < 0) {
        TS_ERR("Control connect failed");
        return -1;
    }
    TS_LOG("Noise transport established");

    /* --- HTTP/2 session --- */
    char authority[64];
    snprintf(authority, sizeof(authority), "%s:%d", TS_CONTROL_HOST, TS_CONTROL_PORT);

    ts_http2_init(&s_h2, &s_ctrl, authority);
    ret = ts_http2_start(&s_h2);
    if (ret < 0) {
        TS_ERR("HTTP/2 start failed");
        ctrl_client_close(&s_ctrl);
        return -1;
    }
    TS_LOG("HTTP/2 session ready");

    /* --- Register --- */
    int json_len = pm_build_register_json(&s_pm, s_json_buf, JSON_BUF_SIZE);
    if (json_len < 0) {
        TS_ERR("Failed to build RegisterRequest");
        ctrl_client_close(&s_ctrl);
        return -1;
    }

    TS_LOG("Sending RegisterRequest (%d bytes)...", json_len);
    int resp_len = ts_http2_post(&s_h2, "/machine/register",
                                   (uint8_t *)s_json_buf, json_len,
                                   s_resp_buf, RESP_BUF_SIZE, 15000);
    if (resp_len < 0) {
        TS_ERR("Register POST failed");
        ctrl_client_close(&s_ctrl);
        return -1;
    }
    TS_LOG("RegisterResponse: %d bytes", resp_len);

    ret = pm_parse_register_response(&s_pm,
                                       (char *)s_resp_buf, resp_len);
    if (ret < 0 || !s_pm.registered) {
        TS_ERR("Registration failed");
        ctrl_client_close(&s_ctrl);
        return -1;
    }
    TS_LOG("Registration successful!");
    return 0;
}

static int send_map_request(void)
{
    /* Single MapRequest: Stream=true, includes Endpoints/Hostinfo/DiscoKey.
     * With Version < 68, server processes all fields even with Stream=true. */
    int json_len = pm_build_map_json(&s_pm, s_json_buf, JSON_BUF_SIZE);
    if (json_len < 0) {
        TS_ERR("Failed to build MapRequest");
        return -1;
    }

    TS_LOG("Sending MapRequest (%d bytes)...", json_len);
    int stream_id = ts_http2_post_begin(&s_h2, "/machine/map",
                                          (uint8_t *)s_json_buf, json_len);
    if (stream_id < 0) {
        TS_ERR("Map POST failed");
        return -1;
    }
    s_map_stream_id = (uint32_t)stream_id;
    TS_LOG("Map stream ID: %lu", (unsigned long)s_map_stream_id);

    /* Read first MapResponse (full peer list) */
    int resp_len = ts_http2_read_json(&s_h2, s_resp_buf,
                                        RESP_BUF_SIZE, 30000);
    if (resp_len <= 0) {
        TS_ERR("No MapResponse");
        return -1;
    }
    TS_LOG("MapResponse: %d bytes", resp_len);

    int peer_count = pm_parse_map_response(&s_pm,
                                             (char *)s_resp_buf, resp_len);
    if (peer_count < 0) {
        TS_ERR("MapResponse parse failed");
        return -1;
    }

    TS_LOG("Self IP: %s, Peers: %d", s_pm.self_ip, s_pm.peer_count);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  DERP integration: recv callback + WG output hook                   */
/* ------------------------------------------------------------------ */

/*
 * DERP recv callback — dispatch DISCO or inject WG packet.
 * Called from derp_recv_task when a peer sends us a packet via DERP.
 */
static void derp_on_recv(const uint8_t *src_key,
                          const uint8_t *pkt, size_t pkt_len,
                          void *ctx)
{
    (void)ctx;

    /* --- Check if DISCO packet (starts with "TS💬" magic) --- */
    if (disco_is_disco_packet(pkt, pkt_len)) {
        TS_MAIN_DBG("DERP rx: DISCO %u bytes from key=%02x%02x..%02x%02x",
               (unsigned)pkt_len,
               src_key[0], src_key[1], src_key[30], src_key[31]);

        uint8_t resp[DISCO_MAX_PKT];
        size_t resp_len = 0;

        if (disco_handle_derp_packet(&s_disco, src_key, pkt, pkt_len,
                                      resp, &resp_len) == 0 && resp_len > 0) {
            /* Send DISCO pong back via DERP to the sender's node key */
            int ret = derp_send_packet(&s_derp, src_key, resp, resp_len);
            if (ret < 0) {
                TS_ERR("DERP DISCO: failed to send pong via DERP");
            }
        }
        return;
    }

    /* --- WG packet — inject into WireGuard stack --- */
    if (!s_pm.wg_ctx || !s_pm.wg_up) {
        TS_LOG("DERP rx WG: DROPPED (WG not ready) %u bytes", (unsigned)pkt_len);
        return;
    }

    /* Find peer index by node key so we inject with the correct virtual addr */
    int peer_idx = -1;
    for (int i = 0; i < s_pm.peer_count; i++) {
        if (s_pm.peers[i].valid &&
            memcmp(s_pm.peers[i].node_key, src_key, 32) == 0) {
            peer_idx = i;
            break;
        }
    }
    if (peer_idx < 0) {
        TS_LOG("DERP rx WG: unknown sender key=%02x%02x..%02x%02x (%u bytes)",
               src_key[0], src_key[1], src_key[30], src_key[31],
               (unsigned)pkt_len);
        /* Still inject — WG will match by its own handshake state */
        peer_idx = 0;
    }

    /*
     * If peer was on direct path but we're now receiving via DERP,
     * the peer may have moved networks.  Only clear direct_valid if
     * no direct WG packet received for >10 s (Go uses 6.5 s trust
     * window; ESP32 uses 30 s PONG timeout — we use 10 s as middle
     * ground to avoid flapping during brief overlap).
     */
    if (peer_idx >= 0 && s_pm.peers[peer_idx].direct_valid) {
        uint32_t now_tick = xTaskGetTickCount();
        uint32_t elapsed = (now_tick - s_pm.peers[peer_idx].direct_last_rx_tick)
                           * portTICK_PERIOD_MS;
        if (elapsed > 10000) {
            s_pm.peers[peer_idx].direct_valid = false;
            TS_LOG("DERP rx WG: peer %d [%s] direct silent %ums, switch to DERP",
                   peer_idx, s_pm.peers[peer_idx].hostname, (unsigned)elapsed);
        }
    }

    TS_MAIN_DBG("DERP rx WG: %u bytes type=%u from peer %d [%s]",
           (unsigned)pkt_len, pkt_len >= 1 ? pkt[0] : 0xFF,
           peer_idx, s_pm.peers[peer_idx].hostname);

    ameba_wg_ctx_t *wg = (ameba_wg_ctx_t *)s_pm.wg_ctx;
    struct netif *wg_netif = &wg->netif;

    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)pkt_len, PBUF_RAM);
    if (!p) {
        TS_ERR("DERP rx: pbuf alloc failed (%u bytes)", (unsigned)pkt_len);
        return;
    }
    memcpy(p->payload, pkt, pkt_len);

    /* Virtual DERP address: 127.3.PEER_IDX.40 — matches output hook encoding */
    ip_addr_t derp_addr;
    IP4_ADDR(ip_2_ip4(&derp_addr), 127, 3, (uint8_t)peer_idx, 40);

    struct wireguard_device *device = (struct wireguard_device *)wg_netif->state;
    wireguardif_network_rx(device, NULL, p, &derp_addr, (u16_t)s_derp.region_id);
}

/*
 * Direct WG packet received on DISCO socket — inject into WireGuard.
 * Called from DISCO task when a non-DISCO packet arrives.
 * src_ip_be is in network byte order.
 */
static void disco_wg_direct_rx(const uint8_t *pkt, size_t pkt_len,
                                 uint32_t src_ip_be, uint16_t src_port,
                                 void *ctx)
{
    (void)ctx;

    if (!s_pm.wg_ctx || !s_pm.wg_up) return;
    if (pkt_len < 4) return;

    ameba_wg_ctx_t *wg = (ameba_wg_ctx_t *)s_pm.wg_ctx;
    struct wireguard_device *device = (struct wireguard_device *)wg->netif.state;
    if (!device) return;

    /* Match source IP to a known peer (from endpoint list or MapResponse) */
    int peer_idx = -1;
    for (int i = 0; i < s_pm.peer_count; i++) {
        ts_peer_t *tp = &s_pm.peers[i];
        if (!tp->valid) continue;
        for (int j = 0; j < tp->ep_count; j++) {
            if (ip4_addr_get_u32(ip_2_ip4(&tp->eps[j].addr)) == src_ip_be) {
                peer_idx = i;
                break;
            }
        }
        if (peer_idx >= 0) break;
    }

    /* Record peer's direct address for bidirectional direct path */
    if (peer_idx >= 0) {
        ts_peer_t *tp = &s_pm.peers[peer_idx];
        tp->direct_last_rx_tick = xTaskGetTickCount();
        if (!tp->direct_valid) {
            ip4_addr_set_u32(ip_2_ip4(&tp->direct_addr), src_ip_be);
            tp->direct_port = src_port;
            tp->direct_valid = true;
            TS_LOG("Direct rx WG: peer %d [%s] direct addr = %s:%u",
                   peer_idx, tp->hostname,
                   ip4addr_ntoa(ip_2_ip4(&tp->direct_addr)), src_port);
        }
    }

    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)pkt_len, PBUF_RAM);
    if (!p) return;
    memcpy(p->payload, pkt, pkt_len);

    /* Inject with virtual DERP address to preserve output hook routing.
     * WG uses receiver_index (not source addr) to identify the peer. */
    ip_addr_t inject_addr;
    if (peer_idx >= 0) {
        IP4_ADDR(ip_2_ip4(&inject_addr), 127, 3, (uint8_t)peer_idx, 40);
    } else {
        /* Unknown peer — inject with real addr, let WG figure it out */
        ip_addr_set_zero(&inject_addr);
        ip4_addr_set_u32(ip_2_ip4(&inject_addr), src_ip_be);
    }

    wireguardif_network_rx(device, NULL, p, &inject_addr,
                            peer_idx >= 0 ? (u16_t)s_derp.region_id : src_port);
}

/*
 * WG output hook — intercepts outgoing WG packets for DERP relay.
 * Called when peer endpoint is 127.3.3.x (virtual DERP address).
 */
static err_t wg_derp_output_hook(struct pbuf *p, const ip_addr_t *dst,
                                   u16_t port, void *ctx)
{
    (void)ctx;

    if (s_pm.peer_count == 0) return ERR_CONN;

    /* Extract peer index from virtual DERP address: 127.3.PEER_IDX.40 */
    const ip4_addr_t *ip4 = ip_2_ip4(dst);
    int peer_idx = ip4_addr3(ip4);  /* third octet = peer manager index */
    ts_peer_t *target = NULL;
    if (peer_idx >= 0 && peer_idx < s_pm.peer_count && s_pm.peers[peer_idx].valid) {
        target = &s_pm.peers[peer_idx];
    }
    /* Fallback to first valid peer */
    if (!target) {
        for (int i = 0; i < s_pm.peer_count; i++) {
            if (s_pm.peers[i].valid) { target = &s_pm.peers[i]; peer_idx = i; break; }
        }
    }
    if (!target) return ERR_CONN;

    /* Check if peer has a known direct address (learned from incoming WG) */
    if (target->direct_valid) {
        /* Time-based trust expiry (like Go's trustBestAddrUntil 6.5s).
         * If no direct WG packet received for >15s, the path is likely
         * broken (peer moved networks, NAT mapping expired).  Clear and
         * fall through to DERP. */
        uint32_t direct_age = (xTaskGetTickCount() - target->direct_last_rx_tick)
                              * portTICK_PERIOD_MS;
        if (direct_age > 15000) {
            TS_LOG("Direct path expired: peer %d [%s] silent %ums, falling back to DERP",
                   peer_idx, target->hostname, (unsigned)direct_age);
            target->direct_valid = false;
            /* Fall through to DERP */
        } else {
            /* Queue for DISCO task to send via DISCO socket.
             * Cannot call BSD sendto() here — we're in tcpip_thread
             * and sendto() would deadlock trying to re-enter lwIP core. */
            uint8_t tmp[1500];
            u16_t clen = pbuf_copy_partial(p, tmp, sizeof(tmp), 0);
            if (clen > 0) {
                TS_MAIN_DBG("TX DIRECT: %u bytes → peer %d [%s] %s:%u",
                       clen, peer_idx, target->hostname,
                       ip4addr_ntoa(ip_2_ip4(&target->direct_addr)),
                       target->direct_port);
                disco_queue_direct_send(&s_disco,
                    ip4_addr_get_u32(ip_2_ip4(&target->direct_addr)),
                    target->direct_port, tmp, clen);
                return ERR_OK;
            }
        }
    }

    /* Fallback: send via DERP */
    if (!s_derp.ready) {
        TS_MAIN_DBG("DERP hook: not ready");
        return ERR_CONN;
    }

    TS_MAIN_DBG("DERP hook: %u bytes -> peer %d [%s] via region %u",
           p ? p->tot_len : 0, peer_idx, target->hostname, port);

    /* Copy pbuf data to contiguous buffer */
    uint8_t *buf = (uint8_t *)malloc(p->tot_len);
    if (!buf) return ERR_MEM;
    pbuf_copy_partial(p, buf, p->tot_len, 0);

    int ret = derp_send_packet(&s_derp, target->node_key, buf, p->tot_len);
    free(buf);

    if (ret < 0) {
        TS_ERR("DERP hook: send failed");
    }
    return (ret == 0) ? ERR_OK : ERR_IF;
}

/*
 * Find DERP node by region ID from our DERPMap.
 */
static derp_node_t *find_derp_node(int region_id)
{
    for (int i = 0; i < s_pm.derp_map.count; i++) {
        if (s_pm.derp_map.nodes[i].region_id == region_id)
            return &s_pm.derp_map.nodes[i];
    }
    return NULL;
}

/*
 * Start DERP connection to our preferred region.
 * Returns 0 on success, -1 on failure.
 */
static int start_derp(void)
{
    int region = s_pm.preferred_derp;
    if (region == 0) {
        /* Match hardcoded PreferredDERP in MapRequest NetInfo */
        region = 20;
    }
    /* If preferred region not in DERPMap, fallback to first available */
    if (!find_derp_node(region) && s_pm.derp_map.count > 0) {
        TS_LOG("DERP region %d not in map, fallback to %d",
               region, s_pm.derp_map.nodes[0].region_id);
        region = s_pm.derp_map.nodes[0].region_id;
    }
    if (region == 0) {
        TS_LOG("No DERP region available");
        return -1;
    }

    derp_node_t *node = find_derp_node(region);
    if (!node) {
        TS_ERR("DERP region %d not in map", region);
        return -1;
    }

    TS_LOG("Starting DERP to region %d: %s:%u",
           node->region_id, node->hostname, node->derp_port);

    derp_init(&s_derp);
    s_derp.region_id = node->region_id;
    memcpy(s_derp.node_priv, s_pm.node_priv, 32);
    memcpy(s_derp.node_pub, s_pm.node_pub, 32);
    s_derp.recv_cb  = derp_on_recv;
    s_derp.recv_ctx = NULL;

    if (derp_connect(&s_derp, node->hostname, node->derp_port) < 0) {
        TS_ERR("DERP connect failed");
        return -1;
    }

    /* Install WG output hook for DERP relay */
    wireguardif_set_output_hook(wg_derp_output_hook, NULL);

    /* Enable dual-path DISCO (direct UDP + DERP) */
    disco_set_derp(&s_disco, &s_derp);

    /* Enable WG direct path injection (non-DISCO packets on DISCO socket) */
    disco_set_raw_rx(&s_disco, disco_wg_direct_rx, NULL);

    /* Start recv task */
    derp_start(&s_derp);
    TS_LOG("DERP connected and recv task started");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Map polling task (reads streaming MapResponse updates)             */
/* ------------------------------------------------------------------ */

static bool s_map_running = false;

static void map_poll_task(void *param)
{
    (void)param;
    /* s_map_running is set by the caller before xTaskCreate */

    TS_LOG("Map poll task started (stream=%lu)", (unsigned long)s_map_stream_id);
    int consecutive_timeouts = 0;

    while (s_map_running) {
        /* 30s read timeout — server sends keepalive every ~30s */
        int resp_len = ts_http2_read_json(&s_h2, s_resp_buf,
                                            RESP_BUF_SIZE, 30000);
        if (resp_len < 0) {
            TS_ERR("Map stream closed");
            break;
        }

        if (resp_len == 0) {
            if (++consecutive_timeouts >= 4) {
                TS_ERR("Map stream dead (%d consecutive timeouts)", consecutive_timeouts);
                break;
            }
            continue;
        }
        consecutive_timeouts = 0;

        TS_LOG("Map update: %d bytes", resp_len);

        /* Skip keepalive responses */
        if (resp_len < 100) {
            s_resp_buf[resp_len] = '\0';
            TS_LOG("  Content: %s", (char *)s_resp_buf);
            if (strstr((char *)s_resp_buf, "KeepAlive")) {
                TS_LOG("  (keepalive ack)");
                continue;
            }
        }

        /* Save peer count before parsing */
        int old_count = s_pm.peer_count;
        int parsed = pm_parse_map_response(&s_pm, (char *)s_resp_buf, resp_len);

        /* Skip partial updates that have no peers (endpoint change notifications) */
        if (parsed == 0 && resp_len < 1000) {
            TS_LOG("  (partial update, no peer changes)");
            continue;
        }

        if (s_pm.peer_count != old_count) {
            TS_LOG("Peer count changed: %d -> %d", old_count, s_pm.peer_count);
        }

        /* Only set up WireGuard if not already running */
        if (s_pm.peer_count > 0 && !s_pm.wg_up) {
            TS_LOG("Peers available, setting up WireGuard");
            if (pm_setup_wireguard(&s_pm) == 0) {
                TS_LOG("WireGuard initialized from map_poll");
            } else {
                TS_ERR("WireGuard setup failed");
            }
        }
    }

    s_map_running = false;
    TS_LOG("Map poll task exiting");
    vTaskDelete(NULL);
}

/* ------------------------------------------------------------------ */
/*  Main state machine task                                            */
/* ------------------------------------------------------------------ */

static void ts_main_task(void *param)
{
    (void)param;

    printf("\r\n");
    printf("========================================\r\n");
    printf("   Tailscale Client for AMB82-MINI\r\n");
    printf("========================================\r\n\r\n");

    /* --- Step 1: WiFi --- */
    vTaskDelay(pdMS_TO_TICKS(5000));
    if (wifi_do_connect() != 0) {
        TS_ERR("No WiFi — aborting");
        goto done;
    }

    /* Start OTA server (available immediately after WiFi) */
    ota_server_start();
    TS_LOG("OTA server started");

    /* --- Step 2: SNTP --- */
    sntp_wait_sync(15000);

    /* --- Step 3: Init peer manager --- */
    pm_init(&s_pm);
    pm_set_hostname(&s_pm, TS_HOSTNAME);
    pm_set_auth_key(&s_pm, TS_AUTH_KEY);

    /* Set LAN IP so MapRequest includes our endpoint */
    {
        uint8_t *ip = LwIP_GetIP(0);
        char lan_ip[20];
        snprintf(lan_ip, sizeof(lan_ip), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
        pm_set_lan_ip(&s_pm, lan_ip);
        TS_LOG("LAN endpoint: %s:%u", lan_ip, s_pm.wg_listen_port);
    }

    pm_generate_keys(&s_pm);
    TS_LOG("Init done. Heap: %u", (unsigned)xPortGetFreeHeapSize());

    /* --- Main loop with reconnection --- */
    int reconnect_failures = 0;

    for (;;) {
        /* --- OTA Protection: heap safety valve --- */
        uint32_t free_heap = xPortGetFreeHeapSize();
        TS_LOG("Heap before reconnect: %u", (unsigned)free_heap);
        if (free_heap < HEAP_SAFETY_MIN) {
            TS_ERR("CRITICAL: Low heap (%u), skipping reconnect to protect OTA",
                   (unsigned)free_heap);
            vTaskDelay(pdMS_TO_TICKS(60000));
            continue;
        }

        /* --- OTA Protection: reconnect failure limit --- */
        if (reconnect_failures >= MAX_RECONNECT_FAILS) {
            TS_ERR("Too many reconnect failures (%d), entering OTA-only mode",
                   reconnect_failures);
            while (1) { vTaskDelay(pdMS_TO_TICKS(300000)); }
        }

        /* --- Step 4: Control connect + register --- */
        if (ctrl_connect_and_register() != 0) {
            reconnect_failures++;
            TS_ERR("Control connection failed (%d/%d), retry in %ds",
                   reconnect_failures, MAX_RECONNECT_FAILS,
                   RETRY_DELAY_MS / 1000);
            vTaskDelay(pdMS_TO_TICKS(RETRY_DELAY_MS));
            continue;
        }

        /* --- Step 5: STUN endpoint discovery (before MapRequest) --- */
        disco_init(&s_disco, &s_pm);
        disco_start(&s_disco, STUN_SERVER);
        TS_LOG("DISCO started, waiting for STUN...");

        /* Wait up to 3s for STUN to discover our public endpoint */
        for (int i = 0; i < 30 && !s_disco.self_endpoint.valid; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }

        if (s_disco.self_endpoint.valid) {
            pm_set_public_endpoint(&s_pm,
                                    s_disco.self_endpoint.ip,
                                    s_disco.self_endpoint.port);
        } else {
            TS_LOG("STUN timeout — continuing with LAN endpoint only");
        }

        /* --- Step 6: MapRequest (Stream=true, includes all fields) --- */
        if (send_map_request() != 0) {
            reconnect_failures++;
            TS_ERR("MapRequest failed (%d/%d), retry...",
                   reconnect_failures, MAX_RECONNECT_FAILS);
            disco_stop(&s_disco);
            ctrl_client_close(&s_ctrl);
            vTaskDelay(pdMS_TO_TICKS(RETRY_DELAY_MS));
            continue;
        }

        /* Connection + map succeeded — reset failure counter */
        reconnect_failures = 0;

        /* --- Step 7: Start DERP relay (before WG, needed for NAT traversal) --- */
        if (s_pm.derp_map.count > 0) {
            if (start_derp() == 0) {
                TS_LOG("DERP relay active");
            } else {
                TS_ERR("DERP failed (will try direct WG only)");
            }
        } else {
            TS_LOG("No DERPMap — DERP relay not available");
        }

        /* --- Step 8: Setup WireGuard --- */
        if (s_pm.peer_count > 0) {
            TS_LOG("Setting up WireGuard (%d peers)...", s_pm.peer_count);

            /* If DERP is connected, set ALL peer endpoints to virtual DERP address
             * 127.3.PEER_IDX.40:REGION_ID — the idx encodes which pm peer it is. */
            if (s_derp.ready) {
                for (int i = 0; i < s_pm.peer_count; i++) {
                    if (s_pm.peers[i].valid && s_pm.peers[i].derp_region > 0) {
                        snprintf(s_pm.peers[i].endpoint,
                                 sizeof(s_pm.peers[i].endpoint),
                                 "127.3.%d.40:%d", i,
                                 s_pm.peers[i].derp_region);
                        s_pm.peers[i].endpoint_port =
                            (uint16_t)s_pm.peers[i].derp_region;
                        TS_LOG("Peer %d [%s] DERP ep: %s:%u", i,
                               s_pm.peers[i].hostname,
                               s_pm.peers[i].endpoint,
                               s_pm.peers[i].endpoint_port);
                    }
                }
            }

            if (pm_setup_wireguard(&s_pm) == 0) {
                TS_LOG("WireGuard initialized with %d peers", s_pm.peer_count);

                /* If using DERP, update all WG peer endpoints to virtual addr
                 * and initiate connection to each. */
                if (s_derp.ready) {
                    ameba_wg_ctx_t *wg = (ameba_wg_ctx_t *)s_pm.wg_ctx;
                    for (int i = 0; i < s_pm.peer_count; i++) {
                        ts_peer_t *p = &s_pm.peers[i];
                        if (!p->valid || p->wg_peer_idx == 0xFF) continue;
                        if (p->derp_region <= 0) continue;
                        ip_addr_t derp_addr;
                        IP4_ADDR(ip_2_ip4(&derp_addr), 127, 3, (uint8_t)i, 40);
                        wireguardif_update_endpoint(&wg->netif, p->wg_peer_idx,
                                                    &derp_addr,
                                                    (u16_t)p->derp_region);
                        wireguardif_connect(&wg->netif, p->wg_peer_idx);
                        TS_LOG("WG peer %d connected via DERP (wg_idx=%u)",
                               i, p->wg_peer_idx);
                    }
                }

                /* Wait for any handshake */
                for (int w = 0; w < 30; w++) {
                    bool any_up = false;
                    for (int i = 0; i < s_pm.peer_count; i++) {
                        if (pm_peer_is_up(&s_pm, i)) {
                            TS_LOG("*** WireGuard TUNNEL UP (peer %d [%s]) ***",
                                   i, s_pm.peers[i].hostname);
                            any_up = true;
                        }
                    }
                    if (any_up) break;
                    vTaskDelay(pdMS_TO_TICKS(1000));
                }
            } else {
                TS_ERR("WireGuard setup failed (continuing without)");
            }
        } else {
            TS_LOG("No peers — skipping WireGuard");
        }

        /* --- Step 9: Start map polling in background --- */
        s_map_running = true;  /* set BEFORE task creation to avoid race */
        xTaskCreate(map_poll_task, "map_poll", 8192, NULL,
                     tskIDLE_PRIORITY + 1, NULL);

        /* --- Step 10: Monitor --- */
        TS_LOG("Running. Self IP: %s  DERP: %s (region %d)",
               s_pm.self_ip,
               s_derp.ready ? "connected" : "off",
               s_derp.region_id);
        TS_LOG("Free heap: %u bytes", (unsigned)xPortGetFreeHeapSize());

        while (s_map_running) {
            /* Print compact status every 30s */
            int up_count = 0;
            for (int i = 0; i < s_pm.peer_count; i++) {
                if (s_pm.peers[i].valid && pm_peer_is_up(&s_pm, i))
                    up_count++;
            }
            TS_LOG("Peers: %d/%d up, DERP: %s, Heap: %u",
                   up_count, s_pm.peer_count,
                   s_derp.ready ? "ok" : "off",
                   (unsigned)xPortGetFreeHeapSize());
            vTaskDelay(pdMS_TO_TICKS(30000));
        }

        /* Map stream closed — reconnect */
        TS_LOG("Control connection lost, cleaning up...");
        s_map_running = false;  /* signal map_poll to stop */
        vTaskDelay(pdMS_TO_TICKS(2000));  /* wait for map_poll to exit */
        wireguardif_set_output_hook(NULL, NULL);  /* remove DERP hook */
        derp_close(&s_derp);
        disco_stop(&s_disco);
        pm_teardown_wireguard(&s_pm);
        ctrl_client_close(&s_ctrl);

        TS_LOG("Reconnecting in %ds...", RETRY_DELAY_MS / 1000);
        vTaskDelay(pdMS_TO_TICKS(RETRY_DELAY_MS));
    }

done:
    TS_LOG("Task exiting");
    vTaskDelete(NULL);
}

/* ------------------------------------------------------------------ */
/*  Entry point (called from main.c / setup)                           */
/* ------------------------------------------------------------------ */

void app_example(void)
{
    if (xTaskCreate(ts_main_task,
                    "ts_main",
                    TS_TASK_STACK,
                    NULL,
                    TS_TASK_PRIO,
                    NULL) != pdPASS) {
        printf(LOG_TAG "Failed to create task!\r\n");
    }
}
