/*
 * peer_manager.c — Tailscale peer management + WireGuard integration
 *
 * Implements:
 *   - Key generation (machine, node, disco)
 *   - RegisterRequest / MapRequest JSON construction (cJSON)
 *   - RegisterResponse / MapResponse parsing
 *   - WireGuard interface setup and peer endpoint management
 */

#include "peer_manager.h"
#include "ts_log.h"
#include "ts_key_store.h"
#include <string.h>
#include <stdio.h>
#include "cJSON.h"
#include "ameba_wireguard.h"
#include "wireguardif.h"
#include "wireguard.h"
#include "lwip/ip_addr.h"
#include "FreeRTOS.h"
#include "task.h"

#define LOG_TAG "[PM] "
#define PM_LOG(fmt, ...) printf(LOG_TAG fmt "\r\n", ##__VA_ARGS__)
#define PM_ERR(fmt, ...) printf(LOG_TAG "ERROR: " fmt "\r\n", ##__VA_ARGS__)
#define PM_DBG(fmt, ...) TS_DBG(LOG_TAG fmt "\r\n", ##__VA_ARGS__)

/* Base64 key buffer: ceil(32/3)*4 + 1 = 45 */
#define B64_KEY_BUF 48

/* "nodekey:" + 64 hex chars + null = 73, round up */
#define PREFIX_KEY_BUF 80

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                   */
/* ------------------------------------------------------------------ */

/* Format key with prefix: "nodekey:HEX64" */
static void format_key(char *out, const char *prefix, const uint8_t *key)
{
    size_t plen = strlen(prefix);
    memcpy(out, prefix, plen);
    ts_key_to_hex(out + plen, key);
    out[plen + 64] = '\0';
}

/* Parse "nodekey:HEX64" → 32-byte key */
static int parse_prefixed_key(uint8_t *key_out, const char *str)
{
    const char *colon = strchr(str, ':');
    if (!colon) return -1;
    const char *hex = colon + 1;
    size_t hex_len = strlen(hex);
    if (hex_len != 64) return -1;
    return ts_hex_to_key(key_out, hex, hex_len);
}

/* Strip CIDR: "100.64.0.2/32" → "100.64.0.2" */
static void strip_cidr(char *dst, size_t dst_len, const char *addr)
{
    const char *slash = strchr(addr, '/');
    size_t len = slash ? (size_t)(slash - addr) : strlen(addr);
    if (len >= dst_len) len = dst_len - 1;
    memcpy(dst, addr, len);
    dst[len] = '\0';
}

/* Parse "IP:port" → IP string + port */
static int parse_endpoint(const char *ep, char *ip_out, size_t ip_len,
                           uint16_t *port_out)
{
    const char *colon = strrchr(ep, ':');
    if (!colon) return -1;
    size_t ipsz = (size_t)(colon - ep);
    if (ipsz >= ip_len) return -1;
    memcpy(ip_out, ep, ipsz);
    ip_out[ipsz] = '\0';
    *port_out = (uint16_t)atoi(colon + 1);
    return 0;
}

/* Binary key → base64 string (for WireGuard API) */
static int key_to_b64(char *out, size_t out_size, const uint8_t *key)
{
    size_t outlen = out_size;
    return wireguard_base64_encode(key, 32, out, &outlen) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/*  API: Initialization                                                */
/* ------------------------------------------------------------------ */

void pm_init(peer_manager_t *pm)
{
    memset(pm, 0, sizeof(*pm));
    pm->wg_listen_port = 41641;  /* Tailscale default */
    for (int i = 0; i < PM_MAX_PEERS; i++) {
        pm->peers[i].wg_peer_idx = 0xFF;
        pm->peers[i].best_ep_idx = -1;
    }
}

void pm_generate_keys(peer_manager_t *pm)
{
    /* Always init TRNG + CTR_DRBG — needed by TLS and Noise even if keys come from flash */
    extern int wireguard_platform_init(void);
    wireguard_platform_init();

    /* Try loading persisted keys from flash first */
    if (ts_key_store_load(pm) == 0) {
        PM_LOG("Keys loaded from flash");
        char hex[65];
        ts_key_to_hex(hex, pm->machine_pub);
        PM_LOG("Machine: mkey:%s", hex);
        ts_key_to_hex(hex, pm->node_pub);
        PM_LOG("Node:    nodekey:%s", hex);
        ts_key_to_hex(hex, pm->disco_pub);
        PM_LOG("Disco:   discokey:%s", hex);
        return;
    }

    /* No saved keys — generate new ones */
    PM_LOG("No saved keys, generating new ones...");

    ts_keygen(pm->machine_priv, pm->machine_pub);
    ts_keygen(pm->node_priv, pm->node_pub);
    ts_keygen(pm->disco_priv, pm->disco_pub);

    /* Persist to flash */
    if (ts_key_store_save(pm) == 0) {
        PM_LOG("Keys saved to flash");
    } else {
        PM_ERR("Failed to save keys to flash!");
    }

    char hex[65];
    ts_key_to_hex(hex, pm->machine_pub);
    PM_LOG("Machine: mkey:%s", hex);
    ts_key_to_hex(hex, pm->node_pub);
    PM_LOG("Node:    nodekey:%s", hex);
    ts_key_to_hex(hex, pm->disco_pub);
    PM_LOG("Disco:   discokey:%s", hex);
}

void pm_set_hostname(peer_manager_t *pm, const char *hostname)
{
    strncpy(pm->hostname, hostname, sizeof(pm->hostname) - 1);
}

void pm_set_auth_key(peer_manager_t *pm, const char *auth_key)
{
    strncpy(pm->auth_key, auth_key, sizeof(pm->auth_key) - 1);
}

void pm_set_lan_ip(peer_manager_t *pm, const char *ip)
{
    strncpy(pm->lan_ip, ip, sizeof(pm->lan_ip) - 1);
}

void pm_set_public_endpoint(peer_manager_t *pm, const char *ip, uint16_t port)
{
    strncpy(pm->public_ip, ip, sizeof(pm->public_ip) - 1);
    pm->public_port = port;
    PM_LOG("Public endpoint set: %s:%u", pm->public_ip, pm->public_port);
}

/* ------------------------------------------------------------------ */
/*  API: JSON builders                                                 */
/* ------------------------------------------------------------------ */

int pm_build_register_json(peer_manager_t *pm, char *buf, size_t buf_len)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    char kbuf[PREFIX_KEY_BUF];

    cJSON_AddNumberToObject(root, "Version", TS_CAP_VERSION);

    format_key(kbuf, "nodekey:", pm->node_pub);
    cJSON_AddStringToObject(root, "NodeKey", kbuf);
    cJSON_AddStringToObject(root, "OldNodeKey", kbuf);

    format_key(kbuf, "mkey:", pm->machine_pub);
    cJSON_AddStringToObject(root, "MachineKey", kbuf);

    format_key(kbuf, "discokey:", pm->disco_pub);
    cJSON_AddStringToObject(root, "DiscoKey", kbuf);

    /* Hostinfo */
    cJSON *hi = cJSON_CreateObject();
    cJSON_AddStringToObject(hi, "Hostname", pm->hostname);
    cJSON_AddStringToObject(hi, "OS", "freertos");
    cJSON_AddStringToObject(hi, "GoArch", "arm");
    cJSON_AddItemToObject(root, "Hostinfo", hi);

    /* Auth */
    if (pm->auth_key[0]) {
        cJSON *auth = cJSON_CreateObject();
        cJSON_AddStringToObject(auth, "AuthKey", pm->auth_key);
        cJSON_AddItemToObject(root, "Auth", auth);
    }

    cJSON_AddBoolToObject(root, "Ephemeral", 0);

    char *js = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!js) return -1;

    int len = (int)strlen(js);
    if ((size_t)len >= buf_len) { free(js); return -1; }
    memcpy(buf, js, len + 1);
    free(js);

    PM_LOG("RegisterRequest: %d bytes", len);
    return len;
}

int pm_build_map_json(peer_manager_t *pm, char *buf, size_t buf_len)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    char kbuf[PREFIX_KEY_BUF];

    cJSON_AddNumberToObject(root, "Version", TS_CAP_VERSION);

    format_key(kbuf, "nodekey:", pm->node_pub);
    cJSON_AddStringToObject(root, "NodeKey", kbuf);

    format_key(kbuf, "discokey:", pm->disco_pub);
    cJSON_AddStringToObject(root, "DiscoKey", kbuf);

    /* Match ESP32: KeepAlive=false, Stream=true, ReadOnly=false */
    cJSON_AddBoolToObject(root, "KeepAlive", 0);
    cJSON_AddBoolToObject(root, "ReadOnly", 0);
    cJSON_AddBoolToObject(root, "Stream", 1);
    cJSON_AddBoolToObject(root, "OmitPeers", 0);
    cJSON_AddStringToObject(root, "Compress", "");

    /* Endpoints — tell control server where peers can reach us */
    {
        cJSON *eps = cJSON_CreateArray();
        cJSON *ept = cJSON_CreateArray();

        /* Public endpoint (from STUN) — type 2 (EndpointSTUN) */
        if (pm->public_ip[0]) {
            char ep_str[64];
            snprintf(ep_str, sizeof(ep_str), "%s:%u", pm->public_ip, pm->public_port);
            cJSON_AddItemToArray(eps, cJSON_CreateString(ep_str));
            cJSON_AddItemToArray(ept, cJSON_CreateNumber(2));
        }

        /* LAN endpoint — type 1 (local) */
        if (pm->lan_ip[0]) {
            char ep_str[64];
            snprintf(ep_str, sizeof(ep_str), "%s:%u", pm->lan_ip, pm->wg_listen_port);
            cJSON_AddItemToArray(eps, cJSON_CreateString(ep_str));
            cJSON_AddItemToArray(ept, cJSON_CreateNumber(1));
        }

        if (cJSON_GetArraySize(eps) > 0) {
            cJSON_AddItemToObject(root, "Endpoints", eps);
            cJSON_AddItemToObject(root, "EndpointTypes", ept);
        } else {
            cJSON_Delete(eps);
            cJSON_Delete(ept);
        }
    }

    /* Hostinfo — required by Tailscale control server */
    cJSON *hi = cJSON_CreateObject();
    cJSON_AddStringToObject(hi, "Hostname", pm->hostname);
    cJSON_AddStringToObject(hi, "OS", "freertos");
    cJSON_AddStringToObject(hi, "GoArch", "arm");

    /* NetInfo inside Hostinfo */
    cJSON *ni = cJSON_CreateObject();
    cJSON_AddNumberToObject(ni, "PreferredDERP", 20);
    cJSON_AddBoolToObject(ni, "MappingVariesByDestIP", 0);
    cJSON_AddBoolToObject(ni, "HairPinning", 0);
    cJSON_AddBoolToObject(ni, "WorkingIPv4", 1);
    cJSON_AddBoolToObject(ni, "WorkingIPv6", 0);
    cJSON_AddStringToObject(ni, "LinkType", "wifi");
    cJSON_AddItemToObject(hi, "NetInfo", ni);

    cJSON_AddItemToObject(root, "Hostinfo", hi);

    char *js = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!js) return -1;

    int len = (int)strlen(js);
    if ((size_t)len >= buf_len) { free(js); return -1; }
    memcpy(buf, js, len + 1);
    free(js);

    PM_LOG("MapRequest: %d bytes", len);
    PM_DBG("MapRequest JSON: %s", buf);
    return len;
}

int pm_build_keepalive_json(peer_manager_t *pm, char *buf, size_t buf_len)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    char kbuf[PREFIX_KEY_BUF];

    cJSON_AddNumberToObject(root, "Version", TS_CAP_VERSION);

    format_key(kbuf, "nodekey:", pm->node_pub);
    cJSON_AddStringToObject(root, "NodeKey", kbuf);

    format_key(kbuf, "discokey:", pm->disco_pub);
    cJSON_AddStringToObject(root, "DiscoKey", kbuf);

    cJSON_AddBoolToObject(root, "KeepAlive", 1);
    cJSON_AddBoolToObject(root, "Stream", 1);
    cJSON_AddBoolToObject(root, "OmitPeers", 1);
    cJSON_AddStringToObject(root, "Compress", "");

    /* Endpoints — update control server with our reachability */
    {
        cJSON *eps = cJSON_CreateArray();
        cJSON *ept = cJSON_CreateArray();

        /* Public endpoint (from STUN) — type 2 (EndpointSTUN) */
        if (pm->public_ip[0]) {
            char ep_str[64];
            snprintf(ep_str, sizeof(ep_str), "%s:%u", pm->public_ip, pm->public_port);
            cJSON_AddItemToArray(eps, cJSON_CreateString(ep_str));
            cJSON_AddItemToArray(ept, cJSON_CreateNumber(2));
        }

        /* LAN endpoint — type 1 (local) */
        if (pm->lan_ip[0]) {
            char ep_str[64];
            snprintf(ep_str, sizeof(ep_str), "%s:%u", pm->lan_ip, pm->wg_listen_port);
            cJSON_AddItemToArray(eps, cJSON_CreateString(ep_str));
            cJSON_AddItemToArray(ept, cJSON_CreateNumber(1));
        }

        if (cJSON_GetArraySize(eps) > 0) {
            cJSON_AddItemToObject(root, "Endpoints", eps);
            cJSON_AddItemToObject(root, "EndpointTypes", ept);
        } else {
            cJSON_Delete(eps);
            cJSON_Delete(ept);
        }
    }

    /* Hostinfo with NetInfo */
    cJSON *hi = cJSON_CreateObject();
    cJSON_AddStringToObject(hi, "Hostname", pm->hostname);
    cJSON_AddStringToObject(hi, "OS", "freertos");
    cJSON_AddStringToObject(hi, "GoArch", "arm");
    cJSON *ni = cJSON_CreateObject();
    cJSON_AddNumberToObject(ni, "PreferredDERP", 20);
    cJSON_AddBoolToObject(ni, "MappingVariesByDestIP", 0);
    cJSON_AddBoolToObject(ni, "HairPinning", 0);
    cJSON_AddBoolToObject(ni, "WorkingIPv4", 1);
    cJSON_AddBoolToObject(ni, "WorkingIPv6", 0);
    cJSON_AddStringToObject(ni, "LinkType", "wifi");
    cJSON_AddItemToObject(hi, "NetInfo", ni);
    cJSON_AddItemToObject(root, "Hostinfo", hi);

    char *js = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!js) return -1;

    int len = (int)strlen(js);
    if ((size_t)len >= buf_len) { free(js); return -1; }
    memcpy(buf, js, len + 1);
    free(js);

    PM_LOG("Keepalive: %d bytes", len);
    return len;
}

/* ------------------------------------------------------------------ */
/*  API: Response parsing                                              */
/* ------------------------------------------------------------------ */

int pm_parse_register_response(peer_manager_t *pm,
                                const char *json, size_t json_len)
{
    char *tmp = (char *)malloc(json_len + 1);
    if (!tmp) return -1;
    memcpy(tmp, json, json_len);
    tmp[json_len] = '\0';

    cJSON *root = cJSON_Parse(tmp);
    free(tmp);
    if (!root) {
        PM_ERR("Parse RegisterResponse failed");
        return -1;
    }

    /* Check for error field */
    cJSON *err = cJSON_GetObjectItem(root, "Error");
    if (err && cJSON_IsString(err) && err->valuestring[0]) {
        PM_ERR("Register error: %s", err->valuestring);
        cJSON_Delete(root);
        return -1;
    }

    /* Check MachineAuthorized */
    cJSON *ma = cJSON_GetObjectItem(root, "MachineAuthorized");
    if (ma && cJSON_IsTrue(ma)) {
        pm->registered = true;
        PM_LOG("Registration authorized");
    } else {
        cJSON *url = cJSON_GetObjectItem(root, "AuthURL");
        if (url && cJSON_IsString(url) && url->valuestring[0]) {
            PM_LOG("AuthURL: %s", url->valuestring);
            pm->registered = false;
        } else {
            /* No error, no AuthURL → assume authorized */
            pm->registered = true;
            PM_LOG("Registration accepted");
        }
    }

    cJSON_Delete(root);
    return 0;
}

int pm_parse_map_response(peer_manager_t *pm,
                           const char *json, size_t json_len)
{
    char *tmp = (char *)malloc(json_len + 1);
    if (!tmp) return -1;
    memcpy(tmp, json, json_len);
    tmp[json_len] = '\0';

    cJSON *root = cJSON_Parse(tmp);
    free(tmp);
    if (!root) {
        PM_ERR("Parse MapResponse failed");
        return -1;
    }

    /* Self IP from Node.Addresses[0] */
    cJSON *node = cJSON_GetObjectItem(root, "Node");
    if (node) {
        cJSON *addrs = cJSON_GetObjectItem(node, "Addresses");
        if (addrs && cJSON_IsArray(addrs)) {
            cJSON *first = cJSON_GetArrayItem(addrs, 0);
            if (first && cJSON_IsString(first)) {
                strip_cidr(pm->self_ip, sizeof(pm->self_ip),
                           first->valuestring);
                PM_LOG("Self IP: %s", pm->self_ip);
            }
        }

        /* Debug: check if server stored our endpoints */
        cJSON *self_ep = cJSON_GetObjectItem(node, "Endpoints");
        if (self_ep && cJSON_IsArray(self_ep)) {
            int ep_count = cJSON_GetArraySize(self_ep);
            PM_DBG("Self endpoints in MapResponse: %d", ep_count);
            for (int i = 0; i < ep_count && i < 4; i++) {
                cJSON *e = cJSON_GetArrayItem(self_ep, i);
                if (e && cJSON_IsString(e))
                    PM_DBG("  EP[%d]: %s", i, e->valuestring);
            }
        } else {
            PM_DBG("Self endpoints: NONE (server didn't store our endpoints)");
        }
    }

    /* DERPMap — extract DERP server nodes */
    cJSON *dmap = cJSON_GetObjectItem(root, "DERPMap");
    if (dmap) {
        cJSON *regions = cJSON_GetObjectItem(dmap, "Regions");
        if (regions) {
            pm->derp_map.count = 0;
            cJSON *reg = NULL;
            cJSON_ArrayForEach(reg, regions) {
                if (pm->derp_map.count >= DERP_MAX_NODES) break;

                int region_id = 0;
                cJSON *rid = cJSON_GetObjectItem(reg, "RegionID");
                if (rid && cJSON_IsNumber(rid)) region_id = rid->valueint;

                cJSON *nodes = cJSON_GetObjectItem(reg, "Nodes");
                if (!nodes || !cJSON_IsArray(nodes)) continue;

                cJSON *n0 = cJSON_GetArrayItem(nodes, 0);
                if (!n0) continue;

                derp_node_t *dn = &pm->derp_map.nodes[pm->derp_map.count];
                memset(dn, 0, sizeof(*dn));
                dn->region_id = region_id;
                dn->derp_port = 443;
                dn->stun_port = 3478;

                cJSON *hn = cJSON_GetObjectItem(n0, "HostName");
                if (hn && cJSON_IsString(hn))
                    strncpy(dn->hostname, hn->valuestring, sizeof(dn->hostname) - 1);

                cJSON *ip4 = cJSON_GetObjectItem(n0, "IPv4");
                if (ip4 && cJSON_IsString(ip4))
                    strncpy(dn->ipv4, ip4->valuestring, sizeof(dn->ipv4) - 1);

                cJSON *dp = cJSON_GetObjectItem(n0, "DERPPort");
                if (dp && cJSON_IsNumber(dp) && dp->valueint > 0)
                    dn->derp_port = (uint16_t)dp->valueint;

                cJSON *sp = cJSON_GetObjectItem(n0, "STUNPort");
                if (sp && cJSON_IsNumber(sp) && sp->valueint > 0)
                    dn->stun_port = (uint16_t)sp->valueint;

                pm->derp_map.count++;
                PM_LOG("DERP region %d: %s (%s:%u)",
                       dn->region_id, dn->hostname, dn->ipv4, dn->derp_port);
            }
            PM_LOG("DERPMap: %d regions", pm->derp_map.count);
        }
    }

    /* Self preferred DERP from Node.DERP (format: "127.3.3.40:N") */
    if (node) {
        cJSON *derp_val = cJSON_GetObjectItem(node, "DERP");
        if (derp_val && cJSON_IsString(derp_val)) {
            const char *dstr = derp_val->valuestring;
            const char *colon = strrchr(dstr, ':');
            if (colon) {
                pm->preferred_derp = atoi(colon + 1);
                PM_LOG("Self preferred DERP: %d", pm->preferred_derp);
            }
        }
    }

    /* Peers array: try "Peers" first, then "PeersChanged" (incremental updates) */
    cJSON *peers_arr = cJSON_GetObjectItem(root, "Peers");
    if (!peers_arr || !cJSON_IsArray(peers_arr)) {
        peers_arr = cJSON_GetObjectItem(root, "PeersChanged");
    }
    if (!peers_arr || !cJSON_IsArray(peers_arr)) {
        PM_LOG("No peers in MapResponse");
        cJSON_Delete(root);
        return 0;
    }

    int count = 0;
    int arr_sz = cJSON_GetArraySize(peers_arr);

    for (int i = 0; i < arr_sz && count < PM_MAX_PEERS; i++) {
        cJSON *pj = cJSON_GetArrayItem(peers_arr, i);
        if (!pj) continue;

        ts_peer_t *p = &pm->peers[count];
        memset(p, 0, sizeof(*p));
        p->wg_peer_idx = 0xFF;
        p->best_ep_idx = -1;

        /* Key (required) = WireGuard peer public key */
        cJSON *key = cJSON_GetObjectItem(pj, "Key");
        if (!key || !cJSON_IsString(key)) continue;
        if (parse_prefixed_key(p->node_key, key->valuestring) < 0) continue;

        /* DiscoKey */
        cJSON *dk = cJSON_GetObjectItem(pj, "DiscoKey");
        if (dk && cJSON_IsString(dk))
            parse_prefixed_key(p->disco_key, dk->valuestring);

        /* Addresses[0] → Tailscale IP */
        cJSON *pa = cJSON_GetObjectItem(pj, "Addresses");
        if (pa && cJSON_IsArray(pa)) {
            cJSON *a0 = cJSON_GetArrayItem(pa, 0);
            if (a0 && cJSON_IsString(a0))
                strip_cidr(p->ip, sizeof(p->ip), a0->valuestring);
        }

        /* Endpoints[0] → "IP:port" */
        cJSON *ep = cJSON_GetObjectItem(pj, "Endpoints");
        if (ep && cJSON_IsArray(ep)) {
            cJSON *e0 = cJSON_GetArrayItem(ep, 0);
            if (e0 && cJSON_IsString(e0)) {
                strncpy(p->endpoint, e0->valuestring,
                        sizeof(p->endpoint) - 1);
                char eip[PM_MAX_IP_LEN];
                parse_endpoint(e0->valuestring, eip, sizeof(eip),
                               &p->endpoint_port);
            }
        }

        /* Hostinfo.Hostname */
        cJSON *hi = cJSON_GetObjectItem(pj, "Hostinfo");
        if (hi) {
            cJSON *hn = cJSON_GetObjectItem(hi, "Hostname");
            if (hn && cJSON_IsString(hn))
                strncpy(p->hostname, hn->valuestring,
                        sizeof(p->hostname) - 1);
        }

        /* DERP region: "127.3.3.40:N" → extract N */
        cJSON *pderp = cJSON_GetObjectItem(pj, "DERP");
        if (pderp && cJSON_IsString(pderp)) {
            const char *dc = strrchr(pderp->valuestring, ':');
            if (dc) p->derp_region = atoi(dc + 1);
        }

        p->valid = true;
        count++;
        PM_LOG("Peer %d: %s (%s) ep=%s", count - 1,
               p->hostname, p->ip, p->endpoint);
    }

    pm->peer_count = count;
    cJSON_Delete(root);
    PM_LOG("Parsed %d peers", count);
    return count;
}

/* ------------------------------------------------------------------ */
/*  API: WireGuard integration                                         */
/* ------------------------------------------------------------------ */

/* Single static WG context */
static ameba_wg_ctx_t s_wg_ctx;

int pm_setup_wireguard(peer_manager_t *pm)
{
    if (!pm->self_ip[0]) {
        PM_ERR("No self IP — call pm_parse_map_response first");
        return -1;
    }
    if (pm->peer_count == 0 || !pm->peers[0].valid) {
        PM_ERR("No valid peers");
        return -1;
    }

    ts_peer_t *peer = &pm->peers[0];

    /* Encode keys to base64 for WG API */
    char priv_b64[B64_KEY_BUF], peer_b64[B64_KEY_BUF];
    if (key_to_b64(priv_b64, sizeof(priv_b64), pm->node_priv) < 0 ||
        key_to_b64(peer_b64, sizeof(peer_b64), peer->node_key) < 0) {
        PM_ERR("Base64 key encoding failed");
        return -1;
    }

    /* Build WG config */
    ameba_wg_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg.private_key = priv_b64;
    cfg.listen_port = pm->wg_listen_port;

    /* Self Tailscale IP — use /10 mask for Tailscale CGNAT range (100.64.0.0/10) */
    ipaddr_aton(pm->self_ip, &cfg.ip);
    ipaddr_aton("255.192.0.0", &cfg.netmask);
    cfg.gateway = cfg.ip;

    /* Peer */
    cfg.peer_public_key = peer_b64;
    cfg.preshared_key = NULL;

    /* Peer endpoint (may be empty — DISCO fills it later) */
    char ep_ip[PM_MAX_IP_LEN] = {0};
    uint16_t ep_port = 0;
    if (peer->endpoint[0]) {
        parse_endpoint(peer->endpoint, ep_ip, sizeof(ep_ip), &ep_port);
        cfg.endpoint = ep_ip;
        cfg.endpoint_port = ep_port;
    }

    /* Allowed IP: peer's Tailscale IP /32 — used for WG send routing */
    if (peer->ip[0]) {
        ipaddr_aton(peer->ip, &cfg.allowed_ip);
        ipaddr_aton("255.255.255.255", &cfg.allowed_mask);
    } else {
        ipaddr_aton("0.0.0.0", &cfg.allowed_ip);
        ipaddr_aton("0.0.0.0", &cfg.allowed_mask);
    }

    cfg.persistent_keepalive = 25;

    PM_LOG("WG init: self=%s port=%u peer=%s ep=%s:%u",
           pm->self_ip, pm->wg_listen_port,
           peer->hostname[0] ? peer->hostname : "?",
           ep_ip[0] ? ep_ip : "none", ep_port);

    int ret = ameba_wg_init(&cfg, &s_wg_ctx);
    if (ret != AMEBA_WG_OK) {
        PM_ERR("ameba_wg_init failed: %d", ret);
        return -1;
    }

    pm->wg_ctx = &s_wg_ctx;
    peer->wg_peer_idx = s_wg_ctx.peer_index;

    ret = ameba_wg_connect(&s_wg_ctx);
    if (ret != AMEBA_WG_OK) {
        PM_ERR("ameba_wg_connect failed: %d", ret);
        return -1;
    }

    /* Add remaining peers */
    for (int i = 1; i < pm->peer_count; i++) {
        ts_peer_t *p = &pm->peers[i];
        if (!p->valid) continue;

        char pb64[B64_KEY_BUF];
        if (key_to_b64(pb64, sizeof(pb64), p->node_key) < 0) {
            PM_ERR("Peer %d key encode failed", i);
            continue;
        }

        ip_addr_t aip, amask, ep_addr;
        /* Allowed IP: peer's Tailscale IP /32 — used for WG send routing */
        if (p->ip[0]) {
            ipaddr_aton(p->ip, &aip);
        } else {
            ipaddr_aton("0.0.0.0", &aip);
        }
        ipaddr_aton("255.255.255.255", &amask);

        /* Parse endpoint for this peer */
        ip_addr_t *ep_ptr = NULL;
        uint16_t p_ep_port = 0;
        char p_ep_ip[PM_MAX_IP_LEN] = {0};
        if (p->endpoint[0]) {
            parse_endpoint(p->endpoint, p_ep_ip, sizeof(p_ep_ip), &p_ep_port);
            if (p_ep_ip[0]) {
                ipaddr_aton(p_ep_ip, &ep_addr);
                ep_ptr = &ep_addr;
            }
        }

        uint8_t pidx = 0xFF;
        ret = ameba_wg_add_peer(&s_wg_ctx, pb64, &aip, &amask,
                                ep_ptr, p_ep_port, 25, &pidx);
        if (ret == AMEBA_WG_OK) {
            p->wg_peer_idx = pidx;
            PM_LOG("WG peer %d [%s] added (idx=%u)", i, p->hostname, pidx);
        } else {
            PM_ERR("WG peer %d add failed: %d", i, ret);
        }
    }

    pm->wg_up = true;
    PM_LOG("WireGuard up with %d peers, connecting...", pm->peer_count);
    return 0;
}

int pm_update_peer_endpoint(peer_manager_t *pm, int peer_idx,
                             const char *ip, uint16_t port)
{
    if (peer_idx < 0 || peer_idx >= pm->peer_count) return -1;
    if (!pm->wg_ctx) return -1;

    ts_peer_t *p = &pm->peers[peer_idx];
    if (p->wg_peer_idx == 0xFF) {
        PM_ERR("Peer %d not in WG", peer_idx);
        return -1;
    }

    ameba_wg_ctx_t *ctx = (ameba_wg_ctx_t *)pm->wg_ctx;

    ip_addr_t ep_addr;
    ipaddr_aton(ip, &ep_addr);

    err_t err = wireguardif_update_endpoint(&ctx->netif,
                                             p->wg_peer_idx,
                                             &ep_addr, port);
    if (err != ERR_OK) {
        PM_ERR("wireguardif_update_endpoint: %d", err);
        return -1;
    }

    /* Update stored info */
    snprintf(p->endpoint, sizeof(p->endpoint), "%s:%u", ip, port);
    p->endpoint_port = port;

    wireguardif_connect(&ctx->netif, p->wg_peer_idx);
    PM_LOG("Peer %d endpoint → %s:%u", peer_idx, ip, port);
    return 0;
}

bool pm_peer_is_up(peer_manager_t *pm, int peer_idx)
{
    if (peer_idx < 0 || peer_idx >= pm->peer_count) return false;
    if (!pm->wg_ctx) return false;

    ts_peer_t *p = &pm->peers[peer_idx];
    if (p->wg_peer_idx == 0xFF) return false;

    ameba_wg_ctx_t *ctx = (ameba_wg_ctx_t *)pm->wg_ctx;
    ip_addr_t cur_ip;
    u16_t cur_port;

    return (wireguardif_peer_is_up(&ctx->netif, p->wg_peer_idx,
                                    &cur_ip, &cur_port) == ERR_OK);
}

void pm_teardown_wireguard(peer_manager_t *pm)
{
    if (!pm->wg_ctx) return;

    ameba_wg_ctx_t *ctx = (ameba_wg_ctx_t *)pm->wg_ctx;
    ameba_wg_disconnect(ctx);

    pm->wg_ctx = NULL;
    pm->wg_up = false;
    for (int i = 0; i < pm->peer_count; i++)
        pm->peers[i].wg_peer_idx = 0xFF;

    PM_LOG("WireGuard torn down");
}

void pm_update_endpoint_latency(peer_manager_t *pm, int peer_idx,
                                 const ip_addr_t *addr, uint16_t port,
                                 uint32_t rtt_ms)
{
    if (peer_idx < 0 || peer_idx >= pm->peer_count) return;
    ts_peer_t *p = &pm->peers[peer_idx];

    /* Find existing endpoint or use a free slot */
    int slot = -1;
    for (int i = 0; i < p->ep_count; i++) {
        if (ip_addr_cmp(&p->eps[i].addr, addr) && p->eps[i].port == port) {
            slot = i;
            break;
        }
    }
    if (slot < 0 && p->ep_count < TS_MAX_EP_PER_PEER) {
        slot = p->ep_count++;
    }
    if (slot < 0) return;  /* No room */

    p->eps[slot].addr = *addr;
    p->eps[slot].port = port;
    p->eps[slot].latency_ms = rtt_ms;
    p->eps[slot].last_pong_tick = xTaskGetTickCount();

    PM_DBG("peer[%d] ep[%d] updated: %ums", peer_idx, slot, rtt_ms);
}

static bool is_private_ip(const ip_addr_t *addr)
{
    const ip4_addr_t *ip4 = ip_2_ip4(addr);
    uint8_t a = ip4_addr1(ip4);
    uint8_t b = ip4_addr2(ip4);
    /* 10.x.x.x || 172.16-31.x.x || 192.168.x.x */
    return (a == 10) ||
           (a == 172 && (b >= 16 && b <= 31)) ||
           (a == 192 && b == 168);
}

int pm_evaluate_best_endpoint(peer_manager_t *pm, int peer_idx)
{
    if (peer_idx < 0 || peer_idx >= pm->peer_count) return -1;
    ts_peer_t *p = &pm->peers[peer_idx];

    int best = -1;
    uint32_t best_score = UINT32_MAX;
    uint32_t now_tick = xTaskGetTickCount();

    for (int i = 0; i < p->ep_count; i++) {
        if (p->eps[i].latency_ms == 0) continue;  /* Not measured */
        uint32_t age_ms = (now_tick - p->eps[i].last_pong_tick) * portTICK_PERIOD_MS;
        if (age_ms > 120000) continue;  /* Expired (120s trust window) */

        uint32_t score = p->eps[i].latency_ms;
        /* Private IP bonus: -20ms */
        if (is_private_ip(&p->eps[i].addr) && score >= 20) {
            score -= 20;
        }

        if (score < best_score) {
            best_score = score;
            best = i;
        }
    }

    p->best_ep_idx = best;
    return best;
}
