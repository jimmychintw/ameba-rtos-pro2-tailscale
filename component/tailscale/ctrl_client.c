/*
 * ctrl_client.c — Tailscale control plane client
 *
 * Implements connection to Headscale/Tailscale control server:
 *   - Fetch server key (GET /key?v=130)
 *   - WebSocket upgrade with Noise_IK handshake
 *   - Noise-encrypted transport over Controlbase + WebSocket framing
 */

#include "ctrl_client.h"
#include "ts_crypto.h"

#include <string.h>
#include <stdio.h>

/* mbedTLS base64 */
#include "mbedtls/base64.h"

/* cJSON for parsing /key response */
#include "cJSON.h"

/* lwIP sockets */
#include "lwip/sockets.h"
#include "lwip/netdb.h"

/* Random bytes (reuse wireguard platform) */
#include "../wireguard/wireguard-platform.h"

/* crypto_zero from wireguard */
#include "../wireguard/crypto.h"

/* Capability version for Noise early payload (matches TS_CAP_VERSION in peer_manager.h) */
#define TS_CAP_VERSION_CTRL  90

/* mbedTLS SSL (for official Tailscale servers) */
#include "mbedtls/ssl.h"

/* ------------------------------------------------------------------ */
/*  Logging                                                            */
/* ------------------------------------------------------------------ */

#define LOG_TAG "[TS_CTRL] "
#define CTRL_LOG(fmt, ...) printf(LOG_TAG fmt "\r\n", ##__VA_ARGS__)
#define CTRL_ERR(fmt, ...) printf(LOG_TAG "ERROR: " fmt "\r\n", ##__VA_ARGS__)

/* ------------------------------------------------------------------ */
/*  TLS helpers (mbedTLS)                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config  conf;
    int sock_fd;
} tls_state_t;

/* RNG callback — uses hardware TRNG via wireguard platform */
static int tls_rng_cb(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    wireguard_random_bytes(buf, len);
    return 0;
}

/* BIO send callback for mbedTLS */
static int tls_bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    tls_state_t *tls = (tls_state_t *)ctx;
    int ret = send(tls->sock_fd, buf, len, 0);
    if (ret < 0) return -0x004E; /* MBEDTLS_ERR_NET_SEND_FAILED */
    return ret;
}

/* BIO recv callback for mbedTLS */
static int tls_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    tls_state_t *tls = (tls_state_t *)ctx;
    int ret = recv(tls->sock_fd, buf, len, 0);
    if (ret < 0) {
        /* EAGAIN/EWOULDBLOCK = socket timeout, not fatal */
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_READ;
        return -0x004C; /* MBEDTLS_ERR_NET_RECV_FAILED */
    }
    if (ret == 0) return -0x0050; /* MBEDTLS_ERR_NET_CONN_RESET */
    return ret;
}

/* Create TLS state and perform handshake. Returns NULL on failure. */
void *ts_tls_handshake(int fd, const char *hostname)
{
    tls_state_t *tls = (tls_state_t *)calloc(1, sizeof(tls_state_t));
    if (!tls) return NULL;

    tls->sock_fd = fd;
    mbedtls_ssl_init(&tls->ssl);
    mbedtls_ssl_config_init(&tls->conf);

    if (mbedtls_ssl_config_defaults(&tls->conf,
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        CTRL_ERR("TLS config failed");
        goto fail;
    }

    mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&tls->conf, tls_rng_cb, NULL);

    if (mbedtls_ssl_setup(&tls->ssl, &tls->conf) != 0) {
        CTRL_ERR("TLS setup failed");
        goto fail;
    }

    if (hostname)
        mbedtls_ssl_set_hostname(&tls->ssl, hostname);

    mbedtls_ssl_set_bio(&tls->ssl, tls, tls_bio_send, tls_bio_recv, NULL);

    CTRL_LOG("TLS handshake with %s ...", hostname ? hostname : "(no SNI)");
    int ret = mbedtls_ssl_handshake(&tls->ssl);
    if (ret != 0) {
        CTRL_ERR("TLS handshake failed: -0x%04X", (unsigned)-ret);
        goto fail;
    }

    CTRL_LOG("TLS: %s", mbedtls_ssl_get_ciphersuite(&tls->ssl));
    return tls;

fail:
    mbedtls_ssl_free(&tls->ssl);
    mbedtls_ssl_config_free(&tls->conf);
    free(tls);
    return NULL;
}

/* Free TLS state */
void ts_tls_close(void *ctx)
{
    if (!ctx) return;
    tls_state_t *tls = (tls_state_t *)ctx;
    mbedtls_ssl_close_notify(&tls->ssl);
    mbedtls_ssl_free(&tls->ssl);
    mbedtls_ssl_config_free(&tls->conf);
    free(tls);
}

/* ------------------------------------------------------------------ */
/*  TCP helpers                                                        */
/* ------------------------------------------------------------------ */

int ts_tcp_connect(const char *host, uint16_t port)
{
    struct hostent *he;
    struct sockaddr_in addr;
    int fd;

    he = gethostbyname(host);
    if (!he) {
        CTRL_ERR("DNS failed: %s", host);
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        CTRL_ERR("socket() failed");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        CTRL_ERR("connect() failed: %s:%d", host, port);
        close(fd);
        return -1;
    }

    return fd;
}

static int tcp_send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return (int)sent;
}

void ts_tcp_set_timeout(int fd, int timeout_ms)
{
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/* ------------------------------------------------------------------ */
/*  Unified I/O (TLS or raw TCP)                                       */
/* ------------------------------------------------------------------ */

/* Send all bytes through TLS */
int ts_tls_send(void *tls, const uint8_t *buf, size_t len)
{
    tls_state_t *t = (tls_state_t *)tls;
    size_t sent = 0;
    while (sent < len) {
        int ret = mbedtls_ssl_write(&t->ssl, buf + sent, len - sent);
        if (ret <= 0) return -1;
        sent += ret;
    }
    return (int)sent;
}

/* Receive from TLS (matches recv() semantics) */
int ts_tls_recv(void *tls, uint8_t *buf, size_t len)
{
    int ret = mbedtls_ssl_read(&((tls_state_t *)tls)->ssl, buf, len);
    if (ret > 0) return ret;
    if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        return 0;
    return -1;
}

/* Non-blocking TLS recv — distinguishes timeout from fatal error.
 * Returns: >0 bytes, 0 closed, -1 fatal error, -2 timeout/WANT_READ. */
int ts_tls_recv_nonblock(void *tls, uint8_t *buf, size_t len)
{
    int ret = mbedtls_ssl_read(&((tls_state_t *)tls)->ssl, buf, len);
    if (ret > 0) return ret;
    if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        return 0;
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_TIMEOUT)
        return -2;   /* timeout — no data available */
    return -1;
}

/* Send all bytes through TLS or raw TCP */
static int io_send_all(int fd, void *tls, const uint8_t *buf, size_t len)
{
    if (tls) return ts_tls_send(tls, buf, len);
    return tcp_send_all(fd, buf, len);
}

/* Receive from TLS or raw TCP (matches recv() semantics) */
static int io_recv(int fd, void *tls, uint8_t *buf, size_t len)
{
    if (tls) return ts_tls_recv(tls, buf, len);
    return recv(fd, buf, len, 0);
}

/* ------------------------------------------------------------------ */
/*  URL encoding (RFC 3986 unreserved chars only)                      */
/* ------------------------------------------------------------------ */

static size_t url_encode(char *dst, size_t dst_len,
                          const uint8_t *src, size_t src_len)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t pos = 0;

    for (size_t i = 0; i < src_len && pos + 3 < dst_len; i++) {
        uint8_t c = src[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            dst[pos++] = (char)c;
        } else {
            dst[pos++] = '%';
            dst[pos++] = hex[c >> 4];
            dst[pos++] = hex[c & 0x0F];
        }
    }
    dst[pos] = '\0';
    return pos;
}

/* ------------------------------------------------------------------ */
/*  WebSocket framing                                                  */
/* ------------------------------------------------------------------ */

/*
 * Encode a WebSocket binary frame with client-side masking.
 * Returns total frame length, or -1 on error.
 */
static int ws_encode_binary(uint8_t *dst, size_t dst_len,
                             const uint8_t *payload, size_t payload_len)
{
    size_t hdr_len;
    uint8_t mask[4];
    size_t total;

    if (payload_len < 126) {
        hdr_len = 2;
    } else if (payload_len < 65536) {
        hdr_len = 4;
    } else {
        return -1;
    }

    total = hdr_len + 4 + payload_len; /* +4 for mask key */
    if (total > dst_len) return -1;

    /* FIN=1 + opcode=0x2 (binary) */
    dst[0] = 0x82;

    /* MASK=1 + payload length */
    if (payload_len < 126) {
        dst[1] = 0x80 | (uint8_t)payload_len;
    } else {
        dst[1] = 0x80 | 126;
        dst[2] = (payload_len >> 8) & 0xFF;
        dst[3] = payload_len & 0xFF;
    }

    /* Random mask key */
    wireguard_random_bytes(mask, 4);
    memcpy(dst + hdr_len, mask, 4);

    /* XOR payload with mask */
    for (size_t i = 0; i < payload_len; i++) {
        dst[hdr_len + 4 + i] = payload[i] ^ mask[i & 3];
    }

    return (int)total;
}

/*
 * Decode a WebSocket frame (server → client, typically unmasked).
 * Returns payload length, or -1 on error, -2 if need more data.
 */
static int ws_decode_frame(const uint8_t *data, size_t data_len,
                            uint8_t *opcode, size_t *payload_offset,
                            size_t *frame_total_len)
{
    if (data_len < 2) return -2;

    *opcode = data[0] & 0x0F;
    bool masked = (data[1] & 0x80) != 0;
    uint64_t payload_len = data[1] & 0x7F;
    size_t hdr = 2;

    if (payload_len == 126) {
        if (data_len < 4) return -2;
        payload_len = ((uint64_t)data[2] << 8) | data[3];
        hdr = 4;
    } else if (payload_len == 127) {
        if (data_len < 10) return -2;
        payload_len = 0;
        for (int i = 0; i < 8; i++)
            payload_len = (payload_len << 8) | data[2 + i];
        hdr = 10;
    }

    if (masked) hdr += 4;

    *payload_offset = hdr;
    *frame_total_len = hdr + (size_t)payload_len;

    if (data_len < *frame_total_len) return -2;

    /* Unmask if needed (unusual for server→client) */
    if (masked) {
        const uint8_t *mk = data + hdr - 4;
        for (size_t i = 0; i < (size_t)payload_len; i++)
            ((uint8_t *)data)[hdr + i] ^= mk[i & 3];
    }

    return (int)payload_len;
}

/* ------------------------------------------------------------------ */
/*  HTTP response helpers                                              */
/* ------------------------------------------------------------------ */

/*
 * Find end of HTTP headers (\r\n\r\n) in buffer.
 * Returns offset of first body byte, or 0 if not found.
 */
static size_t find_header_end(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' &&
            buf[i+2] == '\r' && buf[i+3] == '\n')
            return i + 4;
    }
    return 0;
}

/* Extract HTTP status code (e.g. 200, 101) from first line */
static int http_parse_status(const uint8_t *buf, size_t len)
{
    if (len < 12) return -1;
    if (memcmp(buf, "HTTP/1.1 ", 9) != 0 &&
        memcmp(buf, "HTTP/1.0 ", 9) != 0)
        return -1;
    return (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
}

/*
 * Read from socket until header-end is found, or buffer full / timeout.
 * Returns total bytes in buffer.
 */
static int http_read_response(int fd, void *tls, uint8_t *buf, size_t buf_len,
                               size_t *body_offset, int timeout_ms)
{
    size_t total = 0;
    *body_offset = 0;

    ts_tcp_set_timeout(fd, timeout_ms);

    while (total < buf_len - 1) {
        int n = io_recv(fd, tls, buf + total, buf_len - 1 - total);
        if (n <= 0) {
            if (total > 0) break;
            return -1;
        }
        total += n;

        size_t end = find_header_end(buf, total);
        if (end > 0) {
            *body_offset = end;
            return (int)total;
        }
    }
    return (int)total;
}

/* ------------------------------------------------------------------ */
/*  Public API: init / set_machine_key                                 */
/* ------------------------------------------------------------------ */

void ctrl_client_init(ctrl_client_t *c)
{
    memset(c, 0, sizeof(*c));
    c->sock_fd = -1;
}

void ctrl_client_set_machine_key(ctrl_client_t *c,
                                  const uint8_t *priv,
                                  const uint8_t *pub)
{
    memcpy(c->machine_priv, priv, TS_KEY_LEN);
    memcpy(c->machine_pub, pub, TS_KEY_LEN);
}

void ctrl_client_set_node_key(ctrl_client_t *c, const uint8_t *pub)
{
    memcpy(c->node_pub, pub, TS_KEY_LEN);
}

void ctrl_client_enable_tls(ctrl_client_t *c)
{
    c->use_tls = true;
    CTRL_LOG("TLS enabled");
}

/* ------------------------------------------------------------------ */
/*  Public API: fetch_key                                              */
/* ------------------------------------------------------------------ */

int ctrl_client_fetch_key(ctrl_client_t *c,
                           const char *host, uint16_t port)
{
    char req[256];
    uint8_t resp[1024];
    int fd, n;
    size_t total = 0;

    CTRL_LOG("Fetching server key from %s:%d/key?v=130", host, (int)port);

    fd = ts_tcp_connect(host, port);
    if (fd < 0) return -1;

    /* TLS handshake if enabled */
    void *tls = NULL;
    if (c->use_tls) {
        tls = ts_tls_handshake(fd, host);
        if (!tls) { close(fd); return -1; }
    }

    /* Send GET /key?v=130 with Connection: close */
    n = snprintf(req, sizeof(req),
        "GET /key?v=130 HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Connection: close\r\n"
        "\r\n", host, (int)port);

    if (io_send_all(fd, tls, (uint8_t *)req, n) < 0) {
        CTRL_ERR("Failed to send GET /key");
        ts_tls_close(tls);
        close(fd);
        return -1;
    }

    /* Read entire response (Connection: close → server closes after body) */
    ts_tcp_set_timeout(fd, 5000);
    while (total < sizeof(resp) - 1) {
        n = io_recv(fd, tls, resp + total, sizeof(resp) - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    ts_tls_close(tls);
    close(fd);

    if (total == 0) {
        CTRL_ERR("Empty response from /key");
        return -1;
    }
    resp[total] = '\0';

    /* Find header/body boundary */
    size_t body_off = find_header_end(resp, total);
    if (body_off == 0) {
        CTRL_ERR("Malformed HTTP response from /key");
        return -1;
    }

    /* Check HTTP status */
    int status = http_parse_status(resp, total);
    if (status != 200) {
        CTRL_ERR("GET /key returned status %d", status);
        return -1;
    }

    /* Parse JSON: {"publicKey":"mkey:HEX64"} */
    cJSON *json = cJSON_Parse((char *)(resp + body_off));
    if (!json) {
        CTRL_ERR("Failed to parse /key JSON");
        return -1;
    }

    cJSON *pk = cJSON_GetObjectItemCaseSensitive(json, "publicKey");
    if (!pk || !cJSON_IsString(pk)) {
        pk = cJSON_GetObjectItemCaseSensitive(json, "legacyPublicKey");
    }
    if (!pk || !cJSON_IsString(pk)) {
        CTRL_ERR("No publicKey in /key response");
        cJSON_Delete(json);
        return -1;
    }

    const char *key_str = pk->valuestring;

    /* Strip "mkey:" prefix */
    if (strncmp(key_str, "mkey:", 5) == 0)
        key_str += 5;

    /* Decode hex → 32-byte key */
    if (ts_hex_to_key(c->server_key, key_str, strlen(key_str)) != 0) {
        CTRL_ERR("Bad server key hex: %.20s...", key_str);
        cJSON_Delete(json);
        return -1;
    }

    c->server_key_valid = true;
    cJSON_Delete(json);

    char hex[65];
    ts_key_to_hex(hex, c->server_key);
    CTRL_LOG("Server key: %s", hex);

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public API: connect (WebSocket upgrade + Noise handshake)          */
/* ------------------------------------------------------------------ */

int ctrl_client_connect(ctrl_client_t *c,
                         const char *host, uint16_t port)
{
    uint8_t noise_init[TS_NOISE_MSG1_LEN];
    uint8_t cb_init[CB_CLIENT_HDR_LEN + TS_NOISE_MSG1_LEN];
    uint8_t b64_buf[256];
    size_t  b64_len;
    char    url_buf[512];
    uint8_t ws_key_raw[16];
    uint8_t ws_key_b64[32];
    size_t  ws_key_b64_len;
    char    req[1024];
    uint8_t resp[1024];
    size_t  body_off;
    int     n;

    if (!c->server_key_valid) {
        CTRL_ERR("Server key not fetched — call fetch_key() first");
        return -1;
    }

    strncpy(c->host, host, sizeof(c->host) - 1);
    c->port = port;

    CTRL_LOG("Connecting to %s:%d ...", host, (int)port);

    /* --- 1. Initialize Noise_IK and generate Message 1 (empty payload) --- */
    ts_noise_ik_init(&c->noise,
                     c->machine_priv, c->machine_pub,
                     c->server_key);

    n = ts_noise_ik_write_msg1(&c->noise, noise_init, NULL, 0);
    if (n != TS_NOISE_MSG1_LEN) {
        CTRL_ERR("noise write_msg1 failed (%d)", n);
        return -1;
    }

    /* --- 2. Build Controlbase init frame (5 + 96 bytes) --- */
    cb_init[0] = (CB_VERSION >> 8) & 0xFF;   /* 0x00 */
    cb_init[1] =  CB_VERSION       & 0xFF;   /* 0x01 */
    cb_init[2] = CB_MSG_INIT;                 /* 0x01 */
    cb_init[3] = (TS_NOISE_MSG1_LEN >> 8) & 0xFF;
    cb_init[4] =  TS_NOISE_MSG1_LEN       & 0xFF;
    memcpy(cb_init + 5, noise_init, TS_NOISE_MSG1_LEN);

    /* --- 3. Base64 encode → URL encode --- */
    if (mbedtls_base64_encode(b64_buf, sizeof(b64_buf), &b64_len,
                               cb_init, sizeof(cb_init)) != 0) {
        CTRL_ERR("base64 encode failed");
        return -1;
    }

    url_encode(url_buf, sizeof(url_buf), b64_buf, b64_len);

    /* --- 4. Generate WebSocket key (16 random bytes → base64) --- */
    wireguard_random_bytes(ws_key_raw, sizeof(ws_key_raw));
    mbedtls_base64_encode(ws_key_b64, sizeof(ws_key_b64), &ws_key_b64_len,
                           ws_key_raw, sizeof(ws_key_raw));
    ws_key_b64[ws_key_b64_len] = '\0';

    /* --- 5. TCP connect (+ TLS if enabled) --- */
    c->sock_fd = ts_tcp_connect(host, port);
    if (c->sock_fd < 0) return -1;

    if (c->use_tls) {
        c->tls_ctx = ts_tls_handshake(c->sock_fd, host);
        if (!c->tls_ctx) {
            close(c->sock_fd); c->sock_fd = -1;
            return -1;
        }
    }

    /* --- 6. Send WebSocket upgrade request --- */
    n = snprintf(req, sizeof(req),
        "GET /ts2021?X-Tailscale-Handshake=%s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Protocol: tailscale-control-protocol\r\n"
        "User-Agent: amb82-tailscale/0.1\r\n"
        "\r\n",
        url_buf, host, (int)port, (char *)ws_key_b64);

    CTRL_LOG("Sending WebSocket upgrade (%d bytes)", n);

    if (io_send_all(c->sock_fd, c->tls_ctx, (uint8_t *)req, n) < 0) {
        CTRL_ERR("Failed to send upgrade request");
        goto fail;
    }

    /* --- 7. Read HTTP 101 response --- */
    int resp_len = http_read_response(c->sock_fd, c->tls_ctx, resp, sizeof(resp),
                                       &body_off, 10000);
    if (resp_len < 0) {
        CTRL_ERR("No upgrade response");
        goto fail;
    }

    int status = http_parse_status(resp, resp_len);
    if (status != 101) {
        resp[resp_len < 200 ? resp_len : 200] = '\0';
        CTRL_ERR("Upgrade failed (status %d)", status);
        goto fail;
    }

    CTRL_LOG("WebSocket 101 OK");
    c->connected = true;

    /* Save any extra bytes (WebSocket frame data after HTTP headers) */
    size_t extra = resp_len - body_off;
    if (extra > 0 && extra <= sizeof(c->recv_buf)) {
        memcpy(c->recv_buf, resp + body_off, extra);
        c->recv_buf_len = extra;
    }

    /* --- 8. Read server's Noise response (WS frame → CB header → msg2) ---
     *
     * Expected: WS header (2+) + CB header (3) + Noise msg2 (48) = ~53+ bytes
     */
    ts_tcp_set_timeout(c->sock_fd, 10000);

    while (c->recv_buf_len < 55) {
        n = io_recv(c->sock_fd, c->tls_ctx,
                    c->recv_buf + c->recv_buf_len,
                    sizeof(c->recv_buf) - c->recv_buf_len);
        if (n <= 0) {
            CTRL_ERR("Timeout waiting for Noise response");
            goto fail;
        }
        c->recv_buf_len += n;
    }

    /* Decode WebSocket frame */
    uint8_t  opcode;
    size_t   payload_off, frame_total;
    int payload_len = ws_decode_frame(c->recv_buf, c->recv_buf_len,
                                       &opcode, &payload_off, &frame_total);
    if (payload_len < 0) {
        CTRL_ERR("Bad WS frame (%d)", payload_len);
        goto fail;
    }
    if (opcode == 0x08) {
        CTRL_ERR("Server sent WS close");
        goto fail;
    }
    if (opcode != 0x02) {
        CTRL_ERR("Expected binary frame, got 0x%02x", opcode);
        goto fail;
    }

    CTRL_LOG("WS frame: %d bytes payload", payload_len);

    /* Parse Controlbase response: type(1) + length(2) + noise_msg2(48) */
    uint8_t *cb = c->recv_buf + payload_off;
    if (payload_len < CB_SERVER_HDR_LEN) {
        CTRL_ERR("CB frame too short");
        goto fail;
    }

    uint8_t  msg_type     = cb[0];
    uint16_t cb_data_len  = ((uint16_t)cb[1] << 8) | cb[2];

    if (msg_type == CB_MSG_ERROR) {
        char errbuf[128];
        size_t elen = cb_data_len < sizeof(errbuf) - 1 ? cb_data_len : sizeof(errbuf) - 1;
        memcpy(errbuf, cb + 3, elen);
        errbuf[elen] = '\0';
        CTRL_ERR("Server: %s", errbuf);
        goto fail;
    }
    if (msg_type != CB_MSG_RESPONSE) {
        CTRL_ERR("Expected CB response (0x02), got 0x%02x", msg_type);
        goto fail;
    }
    if (cb_data_len != TS_NOISE_MSG2_LEN) {
        CTRL_ERR("Noise msg2 len=%d (expected %d)", cb_data_len, TS_NOISE_MSG2_LEN);
        goto fail;
    }

    /* --- 9. Process Noise Message 2 --- */
    if (ts_noise_ik_read_msg2(&c->noise, cb + 3, cb_data_len) != 0) {
        CTRL_ERR("Noise msg2 MAC failed");
        goto fail;
    }

    /* --- 10. Split → transport keys --- */
    if (ts_noise_ik_split(&c->noise) != 0) {
        CTRL_ERR("Noise split failed");
        goto fail;
    }

    c->noise_ready = true;
    CTRL_LOG("Noise handshake complete — transport ready");

    /* Remove consumed frame from recv buffer */
    if (frame_total < c->recv_buf_len) {
        memmove(c->recv_buf, c->recv_buf + frame_total,
                c->recv_buf_len - frame_total);
        c->recv_buf_len -= frame_total;
    } else {
        c->recv_buf_len = 0;
    }

    return 0;

fail:
    ts_tls_close(c->tls_ctx); c->tls_ctx = NULL;
    if (c->sock_fd >= 0) { close(c->sock_fd); c->sock_fd = -1; }
    c->connected  = false;
    c->noise_ready = false;
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Public API: send (plaintext → encrypted transport)                 */
/* ------------------------------------------------------------------ */

int ctrl_client_send(ctrl_client_t *c,
                      const uint8_t *data, size_t len)
{
    if (!c->noise_ready || c->sock_fd < 0) return -1;
    if (len > CTRL_MAX_SEND_PT) {
        CTRL_ERR("send: %zu > max %d", len, CTRL_MAX_SEND_PT);
        return -1;
    }

    /* 1. Noise encrypt → ciphertext (len + 16 tag) */
    size_t ct_len = len + TS_AEAD_TAG_LEN;
    uint8_t ct[CTRL_MAX_SEND_PT + TS_AEAD_TAG_LEN];

    int enc = ts_noise_encrypt(&c->noise, ct, data, len);
    if (enc < 0) return -1;

    /* 2. Controlbase record: type(1) + length(2) + ciphertext */
    size_t cb_len = 3 + ct_len;
    uint8_t cb[3 + CTRL_MAX_SEND_PT + TS_AEAD_TAG_LEN];
    cb[0] = CB_MSG_RECORD;
    cb[1] = (ct_len >> 8) & 0xFF;
    cb[2] =  ct_len       & 0xFF;
    memcpy(cb + 3, ct, ct_len);

    /* 3. WebSocket binary frame with mask */
    uint8_t ws[14 + sizeof(cb)]; /* worst-case WS overhead */
    int ws_len = ws_encode_binary(ws, sizeof(ws), cb, cb_len);
    if (ws_len < 0) return -1;

    /* 4. TCP send */
    if (io_send_all(c->sock_fd, c->tls_ctx, ws, ws_len) < 0) {
        CTRL_ERR("send failed");
        return -1;
    }

    return (int)len;
}

/* ------------------------------------------------------------------ */
/*  Public API: recv (encrypted transport → plaintext)                 */
/* ------------------------------------------------------------------ */

int ctrl_client_recv(ctrl_client_t *c,
                      uint8_t *buf, size_t buf_len,
                      int timeout_ms)
{
    if (!c->noise_ready || c->sock_fd < 0) return -1;

    ts_tcp_set_timeout(c->sock_fd, timeout_ms);

    for (;;) {
        /* Try to decode a complete WebSocket frame */
        if (c->recv_buf_len >= 2) {
            uint8_t  opcode;
            size_t   payload_off, frame_total;
            int plen = ws_decode_frame(c->recv_buf, c->recv_buf_len,
                                        &opcode, &payload_off, &frame_total);

            if (plen >= 0) {
                /* Got a complete frame */
                if (opcode == 0x08) {
                    CTRL_ERR("recv: WS close");
                    return -1;
                }
                if (opcode != 0x02) {
                    /* Skip non-binary frames */
                    goto consume;
                }

                /* Parse Controlbase header */
                uint8_t *cb = c->recv_buf + payload_off;
                if (plen < 3) { CTRL_ERR("recv: CB too short"); goto consume; }

                uint8_t  mt = cb[0];
                uint16_t cl = ((uint16_t)cb[1] << 8) | cb[2];

                if (mt == CB_MSG_ERROR) {
                    char errbuf[128];
                    size_t el = cl < sizeof(errbuf) - 1 ? cl : sizeof(errbuf) - 1;
                    memcpy(errbuf, cb + 3, el);
                    errbuf[el] = '\0';
                    CTRL_ERR("recv: server error: %s", errbuf);
                    return -1;
                }
                if (mt != CB_MSG_RECORD) {
                    CTRL_ERR("recv: unexpected CB type 0x%02x", mt);
                    goto consume;
                }
                if (cl < TS_AEAD_TAG_LEN) {
                    CTRL_ERR("recv: ct too short (%d)", cl);
                    return -1;
                }

                size_t pt_len = cl - TS_AEAD_TAG_LEN;
                if (pt_len > buf_len) {
                    CTRL_ERR("recv: buf too small (%zu > %zu)", pt_len, buf_len);
                    return -1;
                }

                /* Noise decrypt */
                int dec = ts_noise_decrypt(&c->noise, buf, cb + 3, cl);
                if (dec < 0) {
                    CTRL_ERR("recv: decrypt failed");
                    return -1;
                }

                /* Consume frame */
                if (frame_total < c->recv_buf_len) {
                    memmove(c->recv_buf, c->recv_buf + frame_total,
                            c->recv_buf_len - frame_total);
                    c->recv_buf_len -= frame_total;
                } else {
                    c->recv_buf_len = 0;
                }

                return dec;

consume:
                if (frame_total <= c->recv_buf_len) {
                    memmove(c->recv_buf, c->recv_buf + frame_total,
                            c->recv_buf_len - frame_total);
                    c->recv_buf_len -= frame_total;
                } else {
                    c->recv_buf_len = 0;
                }
                continue; /* try next frame in buffer */
            }
            /* plen == -2: need more data, fall through */
        }

        /* Read more data from socket */
        if (c->recv_buf_len >= sizeof(c->recv_buf)) {
            CTRL_ERR("recv: buffer full");
            return -1;
        }

        int n = io_recv(c->sock_fd, c->tls_ctx,
                        c->recv_buf + c->recv_buf_len,
                        sizeof(c->recv_buf) - c->recv_buf_len);
        if (n < 0)  return 0;  /* timeout */
        if (n == 0) return -1; /* connection closed */
        c->recv_buf_len += n;
    }
}

/* ------------------------------------------------------------------ */
/*  Public API: close                                                  */
/* ------------------------------------------------------------------ */

void ctrl_client_close(ctrl_client_t *c)
{
    ts_tls_close(c->tls_ctx);
    c->tls_ctx = NULL;
    if (c->sock_fd >= 0) {
        close(c->sock_fd);
        c->sock_fd = -1;
    }
    c->connected   = false;
    c->noise_ready = false;

    /* Zero sensitive data */
    crypto_zero(&c->noise, sizeof(c->noise));
    crypto_zero(c->machine_priv, sizeof(c->machine_priv));
    crypto_zero(c->recv_buf, sizeof(c->recv_buf));
}
