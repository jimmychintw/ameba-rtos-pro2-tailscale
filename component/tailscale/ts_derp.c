/*
 * ts_derp.c — DERP relay client for Tailscale on AMB82-MINI
 *
 * Implements:
 *   - TLS + HTTP upgrade to DERP server
 *   - NaCl box handshake (ClientInfo/ServerInfo)
 *   - SendPacket/RecvPacket for WG packet relay
 *   - KeepAlive + Ping/Pong handling
 *   - Background FreeRTOS recv task
 *
 * Thread safety:
 *   ALL TLS I/O (mbedtls_ssl_read/write) happens exclusively in the recv task.
 *   derp_send_packet() from other threads queues requests via a FreeRTOS queue;
 *   the recv task drains the queue between socket reads.
 *   This avoids mbedTLS concurrent access corruption.
 */

#include "ts_derp.h"
#include "ts_log.h"
#include "ctrl_client.h"   /* ts_tcp_connect, ts_tls_* */
#include "ts_nacl.h"
#include "ts_crypto.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

#include <string.h>
#include <stdio.h>
#include "lwip/sockets.h"

/* Random bytes */
#include "../wireguard/wireguard-platform.h"

/* ------------------------------------------------------------------ */
/*  Logging                                                            */
/* ------------------------------------------------------------------ */

#define LOG_TAG "[DERP] "
#define DERP_LOG(fmt, ...) printf(LOG_TAG fmt "\r\n", ##__VA_ARGS__)
#define DERP_ERR(fmt, ...) printf(LOG_TAG "ERROR: " fmt "\r\n", ##__VA_ARGS__)
#define DERP_DBG(fmt, ...) TS_DBG(LOG_TAG fmt "\r\n", ##__VA_ARGS__)

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define DERP_FRAME_HDR_LEN   5      /* 1B type + 4B BE length */
#define DERP_RECV_BUF_SIZE   2048   /* max expected frame payload */
#define DERP_TASK_STACK      (8 * 1024)
#define DERP_TASK_PRIO       (tskIDLE_PRIORITY + 1)
#define DERP_KEEPALIVE_SEC   60
#define DERP_POLL_TIMEOUT_MS 500    /* short timeout so we can drain send queue */

/* ------------------------------------------------------------------ */
/*  Send queue item                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t  dst_key[32];
    uint8_t *pkt;
    size_t   pkt_len;
} derp_send_req_t;

/* ------------------------------------------------------------------ */
/*  Internal: read exactly N bytes from TLS                            */
/* ------------------------------------------------------------------ */

static int derp_read_exact(derp_client_t *dc, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        int n = ts_tls_recv(dc->tls, buf + got, len - got);
        if (n <= 0) return -1;
        got += n;
    }
    return (int)got;
}

/* ------------------------------------------------------------------ */
/*  Internal: write frame (ONLY call from recv task!)                   */
/* ------------------------------------------------------------------ */

static int derp_write_frame(derp_client_t *dc, uint8_t type,
                             const uint8_t *payload, size_t len)
{
    uint8_t hdr[DERP_FRAME_HDR_LEN];
    hdr[0] = type;
    hdr[1] = (len >> 24) & 0xFF;
    hdr[2] = (len >> 16) & 0xFF;
    hdr[3] = (len >> 8)  & 0xFF;
    hdr[4] =  len        & 0xFF;

    if (ts_tls_send(dc->tls, hdr, DERP_FRAME_HDR_LEN) < 0)
        return -1;
    if (len > 0 && payload) {
        if (ts_tls_send(dc->tls, payload, len) < 0)
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Internal: read frame header                                        */
/* ------------------------------------------------------------------ */

static int derp_read_frame_hdr(derp_client_t *dc, uint8_t *type, uint32_t *len)
{
    uint8_t hdr[DERP_FRAME_HDR_LEN];
    if (derp_read_exact(dc, hdr, DERP_FRAME_HDR_LEN) < 0)
        return -1;
    *type = hdr[0];
    *len  = ((uint32_t)hdr[1] << 24) | ((uint32_t)hdr[2] << 16) |
            ((uint32_t)hdr[3] << 8)  |  (uint32_t)hdr[4];
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Internal: skip N bytes                                             */
/* ------------------------------------------------------------------ */

static int derp_skip(derp_client_t *dc, size_t len)
{
    uint8_t tmp[256];
    while (len > 0) {
        size_t chunk = len < sizeof(tmp) ? len : sizeof(tmp);
        if (derp_read_exact(dc, tmp, chunk) < 0) return -1;
        len -= chunk;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Internal: drain send queue (called from recv task only)            */
/* ------------------------------------------------------------------ */

static void derp_drain_send_queue(derp_client_t *dc)
{
    if (!dc->send_queue) return;

    derp_send_req_t *req;
    while (xQueueReceive((QueueHandle_t)dc->send_queue, &req, 0) == pdTRUE) {
        if (!req) continue;

        /* Build frame payload: 32B dst_key + WG packet */
        size_t payload_len = 32 + req->pkt_len;
        uint8_t *buf = (uint8_t *)malloc(payload_len);
        if (buf) {
            memcpy(buf, req->dst_key, 32);
            memcpy(buf + 32, req->pkt, req->pkt_len);

            int ret = derp_write_frame(dc, DERP_FRAME_SEND_PACKET, buf, payload_len);
            if (ret < 0) {
                DERP_ERR("drain_send: write_frame failed");
            } else {
                DERP_DBG("SendPacket: %u bytes -> key=%02x%02x..%02x%02x",
                         (unsigned)req->pkt_len,
                         req->dst_key[0], req->dst_key[1],
                         req->dst_key[30], req->dst_key[31]);
            }
            free(buf);
        } else {
            DERP_ERR("drain_send: malloc failed");
        }

        /* Free the request */
        free(req->pkt);
        free(req);
    }
}

/* ------------------------------------------------------------------ */
/*  Internal: try to read a frame with short timeout                   */
/*  Returns:  0 = got frame, 1 = timeout (no data), -1 = error        */
/* ------------------------------------------------------------------ */

static int derp_try_read_frame_hdr(derp_client_t *dc, uint8_t *type, uint32_t *len)
{
    /* First byte read uses the short poll timeout already set on socket.
     * ts_tls_recv_nonblock returns -2 on timeout (WANT_READ). */
    uint8_t hdr[DERP_FRAME_HDR_LEN];

    int n = ts_tls_recv_nonblock(dc->tls, &hdr[0], 1);
    if (n == -2) {
        /* Timeout — no data available */
        return 1;
    }
    if (n <= 0) {
        /* Error or connection closed */
        return -1;
    }

    /* Got first byte — read remaining 4 bytes (these should come quickly) */
    if (derp_read_exact(dc, &hdr[1], DERP_FRAME_HDR_LEN - 1) < 0)
        return -1;

    *type = hdr[0];
    *len  = ((uint32_t)hdr[1] << 24) | ((uint32_t)hdr[2] << 16) |
            ((uint32_t)hdr[3] << 8)  |  (uint32_t)hdr[4];
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public API: init                                                   */
/* ------------------------------------------------------------------ */

void derp_init(derp_client_t *dc)
{
    memset(dc, 0, sizeof(*dc));
    dc->sock_fd = -1;
    dc->port = 443;
}

/* ------------------------------------------------------------------ */
/*  Internal: close TLS + socket only (keep task and queue alive)      */
/* ------------------------------------------------------------------ */

static void derp_close_connection(derp_client_t *dc)
{
    if (dc->tls) {
        ts_tls_close(dc->tls);
        dc->tls = NULL;
    }
    if (dc->sock_fd >= 0) {
        close(dc->sock_fd);
        dc->sock_fd = -1;
    }
    dc->connected = false;
    dc->ready = false;
}

/* ------------------------------------------------------------------ */
/*  Internal: connect + handshake (can be called multiple times)       */
/* ------------------------------------------------------------------ */

static int derp_do_connect(derp_client_t *dc)
{
    uint8_t frame_buf[256];
    uint8_t frame_type;
    uint32_t frame_len;

    DERP_LOG("Connecting to %s:%u ...", dc->hostname, dc->port);

    /* --- 1. TCP + TLS connect --- */
    dc->sock_fd = ts_tcp_connect(dc->hostname, dc->port);
    if (dc->sock_fd < 0) {
        DERP_ERR("TCP connect failed");
        return -1;
    }

    dc->tls = ts_tls_handshake(dc->sock_fd, dc->hostname);
    if (!dc->tls) {
        DERP_ERR("TLS handshake failed");
        close(dc->sock_fd); dc->sock_fd = -1;
        return -1;
    }
    DERP_LOG("TLS handshake OK");

    /* --- 2. HTTP Upgrade: DERP --- */
    {
        char req[256];
        int n = snprintf(req, sizeof(req),
            "GET /derp HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: DERP\r\n"
            "User-Agent: amb82-tailscale/0.1\r\n"
            "\r\n", dc->hostname);

        if (ts_tls_send(dc->tls, (uint8_t *)req, n) < 0) {
            DERP_ERR("HTTP upgrade send failed");
            goto fail;
        }
    }

    /* Read HTTP 101 response (byte by byte until \r\n\r\n) */
    {
        uint8_t resp[512];
        int pos = 0;
        ts_tcp_set_timeout(dc->sock_fd, 10000);

        while (pos < (int)sizeof(resp) - 1) {
            if (derp_read_exact(dc, &resp[pos], 1) < 0) {
                DERP_ERR("HTTP response read failed");
                goto fail;
            }
            pos++;
            if (pos >= 4 &&
                resp[pos-4] == '\r' && resp[pos-3] == '\n' &&
                resp[pos-2] == '\r' && resp[pos-1] == '\n') {
                break;
            }
        }
        resp[pos] = '\0';

        /* Check for "101" */
        if (!strstr((char *)resp, "101")) {
            DERP_ERR("HTTP upgrade failed: %.80s", resp);
            goto fail;
        }
        DERP_LOG("HTTP upgrade 101 OK");
    }

    dc->connected = true;

    /* --- 3. Read FrameServerKey (type=0x01) --- */
    if (derp_read_frame_hdr(dc, &frame_type, &frame_len) < 0) {
        DERP_ERR("Failed to read ServerKey frame header");
        goto fail;
    }
    if (frame_type != DERP_FRAME_SERVER_KEY || frame_len != DERP_MAGIC_LEN + 32) {
        DERP_ERR("Bad ServerKey: type=0x%02x len=%lu", frame_type, (unsigned long)frame_len);
        goto fail;
    }

    if (derp_read_exact(dc, frame_buf, DERP_MAGIC_LEN + 32) < 0) {
        DERP_ERR("Failed to read ServerKey payload");
        goto fail;
    }

    /* Verify magic */
    if (memcmp(frame_buf, DERP_MAGIC, DERP_MAGIC_LEN) != 0) {
        DERP_ERR("Bad DERP magic");
        goto fail;
    }
    memcpy(dc->server_pub, frame_buf + DERP_MAGIC_LEN, 32);
    DERP_LOG("ServerKey received");

    /* --- 4. Send FrameClientInfo (type=0x02) --- */
    {
        /* JSON payload: {"version":2,"canAckPings":true} */
        const char *json = "{\"version\":2,\"canAckPings\":true}";
        size_t json_len = strlen(json);

        /* Encrypted payload: 32B our_key + 24B nonce + (json_len + 16) MAC+ct */
        size_t enc_payload_len = 32 + NACL_BOX_NONCEBYTES + json_len + NACL_BOX_MACBYTES;
        uint8_t *payload = (uint8_t *)malloc(enc_payload_len);
        if (!payload) {
            DERP_ERR("ClientInfo malloc failed");
            goto fail;
        }

        /* Our node public key */
        memcpy(payload, dc->node_pub, 32);

        /* Random nonce */
        uint8_t *nonce = payload + 32;
        wireguard_random_bytes(nonce, NACL_BOX_NONCEBYTES);

        /* NaCl box encrypt: JSON → MAC + ciphertext */
        uint8_t *ct = payload + 32 + NACL_BOX_NONCEBYTES;
        if (nacl_box_easy(ct, (const uint8_t *)json, json_len,
                          nonce, dc->server_pub, dc->node_priv) != 0) {
            DERP_ERR("NaCl box encrypt failed");
            free(payload);
            goto fail;
        }

        if (derp_write_frame(dc, DERP_FRAME_CLIENT_INFO, payload, enc_payload_len) < 0) {
            DERP_ERR("ClientInfo send failed");
            free(payload);
            goto fail;
        }
        free(payload);
        DERP_LOG("ClientInfo sent");
    }

    /* --- 5. Read FrameServerInfo (type=0x03) --- */
    if (derp_read_frame_hdr(dc, &frame_type, &frame_len) < 0) {
        DERP_ERR("Failed to read ServerInfo header");
        goto fail;
    }
    if (frame_type != DERP_FRAME_SERVER_INFO) {
        DERP_ERR("Expected ServerInfo (0x03), got 0x%02x", frame_type);
        goto fail;
    }

    /* ServerInfo is NaCl box encrypted — just skip/consume it */
    if (frame_len > 0) {
        if (derp_skip(dc, frame_len) < 0) {
            DERP_ERR("Failed to read ServerInfo payload");
            goto fail;
        }
    }
    DERP_LOG("ServerInfo received (ignored content)");

    /* --- 6. Send FrameNotePreferred (type=0x07) --- */
    {
        uint8_t preferred = 0x01;
        if (derp_write_frame(dc, DERP_FRAME_NOTE_PREFERRED, &preferred, 1) < 0) {
            DERP_ERR("NotePreferred send failed");
            goto fail;
        }
        DERP_LOG("NotePreferred sent");
    }

    dc->ready = true;
    DERP_LOG("Handshake complete — DERP ready (region %d)", dc->region_id);
    return 0;

fail:
    derp_close_connection(dc);
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Public API: connect + handshake                                    */
/* ------------------------------------------------------------------ */

int derp_connect(derp_client_t *dc, const char *hostname, uint16_t port)
{
    strncpy(dc->hostname, hostname, sizeof(dc->hostname) - 1);
    dc->port = port;
    return derp_do_connect(dc);
}

/* ------------------------------------------------------------------ */
/*  Public API: send packet (thread-safe, queues for recv task)        */
/* ------------------------------------------------------------------ */

int derp_send_packet(derp_client_t *dc, const uint8_t *dst_key,
                      const uint8_t *pkt, size_t pkt_len)
{
    if (!dc->ready || !dc->send_queue) {
        DERP_ERR("send_packet: not ready (ready=%d queue=%p)", dc->ready, dc->send_queue);
        return -1;
    }

    /* Allocate request + copy packet data */
    derp_send_req_t *req = (derp_send_req_t *)malloc(sizeof(derp_send_req_t));
    if (!req) return -1;

    req->pkt = (uint8_t *)malloc(pkt_len);
    if (!req->pkt) {
        free(req);
        return -1;
    }

    memcpy(req->dst_key, dst_key, 32);
    memcpy(req->pkt, pkt, pkt_len);
    req->pkt_len = pkt_len;

    DERP_DBG("send_packet: queuing %u bytes -> key=%02x%02x..%02x%02x",
             (unsigned)pkt_len,
             dst_key[0], dst_key[1], dst_key[30], dst_key[31]);

    /* Non-blocking enqueue (zero timeout = ISR-safe) */
    if (xQueueSend((QueueHandle_t)dc->send_queue, &req, 0) != pdTRUE) {
        DERP_ERR("send_packet: queue full");
        free(req->pkt);
        free(req);
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Internal: recv task                                                */
/* ------------------------------------------------------------------ */

static void derp_recv_task(void *param)
{
    derp_client_t *dc = (derp_client_t *)param;

    DERP_LOG("Recv task started");

    uint8_t *recv_buf = (uint8_t *)malloc(DERP_RECV_BUF_SIZE);
    if (!recv_buf) {
        DERP_ERR("recv_buf malloc failed");
        dc->running = false;
        vTaskDelete(NULL);
        return;
    }

recv_loop:
    /* Use short poll timeout so we wake up frequently to drain send queue */
    ts_tcp_set_timeout(dc->sock_fd, DERP_POLL_TIMEOUT_MS);

    {
    TickType_t last_activity = xTaskGetTickCount();
    const TickType_t keepalive_timeout = pdMS_TO_TICKS(DERP_KEEPALIVE_SEC * 2 * 1000);

    while (dc->running) {
        /* --- 1. Drain pending sends first --- */
        derp_drain_send_queue(dc);

        /* --- 2. Try to read a frame (short timeout) --- */
        uint8_t  frame_type;
        uint32_t frame_len;

        int rc = derp_try_read_frame_hdr(dc, &frame_type, &frame_len);
        if (rc == 1) {
            /* Timeout — no data. Check keepalive. */
            TickType_t now = xTaskGetTickCount();
            if ((now - last_activity) > keepalive_timeout) {
                DERP_ERR("Keepalive timeout — no frames for %d sec",
                         DERP_KEEPALIVE_SEC * 2);
                goto reconnect;
            }
            continue;
        }
        if (rc < 0) {
            DERP_ERR("Recv task: read frame header failed");
            goto reconnect;
        }

        /* Got a frame — reset consecutive failures on successful activity */
        last_activity = xTaskGetTickCount();
        dc->consecutive_failures = 0;
        DERP_DBG("Frame: type=0x%02x len=%lu", frame_type, (unsigned long)frame_len);

        switch (frame_type) {
        case DERP_FRAME_RECV_PACKET: {
            /* 32B src_key + WG packet */
            if (frame_len < 33 || frame_len > DERP_RECV_BUF_SIZE) {
                DERP_ERR("RecvPacket bad len: %lu", (unsigned long)frame_len);
                if (derp_skip(dc, frame_len) < 0) goto reconnect;
                break;
            }
            if (derp_read_exact(dc, recv_buf, frame_len) < 0) {
                DERP_ERR("RecvPacket read failed");
                goto reconnect;
            }
            DERP_DBG("RecvPacket: %lu bytes from key=%02x%02x..%02x%02x",
                     (unsigned long)(frame_len - 32),
                     recv_buf[0], recv_buf[1], recv_buf[30], recv_buf[31]);
            if (dc->recv_cb) {
                dc->recv_cb(recv_buf,              /* src_key (32B) */
                            recv_buf + 32,          /* WG packet */
                            frame_len - 32,         /* WG packet length */
                            dc->recv_ctx);
            }
            break;
        }

        case DERP_FRAME_KEEP_ALIVE:
            DERP_DBG("KeepAlive");
            if (frame_len > 0) derp_skip(dc, frame_len);
            break;

        case DERP_FRAME_PING: {
            /* 8B data → reply Pong with same data */
            if (frame_len != 8) {
                if (frame_len > 0) derp_skip(dc, frame_len);
                break;
            }
            uint8_t ping_data[8];
            if (derp_read_exact(dc, ping_data, 8) < 0) goto reconnect;
            DERP_DBG("Ping -> Pong");
            if (derp_write_frame(dc, DERP_FRAME_PONG, ping_data, 8) < 0) {
                DERP_ERR("Pong send failed");
                goto reconnect;
            }
            break;
        }

        case DERP_FRAME_PEER_GONE:
            DERP_LOG("PeerGone (len=%lu)", (unsigned long)frame_len);
            if (frame_len > 0) derp_skip(dc, frame_len);
            break;

        case DERP_FRAME_SERVER_INFO:
            DERP_LOG("ServerInfo (len=%lu)", (unsigned long)frame_len);
            if (frame_len > 0) derp_skip(dc, frame_len);
            break;

        default:
            /* Unknown frame — skip payload */
            DERP_LOG("Unknown frame 0x%02x (len=%lu)", frame_type, (unsigned long)frame_len);
            if (frame_len > 0) {
                if (derp_skip(dc, frame_len) < 0) goto reconnect;
            }
            break;
        }
    }
    } /* end scope for last_activity */

    goto done;

reconnect:
    /* Close TLS/socket but keep task running */
    derp_close_connection(dc);

    /* Exponential backoff reconnect: 5s → 10s → 20s → 30s max */
    while (dc->running) {
        dc->consecutive_failures++;
        int shift = dc->consecutive_failures - 1;
        if (shift > 3) shift = 3;
        uint32_t wait = 5000u << shift;
        if (wait > 30000) wait = 30000;

        DERP_LOG("Reconnecting in %ums (attempt %d)",
                 wait, dc->consecutive_failures);
        vTaskDelay(pdMS_TO_TICKS(wait));

        if (!dc->running) break;

        if (derp_do_connect(dc) == 0) {
            DERP_LOG("Reconnected OK");
            dc->consecutive_failures = 0;
            goto recv_loop;  /* Back to normal recv loop */
        }
        DERP_ERR("Reconnect failed");
    }

done:
    free(recv_buf);
    dc->running = false;
    dc->ready = false;
    DERP_LOG("Recv task exiting");
    vTaskDelete(NULL);
}

/* ------------------------------------------------------------------ */
/*  Public API: start / stop / close                                   */
/* ------------------------------------------------------------------ */

void derp_start(derp_client_t *dc)
{
    if (dc->running) return;

    /* Create send queue */
    if (!dc->send_queue) {
        dc->send_queue = (void *)xQueueCreate(DERP_SEND_QUEUE_DEPTH,
                                               sizeof(derp_send_req_t *));
        if (!dc->send_queue) {
            DERP_ERR("Failed to create send queue");
            return;
        }
    }

    dc->running = true;
    xTaskCreate(derp_recv_task, "derp_rx", DERP_TASK_STACK, dc,
                DERP_TASK_PRIO, (TaskHandle_t *)&dc->task_handle);
}

void derp_stop(derp_client_t *dc)
{
    dc->running = false;
    /* Task will exit on next poll timeout */
}

void derp_close(derp_client_t *dc)
{
    derp_stop(dc);

    /* Wait briefly for task to exit */
    if (dc->task_handle) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        dc->task_handle = NULL;
    }

    /* Drain and delete send queue */
    if (dc->send_queue) {
        derp_send_req_t *req;
        while (xQueueReceive((QueueHandle_t)dc->send_queue, &req, 0) == pdTRUE) {
            if (req) {
                free(req->pkt);
                free(req);
            }
        }
        vQueueDelete((QueueHandle_t)dc->send_queue);
        dc->send_queue = NULL;
    }

    if (dc->tls) {
        ts_tls_close(dc->tls);
        dc->tls = NULL;
    }
    if (dc->sock_fd >= 0) {
        close(dc->sock_fd);
        dc->sock_fd = -1;
    }

    dc->connected = false;
    dc->ready = false;
}
