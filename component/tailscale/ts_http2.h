/*
 * ts_http2.h — Minimal HTTP/2 client for Tailscale control protocol
 *
 * Provides just enough HTTP/2 to send POST requests and receive
 * responses over a Noise-encrypted ctrl_client transport.
 *
 * Features:
 *   - Connection preface + SETTINGS exchange
 *   - HPACK literal-without-indexing encoding (no Huffman)
 *   - POST request (HEADERS + DATA with END_STREAM)
 *   - Response parsing (status code + DATA accumulation)
 *   - WINDOW_UPDATE for flow control
 *   - Tailscale 4-byte LE length prefix handling
 */

#ifndef TS_HTTP2_H
#define TS_HTTP2_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "ctrl_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

/* HTTP/2 frame types */
#define H2_DATA          0x00
#define H2_HEADERS       0x01
#define H2_SETTINGS      0x04
#define H2_PING          0x06
#define H2_GOAWAY        0x07
#define H2_WINDOW_UPDATE 0x08

/* HTTP/2 flags */
#define H2_FLAG_END_STREAM  0x01
#define H2_FLAG_END_HEADERS 0x04
#define H2_FLAG_ACK         0x01  /* SETTINGS/PING ACK */

/* HTTP/2 settings IDs */
#define H2_SETTINGS_ENABLE_PUSH   0x02
#define H2_SETTINGS_MAX_FRAME     0x05

#define H2_FRAME_HDR_LEN    9
#define H2_MAX_FRAME_SIZE   16384  /* RFC 7540 minimum: 2^14 */

/* Internal buffer for accumulating transport data */
#define H2_RECV_BUF_SIZE    (16384 + 512)  /* room for max frame + header */

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    ctrl_client_t *ctrl;         /* Noise transport (not owned) */
    uint32_t       next_stream;  /* Next client stream ID (odd) */
    bool           started;      /* Preface + SETTINGS done */

    /* Authority for Host/:authority header */
    char authority[128];

    /* Receive buffer — accumulates plaintext from ctrl_client_recv
     * which may contain partial or multiple HTTP/2 frames */
    uint8_t recv_buf[H2_RECV_BUF_SIZE];
    size_t  recv_len;

    /* Data accumulation buffer for current response body */
    uint8_t *data_buf;      /* Caller-provided buffer */
    size_t   data_buf_size;
    size_t   data_len;       /* Bytes accumulated so far */

    /* Response status from HEADERS */
    int resp_status;
} ts_http2_t;

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

/*
 * Initialize HTTP/2 session.
 * @param ctrl  Connected ctrl_client (Noise transport ready)
 * @param authority  "host:port" for HTTP/2 :authority header
 */
void ts_http2_init(ts_http2_t *s, ctrl_client_t *ctrl,
                    const char *authority);

/*
 * Start HTTP/2 session: send connection preface + client SETTINGS,
 * receive server SETTINGS, send SETTINGS ACK.
 * @return 0 on success, -1 on error
 */
int ts_http2_start(ts_http2_t *s);

/*
 * Send a POST request and receive the complete response body.
 * Used for /machine/register.
 *
 * @param path      Request path (e.g., "/machine/register")
 * @param body      JSON request body
 * @param body_len  Length of body
 * @param resp      Buffer for response body
 * @param resp_size Size of resp buffer
 * @param timeout_ms  Read timeout
 * @return Response body length (>= 0), or -1 on error
 */
int ts_http2_post(ts_http2_t *s,
                   const char *path,
                   const uint8_t *body, size_t body_len,
                   uint8_t *resp, size_t resp_size,
                   int timeout_ms);

/*
 * Send a POST request for streaming (long-poll).
 * Used for /machine/map with Stream=true.
 * Does NOT read the response — use ts_http2_read_json() for that.
 *
 * @return stream ID (> 0), or -1 on error
 */
int ts_http2_post_begin(ts_http2_t *s,
                         const char *path,
                         const uint8_t *body, size_t body_len);

/*
 * Read one JSON object from a streaming HTTP/2 response.
 * Handles the Tailscale 4-byte little-endian length prefix.
 *
 * @param buf       Buffer for JSON text (null-terminated)
 * @param buf_len   Size of buf
 * @param timeout_ms  Read timeout
 * @return JSON length (> 0), 0 on timeout, -1 on error/stream closed
 */
int ts_http2_read_json(ts_http2_t *s,
                        uint8_t *buf, size_t buf_len,
                        int timeout_ms);

/*
 * Send additional DATA on an existing stream (for keepalive).
 * Wraps payload with 4-byte LE length prefix.
 * Does NOT set END_STREAM — keeps the stream open.
 *
 * @param stream_id  The persistent stream ID (from post_begin)
 * @param data       JSON payload
 * @param data_len   Length of JSON payload
 * @return 0 on success, -1 on error
 */
int ts_http2_send_data(ts_http2_t *s, uint32_t stream_id,
                        const uint8_t *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* TS_HTTP2_H */
