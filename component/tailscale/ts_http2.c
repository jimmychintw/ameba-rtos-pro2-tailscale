/*
 * ts_http2.c — Minimal HTTP/2 client for Tailscale control protocol
 */

#include "ts_http2.h"
#include <string.h>
#include <stdio.h>

#define LOG_TAG "[TS_H2] "
#define H2_LOG(fmt, ...) printf(LOG_TAG fmt "\r\n", ##__VA_ARGS__)
#define H2_ERR(fmt, ...) printf(LOG_TAG "ERROR: " fmt "\r\n", ##__VA_ARGS__)

/* HTTP/2 connection preface (RFC 7540 Section 3.5) */
static const char H2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_PREFACE_LEN 24

/* ------------------------------------------------------------------ */
/*  Frame encode/decode                                                */
/* ------------------------------------------------------------------ */

/*
 * Encode an HTTP/2 frame header + payload into buf.
 * Returns total frame length (9 + payload_len).
 */
static int h2_encode_frame(uint8_t *buf, size_t buf_len,
                            uint8_t type, uint8_t flags,
                            uint32_t stream_id,
                            const uint8_t *payload, size_t payload_len)
{
    size_t total = H2_FRAME_HDR_LEN + payload_len;
    if (total > buf_len) return -1;

    /* Length: 24-bit big-endian */
    buf[0] = (payload_len >> 16) & 0xFF;
    buf[1] = (payload_len >>  8) & 0xFF;
    buf[2] =  payload_len        & 0xFF;
    buf[3] = type;
    buf[4] = flags;
    /* Stream ID: 31-bit big-endian */
    stream_id &= 0x7FFFFFFF;
    buf[5] = (stream_id >> 24) & 0xFF;
    buf[6] = (stream_id >> 16) & 0xFF;
    buf[7] = (stream_id >>  8) & 0xFF;
    buf[8] =  stream_id        & 0xFF;

    if (payload && payload_len > 0)
        memcpy(buf + 9, payload, payload_len);

    return (int)total;
}

/*
 * Parse an HTTP/2 frame header from buf.
 * Returns 0 on success, -1 if insufficient data.
 */
static int h2_parse_header(const uint8_t *buf, size_t buf_len,
                            uint32_t *length, uint8_t *type,
                            uint8_t *flags, uint32_t *stream_id)
{
    if (buf_len < H2_FRAME_HDR_LEN) return -1;

    *length = ((uint32_t)buf[0] << 16) |
              ((uint32_t)buf[1] <<  8) |
               (uint32_t)buf[2];
    *type  = buf[3];
    *flags = buf[4];
    *stream_id = ((uint32_t)buf[5] << 24) |
                 ((uint32_t)buf[6] << 16) |
                 ((uint32_t)buf[7] <<  8) |
                  (uint32_t)buf[8];
    *stream_id &= 0x7FFFFFFF;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  HPACK: literal header without indexing (RFC 7541 §6.2.2)           */
/* ------------------------------------------------------------------ */

/* Encode HPACK integer with prefix bits */
static size_t hpack_encode_int(uint8_t *dst, size_t val, int prefix_bits)
{
    int max_prefix = (1 << prefix_bits) - 1;
    if ((int)val < max_prefix) {
        dst[0] |= (uint8_t)val;
        return 1;
    }
    dst[0] |= (uint8_t)max_prefix;
    val -= max_prefix;
    size_t pos = 1;
    while (val >= 128) {
        dst[pos++] = (uint8_t)((val & 0x7F) | 0x80);
        val >>= 7;
    }
    dst[pos++] = (uint8_t)val;
    return pos;
}

/*
 * Encode a literal header without indexing.
 * Returns bytes written to dst.
 */
static size_t hpack_encode_header(uint8_t *dst, size_t dst_len,
                                   const char *name, const char *value)
{
    size_t nlen = strlen(name);
    size_t vlen = strlen(value);
    size_t pos = 0;

    /* Worst case: 1 + 3 + nlen + 3 + vlen */
    if (pos + 7 + nlen + vlen > dst_len) return 0;

    /* Literal without indexing, new name: 0000 0000 */
    dst[pos] = 0x00;
    pos += 1;

    /* Name string (H=0, no Huffman) */
    dst[pos] = 0x00; /* H=0 */
    pos += hpack_encode_int(dst + pos, nlen, 7);
    memcpy(dst + pos, name, nlen);
    pos += nlen;

    /* Value string (H=0, no Huffman) */
    dst[pos] = 0x00; /* H=0 */
    pos += hpack_encode_int(dst + pos, vlen, 7);
    memcpy(dst + pos, value, vlen);
    pos += vlen;

    return pos;
}

/* ------------------------------------------------------------------ */
/*  Internal: send a frame through Noise transport                     */
/* ------------------------------------------------------------------ */

static int h2_send_frame(ts_http2_t *s,
                          uint8_t type, uint8_t flags,
                          uint32_t stream_id,
                          const uint8_t *payload, size_t payload_len)
{
    uint8_t frame[H2_FRAME_HDR_LEN + 4096]; /* send frames are small */
    int len = h2_encode_frame(frame, sizeof(frame),
                               type, flags, stream_id,
                               payload, payload_len);
    if (len < 0) return -1;
    return ctrl_client_send(s->ctrl, frame, len);
}

/* Send WINDOW_UPDATE for both stream and connection */
static int h2_send_window_update(ts_http2_t *s, uint32_t stream_id,
                                   uint32_t increment)
{
    uint8_t payload[4];
    payload[0] = (increment >> 24) & 0xFF;
    payload[1] = (increment >> 16) & 0xFF;
    payload[2] = (increment >>  8) & 0xFF;
    payload[3] =  increment        & 0xFF;

    /* Stream-level */
    if (stream_id != 0) {
        if (h2_send_frame(s, H2_WINDOW_UPDATE, 0, stream_id, payload, 4) < 0)
            return -1;
    }
    /* Connection-level */
    return h2_send_frame(s, H2_WINDOW_UPDATE, 0, 0, payload, 4);
}

/* ------------------------------------------------------------------ */
/*  Internal: pull data from transport into recv_buf                   */
/* ------------------------------------------------------------------ */

static int h2_pull_data(ts_http2_t *s, int timeout_ms)
{
    if (s->recv_len >= sizeof(s->recv_buf)) return -1;

    int n = ctrl_client_recv(s->ctrl,
                              s->recv_buf + s->recv_len,
                              sizeof(s->recv_buf) - s->recv_len,
                              timeout_ms);
    if (n > 0) s->recv_len += n;
    return n;
}

/* Consume n bytes from front of recv_buf */
static void h2_consume(ts_http2_t *s, size_t n)
{
    if (n >= s->recv_len) {
        s->recv_len = 0;
    } else {
        memmove(s->recv_buf, s->recv_buf + n, s->recv_len - n);
        s->recv_len -= n;
    }
}

/*
 * Read one complete HTTP/2 frame from recv_buf.
 * Returns frame payload pointer and fills out_* params.
 * Returns NULL if need more data (call h2_pull_data first).
 */
static const uint8_t *h2_read_frame(ts_http2_t *s,
                                     uint32_t *out_len, uint8_t *out_type,
                                     uint8_t *out_flags, uint32_t *out_stream,
                                     int timeout_ms)
{
    for (;;) {
        if (s->recv_len >= H2_FRAME_HDR_LEN) {
            uint32_t flen;
            uint8_t ftype, fflags;
            uint32_t fstream;
            h2_parse_header(s->recv_buf, s->recv_len,
                            &flen, &ftype, &fflags, &fstream);

            size_t total = H2_FRAME_HDR_LEN + flen;
            if (s->recv_len >= total) {
                *out_len    = flen;
                *out_type   = ftype;
                *out_flags  = fflags;
                *out_stream = fstream;
                return s->recv_buf + H2_FRAME_HDR_LEN;
            }
        }
        /* Need more data */
        int n = h2_pull_data(s, timeout_ms);
        if (n <= 0) return NULL;
    }
}

/* Consume the frame we just read */
static void h2_consume_frame(ts_http2_t *s, uint32_t payload_len)
{
    h2_consume(s, H2_FRAME_HDR_LEN + payload_len);
}

/* ------------------------------------------------------------------ */
/*  Internal: parse :status from HEADERS frame HPACK block             */
/* ------------------------------------------------------------------ */

static int hpack_parse_status(const uint8_t *block, size_t block_len)
{
    /* We only care about :status. In HPACK, it could be:
     * - Indexed (top bit set): indices 8-14 map to status 200-504
     * - Literal: we search for "200", "404", etc.
     * For simplicity, look for common indexed representations
     * and fall back to searching for ASCII digits. */

    if (block_len == 0) return -1;

    /* Check for indexed header (§6.1): 1xxxxxxx */
    if (block[0] & 0x80) {
        int idx = block[0] & 0x7F;
        /* RFC 7541 Appendix A: static table */
        switch (idx) {
            case 8:  return 200;
            case 9:  return 204;
            case 10: return 206;
            case 11: return 304;
            case 12: return 400;
            case 13: return 404;
            case 14: return 500;
        }
    }

    /* Scan for ":status" literal or just find 3-digit number */
    for (size_t i = 0; i + 2 < block_len; i++) {
        if (block[i] >= '1' && block[i] <= '5' &&
            block[i+1] >= '0' && block[i+1] <= '9' &&
            block[i+2] >= '0' && block[i+2] <= '9') {
            return (block[i] - '0') * 100 +
                   (block[i+1] - '0') * 10 +
                   (block[i+2] - '0');
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Public API: init                                                   */
/* ------------------------------------------------------------------ */

void ts_http2_init(ts_http2_t *s, ctrl_client_t *ctrl,
                    const char *authority)
{
    memset(s, 0, sizeof(*s));
    s->ctrl = ctrl;
    s->next_stream = 1;
    strncpy(s->authority, authority, sizeof(s->authority) - 1);
}

/* ------------------------------------------------------------------ */
/*  Public API: start (preface + SETTINGS exchange)                    */
/* ------------------------------------------------------------------ */

int ts_http2_start(ts_http2_t *s)
{
    /* Build preface (24 bytes) + client SETTINGS frame (9+12 = 21 bytes) */
    uint8_t init_buf[64];
    size_t pos = 0;

    /* Connection preface */
    memcpy(init_buf, H2_PREFACE, H2_PREFACE_LEN);
    pos = H2_PREFACE_LEN;

    /* SETTINGS frame: just disable push (MAX_FRAME_SIZE defaults to 16384) */
    uint8_t settings_payload[6];
    /* SETTINGS_ENABLE_PUSH = 0 */
    settings_payload[0] = 0x00; settings_payload[1] = H2_SETTINGS_ENABLE_PUSH;
    settings_payload[2] = 0; settings_payload[3] = 0;
    settings_payload[4] = 0; settings_payload[5] = 0;

    int flen = h2_encode_frame(init_buf + pos, sizeof(init_buf) - pos,
                                H2_SETTINGS, 0, 0,
                                settings_payload, sizeof(settings_payload));
    if (flen < 0) return -1;
    pos += flen;

    /* Send preface + SETTINGS as one message */
    H2_LOG("Sending preface + SETTINGS (%zu bytes)", pos);
    if (ctrl_client_send(s->ctrl, init_buf, pos) < 0) {
        H2_ERR("Failed to send preface");
        return -1;
    }

    /* Read server SETTINGS (may also get WINDOW_UPDATE, etc.) */
    bool got_settings = false;
    bool got_settings_ack = false;

    for (int attempt = 0; attempt < 10 && !(got_settings && got_settings_ack); attempt++) {
        uint32_t flen2;
        uint8_t ftype, fflags;
        uint32_t fstream;
        const uint8_t *payload = h2_read_frame(s, &flen2, &ftype, &fflags, &fstream, 10000);
        if (!payload) {
            H2_ERR("Timeout reading server frames");
            return -1;
        }

        switch (ftype) {
        case H2_SETTINGS:
            if (fflags & H2_FLAG_ACK) {
                H2_LOG("Got SETTINGS ACK");
                got_settings_ack = true;
            } else {
                H2_LOG("Got server SETTINGS (%u bytes)", flen2);
                got_settings = true;
                /* Send SETTINGS ACK */
                h2_consume_frame(s, flen2);
                if (h2_send_frame(s, H2_SETTINGS, H2_FLAG_ACK, 0, NULL, 0) < 0)
                    return -1;
                continue;
            }
            break;
        case H2_WINDOW_UPDATE:
            /* Ignore server window updates for now */
            break;
        case H2_PING:
            if (!(fflags & H2_FLAG_ACK)) {
                h2_consume_frame(s, flen2);
                h2_send_frame(s, H2_PING, H2_FLAG_ACK, 0, payload, flen2);
                continue;
            }
            break;
        case H2_GOAWAY: {
            /* Parse GOAWAY: last_stream_id(4) + error_code(4) + debug_data */
            uint8_t *gp = s->recv_buf + H2_FRAME_HDR_LEN;
            uint32_t last_sid = 0, err_code = 0;
            if (flen2 >= 8) {
                last_sid = ((uint32_t)gp[0]<<24)|((uint32_t)gp[1]<<16)|
                           ((uint32_t)gp[2]<<8)|gp[3];
                err_code = ((uint32_t)gp[4]<<24)|((uint32_t)gp[5]<<16)|
                           ((uint32_t)gp[6]<<8)|gp[7];
            }
            H2_ERR("GOAWAY: last_stream=%u err=%u", last_sid, err_code);
            if (flen2 > 8) {
                size_t dbg_len = flen2 - 8;
                if (dbg_len > 128) dbg_len = 128;
                char dbg[129];
                memcpy(dbg, gp + 8, dbg_len);
                dbg[dbg_len] = '\0';
                H2_ERR("GOAWAY debug: %s", dbg);
            }
            h2_consume_frame(s, flen2);
            return -1;
        }
        default:
            H2_LOG("Ignoring frame type 0x%02x", ftype);
            break;
        }
        h2_consume_frame(s, flen2);
    }

    if (!got_settings) {
        H2_ERR("No server SETTINGS received");
        return -1;
    }

    s->started = true;
    H2_LOG("HTTP/2 session started");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Internal: send POST request (HEADERS + DATA)                       */
/* ------------------------------------------------------------------ */

static int h2_send_post(ts_http2_t *s, const char *path,
                          const uint8_t *body, size_t body_len,
                          uint32_t stream_id, bool end_stream)
{
    char cl_str[16];
    snprintf(cl_str, sizeof(cl_str), "%u", (unsigned)body_len);

    /* Build HPACK header block */
    uint8_t hpack[512];
    size_t hpos = 0;

    hpos += hpack_encode_header(hpack + hpos, sizeof(hpack) - hpos,
                                 ":method", "POST");
    hpos += hpack_encode_header(hpack + hpos, sizeof(hpack) - hpos,
                                 ":scheme", "https");
    hpos += hpack_encode_header(hpack + hpos, sizeof(hpack) - hpos,
                                 ":authority", s->authority);
    hpos += hpack_encode_header(hpack + hpos, sizeof(hpack) - hpos,
                                 ":path", path);
    hpos += hpack_encode_header(hpack + hpos, sizeof(hpack) - hpos,
                                 "content-type", "application/json");
    hpos += hpack_encode_header(hpack + hpos, sizeof(hpack) - hpos,
                                 "content-length", cl_str);
    hpos += hpack_encode_header(hpack + hpos, sizeof(hpack) - hpos,
                                 "accept", "application/json");

    /* Send HEADERS frame (END_HEADERS flag, no END_STREAM since DATA follows) */
    if (h2_send_frame(s, H2_HEADERS, H2_FLAG_END_HEADERS,
                       stream_id, hpack, hpos) < 0) {
        H2_ERR("Failed to send HEADERS");
        return -1;
    }

    /* Send DATA frame — END_STREAM only for one-shot requests */
    uint8_t data_flags = end_stream ? H2_FLAG_END_STREAM : 0;
    if (h2_send_frame(s, H2_DATA, data_flags,
                       stream_id, body, body_len) < 0) {
        H2_ERR("Failed to send DATA");
        return -1;
    }

    H2_LOG("POST %s stream=%u body=%zu end=%d", path, stream_id, body_len, end_stream);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public API: post (request + complete response)                     */
/* ------------------------------------------------------------------ */

int ts_http2_post(ts_http2_t *s,
                   const char *path,
                   const uint8_t *body, size_t body_len,
                   uint8_t *resp, size_t resp_size,
                   int timeout_ms)
{
    if (!s->started) return -1;

    uint32_t stream_id = s->next_stream;
    s->next_stream += 2;

    if (h2_send_post(s, path, body, body_len, stream_id, true) < 0)
        return -1;

    /* Read response frames until END_STREAM */
    s->resp_status = 0;
    size_t resp_len = 0;
    bool end_stream = false;

    while (!end_stream) {
        uint32_t flen;
        uint8_t ftype, fflags;
        uint32_t fstream;
        const uint8_t *payload = h2_read_frame(s, &flen, &ftype, &fflags, &fstream, timeout_ms);
        if (!payload) {
            H2_ERR("Timeout reading response");
            return -1;
        }

        if (ftype == H2_GOAWAY) {
            H2_ERR("GOAWAY during response");
            h2_consume_frame(s, flen);
            return -1;
        }

        /* Handle frames for our stream */
        if (fstream == stream_id || fstream == 0) {
            switch (ftype) {
            case H2_HEADERS:
                s->resp_status = hpack_parse_status(payload, flen);
                H2_LOG("Response status: %d", s->resp_status);
                if (fflags & H2_FLAG_END_STREAM) end_stream = true;
                break;

            case H2_DATA: {
                /* Tailscale wire format: 4-byte LE length prefix + JSON */
                const uint8_t *json_data = payload;
                size_t json_len = flen;

                if (flen >= 5 && payload[4] == '{') {
                    /* Skip 4-byte LE length prefix */
                    json_data = payload + 4;
                    json_len = flen - 4;
                }

                size_t copy = json_len;
                if (resp_len + copy > resp_size - 1)
                    copy = resp_size - 1 - resp_len;
                memcpy(resp + resp_len, json_data, copy);
                resp_len += copy;

                /* Send WINDOW_UPDATE */
                h2_send_window_update(s, stream_id, flen);

                if (fflags & H2_FLAG_END_STREAM) end_stream = true;
                break;
            }

            case H2_SETTINGS:
                if (!(fflags & H2_FLAG_ACK)) {
                    h2_consume_frame(s, flen);
                    h2_send_frame(s, H2_SETTINGS, H2_FLAG_ACK, 0, NULL, 0);
                    continue;
                }
                break;

            case H2_WINDOW_UPDATE:
                break;

            case H2_PING:
                if (!(fflags & H2_FLAG_ACK)) {
                    h2_consume_frame(s, flen);
                    h2_send_frame(s, H2_PING, H2_FLAG_ACK, 0, payload, flen);
                    continue;
                }
                break;

            default:
                break;
            }
        }
        h2_consume_frame(s, flen);
    }

    resp[resp_len] = '\0';
    return (int)resp_len;
}

/* ------------------------------------------------------------------ */
/*  Public API: post_begin (streaming request)                         */
/* ------------------------------------------------------------------ */

int ts_http2_post_begin(ts_http2_t *s,
                         const char *path,
                         const uint8_t *body, size_t body_len)
{
    if (!s->started) return -1;

    uint32_t stream_id = s->next_stream;
    s->next_stream += 2;

    /* END_STREAM on DATA — server processes request then streams response */
    if (h2_send_post(s, path, body, body_len, stream_id, true) < 0)
        return -1;

    return (int)stream_id;
}

/* ------------------------------------------------------------------ */
/*  Public API: read_json (one JSON object from streaming response)    */
/* ------------------------------------------------------------------ */

int ts_http2_read_json(ts_http2_t *s,
                        uint8_t *buf, size_t buf_len,
                        int timeout_ms)
{
    size_t json_pos = 0;
    uint32_t json_expected = 0;  /* from LE length prefix, 0 = unknown */
    bool got_headers = (s->resp_status > 0);

    for (;;) {
        uint32_t flen;
        uint8_t ftype, fflags;
        uint32_t fstream;
        const uint8_t *payload = h2_read_frame(s, &flen, &ftype, &fflags, &fstream, timeout_ms);
        if (!payload) {
            H2_LOG("read_json: timeout (json_pos=%zu expected=%u)", json_pos, json_expected);
            return 0; /* timeout */
        }

        H2_LOG("read_json: frame type=0x%02x flags=0x%02x stream=%u len=%u",
               ftype, fflags, fstream, flen);

        switch (ftype) {
        case H2_HEADERS: {
            uint32_t act = s->next_stream >= 2 ? s->next_stream - 2 : 0;
            if (act > 0 && fstream != act && fstream != 0) {
                H2_LOG("Skipping HEADERS from old stream=%u (active=%u)", fstream, act);
                h2_consume_frame(s, flen);
                continue;
            }
            if (!got_headers) {
                s->resp_status = hpack_parse_status(payload, flen);
                H2_LOG("Stream status: %d", s->resp_status);
                got_headers = true;
            }
            if (fflags & H2_FLAG_END_STREAM) {
                h2_consume_frame(s, flen);
                return -1; /* stream closed */
            }
            h2_consume_frame(s, flen);
            continue;
        }

        case H2_DATA: {
            /* Skip DATA from old streams */
            uint32_t active = s->next_stream >= 2 ? s->next_stream - 2 : 0;
            if (active > 0 && fstream != active && fstream != 0) {
                H2_LOG("Skipping DATA from old stream=%u (active=%u, len=%u, end=%d)",
                       fstream, active, flen, (fflags & H2_FLAG_END_STREAM) != 0);
                h2_send_window_update(s, fstream, flen);
                h2_consume_frame(s, flen);
                continue;
            }

            const uint8_t *data = payload;
            size_t data_len = flen;

            /* Parse 4-byte LE length prefix at the start of a new message */
            if (json_pos == 0 && data_len >= 5 && data[4] == '{') {
                json_expected = ((uint32_t)data[0])       |
                                ((uint32_t)data[1] << 8)  |
                                ((uint32_t)data[2] << 16) |
                                ((uint32_t)data[3] << 24);
                H2_LOG("LE prefix: expecting %u bytes JSON", json_expected);
                data += 4;
                data_len -= 4;

                if (json_expected >= buf_len) {
                    H2_ERR("MapResponse too large: %u bytes (buf=%zu)",
                           json_expected, buf_len);
                }
            }

            /* Copy to output buffer */
            size_t copy = data_len;
            if (json_pos + copy > buf_len - 1)
                copy = buf_len - 1 - json_pos;
            memcpy(buf + json_pos, data, copy);
            json_pos += copy;

            if (copy < data_len) {
                H2_ERR("Buffer overflow: discarded %zu bytes (pos=%zu buf=%zu)",
                       data_len - copy, json_pos, buf_len);
            }

            /* WINDOW_UPDATE */
            h2_send_window_update(s, fstream, flen);

            bool end = (fflags & H2_FLAG_END_STREAM) != 0;
            h2_consume_frame(s, flen);

            /* Check completeness: prefer LE length prefix if available */
            if (json_expected > 0 && json_pos >= json_expected) {
                buf[json_pos] = '\0';
                H2_LOG("JSON complete via LE prefix (%zu bytes)", json_pos);
                return (int)json_pos;
            }

            /* Fallback: brace-balance check */
            if (json_expected == 0 && json_pos > 0 && buf[json_pos - 1] == '}') {
                int depth = 0;
                for (size_t i = 0; i < json_pos; i++) {
                    if (buf[i] == '{') depth++;
                    else if (buf[i] == '}') depth--;
                }
                if (depth == 0) {
                    buf[json_pos] = '\0';
                    H2_LOG("JSON complete via brace balance (%zu bytes)", json_pos);
                    return (int)json_pos;
                }
            }

            if (end) {
                if (json_pos > 0) {
                    buf[json_pos] = '\0';
                    return (int)json_pos;
                }
                if (flen == 0) {
                    /* Empty END_STREAM from a previous stream — skip */
                    H2_LOG("Skipping empty END_STREAM (stream=%u)", fstream);
                    continue;
                }
                return -1;
            }
            continue;
        }

        case H2_SETTINGS:
            if (!(fflags & H2_FLAG_ACK)) {
                h2_consume_frame(s, flen);
                h2_send_frame(s, H2_SETTINGS, H2_FLAG_ACK, 0, NULL, 0);
                continue;
            }
            break;

        case H2_PING:
            if (!(fflags & H2_FLAG_ACK)) {
                h2_consume_frame(s, flen);
                h2_send_frame(s, H2_PING, H2_FLAG_ACK, 0, payload, flen);
                continue;
            }
            break;

        case 0x03: /* RST_STREAM */ {
            uint32_t err_code = 0;
            if (flen >= 4) {
                err_code = ((uint32_t)payload[0]<<24)|((uint32_t)payload[1]<<16)|
                           ((uint32_t)payload[2]<<8)|payload[3];
            }
            h2_consume_frame(s, flen);
            /* Skip RST_STREAM for older streams (e.g., previous request) */
            uint32_t active_stream = s->next_stream >= 2 ? s->next_stream - 2 : 0;
            if (fstream != active_stream) {
                H2_LOG("Skipping RST_STREAM for old stream=%u err=%u (active=%u)",
                       fstream, err_code, active_stream);
                continue;
            }
            H2_ERR("RST_STREAM stream=%u err=%u", fstream, err_code);
            return -1;
        }

        case H2_GOAWAY:
            H2_ERR("GOAWAY");
            h2_consume_frame(s, flen);
            return -1;

        default:
            break;
        }
        h2_consume_frame(s, flen);
    }
}

/* ------------------------------------------------------------------ */
/*  Public API: send_data (additional DATA on persistent stream)       */
/* ------------------------------------------------------------------ */

int ts_http2_send_data(ts_http2_t *s, uint32_t stream_id,
                        const uint8_t *data, size_t data_len)
{
    if (!s->started || stream_id == 0) return -1;

    /* Build wire format: 4-byte LE length prefix + JSON payload */
    size_t wire_len = 4 + data_len;
    uint8_t *wire = (uint8_t *)malloc(wire_len);
    if (!wire) return -1;

    /* Little-endian length prefix */
    wire[0] =  data_len        & 0xFF;
    wire[1] = (data_len >>  8) & 0xFF;
    wire[2] = (data_len >> 16) & 0xFF;
    wire[3] = (data_len >> 24) & 0xFF;
    memcpy(wire + 4, data, data_len);

    /* Send DATA frame without END_STREAM (flags=0) */
    int ret = h2_send_frame(s, H2_DATA, 0, stream_id, wire, wire_len);
    free(wire);

    if (ret < 0) {
        H2_ERR("Failed to send DATA on stream %u", stream_id);
        return -1;
    }

    H2_LOG("Sent %zu bytes on stream %u (keepalive)", data_len, stream_id);
    return 0;
}
