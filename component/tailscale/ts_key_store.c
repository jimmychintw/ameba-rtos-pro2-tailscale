/*
 * ts_key_store.c — Tailscale key persistence (NOR flash)
 *
 * Stores 3 Curve25519 key pairs (machine, node, disco) in a single
 * 4KB flash sector at TS_KEY_STORE_ADDR (0xF0F000).
 *
 * Format (204 bytes):
 *   [0x00] 4B  magic  "TSk1"
 *   [0x04] 4B  version (0x00000001)
 *   [0x08] 32B machine_priv
 *   [0x28] 32B machine_pub
 *   [0x48] 32B node_priv
 *   [0x68] 32B node_pub
 *   [0x88] 32B disco_priv
 *   [0xA8] 32B disco_pub
 *   [0xC8] 4B  CRC32 (over 0x00..0xC7)
 */

#include "ts_key_store.h"
#include <string.h>
#include <stdio.h>
#include "flash_api.h"
#include "device_lock.h"

#define LOG_TAG "[TS_KS] "
#define KS_LOG(fmt, ...) printf(LOG_TAG fmt "\r\n", ##__VA_ARGS__)
#define KS_ERR(fmt, ...) printf(LOG_TAG "ERROR: " fmt "\r\n", ##__VA_ARGS__)

/* Flash address: gap between FLASH_FCS_DATA and TUNING_IQ_FW */
#define TS_KEY_STORE_ADDR  0xF0F000

#define TS_KS_MAGIC        0x316B5354  /* "TSk1" in little-endian */
#define TS_KS_VERSION      0x00000001

/* On-flash layout */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t version;
    uint8_t  machine_priv[32];
    uint8_t  machine_pub[32];
    uint8_t  node_priv[32];
    uint8_t  node_pub[32];
    uint8_t  disco_priv[32];
    uint8_t  disco_pub[32];
    uint32_t crc32;
} ts_key_store_t;

/* CRC32 (ISO 3309 / zlib polynomial) */
static uint32_t ks_crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }
    return ~crc;
}

int ts_key_store_load(peer_manager_t *pm)
{
    flash_t flash;
    ts_key_store_t ks;

    device_mutex_lock(RT_DEV_LOCK_FLASH);
    flash_stream_read(&flash, TS_KEY_STORE_ADDR, sizeof(ks), (uint8_t *)&ks);
    device_mutex_unlock(RT_DEV_LOCK_FLASH);

    /* Check magic */
    if (ks.magic != TS_KS_MAGIC) {
        KS_LOG("No key store found (magic=0x%08x)", (unsigned)ks.magic);
        return -1;
    }

    /* Check version */
    if (ks.version != TS_KS_VERSION) {
        KS_ERR("Unknown version: 0x%08x", (unsigned)ks.version);
        return -1;
    }

    /* Verify CRC32 (over everything except the CRC field itself) */
    uint32_t expected = ks_crc32((const uint8_t *)&ks,
                                  offsetof(ts_key_store_t, crc32));
    if (ks.crc32 != expected) {
        KS_ERR("CRC mismatch: stored=0x%08x calc=0x%08x",
               (unsigned)ks.crc32, (unsigned)expected);
        return -1;
    }

    /* Copy keys into peer_manager */
    memcpy(pm->machine_priv, ks.machine_priv, 32);
    memcpy(pm->machine_pub,  ks.machine_pub,  32);
    memcpy(pm->node_priv,    ks.node_priv,    32);
    memcpy(pm->node_pub,     ks.node_pub,     32);
    memcpy(pm->disco_priv,   ks.disco_priv,   32);
    memcpy(pm->disco_pub,    ks.disco_pub,    32);

    KS_LOG("Keys loaded from flash (CRC OK)");
    return 0;
}

int ts_key_store_save(peer_manager_t *pm)
{
    flash_t flash;
    ts_key_store_t ks;

    /* Build record */
    ks.magic   = TS_KS_MAGIC;
    ks.version = TS_KS_VERSION;
    memcpy(ks.machine_priv, pm->machine_priv, 32);
    memcpy(ks.machine_pub,  pm->machine_pub,  32);
    memcpy(ks.node_priv,    pm->node_priv,    32);
    memcpy(ks.node_pub,     pm->node_pub,     32);
    memcpy(ks.disco_priv,   pm->disco_priv,   32);
    memcpy(ks.disco_pub,    pm->disco_pub,    32);
    ks.crc32 = ks_crc32((const uint8_t *)&ks, offsetof(ts_key_store_t, crc32));

    device_mutex_lock(RT_DEV_LOCK_FLASH);
    flash_erase_sector(&flash, TS_KEY_STORE_ADDR);
    flash_stream_write(&flash, TS_KEY_STORE_ADDR, sizeof(ks), (uint8_t *)&ks);
    device_mutex_unlock(RT_DEV_LOCK_FLASH);

    KS_LOG("Keys saved to flash (%u bytes, CRC=0x%08x)",
           (unsigned)sizeof(ks), (unsigned)ks.crc32);
    return 0;
}

int ts_key_store_erase(void)
{
    flash_t flash;

    device_mutex_lock(RT_DEV_LOCK_FLASH);
    flash_erase_sector(&flash, TS_KEY_STORE_ADDR);
    device_mutex_unlock(RT_DEV_LOCK_FLASH);

    KS_LOG("Key store erased");
    return 0;
}
