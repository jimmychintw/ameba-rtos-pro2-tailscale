/*
 * ts_key_store.h — Tailscale key persistence (NOR flash)
 *
 * Stores machine/node/disco key pairs to flash so the device
 * keeps the same Tailscale identity across reboots.
 */

#ifndef TS_KEY_STORE_H
#define TS_KEY_STORE_H

#include "peer_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Load keys from flash into peer_manager.
 * @return 0 on success, -1 if no valid data (first boot or corrupted)
 */
int ts_key_store_load(peer_manager_t *pm);

/*
 * Save current keys from peer_manager to flash.
 * Erases the sector first, then writes.
 * @return 0 on success, -1 on failure
 */
int ts_key_store_save(peer_manager_t *pm);

/*
 * Erase key store (factory reset).
 * Next boot will generate fresh keys.
 * @return 0 on success, -1 on failure
 */
int ts_key_store_erase(void);

#ifdef __cplusplus
}
#endif

#endif /* TS_KEY_STORE_H */
