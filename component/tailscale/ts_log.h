/*
 * ts_log.h — Tailscale debug log control
 *
 * TS_DEBUG=0 : Production (quiet — errors + state changes only)
 * TS_DEBUG=1 : Verbose (per-packet logs for debugging)
 */

#ifndef TS_LOG_H
#define TS_LOG_H

#include <stdio.h>

/* Set to 1 for verbose per-packet debug output */
#define TS_DEBUG 0

#if TS_DEBUG
#define TS_DBG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define TS_DBG(fmt, ...) ((void)0)
#endif

#endif /* TS_LOG_H */
