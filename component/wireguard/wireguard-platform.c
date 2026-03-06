/*
 * WireGuard platform implementation for AMB82-MINI (RTL8735B)
 *
 * Provides the 5 platform functions required by wireguard-lwip:
 *   - wireguard_platform_init()
 *   - wireguard_sys_now()
 *   - wireguard_random_bytes()
 *   - wireguard_tai64n_now()
 *   - wireguard_is_under_load()
 */

#include "wireguard-platform.h"

#include <stdlib.h>
#include <string.h>

#include "FreeRTOS_POSIX/time.h"
#include "lwip/sys.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "basic_types.h"
#include "trng_api.h"

#include "crypto.h"

#define TAG "wireguard"
#define ENTROPY_MINIMUM_REQUIRED_THRESHOLD (134)

static mbedtls_ctr_drbg_context random_context;
static mbedtls_entropy_context entropy_context;
static int platform_initialized = 0;

/* Hardware TRNG entropy source for mbedTLS */
static int entropy_hw_random_source(void *data, unsigned char *output, size_t len, size_t *olen)
{
	(void)data;
	size_t i;
	uint32_t rand_val;

	for (i = 0; i + 4 <= len; i += 4) {
		rand_val = trng_get_rand();
		memcpy(output + i, &rand_val, 4);
	}
	if (i < len) {
		rand_val = trng_get_rand();
		memcpy(output + i, &rand_val, len - i);
	}
	*olen = len;
	return 0;
}

int wireguard_platform_init(void)
{
	int ret;

	if (platform_initialized) {
		return 0;
	}

	/* Initialize hardware TRNG */
	trng_init();

	/* Setup mbedTLS CSPRNG: HW TRNG -> Entropy Pool -> CTR_DRBG */
	mbedtls_entropy_init(&entropy_context);
	mbedtls_ctr_drbg_init(&random_context);

	ret = mbedtls_entropy_add_source(
		&entropy_context,
		entropy_hw_random_source,
		NULL,
		ENTROPY_MINIMUM_REQUIRED_THRESHOLD,
		MBEDTLS_ENTROPY_SOURCE_STRONG);
	if (ret != 0) {
		return -1;
	}

	ret = mbedtls_ctr_drbg_seed(
		&random_context,
		mbedtls_entropy_func,
		&entropy_context,
		NULL,
		0);
	if (ret != 0) {
		return -1;
	}

	platform_initialized = 1;
	return 0;
}

void wireguard_random_bytes(void *bytes, size_t size)
{
	mbedtls_ctr_drbg_random(&random_context, bytes, size);
}

uint32_t wireguard_sys_now(void)
{
	return sys_now();
}

void wireguard_tai64n_now(uint8_t *output)
{
	/*
	 * TAI64N format: 12 bytes
	 *   - 8 bytes: seconds since epoch + TAI offset (0x400000000000000a)
	 *   - 4 bytes: nanoseconds within current second
	 *
	 * Requires SNTP to be initialized for accurate wall-clock time.
	 * If SNTP is not running, gettimeofday() falls back to
	 * FreeRTOS tick count + CFG_RTC_DEFAULT_TIMESTAMP.
	 */
	struct timeval tv;
	gettimeofday(&tv, NULL);

	uint64_t seconds = 0x400000000000000aULL + (uint64_t)tv.tv_sec;
	uint32_t nanos = (uint32_t)tv.tv_usec * 1000;
	U64TO8_BIG(output + 0, seconds);
	U32TO8_BIG(output + 8, nanos);
}

bool wireguard_is_under_load(void)
{
	return false;
}
