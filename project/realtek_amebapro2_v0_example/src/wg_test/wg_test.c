/*
 * WireGuard Test Application for AMB82-MINI
 *
 * Flow: WiFi connect -> DHCP -> SNTP time sync -> WireGuard init -> Connect -> Verify
 *
 * Build: cmake -DEXAMPLE=OFF .. && make
 *   (this file is added via scenario.cmake)
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

#include "ameba_wireguard.h"

/* ------------------------------------------------------------------ */
/*  Configuration — edit these for your setup                         */
/* ------------------------------------------------------------------ */

/* WiFi */
#define WIFI_SSID          "YOUR_WIFI_SSID"
#define WIFI_PASSWORD      "YOUR_WIFI_PASSWORD"

/* WireGuard local (AMB82) */
#define WG_PRIVATE_KEY     "YOUR_WG_PRIVATE_KEY_BASE64"
#define WG_LOCAL_IP        "10.0.0.2"
#define WG_LOCAL_NETMASK   "255.255.255.0"
#define WG_LOCAL_GATEWAY   "10.0.0.2"
#define WG_LISTEN_PORT     51820

/* WireGuard peer (MBP) */
#define WG_PEER_PUBKEY     "YOUR_WG_PEER_PUBLIC_KEY_BASE64"
#define WG_PEER_ENDPOINT   "192.168.3.105"
#define WG_PEER_PORT       51820
#define WG_KEEPALIVE       25

/* ------------------------------------------------------------------ */

#define WG_TASK_STACK      4096
#define WG_TASK_PRIO       (tskIDLE_PRIORITY + 2)

extern struct netif xnetif[];

static ameba_wg_ctx_t wg_ctx;

static int wifi_do_connect(void)
{
	rtw_network_info_t connect_param = {0};

	printf("[WG_TEST] Connecting to WiFi '%s'...\r\n", WIFI_SSID);

	memcpy(connect_param.ssid.val, WIFI_SSID, strlen(WIFI_SSID));
	connect_param.ssid.len = strlen(WIFI_SSID);
	connect_param.password = (unsigned char *)WIFI_PASSWORD;
	connect_param.password_len = strlen(WIFI_PASSWORD);
	connect_param.security_type = RTW_SECURITY_WPA2_AES_PSK;

	if (wifi_connect(&connect_param, 1) != RTW_SUCCESS) {
		printf("[WG_TEST] wifi_connect failed!\r\n");
		return -1;
	}
	printf("[WG_TEST] WiFi associated, starting DHCP...\r\n");
	LwIP_DHCP(0, DHCP_START);

	/* Wait for IP */
	for (int i = 0; i < 20; i++) {
		if (*(u32 *)LwIP_GetIP(0) != IP_ADDR_INVALID) {
			uint8_t *ip = LwIP_GetIP(0);
			printf("[WG_TEST] WiFi connected! IP: %d.%d.%d.%d\r\n",
			       ip[0], ip[1], ip[2], ip[3]);
			return 0;
		}
		vTaskDelay(pdMS_TO_TICKS(500));
	}
	printf("[WG_TEST] DHCP timeout!\r\n");
	return -1;
}

static void sntp_wait_sync(uint32_t timeout_ms)
{
	uint32_t waited = 0;
	time_t now;

	printf("[WG_TEST] Starting SNTP time sync (pool.ntp.org)...\r\n");
	sntp_init();

	/* Wait until time is set (year > 2024) */
	while (waited < timeout_ms) {
		now = time(NULL);
		if (now > 1704067200) { /* 2024-01-01 00:00:00 UTC */
			struct tm *t = localtime(&now);
			printf("[WG_TEST] Time synced: %04d-%02d-%02d %02d:%02d:%02d UTC\r\n",
			       t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
			       t->tm_hour, t->tm_min, t->tm_sec);
			return;
		}
		vTaskDelay(pdMS_TO_TICKS(1000));
		waited += 1000;
	}
	printf("[WG_TEST] SNTP sync timeout — continuing with fallback time\r\n");
}

static void wg_test_task(void *param)
{
	(void)param;
	int ret;

	printf("\r\n========================================\r\n");
	printf("   WireGuard Test for AMB82-MINI\r\n");
	printf("========================================\r\n\r\n");

	/* --- Step 1: Connect WiFi --- */
	vTaskDelay(pdMS_TO_TICKS(5000)); /* Wait for WiFi driver init */
	if (wifi_do_connect() != 0) {
		printf("[WG_TEST] FAILED: no WiFi\r\n");
		goto done;
	}

	/* --- Step 2: SNTP time sync --- */
	sntp_wait_sync(15000);

	/* --- Step 3: Configure WireGuard --- */
	printf("[WG_TEST] Configuring WireGuard tunnel...\r\n");

	ameba_wg_config_t config;
	memset(&config, 0, sizeof(config));

	config.private_key = WG_PRIVATE_KEY;
	config.listen_port = WG_LISTEN_PORT;

	IP_ADDR4(&config.ip,       10, 0, 0, 2);
	IP_ADDR4(&config.netmask, 255, 255, 255, 0);
	IP_ADDR4(&config.gateway,  10, 0, 0, 2);

	config.peer_public_key     = WG_PEER_PUBKEY;
	config.preshared_key       = NULL;
	config.endpoint            = WG_PEER_ENDPOINT;
	config.endpoint_port       = WG_PEER_PORT;
	config.persistent_keepalive = WG_KEEPALIVE;

	/* AllowedIPs = 0.0.0.0/0 (route everything) */
	IP_ADDR4(&config.allowed_ip,   0, 0, 0, 0);
	IP_ADDR4(&config.allowed_mask, 0, 0, 0, 0);

	/* --- Step 4: Init WireGuard --- */
	printf("[WG_TEST] Initializing WireGuard...\r\n");
	ret = ameba_wg_init(&config, &wg_ctx);
	if (ret != AMEBA_WG_OK) {
		printf("[WG_TEST] FAILED: ameba_wg_init returned %d\r\n", ret);
		goto done;
	}
	printf("[WG_TEST] WireGuard interface created (wg tunnel IP: %s)\r\n", WG_LOCAL_IP);

	/* --- Step 5: Connect (initiate handshake) --- */
	printf("[WG_TEST] Connecting to peer %s:%d ...\r\n", WG_PEER_ENDPOINT, WG_PEER_PORT);
	ret = ameba_wg_connect(&wg_ctx);
	if (ret != AMEBA_WG_OK) {
		printf("[WG_TEST] FAILED: ameba_wg_connect returned %d\r\n", ret);
		goto cleanup;
	}

	/* --- Step 6: Wait for handshake --- */
	printf("[WG_TEST] Waiting for handshake...\r\n");
	for (int i = 0; i < 30; i++) {
		if (ameba_wg_is_up(&wg_ctx)) {
			printf("[WG_TEST] *** TUNNEL IS UP! ***\r\n");
			break;
		}
		vTaskDelay(pdMS_TO_TICKS(1000));
		if (i == 29) {
			printf("[WG_TEST] Handshake timeout (30s)\r\n");
			goto cleanup;
		}
	}

	/* --- Step 7: Set as default route --- */
	ameba_wg_set_default(&wg_ctx);
	printf("[WG_TEST] WireGuard set as default route\r\n");

	/* --- Step 8: Monitor tunnel --- */
	printf("[WG_TEST] Tunnel active. Monitoring...\r\n");
	printf("[WG_TEST] Try from MBP: ping 10.0.0.2\r\n\r\n");

	while (1) {
		bool up = ameba_wg_is_up(&wg_ctx);
		printf("[WG_TEST] Tunnel %s | Free heap: %u bytes\r\n",
		       up ? "UP" : "DOWN",
		       (unsigned)xPortGetFreeHeapSize());
		vTaskDelay(pdMS_TO_TICKS(10000));
	}

cleanup:
	ameba_wg_disconnect(&wg_ctx);
	printf("[WG_TEST] WireGuard disconnected\r\n");
done:
	printf("[WG_TEST] Task exiting\r\n");
	vTaskDelete(NULL);
}

void app_example(void)
{
	if (xTaskCreate(wg_test_task,
	                "wg_test",
	                WG_TASK_STACK,
	                NULL,
	                WG_TASK_PRIO,
	                NULL) != pdPASS) {
		printf("[WG_TEST] Failed to create task!\r\n");
	}
}
