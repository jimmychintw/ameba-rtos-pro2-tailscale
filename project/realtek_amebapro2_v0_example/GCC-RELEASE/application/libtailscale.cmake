cmake_minimum_required(VERSION 3.6)
project(tailscale)

include(../includepath.cmake)

set(tailscale tailscale)

list(APPEND tailscale_sources
	# Stage A: Noise_IK crypto layer
	${sdk_root}/component/tailscale/ts_crypto.c

	# Stage B: Control plane client (WebSocket + Noise handshake)
	${sdk_root}/component/tailscale/ctrl_client.c

	# Stage C: HTTP/2 framing + Register/Map
	${sdk_root}/component/tailscale/ts_http2.c

	# Stage D: Peer management + WireGuard integration
	${sdk_root}/component/tailscale/peer_manager.c

	# Stage E: NaCl box crypto + DISCO/STUN
	${sdk_root}/component/tailscale/ts_nacl.c
	${sdk_root}/component/tailscale/ts_disco.c

	# Stage F: DERP relay client
	${sdk_root}/component/tailscale/ts_derp.c

	# Key persistence (flash storage)
	${sdk_root}/component/tailscale/ts_key_store.c
)

add_library(${tailscale} STATIC ${tailscale_sources})

list(APPEND tailscale_flags
	CONFIG_BUILD_RAM=1
	CONFIG_BUILD_LIB=1
	CONFIG_PLATFORM_8735B
)

target_compile_definitions(${tailscale} PRIVATE ${tailscale_flags})

target_include_directories(
	${tailscale} PUBLIC
	${inc_path}
	${sdk_root}/component/os/freertos/${freertos}/Source/portable/GCC/ARM_CM33/non_secure
	${sdk_root}/component/os/freertos/${freertos}/Source/portable/GCC/ARM_CM33/secure
	${sdk_root}/component/tailscale
	${sdk_root}/component/wireguard
	${sdk_root}/component/wireguard/crypto/refc
	${sdk_root}/component/mbed/hal
)
