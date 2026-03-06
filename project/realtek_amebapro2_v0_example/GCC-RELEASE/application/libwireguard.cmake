cmake_minimum_required(VERSION 3.6)
project(wireguard)

include(../includepath.cmake)

set(wireguard wireguard)

list(APPEND wireguard_sources
	# Core WireGuard protocol (from wireguard-lwip, unmodified)
	${sdk_root}/component/wireguard/wireguard.c
	${sdk_root}/component/wireguard/wireguardif.c
	${sdk_root}/component/wireguard/crypto.c

	# Crypto implementations (pure C, self-contained)
	${sdk_root}/component/wireguard/crypto/refc/blake2s.c
	${sdk_root}/component/wireguard/crypto/refc/chacha20.c
	${sdk_root}/component/wireguard/crypto/refc/chacha20poly1305.c
	${sdk_root}/component/wireguard/crypto/refc/poly1305-donna.c
	${sdk_root}/component/wireguard/crypto/refc/x25519.c

	# AMB82 platform layer
	${sdk_root}/component/wireguard/wireguard-platform.c
	${sdk_root}/component/wireguard/ameba_wireguard.c
)

add_library(${wireguard} STATIC ${wireguard_sources})

list(APPEND wireguard_flags
	CONFIG_BUILD_RAM=1
	CONFIG_BUILD_LIB=1
	CONFIG_PLATFORM_8735B
)

target_compile_definitions(${wireguard} PRIVATE ${wireguard_flags})

target_include_directories(
	${wireguard} PUBLIC
	${inc_path}
	${sdk_root}/component/os/freertos/${freertos}/Source/portable/GCC/ARM_CM33/non_secure
	${sdk_root}/component/os/freertos/${freertos}/Source/portable/GCC/ARM_CM33/secure
	${sdk_root}/component/wireguard
	${sdk_root}/component/wireguard/crypto/refc
	${sdk_root}/component/mbed/hal
)
