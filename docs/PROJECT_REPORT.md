# AMB82-MINI Tailscale Client — 專案報告

## 專案概述

本專案在 Realtek AMB82-MINI（RTL8735B）微控制器上實作了完整的 **Tailscale VPN 客戶端**，使嵌入式裝置能加入 Tailscale 網路（tailnet），與任何 Tailscale 節點進行端對端加密通訊。

這是目前已知第二個在微控制器上實作 Tailscale 協議的專案（第一個是 ESP32 平台的 [tailscale-iot](https://github.com/alfs/tailscale-iot)），也是首個在 **Realtek ARM Cortex-M33** 平台上的實作。

### 硬體規格

| 項目 | 規格 |
|------|------|
| **MCU** | Realtek RTL8735B (ARM Cortex-M33, TrustZone) |
| **開發板** | AMB82-MINI |
| **RAM** | ~512KB SRAM + PSRAM |
| **Flash** | 16MB (Nor Flash) |
| **WiFi** | 802.11 b/g/n (2.4GHz) |
| **RTOS** | FreeRTOS v10.2.0 |
| **SDK** | ameba-rtos-pro2 (Realtek ASDK) |
| **Toolchain** | arm-none-eabi-gcc 10.3.0 |

### 韌體大小

| 檔案 | 大小 | 用途 |
|------|------|------|
| `firmware_ntz.bin` | 2.87 MB | OTA 更新韌體 |
| `flash_ntz.bin` | 4.73 MB | USB 完整燒錄（含 bootloader） |
| `libtailscale.a` | 336 KB | Tailscale 靜態函式庫 |
| `libwireguard.a` | 252 KB | WireGuard 靜態函式庫 |

---

## 功能特性

### 已實作

- **Tailscale 控制平面**：連線官方 controlplane.tailscale.com，Noise_IK 握手 + HTTP/2 通訊
- **註冊與認證**：Pre-auth key 自動註冊，無需人工操作
- **WireGuard 隧道**：完整 WireGuard 協議（握手、加密傳輸、keepalive）
- **DERP 中繼**：透過 Tailscale DERP relay 伺服器進行 NAT 穿透（RTT ~125ms via HKG）
- **LAN 直連**：同一區域網路時自動發現並建立直連（RTT < 10ms）
- **DISCO 協議**：NAT 穿透端點發現（Ping/Pong/CallMeMaybe）
- **STUN**：RFC 8489 Binding Request 發現公網 IP
- **動態路徑選擇**：bestAddr 演算法自動選擇最佳路徑（direct 優先，DERP fallback）
- **DERP 自動重連**：斷線偵測 + 指數退避重連（5s → 10s → 20s → 30s）
- **控制連線重連**：控制平面斷線時自動重連
- **Multi-peer 支援**：最多 4 個 Tailscale peer 同時連線
- **WiFi OTA 更新**：HTTP OTA 伺服器，支援遠端韌體更新
- **OTA 保護機制**：Heap 監控 + 重連次數限制，確保 OTA 永遠可用
- **條件編譯 Log**：TS_DEBUG 開關控制日誌詳細程度

### 效能指標

| 指標 | 數值 |
|------|------|
| **DERP relay RTT** | ~125ms (via HKG DERP server) |
| **LAN 直連 RTT** | < 10ms |
| **路徑切換時間** | ~5 秒（DERP → direct） |
| **OTA 更新速度** | ~80 KB/s（WiFi, 2.87MB / ~36秒） |
| **Heap 使用** | ~110 MB free（啟動後穩定） |
| **WG Handshake** | < 2 秒 |

---

## 架構設計

### 協議棧

```
┌─────────────────────────────────────────────┐
│              Application Layer              │
│         ts_main.c (狀態機 + 協調)            │
├──────────┬──────────┬───────────┬───────────┤
│ Control  │   DERP   │   DISCO   │    OTA    │
│  Plane   │  Relay   │  NAT穿透   │  Server   │
├──────────┼──────────┼───────────┤           │
│ctrl_client│ ts_derp  │ ts_disco  │ota_server │
│ ts_http2 │          │ ts_nacl   │           │
├──────────┴──────────┴───────────┤           │
│          WireGuard Tunnel       │           │
│   wireguard + wireguardif       │           │
├─────────────────────────────────┤           │
│        Crypto Layer             │           │
│  ts_crypto (Noise_IK)          │           │
│  ts_nacl (NaCl box)            │           │
│  chacha20poly1305 / x25519     │           │
│  blake2s                       │           │
├─────────────────────────────────┼───────────┤
│         Key Storage             │           │
│      ts_key_store (Flash)       │           │
├─────────────────────────────────┴───────────┤
│              Network Layer                  │
│        lwIP + mbedTLS + FreeRTOS            │
├─────────────────────────────────────────────┤
│              Hardware Layer                 │
│     RTL8735B WiFi + UART + Flash            │
└─────────────────────────────────────────────┘
```

### 連線流程

```
WiFi 連線 (DHCP)
     │
SNTP 時間同步
     │
Flash 讀取/生成金鑰 (Machine/Node/Disco)
     │
TLS 連線 controlplane.tailscale.com:443
     │
GET /key → 取得伺服器公鑰
     │
WebSocket Upgrade + Noise_IK 握手
     │
HTTP/2 SETTINGS 交換
     │
POST /machine/register (Pre-auth key 認證)
     │
POST /machine/map (Stream=true, 持久連線)
     │
解析 MapResponse → 取得自己的 IP、Peers、DERPMap
     │
WireGuard 初始化 (Tailscale IP, multi-peer)
     │
DERP 連線 (TLS + HTTP upgrade + NaCl 握手)
     │
DISCO/STUN 啟動 (端點發現)
     │
┌─────────────────────────┐
│    正常運行迴圈          │
│  • map_poll 監聽更新      │
│  • DERP 收發封包          │
│  • DISCO ping/pong       │
│  • bestAddr 路徑選擇      │
│  • OTA server 持續運行    │
└─────────────────────────┘
```

### 模組依賴關係

```
ts_main.c ─────────┬── ctrl_client ──┬── ts_crypto (Noise_IK)
  (狀態機)          │    (控制平面)     │── ts_http2 (HTTP/2)
                   │                 └── mbedTLS (TLS)
                   │
                   ├── peer_manager ─┬── ts_crypto (金鑰)
                   │   (節點管理)      │── cJSON (JSON)
                   │                 └── ameba_wireguard (WG)
                   │
                   ├── ts_derp ──────┬── ts_nacl (NaCl box)
                   │   (DERP relay)   │── ts_crypto (金鑰)
                   │                 └── mbedTLS (TLS)
                   │
                   ├── ts_disco ─────┬── ts_nacl (NaCl box)
                   │   (NAT穿透)      │── peer_manager
                   │                 └── ts_derp (DERP送)
                   │
                   └── ota_server
                       (OTA更新)
```

---

## 原始碼結構

### 程式碼統計

| 元件 | 檔案數 | 行數 | 說明 |
|------|--------|------|------|
| **Tailscale 客戶端** | 17 | 6,131 | 控制平面、DERP、DISCO、加密 |
| **WireGuard 隧道** | 21 | 4,744 | VPN 核心協議 + 密碼學 |
| **主程式 (ts_main)** | 1 | 906 | 狀態機 + 初始化 |
| **OTA 伺服器** | 2 | 403 | HTTP OTA 更新 |
| **合計** | **41** | **12,184** | |

### 檔案清單

```
component/tailscale/                    # Tailscale VPN 客戶端元件
├── ts_crypto.c/h       (395+189 行)    Stage A: Noise_IK 加密
├── ctrl_client.c/h     (957+201 行)    Stage B: 控制平面客戶端
├── ts_http2.c/h        (779+159 行)    Stage C: HTTP/2 幀處理
├── peer_manager.c/h    (882+235 行)    Stage D: 節點管理 + WG 整合
├── ts_nacl.c/h         (318+61 行)     Stage E: NaCl box 加密
├── ts_disco.c/h        (739+222 行)    Stage E: DISCO/STUN 穿透
├── ts_derp.c/h         (678+111 行)    Stage G: DERP relay 客戶端
├── ts_key_store.c/h    (142+41 行)     金鑰 Flash 持久化
└── ts_log.h            (22 行)         條件編譯日誌

component/wireguard/                    # WireGuard VPN 核心
├── wireguard.c/h       (1120+284 行)   WireGuard 核心協議
├── wireguardif.c/h     (1015+143 行)   lwIP 網路介面
├── ameba_wireguard.c/h (199+114 行)    AMB82 平台適配層
├── wireguard-platform.c/h (124+70 行)  平台相依實作
├── crypto.c/h          (23+105 行)     加密包裝層
└── crypto/refc/                        純 C 密碼學實作
    ├── x25519.c/h          (448+129)   Curve25519 金鑰交換
    ├── chacha20.c/h        (202+53)    ChaCha20 串流密碼
    ├── chacha20poly1305.c/h (193+50)   AEAD 認証加密
    ├── blake2s.c/h         (156+39)    BLAKE2s 雜湊
    └── poly1305-donna.c/h  (41+236)    Poly1305 認証碼

project/.../src/tailscale_main/
└── ts_main.c           (906 行)        主狀態機

project/.../src/ota_server/
├── ota_server.c        (396 行)        WiFi OTA HTTP 伺服器
└── ota_server.h        (7 行)

project/.../GCC-RELEASE/application/
├── libtailscale.cmake                  Tailscale 建置配置
├── libwireguard.cmake                  WireGuard 建置配置
└── application.cmake                   主應用建置（含庫鏈接）
```

---

## 關鍵技術實作

### 1. Noise_IK 握手（ts_crypto）

Tailscale 使用 `Noise_IK_25519_ChaChaPoly_BLAKE2s` 作為控制平面加密協議。

**關鍵差異**：
- Go 的 `crypto/chacha20poly1305` 使用 **Big-Endian** nonce（與標準 Noise / WireGuard 的 Little-Endian 不同）
- Prologue: `"Tailscale Control Protocol v1"` (29 bytes)
- Machine Key 作為 Noise static key（不是 Node Key）

**金鑰體系**（3 組 Curve25519）：

| 金鑰 | 用途 | 格式 |
|------|------|------|
| Machine Key | 控制面 Noise 握手身份 | `mkey:HEX` |
| Node Key | = WireGuard key，資料面加密 | `nodekey:HEX` |
| Disco Key | DISCO NAT 穿透協議 | `discokey:HEX` |

### 2. 控制平面通訊（ctrl_client + ts_http2）

```
TLS 1.2 → WebSocket → Controlbase 幀 → Noise_IK → HTTP/2 → JSON
```

- TS_CAP_VERSION = 49（與 ESP32 相同，Version < 68 讓 server 處理所有欄位）
- MapRequest: Stream=true, 單一長連線接收更新
- MapResponse: JSON 格式（~30KB，含 DERPMap）

### 3. DERP Relay（ts_derp）

DERP（Designated Encrypted Relay for Packets）是 Tailscale 的 NAT 穿透中繼。

- **虛擬地址**：`127.3.PEER_IDX.40:REGION_ID`（Go 的 DerpMagicIPAddr）
- **WG output hook**：攔截虛擬地址封包 → DERP SendPacket
- **WG 注入**：DERP RecvPacket → pbuf → `wireguardif_network_rx()`
- **線程安全**：FreeRTOS queue（深度 8）序列化 TLS I/O

### 4. DISCO NAT 穿透（ts_disco + ts_nacl）

- **加密**：NaCl box (X25519 + XSalsa20-Poly1305)
- **魔數**：`TS💬` (6 bytes)
- **訊息類型**：Ping (0x01), Pong (0x02), CallMeMaybe (0x03)
- **雙路徑發送**：同時經直接 UDP 和 DERP relay 發送
- **CallMeMaybe**：解析 18B/endpoint 格式，觸發 DISCO ping 到所有 endpoint

### 5. bestAddr 路徑選擇（peer_manager）

```
評分 = latency_ms - (private_IP ? 20 : 0)
```

- 每個 peer 最多 8 個 endpoint
- Pong 回應觸發 latency 更新
- 最低評分的 endpoint 成為 bestAddr
- 信任窗口 120 秒，過期自動 fallback 到 DERP
- 重新觸發 DISCO ping 探測

### 6. WireGuard 整合（wireguard + ameba_wireguard）

- 移植自 [wireguard-lwip](https://github.com/smartalock/wireguard-lwip)
- **新增功能**：
  - `wireguardif_fini()` — 完整資源清理（UDP/timer/device）
  - `wireguardif_set_output_hook()` — DERP 輸出攔截
  - `wireguardif_network_rx()` — DERP 封包注入
  - Multi-peer 支援（最多 8 個 peer）
  - 動態 endpoint 更新
- **修正**：`allowed_ip` 檢查改為 `iphdr->src`（WG 規範）

### 7. OTA 保護機制

```c
// Heap 安全閥：< 50KB 時跳過重連
if (free_heap < 50000) {
    TS_ERR("Low heap, skipping reconnect to protect OTA");
    vTaskDelay(60s);
    continue;
}

// 連續失敗 5 次 → OTA-only 模式
if (reconnect_failures >= 5) {
    TS_ERR("Too many failures, entering OTA-only mode");
    while (1) { vTaskDelay(300s); }
}
```

---

## 與參考實作的比較

### 三方比對：AMB82 vs ESP32 vs Go

| 功能 | Go (官方) | ESP32 (tailscale-iot) | AMB82 (本專案) |
|------|-----------|----------------------|----------------|
| **語言** | Go | C++ | C |
| **RTOS** | goroutine | ESP-IDF / FreeRTOS | FreeRTOS |
| **WireGuard** | 自有實作 | 無（DERP-only） | wireguard-lwip 移植 |
| **DERP** | 完整 | 完整 | 完整 |
| **DISCO** | 雙路徑 | 直接 UDP only | 雙路徑（UDP + DERP） |
| **CallMeMaybe** | 完整 + 回應 | 不支援 | 解析 + ping（不回應） |
| **直連** | bestAddr 複雜評分 | 二元（direct/DERP） | 簡化 bestAddr + 信任窗口 |
| **DERP 重連** | lazy reconnect | 狀態機 | recv task 指數退避 |
| **控制協議** | Protobuf（v68+）| JSON | JSON |
| **Cap Version** | 133 | 49 | 49 |
| **TLS 線程** | goroutine | 單線程 | 單線程 + queue |

### 有意的簡化

| 簡化項目 | 原因 |
|----------|------|
| 不回應 CallMeMaybe | 嵌入式不主動觸發直連邀請，由對端發起 |
| 不做 MTU 探測 | 嵌入式 MTU 固定 1280 |
| 不做 IPv6 | 目標環境只需 IPv4 |
| Version 49 | 避免 v68+ 的 Protobuf 需求 |
| 不做 connGen | FreeRTOS task 模型不需追蹤連線版本 |

---

## 開發歷程

### Phase 1：WireGuard 移植

將 [wireguard-lwip](https://github.com/smartalock/wireguard-lwip) 和 [esp_wireguard](https://github.com/trombik/esp_wireguard) 移植到 AMB82 平台。

**主要挑戰**：
- FreeRTOS portable include 路徑差異
- `sys/time.h` 不可用，改用 `FreeRTOS_POSIX/time.h`
- SDK SNTP API 差異
- 驗證：MBP ↔ AMB82 雙向 ping 成功

### Phase 2：Headscale PoC

使用自建 Headscale 伺服器驗證控制協議實作。

### Phase 3A：Tailscale 控制平面

連線官方 controlplane.tailscale.com，完成 Noise 握手、HTTP/2 通訊、Register、Map。

**已解決的關鍵 Bug**：
- MapResponse buffer 8KB→48KB（DERPMap 約 30KB）
- HTTP/2 PING ACK 缺失
- LE length prefix 精確 JSON 分界
- Version 90→49（避免 GOAWAY）
- lwIP socket 不足（NETCONN 8→16）
- mbedTLS BIO recv timeout 修正

### Phase 3B：DERP Relay

實作 DERP 中繼通訊，ping 首次通過。

**關鍵突破**：
- WG output hook 攔截虛擬 DERP 地址封包
- DERP recv → pbuf → WG network_rx 注入
- `allowed_ip` 檢查方向修正（src vs dest）
- 結果：`ping 100.127.232.33` 成功（5/5, ~125ms via DERP HKG）

### Phase 3C：穩定性與直連

完整的穩定性改進和 LAN 直連支援。

| Task | 內容 | 狀態 |
|------|------|------|
| 0 | OTA 保護（Heap 監控 + 重連限制） | ✓ |
| 1 | WG 資源清理（wireguardif_fini） | ✓ |
| 2 | DISCO 雙路徑（UDP + DERP） | ✓ |
| 3 | CallMeMaybe 處理 | ✓ |
| 4 | 直連 + bestAddr | ✓ |
| 5 | DERP 重連（指數退避） | ✓ |
| 6 | Debug Log 清理 | ✓ |

---

## 建置與部署

### 前置需求

- Realtek ASDK Toolchain 10.3.0
- CMake 3.x
- macOS / Linux

### 建置

```bash
export PATH="/opt/homebrew/bin:/tmp/asdk-10.3.0/darwin/newlib/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
cd project/realtek_amebapro2_v0_example/GCC-RELEASE/build
cmake --build .                  # 產生 firmware_ntz.bin（OTA 用）
cmake --build . --target flash   # 產生 flash_ntz.bin（USB 燒錄用）
```

### 部署

**USB 首次燒錄**（按 BOOT+RESET 進入下載模式）：
```bash
uartfwburn.arm.darwin -p /dev/cu.wchusbserial120 -f build/flash_ntz.bin -b 2000000 -U -x 32 -r
```

**OTA 遠端更新**（之後的更新）：
```bash
curl -X POST --data-binary @build/application/firmware_ntz.bin http://192.168.3.112:8080/ota
```

### 配置

修改 `ts_main.c` 中的常數：
```c
#define WIFI_SSID       "YourSSID"
#define WIFI_PASSWORD   "YourPassword"
#define TS_AUTH_KEY     "tskey-auth-..."    // Tailscale pre-auth key
#define TS_CONTROL_HOST "controlplane.tailscale.com"
```

---

## 已知限制

1. **WiFi only**：不支援 Ethernet（硬體限制）
2. **IPv4 only**：不支援 IPv6 DISCO/endpoint
3. **最多 4 peers**：受記憶體限制
4. **不主動發送 CallMeMaybe**：依賴對端發起直連
5. **金鑰未加密存儲**：Flash 中的金鑰為明文
6. **單一 DERP 連線**：只連到自己的 PreferredDERP（目前硬編碼 region 20 = HKG）

---

## 未來方向

- **PreferredDERP 自動選擇**：從 MapResponse 的 Node.DERP 取得
- **MagicDNS**：解析 Tailscale 域名
- **ACL 整合**：根據 Tailscale ACL 控制存取
- **Taildrop**：檔案傳輸
- **金鑰加密存儲**：使用 TrustZone 保護金鑰
- **低功耗模式**：WiFi sleep + WG keepalive 最佳化

---

## 授權與致謝

### 參考專案

| 專案 | 授權 | 用途 |
|------|------|------|
| [ameba-rtos-pro2](https://github.com/Ameba-AIoT/ameba-rtos-pro2) | Apache-2.0 | 基礎 SDK |
| [wireguard-lwip](https://github.com/smartalock/wireguard-lwip) | BSD-3 | WireGuard 核心 |
| [esp_wireguard](https://github.com/trombik/esp_wireguard) | MIT | WireGuard 平台層參考 |
| [tailscale-iot](https://github.com/alfs/tailscale-iot) | MIT | ESP32 Tailscale 參考實作 |
| [tailscale](https://github.com/tailscale/tailscale) | BSD-3 | 官方 Go 原始碼（協議真相來源） |

---

*報告產生日期：2026-03-06*
