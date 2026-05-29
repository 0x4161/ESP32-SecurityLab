# REAPER — Wireless Offensive Toolkit

A pocket-sized wireless attack platform running on an ESP32-WROOM-32 with a 0.96" OLED. Every operation is controlled from the device itself (single BOOT button + on-screen menu). The web surface is a public landing page only — no remote control endpoints.

> **For authorized security research, hardware education, and CTF/lab use only.** Using this against any network or device you do not own or have written permission to test is illegal and not endorsed by the author.

## Arsenal

### Wi-Fi (2.4 GHz)
- **Scan** — full band enumeration: SSID / BSSID / RSSI / channel / encryption
- **Deauth / Disassoc** — raw 802.11 frame injection (`0xC0` / `0xA0`) on the target's channel
- **Multi-target deauth** — rotates through every AP marked on the scan list
- **PSK Brute-Force** — iterates a 5,000-password built-in wordlist (`/wordlist.txt`) via `WiFi.begin()`; ~3–4 s per password
- **Beacon Flood** — broadcasts thousands of sequentially numbered phantom SSIDs (`#VOID TEST 1 .. N`)
- **Probe Sniffer** — captures probe requests (MAC + remembered SSID + RSSI)
- **EAPOL Sniffer** — captures WPA 4-way handshake frames (EtherType `0x888E`) for offline cracking
- **Evil Twin** — clones a target SSID as an open AP on the same channel

### Bluetooth LE
- **Scan** — BLE advertising scanner with name / RSSI / address
- **BLE Spam** — Apple Continuity / Microsoft Swift Pair / Samsung Easy Setup payloads, cycled

## Control surface

The entire device is driven by a single button (BOOT, GPIO0) and the OLED.

| Action | Meaning |
|--------|---------|
| Short press | Move cursor / cycle selector |
| Long press  | Enter screen / start operation / commit |

Web surface is `http://192.168.4.1/` — a static landing page describing the project and linking to author socials. There are **no operational HTTP endpoints**.

## Hardware

- ESP32-WROOM-32 dev board
- SSD1306 0.96″ I²C OLED (auto-detected on SDA=21 SCL=22 or alt pins)
- BOOT button on GPIO0 (already on most dev boards)
- USB-to-serial cable for flashing

## Build & Flash

Requires [PlatformIO](https://platformio.org/).

```bash
# 1. Firmware
pio run -t upload

# 2. Filesystem (landing page + wordlist)
pio run -t uploadfs

# 3. Serial monitor (115200 baud)
pio device monitor
```

Defaults:
- AP SSID: `ESP32-SecurityLab`
- AP pass: `lab12345`
- Landing page: http://192.168.4.1/

## Layout

```
.
├── platformio.ini
├── src/main.cpp              # firmware
└── data/                     # LittleFS
    ├── index.html            # landing page (project + socials)
    ├── style.css
    └── wordlist.txt          # 5000 passwords, brute-force input
```

## Implementation notes

- **Raw frame injection bypass.** Overrides `ieee80211_raw_frame_sanity_check()` so ESP-IDF's WiFi driver accepts injected management frames instead of dropping them with "unsupport frame type 0c0/0a0". Linker flag `-Wl,-zmuldefs` lets our definition replace the library's.
- **Country = "JP".** Set at boot with `WIFI_COUNTRY_POLICY_MANUAL` so channels 12–14 are TX-enabled. The default ("01" worldwide indoor) silently caps TX at ch 1–11.
- **AP off during deauth.** During an active deauth attack the radio is switched to STA-only mode (`esp_wifi_set_mode(WIFI_MODE_STA)`) so the AP beacon scheduler does not pull the radio back to the dashboard channel. Restored afterwards.
- **Promiscuous mode + MGMT filter.** Pauses AP beacon contest so raw injection actually goes out on the target's channel.
- **Bluedroid + BT controller deinit/reinit** around Wi-Fi scans (BLE and Wi-Fi share the 2.4 GHz radio; scanning needs exclusive access).
- **Cores:** Wi-Fi attacks, BLE scan, BLE spam, brute-force → Core 0. AsyncTCP web server → Core 1.

## Limits

- **2.4 GHz only.** ESP32-WROOM-32 has no 5 GHz radio. Clients connected on a router's 5 GHz band are physically unreachable from this device — this is a hardware limit shared by every ESP32-based wireless tool (Marauder, SpaceHuhn, etc.). Use ESP32-C5 or a Linux + dual-band USB adapter for full coverage.
- **PMF (802.11w).** WPA3 and WPA2 with PMF "required" cryptographically protect management frames; deauth has no effect on those clients.

## Author

Built and maintained by **0x4161 (Ahmad Alanazi)**.

- GitHub:    https://github.com/0x4161
- LinkedIn:  https://www.linkedin.com/in/ahmad-alanazi-b1040933b
- X:         https://x.com/0x4161
- Instagram: https://instagram.com/fx_py3
- YouTube:   https://youtube.com/@0x5952
