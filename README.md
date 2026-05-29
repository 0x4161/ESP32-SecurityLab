# ESP32 Security Lab

Offensive Wi-Fi & BLE security toolkit running on an ESP32-WROOM-32 with a 0.96" SSD1306 OLED. Includes a web dashboard, an OLED menu controlled by a single button, and a set of 802.11 attack primitives written directly against ESP-IDF.

> **For authorized security research and education only.** Do not use on networks or devices you do not own or have explicit permission to test.

## Features

### Wi-Fi
- **Scan** — full 2.4 GHz band enumeration with SSID / BSSID / RSSI / channel / encryption
- **Deauthentication / Disassociation** — raw 802.11 frame injection (`0xC0` / `0xA0`) on the target's channel
- **Multi-target deauth** — rotates through every AP selected on the OLED list
- **Beacon flood** — broadcasts up to 1000+ fake SSIDs per second (sequentially numbered)
- **Probe-request sniffer** — captures probes from nearby clients (MAC + searched SSID + RSSI)
- **EAPOL sniffer** — captures the WPA 4-way handshake (`0x888E`) for offline cracking
- **Evil Twin** — clones a target SSID as an open AP on the same channel

### Bluetooth LE
- **Scan** — BLE advertising scanner with name / RSSI / address
- **BLE Spam** — Apple proximity / Microsoft Swift Pair / Samsung Easy Setup payloads, cycled

### UI
- **Web dashboard** at `192.168.4.1` — session-cookie authenticated (httpOnly, SameSite=Strict)
- **OLED menu** — single BOOT-button (GPIO0) navigation, short / long press
- **Serial logs** at 115200 baud

## Hardware

- **ESP32-WROOM-32** (any dev board)
- **SSD1306 0.96" I²C OLED** — auto-detected on common pin combinations (SDA=21 SCL=22 default)
- **BOOT button (GPIO0)** for menu navigation
- USB-to-serial cable for flashing

## Build & Flash

Requires [PlatformIO](https://platformio.org/) (CLI or VSCode).

```bash
# Build firmware
pio run

# Flash firmware to board
pio run -t upload

# Upload web dashboard files (LittleFS)
pio run -t uploadfs

# Serial monitor
pio device monitor
```

Default Wi-Fi AP credentials:
- **SSID:** `ESP32-SecurityLab`
- **Pass:** `lab12345`
- **Dashboard:** http://192.168.4.1

## Project Structure

```
.
├── platformio.ini          PlatformIO build config
├── src/
│   └── main.cpp            Firmware (Wi-Fi, BLE, OLED, web server, attacks)
└── data/                   LittleFS web dashboard
    ├── index.html
    ├── attack.html
    ├── wifi.html
    ├── ble.html
    ├── lab.html
    ├── logs.html
    ├── settings.html
    ├── advanced.html
    ├── app.js
    └── style.css
```

## Architecture Notes

- **Cores:** Wi-Fi attacks, BLE scan, BLE spam → Core 0. AsyncTCP web server → Core 1.
- **BLE / Wi-Fi radio coexistence:** Wi-Fi scan path fully deinits Bluedroid + BT controller before starting the scan, then re-inits both. The shared 2.4 GHz radio cannot run a `WiFi.scanNetworks()` while BLE is active.
- **Raw frame injection bypass:** Overrides `ieee80211_raw_frame_sanity_check()` so ESP-IDF's WiFi driver accepts injected management frames (Deauth `0xC0`, Disassoc `0xA0`) instead of dropping them with "unsupport frame type".
- **AP off during deauth:** During an active deauth attack the radio is moved to STA-only mode (`esp_wifi_set_mode(WIFI_MODE_STA)`) so the AP beacon scheduler does not pull the radio back to the dashboard's channel.
- **Country code = "JP":** Set at boot with `WIFI_COUNTRY_POLICY_MANUAL` so channels 12–14 are TX-enabled. Default ("01" worldwide indoor) silently restricts TX to ch 1–11.
- **Authentication:** Web AP password is transport-layer protection. Sessions use an httpOnly cookie (hardware RNG, constant-time comparison, SameSite=Strict, no `Secure` flag because the device is HTTP-only).

## Known Limits

- **2.4 GHz only.** ESP32-WROOM-32 has no 5 GHz radio. Any client connected on a router's 5 GHz band cannot be deauthed by this device — this is a hardware limit shared by every ESP32-based deauther (Marauder, SpaceHuhn, etc.). Use an ESP32-C5 dev board or a Linux + AWUS036ACH-class adapter for full-band coverage.
- **PMF (802.11w).** Targets that use WPA3 or WPA2 with PMF "required" cryptographically protect management frames; deauth has no effect on those clients.

## License

MIT — see `LICENSE` if present, otherwise treat as MIT.
