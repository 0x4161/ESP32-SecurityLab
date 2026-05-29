# REAPER &mdash; Wireless Offensive Toolkit

<p align="center">
  <img src="docs/board.jpg" alt="ideaspark ESP32 0.96&quot; OLED Board" width="640">
  <br>
  <em>Built on the <strong>ideaspark ESP32-WROOM-32 + 0.96&quot; OLED</strong> dev board.</em>
</p>

A pocket-sized wireless attack platform running entirely on an ESP32-WROOM-32 with a 0.96&Prime; SSD1306 OLED. Every operation is controlled from the device itself &mdash; **a single BOOT button and the on-screen menu**. The web surface is a static landing page only; there are no remote-control HTTP endpoints.

> **For authorized security research, hardware education, and CTF/lab use only.** Using REAPER against any network or device you do not own or have written permission to test is illegal and not endorsed by the author.

---

## Arsenal

### Wi-Fi (2.4 GHz)

| Module | What it does |
|--------|--------------|
| **Scan** | Full 2.4&nbsp;GHz band enumeration &mdash; SSID, BSSID, RSSI, channel, encryption |
| **Deauth / Disassoc** | Raw 802.11 frame injection (`0xC0`/`0xA0`) on the target's channel |
| **Multi-target deauth** | Rotates through every AP marked on the scan list |
| **PSK Brute-Force** | Iterates a 5,000-password built-in wordlist against any visible WPA/WPA2 SSID |
| **Capture HS** &nbsp;NEW | Auto-chain: deauth burst (3 s) → EAPOL listen (20 s) → frames saved to `/captures/handshake.pcap` |
| **PMKID Grab** &nbsp;NEW | Triggers Association Request, sniffs EAPOL M1 from AP, extracts PMKID, writes hashcat-ready `/captures/pmkid.hc22000` |
| **Beacon Flood** | Broadcasts thousands of sequentially-numbered phantom SSIDs (`#VOID TEST 1..N`) |
| **Probe Sniffer** | Captures probe requests &mdash; MAC + remembered SSID + RSSI |
| **EAPOL Sniffer** | Captures WPA 4-way handshake frames (`0x888E`) for offline cracking |
| **Evil Twin** | Clones a target SSID as an open AP on the same channel |
| **PCAP Export** &nbsp;NEW | All capture modules write to standard libpcap files (linktype 105) under `/captures/` &mdash; opens directly in Wireshark / hashcat |

### Bluetooth LE

| Module | What it does |
|--------|--------------|
| **BLE Scan** | Advertising scanner &mdash; name, RSSI, address |
| **AirTag Hunt** &nbsp;NEW | Apple Find My / AirTag detector. Filters BLE adverts with company ID `0x004C` + type `0x12`; surfaces unique tags with RSSI + status byte (online vs separated) |
| **BLE Spam** | Apple Continuity / Microsoft Swift Pair / Google Fast Pair payloads, cycled |
| **Sour Apple** &nbsp;NEW | iPhone DoS variant of BLE spam. Sends Continuity TLVs with mismatched declared/actual lengths &mdash; freezes BT stack on older iOS, may force reboot. Selectable via Spam Target menu. |

---

## :unlock: PSK Brute-Force in detail

The brute-force module iterates a wordlist stored on LittleFS, attempting `WiFi.begin()` against the target SSID and watching for `WL_CONNECTED`.

**Specs**

- Wordlist: `data/wordlist.txt` &mdash; **5,000 passwords**, &asymp;47&nbsp;KB
- Source: NCSC top-100k + custom prefix for router defaults
- Filtered to 8&ndash;63 chars (WPA constraint)
- Speed: **~3&ndash;4&nbsp;seconds per password** (4-way-handshake timing is the floor &mdash; this is a protocol limit, not an ESP32 limit)
- Worst case: 5,000 &times; 4&nbsp;s &approx; **5.5 hours** for a full sweep
- Result is shown live on the OLED: SSID, tried/total, current password, and on success the discovered PSK

**Menu flow (OLED only)**

```
[Long]   WiFi >
[Long]   WiFi Scan          -> radio scan, list builds
[Long]   * Alanazi          -> mark target with *
[Long]   << Back
[Long]   WiFi Brute         -> brute starts on first marked AP
```

While running:

```
+------------------------+
| WiFi Brute        RUN  |
+------------------------+
| SSID: Alanazi          |
| Try: 1/5000            |
| Now: 15741574          |
+------------------------+
| > back   hold = stop   |
+------------------------+
```

On success:

```
+------------------------+
| WiFi Brute      FOUND  |
+------------------------+
| SSID: Alanazi          |
| Try: 1/5000            |
| PWD: 15741574          |
+------------------------+
| > back   hold = back   |
+------------------------+
```

---

## Control surface

The whole device is driven by **one button** (BOOT, GPIO0).

| Action | Meaning |
|--------|---------|
| Short press | Move cursor / cycle selector |
| Long press &nbsp;(&ge;600&nbsp;ms) | Enter screen / start operation / commit |

The web surface (`http://192.168.4.1/`) is a static landing page describing the project and linking to author socials. **No HTTP control endpoints exist** &mdash; remote takeover is impossible.

---

## Hardware

This firmware is built and tested on the **ideaspark ESP32 0.96-inch OLED Board** &mdash; an all-in-one dev board with the SSD1306 OLED, ESP32-WROOM-32 module, and BOOT button already wired.

| Component | Spec |
|-----------|------|
| MCU | ESP32-WROOM-32 (Tensilica Xtensa LX6 dual-core @ 240 MHz) |
| Wi-Fi | 802.11 b/g/n, 2.4 GHz only |
| Bluetooth | BLE 4.2 |
| Flash | 4 MB |
| OLED | SSD1306 0.96&Prime; I&sup2;C (auto-detected on SDA=21 SCL=22 or alt pins) |
| Button | BOOT &mdash; GPIO0, active LOW, internal pull-up |
| USB | micro-USB &mdash; CP2102 or CH340 serial |

The firmware will also run on a bare ESP32-WROOM-32 dev board + an external SSD1306 wired to I&sup2;C (any pin combo &mdash; the boot-time auto-probe walks the common pairs).

---

## Build & Flash

Requires [PlatformIO](https://platformio.org/) (CLI or VSCode extension).

```bash
# 1. Firmware
pio run -t upload

# 2. LittleFS (landing page + wordlist)
pio run -t uploadfs

# 3. Serial monitor (115200 baud)
pio device monitor
```

Defaults after first boot:

- AP SSID: `ESP32-SecurityLab`
- AP pass: `lab12345`
- Landing page: `http://192.168.4.1/`

---

## Repository layout

```
.
&#x251C;&#x2500;&#x2500; platformio.ini
&#x251C;&#x2500;&#x2500; src/main.cpp         # firmware (~2100 lines)
&#x251C;&#x2500;&#x2500; data/                # LittleFS image
&#x2502;   &#x251C;&#x2500;&#x2500; index.html       # landing page
&#x2502;   &#x251C;&#x2500;&#x2500; style.css        # REAPER theme
&#x2502;   &#x2514;&#x2500;&#x2500; wordlist.txt     # 5000 PSKs (47KB)
&#x2514;&#x2500;&#x2500; docs/
    &#x2514;&#x2500;&#x2500; board.jpg        # ideaspark board reference
```

---

## Implementation highlights

- **Raw frame injection bypass.** Provides a weak override of `ieee80211_raw_frame_sanity_check()` so ESP-IDF's WiFi driver accepts injected management frames (Deauth `0xC0`, Disassoc `0xA0`). Without this the driver drops them with `unsupport frame type` and nothing ever leaves the radio. Linker flag `-Wl,-zmuldefs` lets the override replace the library symbol.
- **Country = "JP", manual policy.** Set at boot. The default "01" (worldwide indoor) silently caps TX at channels 1&ndash;11; with "JP" channels 1&ndash;14 are TX-enabled and deauth works on the full band.
- **AP off during deauth.** The radio is switched to STA-only during attack so the AP beacon scheduler can't pull the radio back to the dashboard channel. Restored afterwards.
- **Promiscuous + MGMT filter** while injecting &mdash; pauses AP beacon contest so frames actually leave on the target's channel.
- **Bluedroid + BT controller deinit/reinit** around Wi-Fi scans (BLE and Wi-Fi share the 2.4 GHz radio).
- **Cores.** Wi-Fi attacks, BLE scan, BLE spam, brute-force &rarr; Core 0. AsyncTCP web server &rarr; Core 1.

---

## Limits

- **2.4 GHz only.** ESP32-WROOM-32 has no 5 GHz radio. Clients on a router's 5&nbsp;GHz band are physically unreachable from this device &mdash; this is a hardware limit shared by every ESP32-based wireless tool (Marauder, SpaceHuhn, etc.). Use ESP32-C5 or Linux + dual-band USB adapter for full coverage.
- **PMF (802.11w).** WPA3 and WPA2 with PMF "required" cryptographically protect management frames; deauth has no effect on those clients.

---

## Author

Built &amp; maintained by **0x4161 (Ahmad Alanazi)**.

[![GitHub](https://img.shields.io/badge/GitHub-0x4161-181717?style=for-the-badge&logo=github)](https://github.com/0x4161)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ahmad%20Alanazi-0A66C2?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/ahmad-alanazi-b1040933b)
[![X](https://img.shields.io/badge/X-@0x4161-000000?style=for-the-badge&logo=x)](https://x.com/0x4161)
[![Instagram](https://img.shields.io/badge/Instagram-@fx_py3-E4405F?style=for-the-badge&logo=instagram)](https://instagram.com/fx_py3)
[![YouTube](https://img.shields.io/badge/YouTube-@0x5952-FF0000?style=for-the-badge&logo=youtube)](https://youtube.com/@0x5952)
