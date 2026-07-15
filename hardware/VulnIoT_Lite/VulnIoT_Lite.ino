/*
 * VulnIoT-Lite — Intentionally Vulnerable ESP8266 Firmware
 * Built by Srinidhi B Iyer as a safe, legal target for the
 * IoT Firmware Vulnerability Scanner portfolio project.
 *
 * WARNING: This firmware contains DELIBERATE security flaws.
 * Never deploy this on a real network. For research/demo use only.
 */

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>

// ── VULNERABILITY #1: Hardcoded WiFi Credentials ────────────────────────────
const char* WIFI_SSID     = "Kingmaker07";
const char* WIFI_PASSWORD = "aaaaa@111";

// ── VULNERABILITY #2: Hardcoded Admin Credentials ───────────────────────────
const char* ADMIN_USER = "admin";
const char* ADMIN_PASS = "admin";  // default creds never changed

// ── VULNERABILITY #3: Hardcoded API Secret ──────────────────────────────────
const char* API_SECRET_TOKEN = "sk_live_a8f92hd82hf82hf92hf82h";

// ── VULNERABILITY #4: Weak "Encryption" (XOR cipher, trivially breakable) ──
const char XOR_KEY = 0x2A;  // single-byte XOR — not real encryption

ESP8266WebServer server(80);

char lastLoginBuffer[32];  // fixed-size buffer, no bounds checking later

unsigned long requestCount = 0;
unsigned long lastHeapCheck = 0;
unsigned int minHeapSeen = 999999;

String weakEncrypt(String input) {
  String output = "";
  for (unsigned int i = 0; i < input.length(); i++) {
    output += (char)(input[i] ^ XOR_KEY);
  }
  return output;
}

void logRequest(String path, String method) {
  requestCount++;
  Serial.print("[REQUEST #");
  Serial.print(requestCount);
  Serial.print("] ");
  Serial.print(method);
  Serial.print(" ");
  Serial.print(path);
  Serial.print(" | Heap: ");
  Serial.print(ESP.getFreeHeap());
  Serial.println(" bytes");
}

// ── Home page ────────────────────────────────────────────────────────────────
void handleRoot() {
  logRequest("/", "GET");
  String html = "<html><body style='font-family:sans-serif;background:#111;color:#eee;padding:40px;'>";
  html += "<h1>VulnIoT-Lite Control Panel</h1>";
  html += "<p>Device Status: <b style='color:lightgreen;'>Online</b></p>";
  html += "<p><a href='/login' style='color:#4a90d9;'>Admin Login</a></p>";
  html += "<p><a href='/debug' style='color:#4a90d9;'>Debug Info</a></p>";
  html += "<p><a href='/config' style='color:#4a90d9;'>Config Backup</a></p>";
  html += "<p style='color:#555;font-size:0.8em;'>VulnIoT-Lite v1.0 — Firmware built " __DATE__ "</p>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

// ── VULNERABILITY #5: Debug endpoint with NO authentication ────────────────
void handleDebug() {
  logRequest("/debug", "GET");
  String html = "<html><body style='font-family:monospace;background:#000;color:#0f0;padding:20px;'>";
  html += "<h2>DEBUG MODE — INTERNAL USE ONLY</h2>";
  html += "<p>WiFi SSID: " + String(WIFI_SSID) + "</p>";
  html += "<p>WiFi Password: " + String(WIFI_PASSWORD) + "</p>";
  html += "<p>Admin User: " + String(ADMIN_USER) + "</p>";
  html += "<p>Admin Pass: " + String(ADMIN_PASS) + "</p>";
  html += "<p>API Secret Token: " + String(API_SECRET_TOKEN) + "</p>";
  html += "<p>Free Heap: " + String(ESP.getFreeHeap()) + " bytes</p>";
  html += "<p>Chip ID: " + String(ESP.getChipId()) + "</p>";
  html += "<p>Uptime: " + String(millis() / 1000) + "s</p>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

// ── Login page ───────────────────────────────────────────────────────────────
void handleLoginPage() {
  logRequest("/login", "GET");
  String html = "<html><body style='font-family:sans-serif;background:#111;color:#eee;padding:40px;'>";
  html += "<h2>Admin Login</h2>";
  html += "<form action='/login' method='POST'>";
  html += "Username: <input name='user'><br><br>";
  html += "Password: <input name='pass' type='password'><br><br>";
  html += "<input type='submit' value='Login'>";
  html += "</form></body></html>";
  server.send(200, "text/html", html);
}

// ── VULNERABILITY #6: Buffer Overflow — no length check before copying ─────
void handleLoginSubmit() {
  logRequest("/login", "POST");
  String user = server.arg("user");
  String pass = server.arg("pass");

  Serial.print("[LOGIN ATTEMPT] user_len=");
  Serial.print(user.length());
  Serial.print(" pass_len=");
  Serial.println(pass.length());

  // DANGEROUS: copies into fixed 32-byte buffer with no bounds check
  user.toCharArray(lastLoginBuffer, user.length() + 1);

  if (user == ADMIN_USER && pass == ADMIN_PASS) {
    server.send(200, "text/html", "<h2>Login successful. Welcome, admin.</h2>");
  } else {
    // ── VULNERABILITY #7: Verbose error leaks whether username is valid ────
    if (user == ADMIN_USER) {
      server.send(401, "text/html", "<h2>Wrong password for user 'admin'</h2>");
    } else {
      server.send(401, "text/html", "<h2>Unknown user</h2>");
    }
  }
}

// ── VULNERABILITY #8: "Encrypted" config endpoint using weak XOR ───────────
void handleConfig() {
  logRequest("/config", "GET");
  String secretConfig = "wifi_pass=" + String(WIFI_PASSWORD) + ";admin_pass=" + String(ADMIN_PASS);
  String encrypted = weakEncrypt(secretConfig);

  String html = "<html><body style='font-family:monospace;background:#111;color:#eee;padding:20px;'>";
  html += "<h3>Encrypted Config Backup</h3>";
  html += "<p>(XOR 'encrypted' — trivially reversible)</p>";
  html += "<textarea rows='4' cols='60'>" + encrypted + "</textarea>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

void printDebugInfoToSerial() {
  Serial.println("\n========================================");
  Serial.println("  [DEBUG] Internal Diagnostics Dump");
  Serial.println("========================================");
  Serial.print("  WiFi SSID:            "); Serial.println(WIFI_SSID);
  Serial.print("  WiFi Password:        "); Serial.println(WIFI_PASSWORD);
  Serial.print("  Admin Username:       "); Serial.println(ADMIN_USER);
  Serial.print("  Admin Password:       "); Serial.println(ADMIN_PASS);
  Serial.print("  API Secret Token:     "); Serial.println(API_SECRET_TOKEN);
  Serial.print("  Free Heap:            "); Serial.print(ESP.getFreeHeap()); Serial.println(" bytes");
  Serial.print("  Chip ID:              "); Serial.println(ESP.getChipId());
  Serial.println("========================================\n");

  String secretConfig = "wifi_pass=" + String(WIFI_PASSWORD) + ";admin_pass=" + String(ADMIN_PASS);
  String encrypted = weakEncrypt(secretConfig);
  Serial.println("  [DEBUG] 'Encrypted' Config Backup (XOR, trivially reversible):");
  Serial.println("  " + encrypted);
  Serial.println("========================================\n");
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("VulnIoT-Lite booting...");
  Serial.println("WARNING: This firmware contains intentional vulnerabilities.");
  Serial.print("Connecting to WiFi: ");
  Serial.println(WIFI_SSID);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(500);
    Serial.print(".");
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\nConnected!");
    Serial.print("IP Address: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("\nWiFi connect failed — check credentials and try again.");
  }

  server.on("/", handleRoot);
  server.on("/debug", handleDebug);
  server.on("/login", HTTP_GET, handleLoginPage);
  server.on("/login", HTTP_POST, handleLoginSubmit);
  server.on("/config", handleConfig);

  server.begin();
  Serial.println("HTTP server started on port 80");
  Serial.println("Endpoints: / | /debug | /login | /config");
  Serial.println("\nWARNING: This firmware leaks credentials to serial console below (simulates UART debug backdoor):");

  printDebugInfoToSerial();

  Serial.println("[LIVE MONITOR] Watching requests + heap every 2s below...\n");
  minHeapSeen = ESP.getFreeHeap();
}

void loop() {
  server.handleClient();

  // Live heap monitor — watch this during fuzzing to spot memory exhaustion
  if (millis() - lastHeapCheck > 2000) {
    unsigned int currentHeap = ESP.getFreeHeap();
    if (currentHeap < minHeapSeen) minHeapSeen = currentHeap;

    Serial.print("[LIVE] Heap: ");
    Serial.print(currentHeap);
    Serial.print(" bytes | Min seen: ");
    Serial.print(minHeapSeen);
    Serial.print(" bytes | Uptime: ");
    Serial.print(millis() / 1000);
    Serial.print("s | Requests handled: ");
    Serial.println(requestCount);

    lastHeapCheck = millis();
  }
}