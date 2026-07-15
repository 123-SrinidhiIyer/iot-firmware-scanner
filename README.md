# 🔍 IoT Firmware Vulnerability Scanner

An end-to-end IoT security research tool — analyze firmware files for vulnerabilities, or actively scan and fuzz live devices on the network. Built and tested against both real router firmware and a custom-built vulnerable ESP8266 device.

Built by **Srinidhi B Iyer** — Electronics & Communication Engineering, Vidyavardhaka College of Engineering, Mysuru — as a Security Engineering portfolio project.

---

## What It Does

Point it at a firmware `.bin` file, or a live device's IP address (or both), and it will:

1. **Extract** the embedded filesystem from a firmware image
2. **Statically analyze** every file for hardcoded credentials, weak crypto, and backdoors
3. **Audit every ELF binary** for missing security mitigations (NX, PIE, Stack Canary, RELRO)
4. **Discover live services** running on a real device (HTTP, Telnet, FTP, MQTT, DNS, etc.)
5. **Fuzz those services** with malformed payloads to find crashes, hangs, and DoS conditions
6. **Generate a live dashboard** and a **professional PDF security report**

---

## Real Results

### Firmware Analysis — D-Link DIR-615 (real router firmware)
- **570 static findings** across 325 files — including 16 CRITICAL (hardcoded admin credentials, SSLv3/POODLE-vulnerable code, debug shell spawning)
- **119 of 119 ELF binaries (100%)** lacking all four security mitigations (NX, PIE, Canary, RELRO)
- **22 of 24 network fuzzing payloads** caused DNS service timeouts on a live home router — a real reproducible DoS condition

### Live Hardware Testing — Custom ESP8266 Target
To validate the tool against a real, physically-verified device (not just downloaded firmware), a deliberately vulnerable IoT web server — **VulnIoT-Lite** — was built and flashed onto a real ESP8266 chip. It runs on the local network with 8 intentional vulnerability classes (hardcoded credentials, no-auth debug endpoint, buffer overflow, weak XOR "encryption", etc.).

Fuzzing this real hardware target found:
- **17 of 33 malformed HTTP requests caused the device to hang** at the protocol parsing layer — before ever reaching the application's own route handlers
- Free heap dropped from ~43KB to ~21KB during the attack and fully recovered afterward — a **temporary resource-exhaustion DoS**, not a crash or memory leak
- Root cause traced to the `ESP8266WebServer` library's HTTP parser, not the application code — meaning this class of bug likely affects many consumer devices using the same library

This closes the full loop: a tool that finds bugs in firmware you didn't write, validated against a device you built and fully understand.

---

## Architecture

```
iot-firmware-scanner/
├── extractor/           → 7-Zip based firmware unpacking + file type detection
├── analyzer/
│   ├── static_analyzer.py   → regex-based credential/crypto/backdoor scanning
│   └── binary_analyzer.py   → manual ELF header parsing for security mitigations
├── fuzzer/
│   ├── service_executor.py  → live port scanning + service fingerprinting
│   └── fuzzer.py             → protocol-aware fuzzing engine (HTTP/Telnet/FTP/MQTT/generic)
├── dashboard/            → Flask web UI — upload firmware, live progress, results tabs
├── reporter/             → ReportLab PDF generator (executive report style)
├── hardware/
│   └── VulnIoT_Lite.ino      → custom vulnerable ESP8266 firmware (test target)
├── main.py               → orchestrates the full pipeline end-to-end
└── reports/               → JSON + PDF outputs
```

---

## Tech Stack

| Layer | Tools |
|---|---|
| Firmware Extraction | 7-Zip, python-magic |
| Static Analysis | Python regex, custom vulnerability signatures |
| Binary Analysis | Manual ELF header parsing (`struct`) — no external disassembler needed |
| Network Fuzzing | Raw sockets, custom protocol-aware payload generators |
| Dashboard | Flask, Jinja2, drag-and-drop upload, live progress tracking |
| Reporting | ReportLab (PDF) |
| Hardware Target | ESP8266 (NodeMCU), Arduino/C++ |
| Language | Python 3.11 |

---

## Usage

```bash
# Install dependencies
python -m pip install -r requirements.txt

# Option 1: Web UI (recommended — no terminal commands needed after this)
python dashboard/app.py
# → open http://localhost:5000, drag in a firmware file, optionally add a target IP

# Option 2: CLI — full pipeline (firmware + live device)
python main.py firmware.bin <target_ip>

# Option 2b: CLI — firmware analysis only
python main.py firmware.bin

# Generate PDF report
python reporter/pdf_reporter.py
```

---

## Key Design Decisions

- **No dependency on Linux-only tools** — binwalk's Python bindings are broken on Windows, so extraction is done with 7-Zip, which handles SquashFS/CramFS/JFFS2 natively on any OS.
- **ELF analysis implemented from scratch** by parsing binary headers directly with Python's `struct` module, rather than shelling out to `checksec` — keeping the tool portable and dependency-light.
- **Fuzzing is protocol-aware**: HTTP, Telnet, FTP, and MQTT each get tailored payloads in addition to generic buffer overflow / format string / injection payloads.
- **Validated against real hardware, not just downloaded firmware** — building the ESP8266 target meant every finding could be independently confirmed against source code the author wrote and fully understood, rather than trusting the tool's own output on an opaque binary.

---

## Disclaimer

This tool was built for educational and portfolio purposes. Firmware analyzed was publicly available legacy firmware; live device testing was performed only against hardware built and owned by the author, and against the author's own home network devices with explicit authorization. This tool should not be used against systems you do not own or have explicit authorization to test.

---

## Author

**Srinidhi B Iyer**
Electronics & Communication Engineering, Vidyavardhaka College of Engineering, Mysuru
iyersrinidhiii@gmail.com
