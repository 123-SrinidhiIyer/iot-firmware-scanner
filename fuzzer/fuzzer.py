import socket
import json
import os
import time
import random
import string
import threading
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

console = Console()

BASE_DIR    = r"D:\Srinidhi_Iyer\iot-firmware-scanner"
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# ── FUZZ PAYLOADS ─────────────────────────────────────────────────────────────
class FuzzPayloads:

    @staticmethod
    def buffer_overflow(sizes=[100, 500, 1000, 5000, 10000]):
        """Classic buffer overflow strings."""
        return [b"A" * s for s in sizes]

    @staticmethod
    def format_strings():
        """Format string attack payloads."""
        return [
            b"%s%s%s%s%s%s%s%s%s%s",
            b"%x%x%x%x%x%x%x%x%x%x",
            b"%n%n%n%n%n%n",
            b"%.1000d",
            b"%99999999d",
            b"AAAA%p%p%p%p%p%p%p%p",
        ]

    @staticmethod
    def null_bytes():
        """Null byte injection."""
        return [
            b"\x00" * 100,
            b"test\x00injection",
            b"\x00" + b"A" * 100,
            b"A" * 100 + b"\x00",
        ]

    @staticmethod
    def special_chars():
        """Special character injection."""
        return [
            b"'; DROP TABLE users; --",
            b"<script>alert(1)</script>",
            b"../../../etc/passwd",
            b"| cat /etc/passwd",
            b"`id`",
            b"$(id)",
            b"&& id &&",
            b"\r\n\r\n",
            b"\xff\xfe" * 50,
        ]

    @staticmethod
    def http_fuzzing(host, port):
        """HTTP-specific fuzz payloads."""
        return [
            f"GET /{{}}{{}}{{}}{{}}{{}}{{}}{{}}{{}}{{}}{{}}.php HTTP/1.1\r\nHost: {host}\r\n\r\n".encode(),
            f"GET /../../../etc/passwd HTTP/1.1\r\nHost: {host}\r\n\r\n".encode(),
            f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {'A'*5000}\r\n\r\n".encode(),
            f"POST /login HTTP/1.1\r\nHost: {host}\r\nContent-Length: 10000\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername={'A'*5000}&password={'B'*5000}".encode(),
            f"GET / HTTP/1.1\r\nHost: {host}\r\nCookie: session={'A'*2000}\r\n\r\n".encode(),
            f"GET /{'A'*2000} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode(),
            b"GET / HTTP/9.9\r\n\r\n",
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
            ("GET / HTTP/1.1\r\nHost: " + host + "\r\n" + "X-Custom: A\r\n"*100 + "\r\n").encode(),
        ]

    @staticmethod
    def telnet_fuzzing():
        """Telnet-specific fuzz payloads."""
        return [
            b"admin\r\n",
            b"root\r\n",
            b"A" * 1000 + b"\r\n",
            b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x0f",
            b"\x00" * 500,
            b"administrator\r\npassword\r\n",
            b"' OR '1'='1\r\n",
        ]

    @staticmethod
    def ftp_fuzzing():
        """FTP-specific fuzz payloads."""
        return [
            b"USER anonymous\r\n",
            b"USER " + b"A" * 5000 + b"\r\n",
            b"PASS " + b"B" * 5000 + b"\r\n",
            b"CWD " + b"../../../" * 100 + b"\r\n",
            b"LIST " + b"A" * 2000 + b"\r\n",
            b"USER root\r\nPASS root\r\n",
            b"USER admin\r\nPASS admin\r\n",
            b"USER admin\r\nPASS \r\n",
        ]

    @staticmethod
    def mqtt_fuzzing():
        """MQTT-specific fuzz payloads."""
        return [
            b"\x10\x17\x00\x04MQTT\x04\x02\x00\x3c\x00\x0bMQTTClient",
            b"\x10" + b"\xff" * 100,
            b"\x30\x00\x00\x00" + b"A" * 1000,
            b"\x82\x09\x00\x01\x00\x04test\x00",
            b"\xff\xff\xff\xff" * 100,
        ]

    @staticmethod
    def get_all_generic():
        """All generic payloads combined."""
        payloads = []
        payloads.extend(FuzzPayloads.buffer_overflow())
        payloads.extend(FuzzPayloads.format_strings())
        payloads.extend(FuzzPayloads.null_bytes())
        payloads.extend(FuzzPayloads.special_chars())
        return payloads


# ── FUZZER ENGINE ────────────────────────────────────────────────────────────
class ServiceFuzzer:

    def __init__(self, host, port, service, timeout=3):
        self.host     = host
        self.port     = port
        self.service  = service
        self.timeout  = timeout
        self.findings = []
        self.stats    = {
            "total_sent":    0,
            "crashes":       0,
            "timeouts":      0,
            "errors":        0,
            "interesting":   0,
        }

    def send_payload(self, payload):
        """Send a single payload and capture response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))

            start_time = time.time()
            sock.send(payload)

            try:
                response = sock.recv(4096)
                elapsed  = time.time() - start_time
                sock.close()
                return {
                    "status":   "response",
                    "response": response[:500],
                    "elapsed":  round(elapsed, 3),
                    "length":   len(response)
                }
            except socket.timeout:
                elapsed = time.time() - start_time
                sock.close()
                self.stats["timeouts"] += 1
                return {
                    "status":  "timeout",
                    "elapsed": round(elapsed, 3),
                    "length":  0
                }

        except ConnectionRefusedError:
            self.stats["crashes"] += 1
            return {"status": "connection_refused", "elapsed": 0, "length": 0}
        except ConnectionResetError:
            self.stats["crashes"] += 1
            return {"status": "connection_reset", "elapsed": 0, "length": 0}
        except Exception as e:
            self.stats["errors"] += 1
            return {"status": f"error: {str(e)[:50]}", "elapsed": 0, "length": 0}

    def get_payloads(self):
        """Get service-specific payloads."""
        if self.service in ["HTTP", "HTTP-ALT", "HTTP-DEV", "HTTPS-ALT"]:
            return FuzzPayloads.http_fuzzing(self.host, self.port) + FuzzPayloads.get_all_generic()
        elif self.service == "Telnet":
            return FuzzPayloads.telnet_fuzzing() + FuzzPayloads.get_all_generic()
        elif self.service == "FTP":
            return FuzzPayloads.ftp_fuzzing() + FuzzPayloads.get_all_generic()
        elif self.service == "MQTT":
            return FuzzPayloads.mqtt_fuzzing() + FuzzPayloads.get_all_generic()
        else:
            return FuzzPayloads.get_all_generic()

    def analyze_response(self, payload, result):
        """Analyze response for interesting behaviors."""
        interesting = False
        reason      = []

        if result["status"] in ["connection_refused", "connection_reset"]:
            interesting = True
            reason.append("Service crash/reset detected")

        if result["status"] == "timeout" and result["elapsed"] > 2.5:
            interesting = True
            reason.append("Potential hang/DoS detected")

        if result.get("response"):
            resp_str = result["response"].decode('utf-8', errors='ignore').lower()
            crash_indicators = [
                "segfault", "sigsegv", "core dump", "panic",
                "assertion failed", "stack overflow", "heap corruption",
                "null pointer", "invalid memory"
            ]
            for indicator in crash_indicators:
                if indicator in resp_str:
                    interesting = True
                    reason.append(f"Crash indicator: '{indicator}'")

            error_indicators = [
                "error", "exception", "fatal", "warning", "failed",
                "invalid", "overflow", "undefined"
            ]
            error_count = sum(1 for i in error_indicators if i in resp_str)
            if error_count >= 3:
                interesting = True
                reason.append(f"Multiple error indicators ({error_count})")

        if interesting:
            self.stats["interesting"] += 1
            finding = {
                "payload_hex":   payload[:50].hex(),
                "payload_str":   payload[:50].decode('utf-8', errors='ignore'),
                "payload_size":  len(payload),
                "result_status": result["status"],
                "elapsed":       result["elapsed"],
                "reasons":       reason,
                "severity":      "HIGH" if "crash" in " ".join(reason).lower() else "MEDIUM"
            }
            self.findings.append(finding)

        return interesting, reason

    def fuzz(self):
        """Run the fuzzing session."""
        payloads = self.get_payloads()

        console.print(f"\n[bold cyan]>> Fuzzing {self.service} on "
                      f"{self.host}:{self.port}[/bold cyan]")
        console.print(f"   [dim]Payloads: {len(payloads)} | "
                      f"Timeout: {self.timeout}s[/dim]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task(
                f"[cyan]Fuzzing {self.service}:{self.port}",
                total=len(payloads)
            )

            for i, payload in enumerate(payloads):
                result = self.send_payload(payload)
                self.stats["total_sent"] += 1

                interesting, reasons = self.analyze_response(payload, result)

                if interesting:
                    progress.print(
                        f"  [bold yellow]⚠ INTERESTING:[/bold yellow] "
                        f"Payload #{i+1} — {', '.join(reasons)}"
                    )

                progress.update(task, advance=1)
                time.sleep(0.05)  # Rate limiting — be nice

        return self.findings, self.stats


# ── MAIN FUZZER ORCHESTRATOR ─────────────────────────────────────────────────
def run_fuzzer(host, target_ports=None):
    console.print(Panel(
        "[bold red]IoT Firmware Scanner[/bold red] — [cyan]Fuzzer Module[/cyan]",
        expand=False
    ))

    # Load service scan report
    scan_report_path = os.path.join(REPORTS_DIR, "service_scan_report.json")
    if not os.path.exists(scan_report_path):
        console.print("[bold red]ERROR:[/bold red] No service scan report found.")
        console.print("[cyan]Run service_executor.py first to discover open services.[/cyan]")
        return

    with open(scan_report_path) as f:
        scan_report = json.load(f)

    open_services = scan_report.get("open_services", [])

    if not open_services:
        console.print("[bold yellow]⚠ No open services found to fuzz.[/bold yellow]")
        console.print(f"[cyan]The target ({scan_report.get('target_host')}) had no open ports.[/cyan]")
        console.print("[cyan]Make sure your router/IoT device is connected and powered on.[/cyan]")
        return

    # Filter by target ports if specified
    if target_ports:
        open_services = [s for s in open_services if s["port"] in target_ports]

    console.print(f"\n[bold yellow]Target:[/bold yellow] {host}")
    console.print(f"[bold yellow]Services to fuzz:[/bold yellow] {len(open_services)}\n")

    all_findings = []
    all_stats    = {}

    for svc in open_services:
        port    = svc["port"]
        service = svc["service"]

        fuzzer   = ServiceFuzzer(host, port, service)
        findings, stats = fuzzer.fuzz()

        all_findings.extend(findings)
        all_stats[f"{service}:{port}"] = stats

        # Per-service summary
        result_table = Table(title=f"{service}:{port} Results", box=box.SIMPLE)
        result_table.add_column("Metric",  style="cyan")
        result_table.add_column("Value",   style="white", justify="right")

        result_table.add_row("Payloads Sent",        str(stats["total_sent"]))
        result_table.add_row("Crashes/Resets",        f"[bold red]{stats['crashes']}[/bold red]")
        result_table.add_row("Timeouts (potential DoS)", f"[yellow]{stats['timeouts']}[/yellow]")
        result_table.add_row("Interesting Responses", f"[bold cyan]{stats['interesting']}[/bold cyan]")
        result_table.add_row("Errors",               str(stats["errors"]))

        console.print(result_table)

    # Final summary
    console.print()
    console.print("[bold cyan]>> FUZZING COMPLETE — Summary[/bold cyan]")

    summary_table = Table(title="Overall Fuzzing Results", box=box.ROUNDED)
    summary_table.add_column("Service",     style="cyan")
    summary_table.add_column("Sent",        justify="center")
    summary_table.add_column("Crashes",     justify="center")
    summary_table.add_column("Timeouts",    justify="center")
    summary_table.add_column("Interesting", justify="center")

    total_sent        = 0
    total_crashes     = 0
    total_timeouts    = 0
    total_interesting = 0

    for svc_key, stats in all_stats.items():
        summary_table.add_row(
            svc_key,
            str(stats["total_sent"]),
            f"[red]{stats['crashes']}[/red]"       if stats["crashes"]     else "0",
            f"[yellow]{stats['timeouts']}[/yellow]" if stats["timeouts"]    else "0",
            f"[cyan]{stats['interesting']}[/cyan]"  if stats["interesting"] else "0",
        )
        total_sent        += stats["total_sent"]
        total_crashes     += stats["crashes"]
        total_timeouts    += stats["timeouts"]
        total_interesting += stats["interesting"]

    console.print(summary_table)

    # Findings detail
    if all_findings:
        console.print(f"\n[bold yellow]⚠ {len(all_findings)} Interesting Findings:[/bold yellow]")
        findings_table = Table(show_lines=True, box=box.SIMPLE_HEAVY)
        findings_table.add_column("Severity", style="bold")
        findings_table.add_column("Payload",  style="cyan",  max_width=30)
        findings_table.add_column("Size",     justify="right")
        findings_table.add_column("Status",   style="white")
        findings_table.add_column("Reasons",  style="yellow")

        for f in all_findings[:20]:
            sev_color = "bold red" if f["severity"] == "HIGH" else "yellow"
            findings_table.add_row(
                f"[{sev_color}]{f['severity']}[/{sev_color}]",
                f["payload_str"][:30],
                str(f["payload_size"]),
                f["result_status"],
                " | ".join(f["reasons"])[:60]
            )
        console.print(findings_table)
    else:
        console.print("\n[bold green]✔ No crashes or interesting behavior detected.[/bold green]")
        console.print("[dim]The target services handled all payloads gracefully.[/dim]")

    # Save report
    report = {
        "timestamp":    datetime.now().isoformat(),
        "target_host":  host,
        "services_fuzzed": list(all_stats.keys()),
        "total_payloads_sent": total_sent,
        "total_crashes":      total_crashes,
        "total_timeouts":     total_timeouts,
        "total_interesting":  total_interesting,
        "findings":    all_findings,
        "stats":       all_stats,
    }

    report_path = os.path.join(REPORTS_DIR, "fuzzing_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    console.print(f"\n[bold green]✔ Fuzzing complete![/bold green]")
    console.print(f"[bold green]✔ Total payloads sent:[/bold green] {total_sent}")
    console.print(f"[bold green]✔ Report saved:[/bold green] {report_path}")

    return report


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.1"
    run_fuzzer(host)