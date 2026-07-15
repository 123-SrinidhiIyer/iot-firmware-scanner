import socket
import subprocess
import threading
import time
import json
import os
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

BASE_DIR    = r"D:\Srinidhi_Iyer\iot-firmware-scanner"
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# ── COMMON IOT SERVICE PORTS ─────────────────────────────────────────────────
IOT_SERVICES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    443:  "HTTPS",
    1883: "MQTT",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    8888: "HTTP-DEV",
    9999: "MANAGEMENT",
    102:  "S7COMM",
    502:  "MODBUS",
    4840: "OPC-UA",
}

# ── BANNER GRABS ─────────────────────────────────────────────────────────────
SERVICE_PROBES = {
    21:   b"",
    22:   b"",
    23:   b"",
    80:   b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    8888: b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    1883: b"\x10\x17\x00\x04MQTT\x04\x02\x00\x3c\x00\x0bMQTTClient",
    25:   b"EHLO test\r\n",
    53:   b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",
}

def check_port(host, port, timeout=2):
    """Check if a port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def grab_banner(host, port, timeout=3):
    """Grab service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        probe = SERVICE_PROBES.get(port, b"")
        if probe:
            sock.send(probe)

        time.sleep(0.5)
        banner = sock.recv(1024)
        sock.close()
        return banner.decode('utf-8', errors='ignore').strip()[:200]
    except Exception as e:
        return f"No banner ({str(e)[:50]})"

def detect_http_info(host, port, timeout=5):
    """Get detailed HTTP service info."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"User-Agent: IoT-Scanner/1.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.send(request.encode())
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(response) > 8192:
                break
        sock.close()

        response_str = response.decode('utf-8', errors='ignore')
        headers = {}
        lines = response_str.split('\r\n')
        status = lines[0] if lines else "Unknown"
        for line in lines[1:20]:
            if ':' in line:
                key, val = line.split(':', 1)
                headers[key.strip()] = val.strip()

        return {
            "status": status,
            "server": headers.get("Server", "Unknown"),
            "content_type": headers.get("Content-Type", "Unknown"),
            "powered_by": headers.get("X-Powered-By", "Not disclosed"),
            "headers": headers
        }
    except Exception as e:
        return {"error": str(e)[:100]}

def scan_target(host):
    """Scan target host for open IoT services."""
    console.print(Panel(
        "[bold red]IoT Firmware Scanner[/bold red] — [cyan]Service Executor Module[/cyan]",
        expand=False
    ))

    console.print(f"\n[bold yellow]Target Host:[/bold yellow] {host}")
    console.print(f"[bold yellow]Scanning:[/bold yellow] {len(IOT_SERVICES)} IoT service ports\n")

    open_services = []
    closed_services = []

    # Port scan with threading
    console.print("[bold cyan]>> Scanning ports...[/bold cyan]")
    threads = []
    results = {}
    lock = threading.Lock()

    def scan_port(port, service):
        is_open = check_port(host, port)
        with lock:
            results[port] = {"service": service, "open": is_open}

    for port, service in IOT_SERVICES.items():
        t = threading.Thread(target=scan_port, args=(port, service))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=5)

    # Display scan results
    scan_table = Table(title=f"Port Scan Results — {host}", box=box.ROUNDED)
    scan_table.add_column("Port",    style="cyan",  justify="right")
    scan_table.add_column("Service", style="white")
    scan_table.add_column("Status",  justify="center")

    for port in sorted(results.keys()):
        info = results[port]
        if info["open"]:
            scan_table.add_row(
                str(port),
                info["service"],
                "[bold green]OPEN[/bold green]"
            )
            open_services.append({"port": port, "service": info["service"]})
        else:
            scan_table.add_row(
                str(port),
                info["service"],
                "[dim red]CLOSED[/dim red]"
            )
            closed_services.append(port)

    console.print(scan_table)
    console.print(f"\n[bold green]Open services: {len(open_services)}[/bold green] | "
                  f"[dim]Closed: {len(closed_services)}[/dim]")

    if not open_services:
        console.print("\n[bold yellow]⚠ No open services found on target.[/bold yellow]")
        console.print("[cyan]Tip: Make sure the target device is on your network and powered on.[/cyan]")
        console.print("[cyan]For testing, try scanning localhost (127.0.0.1)[/cyan]")
        return {"host": host, "open_services": [], "service_details": {}}

    # Banner grab + service fingerprinting
    console.print("\n[bold cyan]>> Fingerprinting open services...[/bold cyan]\n")
    service_details = {}

    for svc in open_services:
        port    = svc["port"]
        service = svc["service"]
        console.print(f"  [yellow]→ Probing {service} on port {port}...[/yellow]")

        banner = grab_banner(host, port)
        detail = {
            "port":    port,
            "service": service,
            "banner":  banner,
            "fuzzable": True
        }

        # Extra HTTP fingerprinting
        if port in [80, 8080, 8443, 8888]:
            http_info = detect_http_info(host, port)
            detail["http_info"] = http_info
            server = http_info.get("server", "Unknown")
            status = http_info.get("status", "Unknown")
            console.print(f"    [green]Status:[/green] {status}")
            console.print(f"    [green]Server:[/green] {server}")
        else:
            console.print(f"    [green]Banner:[/green] {banner[:100]}")

        service_details[port] = detail

    # Save service report
    report = {
        "timestamp":       datetime.now().isoformat(),
        "target_host":     host,
        "ports_scanned":   list(IOT_SERVICES.keys()),
        "open_services":   open_services,
        "service_details": service_details,
        "total_open":      len(open_services),
        "total_closed":    len(closed_services),
    }

    report_path = os.path.join(REPORTS_DIR, "service_scan_report.json")
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    console.print(f"\n[bold green]✔ Service scan complete![/bold green]")
    console.print(f"[bold green]✔ Open services:[/bold green] {len(open_services)}")
    console.print(f"[bold green]✔ Report saved:[/bold green] {report_path}")

    return report


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.1"
    scan_target(host)