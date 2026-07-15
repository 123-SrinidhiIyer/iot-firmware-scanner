import os
import sys
import time
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich import box

console = Console()

# ── PATHS ────────────────────────────────────────────────────────────────────
BASE_DIR       = r"D:\Srinidhi_Iyer\iot-firmware-scanner"
EXTRACTOR_OUT  = os.path.join(BASE_DIR, "extractor", "extracted_output")
REPORTS_DIR    = os.path.join(BASE_DIR, "reports")

# ── IMPORT MODULES ───────────────────────────────────────────────────────────
sys.path.insert(0, BASE_DIR)
from extractor.extractor          import extract_firmware
from analyzer.static_analyzer     import analyze
from analyzer.binary_analyzer     import analyze_binaries
from fuzzer.service_executor      import scan_target
from fuzzer.fuzzer                import run_fuzzer

# ── BANNER ───────────────────────────────────────────────────────────────────
def print_banner():
    console.print()
    console.print(Panel.fit(
        "[bold red]██╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ \n"
        "[bold red]██║██╔═══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗\n"
        "[bold red]██║██║   ██║   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝\n"
        "[bold red]██║██║   ██║   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗\n"
        "[bold red]██║╚██████╔╝   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║\n"
        "[bold red]╚═╝ ╚═════╝    ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝",
        title="[bold white]IoT Firmware Vulnerability Scanner[/bold white]",
        subtitle="[dim]Srinidhi B Iyer — Security Engineering Portfolio[/dim]",
        border_style="red"
    ))
    console.print()

# ── STEP PRINTER ─────────────────────────────────────────────────────────────
def step_header(num, title, description):
    console.print()
    console.print(Rule(f"[bold cyan]STEP {num}: {title}[/bold cyan]", style="cyan"))
    console.print(f"[dim]{description}[/dim]")
    console.print()

def step_done(num, title, duration):
    console.print()
    console.print(f"[bold green]✔ Step {num} Complete:[/bold green] [cyan]{title}[/cyan] [dim]({duration:.1f}s)[/dim]")
    console.print(Rule(style="green"))

def step_failed(num, title, error):
    console.print()
    console.print(f"[bold red]✘ Step {num} Failed:[/bold red] [cyan]{title}[/cyan]")
    console.print(f"[red]Error: {error}[/red]")
    console.print(Rule(style="red"))

def step_skipped(num, title, reason):
    console.print()
    console.print(f"[bold yellow]⊘ Step {num} Skipped:[/bold yellow] [cyan]{title}[/cyan]")
    console.print(f"[yellow]Reason: {reason}[/yellow]")
    console.print(Rule(style="yellow"))

# ── FINAL SUMMARY ────────────────────────────────────────────────────────────
def print_final_summary(firmware_path, target_host, results, total_time):
    console.print()
    console.print(Rule("[bold white]FINAL SCAN REPORT[/bold white]", style="white"))
    console.print()

    ext     = results.get("extraction", {})
    static  = results.get("static", {})
    binary  = results.get("binary", {})
    service = results.get("service", {})
    fuzz    = results.get("fuzz", {})

    # Main stats table
    stats = Table(title="Pipeline Results", box=box.ROUNDED, border_style="blue")
    stats.add_column("Module",   style="bold cyan",  min_width=20)
    stats.add_column("Status",   justify="center",   min_width=10)
    stats.add_column("Key Metric",                   min_width=32)
    stats.add_column("Duration", justify="right",    min_width=10)

    stats.add_row(
        "Extractor",
        "[bold green]✔ DONE[/bold green]" if ext.get("success") else "[bold red]✘ FAIL[/bold red]",
        f"{ext.get('total_files_extracted', 0)} files extracted ({ext.get('total_size_kb', 0)} KB)",
        f"{results.get('t_extract', 0):.1f}s"
    )
    stats.add_row(
        "Static Analyzer",
        "[bold green]✔ DONE[/bold green]" if static.get("files_scanned") else "[bold red]✘ FAIL[/bold red]",
        f"{static.get('files_scanned', 0)} files scanned | {static.get('total_findings', 0)} findings",
        f"{results.get('t_static', 0):.1f}s"
    )
    stats.add_row(
        "Binary Analyzer",
        "[bold green]✔ DONE[/bold green]" if binary.get("total_elf_binaries") else "[bold red]✘ FAIL[/bold red]",
        f"{binary.get('total_elf_binaries', 0)} binaries | {binary.get('risk_summary', {}).get('VULNERABLE', 0)} vulnerable",
        f"{results.get('t_binary', 0):.1f}s"
    )

    if target_host:
        stats.add_row(
            "Service Scanner",
            "[bold green]✔ DONE[/bold green]" if service else "[bold yellow]⊘ SKIP[/bold yellow]",
            f"{service.get('total_open', 0)} open ports on {target_host}",
            f"{results.get('t_service', 0):.1f}s"
        )
        stats.add_row(
            "Fuzzer",
            "[bold green]✔ DONE[/bold green]" if fuzz else "[bold yellow]⊘ SKIP[/bold yellow]",
            f"{fuzz.get('total_payloads_sent', 0)} payloads | {fuzz.get('total_interesting', 0)} interesting",
            f"{results.get('t_fuzz', 0):.1f}s"
        )
    else:
        stats.add_row("Service Scanner", "[bold yellow]⊘ SKIP[/bold yellow]", "No target host provided", "-")
        stats.add_row("Fuzzer",          "[bold yellow]⊘ SKIP[/bold yellow]", "No target host provided", "-")

    console.print(stats)
    console.print()

    # Severity breakdown
    summary = static.get("summary", {})
    sev_table = Table(title="Vulnerability Summary", box=box.ROUNDED, border_style="red")
    sev_table.add_column("Severity", style="bold", min_width=12)
    sev_table.add_column("Count",    justify="center", min_width=8)
    sev_table.add_column("Action Required")

    sev_table.add_row("[bold red]CRITICAL[/bold red]",    str(summary.get("CRITICAL", 0)), "[red]Immediate remediation required[/red]")
    sev_table.add_row("[bold yellow]HIGH[/bold yellow]",  str(summary.get("HIGH", 0)),     "[yellow]Fix before deployment[/yellow]")
    sev_table.add_row("[cyan]MEDIUM[/cyan]",              str(summary.get("MEDIUM", 0)),   "[cyan]Review and patch[/cyan]")
    sev_table.add_row("[dim white]LOW[/dim white]",       str(summary.get("LOW", 0)),      "[dim]Informational[/dim]")

    console.print(sev_table)
    console.print()

    # Binary security
    risk = binary.get("risk_summary", {})
    bin_table = Table(title="Binary Security Overview", box=box.ROUNDED, border_style="yellow")
    bin_table.add_column("Risk Level", style="bold", min_width=14)
    bin_table.add_column("Count",      justify="center", min_width=8)
    bin_table.add_column("Meaning")

    bin_table.add_row("[bold red]VULNERABLE[/bold red]",   str(risk.get("VULNERABLE", 0)), "No security mitigations — trivially exploitable")
    bin_table.add_row("[bold yellow]PARTIAL[/bold yellow]", str(risk.get("PARTIAL", 0)),   "Some protections — moderate risk")
    bin_table.add_row("[bold green]SECURE[/bold green]",    str(risk.get("SECURE", 0)),    "Strong mitigations present")

    console.print(bin_table)
    console.print()

    # Fuzzing summary (only if run)
    if fuzz:
        fuzz_table = Table(title="Fuzzing Overview", box=box.ROUNDED, border_style="magenta")
        fuzz_table.add_column("Metric", style="bold", min_width=20)
        fuzz_table.add_column("Value", justify="center", min_width=10)

        fuzz_table.add_row("Target Host",             str(target_host))
        fuzz_table.add_row("Payloads Sent",            str(fuzz.get("total_payloads_sent", 0)))
        fuzz_table.add_row("Crashes/Resets",           str(fuzz.get("total_crashes", 0)))
        fuzz_table.add_row("Timeouts (Potential DoS)", str(fuzz.get("total_timeouts", 0)))
        fuzz_table.add_row("Interesting Findings",     str(fuzz.get("total_interesting", 0)))

        console.print(fuzz_table)
        console.print()

    # Reports location
    reports_table = Table(title="Generated Reports", box=box.SIMPLE, border_style="dim")
    reports_table.add_column("Report",   style="cyan")
    reports_table.add_column("Location", style="dim")

    report_files = [
        "extraction_report.json",
        "static_analysis_report.json",
        "binary_analysis_report.json",
    ]
    if target_host:
        report_files += ["service_scan_report.json", "fuzzing_report.json"]

    for rfile in report_files:
        rpath = os.path.join(REPORTS_DIR, rfile)
        exists = "[green]✔[/green]" if os.path.exists(rpath) else "[red]✘[/red]"
        reports_table.add_row(f"{exists} {rfile}", rpath)

    console.print(reports_table)
    console.print()

    # Footer
    console.print(Panel(
        f"[bold white]Scan Complete![/bold white]\n"
        f"[dim]Firmware:[/dim] [cyan]{os.path.basename(firmware_path)}[/cyan]\n"
        f"[dim]Target Host:[/dim] [cyan]{target_host if target_host else 'Not scanned'}[/cyan]\n"
        f"[dim]Total Time:[/dim] [cyan]{total_time:.1f} seconds[/cyan]\n"
        f"[dim]Dashboard:[/dim] [cyan]python dashboard/app.py → http://localhost:5000[/cyan]\n"
        f"[dim]PDF Report:[/dim] [cyan]python reporter/pdf_reporter.py[/cyan]",
        border_style="green",
        title="[bold green]IoT Firmware Scanner — Done[/bold green]"
    ))

# ── MAIN PIPELINE ─────────────────────────────────────────────────────────────
def run_pipeline(firmware_path: str, target_host: str = None):
    print_banner()

    if not os.path.exists(firmware_path):
        console.print(f"[bold red]ERROR:[/bold red] Firmware file not found: {firmware_path}")
        sys.exit(1)

    firmware_name = os.path.basename(firmware_path)
    console.print(f"[bold yellow]Firmware:[/bold yellow]    {firmware_name}")
    console.print(f"[bold yellow]Size:[/bold yellow]        {round(os.path.getsize(firmware_path)/1024, 2)} KB")
    console.print(f"[bold yellow]Target Host:[/bold yellow] {target_host if target_host else 'Not provided — skipping fuzzing'}")
    console.print(f"[bold yellow]Time:[/bold yellow]        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print()

    results     = {}
    total_start = time.time()

    # ── STEP 1: EXTRACTION ──────────────────────────────────────────────────
    step_header(1, "FIRMWARE EXTRACTION",
                "Unpacking firmware filesystem using 7-Zip and file type detection")
    t0 = time.time()
    try:
        results["extraction"] = extract_firmware(firmware_path, EXTRACTOR_OUT)
        results["t_extract"]  = time.time() - t0
        step_done(1, "Firmware Extraction", results["t_extract"])
    except Exception as e:
        step_failed(1, "Firmware Extraction", str(e))
        results["extraction"] = {"success": False}
        results["t_extract"]  = time.time() - t0

    # ── STEP 2: STATIC ANALYSIS ─────────────────────────────────────────────
    step_header(2, "STATIC ANALYSIS",
                "Scanning extracted files for hardcoded credentials, weak crypto, and backdoors")
    t0 = time.time()
    try:
        results["static"]   = analyze(EXTRACTOR_OUT)
        results["t_static"] = time.time() - t0
        step_done(2, "Static Analysis", results["t_static"])
    except Exception as e:
        step_failed(2, "Static Analysis", str(e))
        results["static"]   = {}
        results["t_static"] = time.time() - t0

    # ── STEP 3: BINARY ANALYSIS ─────────────────────────────────────────────
    step_header(3, "BINARY ANALYSIS",
                "Checking all ELF binaries for missing security mitigations (NX, PIE, Canary, RELRO)")
    t0 = time.time()
    try:
        results["binary"]   = analyze_binaries(EXTRACTOR_OUT)
        results["t_binary"] = time.time() - t0
        step_done(3, "Binary Analysis", results["t_binary"])
    except Exception as e:
        step_failed(3, "Binary Analysis", str(e))
        results["binary"]   = {}
        results["t_binary"] = time.time() - t0

    # ── STEP 4: SERVICE SCAN ────────────────────────────────────────────────
    if target_host:
        step_header(4, "SERVICE DISCOVERY",
                    f"Scanning {target_host} for open IoT services (HTTP, Telnet, FTP, MQTT, etc.)")
        t0 = time.time()
        try:
            results["service"]   = scan_target(target_host)
            results["t_service"] = time.time() - t0
            step_done(4, "Service Discovery", results["t_service"])
        except Exception as e:
            step_failed(4, "Service Discovery", str(e))
            results["service"]   = {}
            results["t_service"] = time.time() - t0
    else:
        step_skipped(4, "Service Discovery", "No target host provided (usage: python main.py <firmware> <host>)")
        results["service"]   = {}
        results["t_service"] = 0

    # ── STEP 5: FUZZING ─────────────────────────────────────────────────────
    if target_host and results.get("service", {}).get("total_open", 0) > 0:
        step_header(5, "NETWORK FUZZING",
                    f"Sending malformed payloads to open services on {target_host}")
        t0 = time.time()
        try:
            results["fuzz"]   = run_fuzzer(target_host)
            results["t_fuzz"] = time.time() - t0
            step_done(5, "Network Fuzzing", results["t_fuzz"])
        except Exception as e:
            step_failed(5, "Network Fuzzing", str(e))
            results["fuzz"]   = {}
            results["t_fuzz"] = time.time() - t0
    else:
        reason = "No target host provided" if not target_host else "No open services found to fuzz"
        step_skipped(5, "Network Fuzzing", reason)
        results["fuzz"]   = {}
        results["t_fuzz"] = 0

    # ── FINAL SUMMARY ────────────────────────────────────────────────────────
    total_time = time.time() - total_start
    print_final_summary(firmware_path, target_host, results, total_time)

    # Save master report
    master_report = {
        "timestamp":     datetime.now().isoformat(),
        "firmware":      firmware_name,
        "target_host":   target_host,
        "total_time_s":  round(total_time, 2),
        "pipeline": {
            "extraction": results.get("extraction", {}),
            "static":     results.get("static", {}),
            "binary":     results.get("binary", {}),
            "service":    results.get("service", {}),
            "fuzz":       results.get("fuzz", {}),
        }
    }
    master_path = os.path.join(REPORTS_DIR, "master_report.json")
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(master_path, "w") as f:
        json.dump(master_report, f, indent=4)

    console.print(f"\n[dim]Master report saved: {master_path}[/dim]")

# ── ENTRY POINT ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print(Panel(
            "[bold red]Usage:[/bold red]   python main.py <firmware.bin> [target_host]\n"
            "[bold yellow]Example (firmware only):[/bold yellow] python main.py test_firmware.bin\n"
            "[bold yellow]Example (full pipeline):[/bold yellow]  python main.py test_firmware.bin 10.121.160.43\n\n"
            "[dim]This will run the full pipeline:\n"
            "  1. Extract firmware filesystem\n"
            "  2. Static analysis (credentials, crypto, backdoors)\n"
            "  3. Binary analysis (NX, PIE, Canary, RELRO)\n"
            "  4. Service discovery (if target_host given)\n"
            "  5. Network fuzzing (if target_host given)[/dim]",
            title="[bold white]IoT Firmware Vulnerability Scanner[/bold white]",
            border_style="red"
        ))
        sys.exit(0)

    firmware = sys.argv[1]
    if not os.path.isabs(firmware):
        firmware = os.path.join(BASE_DIR, firmware)

    target_host = sys.argv[2] if len(sys.argv) > 2 else None

    run_pipeline(firmware, target_host)