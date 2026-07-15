import os
import re
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

# ── REGEX PATTERNS ──────────────────────────────────────────────────────────

PATTERNS = {
    "CRITICAL": {
        "Private Key": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
        "Hardcoded Password Assignment": r'(?i)(password|passwd|pwd|pass)\s*[=:]\s*["\']?([^\s"\']{4,})',
        "Hardcoded Secret/Token": r'(?i)(secret|token|api_key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{8,})',
        "Default Credentials": r'(?i)(admin|root|guest)\s*[=:]\s*["\']?(admin|root|guest|password|1234|12345|0000)',
    },
    "HIGH": {
        "IP Address Hardcoded": r'\b(?:192\.168|10\.\d+|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+\b',
        "Public IP Hardcoded": r'\b(?!10\.|192\.168|172\.(?:1[6-9]|2\d|3[01]))(\d{1,3}\.){3}\d{1,3}\b',
        "Telnet Enabled": r'(?i)(telnet|telnets)',
        "Debug Shell": r'(?i)(/bin/sh|/bin/bash|/bin/ash)\s',
        "Root Shell Spawn": r'(?i)(system\s*\(\s*["\'].*sh|exec\s*\(\s*["\'].*sh)',
        "FTP Credentials": r'(?i)(ftp_user|ftp_pass|ftpuser|ftppass)\s*[=:]\s*\S+',
    },
    "MEDIUM": {
        "MD5 Usage": r'(?i)(md5|MD5_Init|MD5_Update|MD5_Final)',
        "DES Usage": r'(?i)(des_ecb|des_cbc|DES_set_key)',
        "Old SSL Version": r'(?i)(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)',
        "Weak Random": r'(?i)(rand\(\)|srand\(|random\(\))',
        "Base64 Encoded String": r'(?i)["\']([A-Za-z0-9+/]{20,}={0,2})["\']',
        "Email Address": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    },
    "LOW": {
        "URL Hardcoded": r'https?://[^\s"\'<>]{10,}',
        "Debug Print Statement": r'(?i)(printf|fprintf|dprintf)\s*\(\s*["\'].*debug',
        "TODO/FIXME Comment": r'(?i)(#|//)\s*(todo|fixme|hack|xxx|bug)',
        "Version String": r'(?i)(version|ver)\s*[=:]\s*["\']?[\d\.]+',
    }
}

# File extensions to scan (text-readable files)
SCANNABLE_EXTENSIONS = {
    "", ".txt", ".conf", ".cfg", ".ini", ".sh", ".py", ".js",
    ".html", ".htm", ".xml", ".json", ".lua", ".php", ".asp",
    ".c", ".h", ".cpp", ".mk", ".config", ".nvram", ".default",
    ".sql", ".env", ".properties", ".yaml", ".yml", ".log"
}

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "cyan",
    "LOW": "dim white"
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def is_scannable(filepath):
    """Check if file should be scanned based on extension and size."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in SCANNABLE_EXTENSIONS:
        return False
    try:
        if os.path.getsize(filepath) > 5 * 1024 * 1024:  # Skip files > 5MB
            return False
    except Exception:
        return False
    return True

def is_text_file(filepath):
    """Check if file is readable as text."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            f.read(512)
        return True
    except Exception:
        return False

def scan_file(filepath, base_dir):
    """Scan a single file for all patterns."""
    findings = []
    relative_path = os.path.relpath(filepath, base_dir).replace("\\", "/")

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_num, line in enumerate(lines, start=1):
        line = line.rstrip()
        if not line.strip():
            continue

        for severity, pattern_dict in PATTERNS.items():
            for pattern_name, pattern in pattern_dict.items():
                try:
                    matches = re.findall(pattern, line)
                    if matches:
                        # Clean match display
                        match_str = str(matches[0]) if matches else ""
                        if isinstance(match_str, tuple):
                            match_str = " | ".join(m for m in match_str if m)
                        match_str = match_str[:120]  # Truncate long matches

                        findings.append({
                            "severity": severity,
                            "pattern": pattern_name,
                            "file": relative_path,
                            "line_number": line_num,
                            "matched_content": match_str,
                            "raw_line": line.strip()[:200]
                        })
                except Exception:
                    continue

    return findings

def analyze(extracted_dir: str) -> dict:
    console.print(Panel("[bold red]IoT Firmware Scanner[/bold red] — [cyan]Static Analyzer Module[/cyan]", expand=False))

    if not os.path.exists(extracted_dir):
        console.print(f"[bold red]ERROR:[/bold red] Extracted directory not found: {extracted_dir}")
        return {"success": False, "error": "Extracted directory not found"}

    console.print(f"\n[bold yellow]Scanning:[/bold yellow] {extracted_dir}\n")

    # Collect all scannable files
    all_files = []
    for root, dirs, files in os.walk(extracted_dir):
        for file in files:
            full_path = os.path.join(root, file)
            if is_scannable(full_path) and is_text_file(full_path):
                all_files.append(full_path)

    console.print(f"[bold cyan]>> Found {len(all_files)} scannable text files[/bold cyan]\n")

    # Scan each file
    all_findings = []
    for filepath in all_files:
        findings = scan_file(filepath, extracted_dir)
        all_findings.extend(findings)

    # Also force-scan special files regardless of extension
    special_files = ["wps_default_pin.txt", "nvram", "passwd", "shadow", "config"]
    for root, dirs, files in os.walk(extracted_dir):
        for file in files:
            if file in special_files:
                full_path = os.path.join(root, file)
                if full_path not in all_files and is_text_file(full_path):
                    findings = scan_file(full_path, extracted_dir)
                    all_findings.extend(findings)
                    console.print(f"[bold red]>> Special file found and scanned:[/bold red] {file}")

    # Sort by severity
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    # Count by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    # Display summary table
    summary_table = Table(title="Scan Summary", box=box.ROUNDED)
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="center")
    summary_table.add_column("Status")

    severity_icons = {
        "CRITICAL": ("bold red", "🔴 IMMEDIATE ACTION REQUIRED"),
        "HIGH":     ("bold yellow", "🟠 High Risk"),
        "MEDIUM":   ("cyan", "🟡 Review Recommended"),
        "LOW":      ("dim white", "🟢 Low Risk / Informational"),
    }

    for sev, (color, status) in severity_icons.items():
        summary_table.add_row(
            f"[{color}]{sev}[/{color}]",
            f"[{color}]{counts[sev]}[/{color}]",
            f"[{color}]{status}[/{color}]"
        )

    console.print(summary_table)
    console.print()

    # Display findings tables per severity
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_findings = [f for f in all_findings if f["severity"] == severity]
        if not sev_findings:
            continue

        color = SEVERITY_COLORS[severity]
        table = Table(
            title=f"[{color}]{severity} Findings ({len(sev_findings)})[/{color}]",
            show_lines=True, box=box.SIMPLE_HEAVY
        )
        table.add_column("Pattern", style=color, min_width=20)
        table.add_column("File", style="cyan", max_width=40)
        table.add_column("Line", style="green", justify="right")
        table.add_column("Match", style="white", max_width=50)

        for finding in sev_findings[:20]:  # Show top 20 per severity
            table.add_row(
                finding["pattern"],
                finding["file"],
                str(finding["line_number"]),
                finding["matched_content"]
            )

        console.print(table)
        if len(sev_findings) > 20:
            console.print(f"[yellow]  ... and {len(sev_findings) - 20} more {severity} findings in report[/yellow]\n")

    # Save report
    report = {
        "timestamp": datetime.now().isoformat(),
        "extracted_directory": extracted_dir,
        "files_scanned": len(all_files),
        "total_findings": len(all_findings),
        "summary": counts,
        "findings": all_findings
    }

    report_path = os.path.join("reports", "static_analysis_report.json")
    os.makedirs("reports", exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    console.print(f"\n[bold green]✔ Static analysis complete![/bold green]")
    console.print(f"[bold green]✔ Files scanned:[/bold green] {len(all_files)}")
    console.print(f"[bold green]✔ Total findings:[/bold green] {len(all_findings)}")
    console.print(f"[bold green]✔ Report saved:[/bold green] {report_path}")

    return report


if __name__ == "__main__":
    extracted_dir = os.path.join(
        "D:\\Srinidhi_Iyer\\iot-firmware-scanner",
        "extractor", "extracted_output"
    )
    result = analyze(extracted_dir)