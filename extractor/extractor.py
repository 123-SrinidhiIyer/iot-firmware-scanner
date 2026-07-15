import subprocess
import os
import json
import magic
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

SEVENZIP = r"C:\Program Files\7-Zip\7z.exe"

def detect_file_type(filepath):
    """Detect file type using python-magic."""
    try:
        mime = magic.from_file(filepath, mime=True)
        desc = magic.from_file(filepath)
        return mime, desc
    except Exception as e:
        return "unknown", str(e)

def run_7zip_extract(firmware_path, output_dir):
    """Extract firmware using 7-Zip."""
    try:
        result = subprocess.run(
            [SEVENZIP, "x", firmware_path, f"-o{output_dir}", "-y"],
            capture_output=True, text=True
        )
        return result.stdout, result.returncode
    except Exception as e:
        return str(e), -1

def scan_with_7zip(firmware_path):
    """List contents of firmware using 7-Zip without extracting."""
    try:
        result = subprocess.run(
            [SEVENZIP, "l", firmware_path],
            capture_output=True, text=True
        )
        return result.stdout
    except Exception as e:
        return str(e)

def walk_extracted_files(output_dir):
    """Walk extracted directory and collect file info."""
    extracted_files = []
    total_size = 0

    for root, dirs, files in os.walk(output_dir):
        for file in files:
            full_path = os.path.join(root, file)
            relative_path = os.path.relpath(full_path, output_dir)
            try:
                size = os.path.getsize(full_path)
                total_size += size
                extracted_files.append({
                    "file": relative_path.replace("\\", "/"),
                    "size_kb": round(size / 1024, 2),
                    "extension": os.path.splitext(file)[1].lower()
                })
            except Exception:
                continue

    return extracted_files, total_size

def extract_firmware(firmware_path: str, output_dir: str) -> dict:
    console.print(Panel("[bold red]IoT Firmware Scanner[/bold red] — [cyan]Extractor Module[/cyan]", expand=False))

    if not os.path.exists(firmware_path):
        console.print(f"[bold red]ERROR:[/bold red] Firmware file not found: {firmware_path}")
        return {"success": False, "error": "Firmware file not found"}

    firmware_name = os.path.basename(firmware_path)
    firmware_size = round(os.path.getsize(firmware_path) / 1024, 2)

    console.print(f"\n[bold yellow]Target Firmware:[/bold yellow] {firmware_name}")
    console.print(f"[bold yellow]File Size:[/bold yellow] {firmware_size} KB")
    console.print(f"[bold yellow]Output Directory:[/bold yellow] {output_dir}\n")

    # Step 1 - Detect file type
    console.print("[bold cyan]>> Detecting firmware file type...[/bold cyan]")
    mime_type, description = detect_file_type(firmware_path)
    console.print(f"  [green]MIME:[/green] {mime_type}")
    console.print(f"  [green]Description:[/green] {description}\n")

    # Step 2 - Scan with 7-Zip
    console.print("[bold cyan]>> Scanning firmware contents with 7-Zip...[/bold cyan]")
    scan_output = scan_with_7zip(firmware_path)
    if scan_output:
        console.print(scan_output[:1500])
    else:
        console.print("[yellow]No contents detected in scan[/yellow]")

    # Step 3 - Extract with 7-Zip
    console.print("[bold cyan]>> Extracting firmware with 7-Zip...[/bold cyan]")
    os.makedirs(output_dir, exist_ok=True)
    extract_output, return_code = run_7zip_extract(firmware_path, output_dir)

    if return_code == 0:
        console.print(f"[bold green]✔ Extraction successful![/bold green]")
    else:
        console.print(f"[bold yellow]⚠ 7-Zip returned code {return_code} — attempting nested extraction...[/bold yellow]")

    console.print(extract_output[:800] if extract_output else "")

    # Step 4 - Check for nested archives and extract them too
    console.print("\n[bold cyan]>> Checking for nested compressed files...[/bold cyan]")
    nested_count = 0
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in [".gz", ".bz2", ".xz", ".zip", ".tar", ".lzma", ".7z", ".squashfs"]:
                nested_path = os.path.join(root, file)
                nested_out = os.path.join(root, file + "_extracted")
                console.print(f"  [yellow]Found nested archive:[/yellow] {file} — extracting...")
                out, code = run_7zip_extract(nested_path, nested_out)
                if code == 0:
                    console.print(f"  [green]✔ Extracted:[/green] {file}")
                    nested_count += 1
                else:
                    console.print(f"  [red]✘ Failed:[/red] {file}")

    if nested_count > 0:
        console.print(f"\n[green]✔ Extracted {nested_count} nested archive(s)[/green]")

    # Step 5 - Walk all extracted files
    console.print("\n[bold cyan]>> Scanning extracted filesystem...[/bold cyan]")
    extracted_files, total_size = walk_extracted_files(output_dir)

    # Display table
    table = Table(title=f"Extracted Files ({len(extracted_files)} total)", show_lines=True)
    table.add_column("File Path", style="cyan", no_wrap=False, max_width=70)
    table.add_column("Size (KB)", style="green", justify="right")
    table.add_column("Type", style="yellow")

    for f in extracted_files[:40]:
        table.add_row(f["file"], str(f["size_kb"]), f["extension"] or "binary")

    if extracted_files:
        console.print(table)
        if len(extracted_files) > 40:
            console.print(f"[yellow]... and {len(extracted_files) - 40} more files[/yellow]")
    else:
        console.print("[bold yellow]⚠ No files extracted.[/bold yellow]")
        console.print("[yellow]The firmware may be encrypted or in an unsupported format.[/yellow]")
        console.print("[cyan]Tip: Try a different firmware version or check if it needs decryption first.[/cyan]")

    # Step 6 - Build and save report
    report = {
        "timestamp": datetime.now().isoformat(),
        "firmware_file": firmware_name,
        "firmware_size_kb": firmware_size,
        "file_type": {
            "mime": mime_type,
            "description": description
        },
        "extraction_path": output_dir,
        "total_files_extracted": len(extracted_files),
        "total_size_kb": round(total_size / 1024, 2),
        "nested_archives_extracted": nested_count,
        "files": extracted_files,
        "success": len(extracted_files) > 0
    }

    report_path = os.path.join("reports", "extraction_report.json")
    os.makedirs("reports", exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    console.print(f"\n[bold green]✔ Total files found:[/bold green] {len(extracted_files)}")
    console.print(f"[bold green]✔ Total size:[/bold green] {round(total_size / 1024, 2)} KB")
    console.print(f"[bold green]✔ Report saved:[/bold green] {report_path}")

    return report


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        console.print("[bold red]Usage:[/bold red] python extractor.py <path_to_firmware.bin>")
        console.print("[yellow]Example:[/yellow] python extractor.py test_firmware.bin")
    else:
        firmware = sys.argv[1]
        output = os.path.join(
            "D:\\Srinidhi_Iyer\\iot-firmware-scanner",
            "extractor", "extracted_output"
        )
        result = extract_firmware(firmware, output)