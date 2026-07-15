import os
import json
import struct
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

# ELF Magic bytes
ELF_MAGIC = b'\x7fELF'

# ELF constants
ET_EXEC = 2       # Executable
ET_DYN  = 3       # Shared object / PIE

# Section/segment names we care about
CANARY_SYMBOLS   = [b'__stack_chk_fail', b'__stack_chk_guard', b'stack_chk']
NX_PT_GNU_STACK  = 0x6474e551   # GNU_STACK program header type
RELRO_PT_GNU_RELRO = 0x6474e552 # GNU_RELRO

def read_elf_header(data):
    """Parse basic ELF header."""
    if len(data) < 64:
        return None
    if data[:4] != ELF_MAGIC:
        return None

    ei_class = data[4]   # 1=32bit, 2=64bit
    ei_data  = data[5]   # 1=LE, 2=BE
    endian   = '>' if ei_data == 2 else '<'

    if ei_class == 1:   # 32-bit
        fmt = f'{endian}HHIIIIIHHHHHH'
        size = struct.calcsize(fmt)
        if len(data) < 16 + size:
            return None
        fields = struct.unpack(fmt, data[16:16+size])
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, \
            e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = fields
        ph_entry_size = e_phentsize
        ph_num        = e_phnum
        ph_offset     = e_phoff
        bits = 32
    elif ei_class == 2:  # 64-bit
        fmt = f'{endian}HHIQQQIHHHHHH'
        size = struct.calcsize(fmt)
        if len(data) < 16 + size:
            return None
        fields = struct.unpack(fmt, data[16:16+size])
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, \
            e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = fields
        ph_entry_size = e_phentsize
        ph_num        = e_phnum
        ph_offset     = e_phoff
        bits = 64
    else:
        return None

    return {
        "bits": bits,
        "endian": endian,
        "e_type": e_type,
        "e_machine": e_machine,
        "ph_offset": ph_offset,
        "ph_num": ph_num,
        "ph_entry_size": ph_entry_size,
        "ei_class": ei_class
    }

def check_nx(data, header):
    """Check if GNU_STACK segment has execute permission (NX disabled)."""
    endian   = header['endian']
    bits     = header['bits']
    ph_off   = header['ph_offset']
    ph_num   = header['ph_num']
    ph_size  = header['ph_entry_size']

    nx_present    = False
    stack_exec    = False

    for i in range(ph_num):
        offset = ph_off + i * ph_size
        if bits == 32:
            if offset + 32 > len(data):
                continue
            fmt = f'{endian}IIIIIIII'
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                struct.unpack(fmt, data[offset:offset+32])
        else:
            if offset + 56 > len(data):
                continue
            fmt = f'{endian}IIQQQQQQ'
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                struct.unpack(fmt, data[offset:offset+56])

        if p_type == NX_PT_GNU_STACK:
            nx_present = True
            # PF_X = 0x1, if set stack is executable (NX disabled)
            stack_exec = bool(p_flags & 0x1)

    if not nx_present:
        return "UNKNOWN"
    return "DISABLED" if stack_exec else "ENABLED"

def check_pie(header):
    """Check if binary is PIE (Position Independent Executable)."""
    return "ENABLED" if header['e_type'] == ET_DYN else "DISABLED"

def check_canary(data):
    """Check if binary has stack canary by looking for canary symbols."""
    for sym in CANARY_SYMBOLS:
        if sym in data:
            return "ENABLED"
    return "DISABLED"

def check_relro(data, header):
    """Check for RELRO (Relocation Read-Only) protection."""
    endian   = header['endian']
    bits     = header['bits']
    ph_off   = header['ph_offset']
    ph_num   = header['ph_num']
    ph_size  = header['ph_entry_size']

    for i in range(ph_num):
        offset = ph_off + i * ph_size
        if bits == 32:
            if offset + 32 > len(data):
                continue
            fmt = f'{endian}IIIIIIII'
            fields = struct.unpack(fmt, data[offset:offset+32])
            p_type = fields[0]
        else:
            if offset + 56 > len(data):
                continue
            fmt = f'{endian}IIQQQQQQ'
            fields = struct.unpack(fmt, data[offset:offset+56])
            p_type = fields[0]

        if p_type == RELRO_PT_GNU_RELRO:
            return "ENABLED"

    return "DISABLED"

def get_arch_name(e_machine):
    """Get human-readable architecture name."""
    arch_map = {
        0x08: "MIPS",
        0x28: "ARM",
        0xB7: "AArch64",
        0x03: "x86",
        0x3E: "x86-64",
        0x14: "PowerPC",
    }
    return arch_map.get(e_machine, f"Unknown(0x{e_machine:02x})")

def score_binary(nx, pie, canary, relro):
    """Calculate security score and risk level."""
    score = 0
    if nx     == "ENABLED":  score += 25
    if pie    == "ENABLED":  score += 25
    if canary == "ENABLED":  score += 30
    if relro  == "ENABLED":  score += 20

    if score >= 75:   risk = "SECURE"
    elif score >= 40: risk = "PARTIAL"
    else:             risk = "VULNERABLE"

    return score, risk

def analyze_binary(filepath, base_dir):
    """Analyze a single ELF binary."""
    relative = os.path.relpath(filepath, base_dir).replace("\\", "/")
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception:
        return None

    if data[:4] != ELF_MAGIC:
        return None

    header = read_elf_header(data)
    if not header:
        return None

    nx     = check_nx(data, header)
    pie    = check_pie(header)
    canary = check_canary(data)
    relro  = check_relro(data, header)
    score, risk = score_binary(nx, pie, canary, relro)
    arch   = get_arch_name(header['e_machine'])
    bits   = header['bits']
    size   = round(len(data) / 1024, 2)

    return {
        "file": relative,
        "arch": f"{arch} {bits}-bit",
        "size_kb": size,
        "nx": nx,
        "pie": pie,
        "canary": canary,
        "relro": relro,
        "score": score,
        "risk": risk
    }

def analyze_binaries(extracted_dir: str) -> dict:
    console.print(Panel("[bold red]IoT Firmware Scanner[/bold red] — [cyan]Binary Analyzer Module[/cyan]", expand=False))

    if not os.path.exists(extracted_dir):
        console.print(f"[bold red]ERROR:[/bold red] Directory not found: {extracted_dir}")
        return {"success": False}

    console.print(f"\n[bold yellow]Scanning:[/bold yellow] {extracted_dir}\n")

    # Find all ELF binaries
    console.print("[bold cyan]>> Discovering ELF binaries...[/bold cyan]")
    elf_files = []
    for root, dirs, files in os.walk(extracted_dir):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                with open(full_path, 'rb') as f:
                    magic = f.read(4)
                if magic == ELF_MAGIC:
                    elf_files.append(full_path)
            except Exception:
                continue

    console.print(f"[bold green]Found {len(elf_files)} ELF binaries[/bold green]\n")

    if not elf_files:
        console.print("[yellow]No ELF binaries found.[/yellow]")
        return {"success": False, "error": "No ELF binaries found"}

    # Analyze each binary
    console.print("[bold cyan]>> Analyzing security protections...[/bold cyan]\n")
    results = []
    for filepath in elf_files:
        result = analyze_binary(filepath, extracted_dir)
        if result:
            results.append(result)

    # Sort by score ascending (most vulnerable first)
    results.sort(key=lambda x: x['score'])

    # Count risk levels
    risk_counts = {"VULNERABLE": 0, "PARTIAL": 0, "SECURE": 0}
    for r in results:
        risk_counts[r['risk']] = risk_counts.get(r['risk'], 0) + 1

    # Summary table
    summary = Table(title="Binary Security Summary", box=box.ROUNDED)
    summary.add_column("Risk Level", style="bold")
    summary.add_column("Count", justify="center")
    summary.add_column("Description")

    summary.add_row("[bold red]VULNERABLE[/bold red]",   str(risk_counts["VULNERABLE"]),  "Score < 40 — Multiple protections missing")
    summary.add_row("[bold yellow]PARTIAL[/bold yellow]", str(risk_counts["PARTIAL"]),    "Score 40-74 — Some protections present")
    summary.add_row("[bold green]SECURE[/bold green]",    str(risk_counts["SECURE"]),     "Score >= 75 — Most protections present")
    console.print(summary)
    console.print()

    # Detailed findings table
    detail = Table(title=f"Binary Analysis Results ({len(results)} binaries)", show_lines=True, box=box.SIMPLE_HEAVY)
    detail.add_column("Binary",   style="cyan",  max_width=30)
    detail.add_column("Arch",     style="white", justify="center")
    detail.add_column("NX",       justify="center")
    detail.add_column("PIE",      justify="center")
    detail.add_column("Canary",   justify="center")
    detail.add_column("RELRO",    justify="center")
    detail.add_column("Score",    justify="center")
    detail.add_column("Risk",     justify="center")

    def flag(val):
        if val == "ENABLED":  return "[green]✔[/green]"
        if val == "DISABLED": return "[red]✘[/red]"
        return "[yellow]?[/yellow]"

    def risk_color(r):
        if r == "VULNERABLE": return "[bold red]VULN[/bold red]"
        if r == "PARTIAL":    return "[bold yellow]PART[/bold yellow]"
        return "[bold green]OK[/bold green]"

    for r in results[:50]:
        binary_name = r['file'].split('/')[-1]
        detail.add_row(
            binary_name,
            r['arch'],
            flag(r['nx']),
            flag(r['pie']),
            flag(r['canary']),
            flag(r['relro']),
            str(r['score']),
            risk_color(r['risk'])
        )

    console.print(detail)
    if len(results) > 50:
        console.print(f"[yellow]... and {len(results) - 50} more binaries in report[/yellow]")

    # Most vulnerable binaries highlight
    vuln_list = [r for r in results if r['risk'] == "VULNERABLE"]
    if vuln_list:
        console.print(f"\n[bold red]🚨 Top Most Vulnerable Binaries:[/bold red]")
        for r in vuln_list[:5]:
            console.print(f"  [red]✘[/red] [cyan]{r['file']}[/cyan] — Score: {r['score']}/100 | {r['arch']}")

    # Save report
    report = {
        "timestamp": datetime.now().isoformat(),
        "extracted_directory": extracted_dir,
        "total_elf_binaries": len(results),
        "risk_summary": risk_counts,
        "binaries": results
    }

    report_path = os.path.join("reports", "binary_analysis_report.json")
    os.makedirs("reports", exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    console.print(f"\n[bold green]✔ Binary analysis complete![/bold green]")
    console.print(f"[bold green]✔ Binaries analyzed:[/bold green] {len(results)}")
    console.print(f"[bold green]✔ Report saved:[/bold green] {report_path}")

    return report


if __name__ == "__main__":
    extracted_dir = os.path.join(
        "D:\\Srinidhi_Iyer\\iot-firmware-scanner",
        "extractor", "extracted_output"
    )
    analyze_binaries(extracted_dir)