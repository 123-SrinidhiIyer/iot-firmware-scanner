import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, NextPageTemplate
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate

# ── PATHS ────────────────────────────────────────────────────────────────────
BASE_DIR    = r"D:\Srinidhi_Iyer\iot-firmware-scanner"
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
OUTPUT_PDF  = os.path.join(REPORTS_DIR, "IoT_Firmware_Security_Report.pdf")

# ── COLORS ───────────────────────────────────────────────────────────────────
C_BG        = colors.HexColor("#0D1B2A")
C_RED       = colors.HexColor("#C0392B")
C_BLUE      = colors.HexColor("#4A90D9")
C_DARK      = colors.HexColor("#1a2a4a")
C_LIGHT     = colors.HexColor("#F5F8FC")
C_LIGHTER   = colors.HexColor("#E8EFF7")
C_WHITE     = colors.white
C_GRAY      = colors.HexColor("#888888")
C_CRITICAL  = colors.HexColor("#FDECEA")
C_HIGH      = colors.HexColor("#FFF8E1")
C_MEDIUM    = colors.HexColor("#E3F2FD")
C_LOW       = colors.HexColor("#E8F5E9")
C_CRIT_TEXT = colors.HexColor("#C0392B")
C_HIGH_TEXT = colors.HexColor("#E67E22")
C_MED_TEXT  = colors.HexColor("#2980B9")
C_LOW_TEXT  = colors.HexColor("#27AE60")
C_TEXT      = colors.HexColor("#1a1a1a")

W, H = A4

# ── STYLES ───────────────────────────────────────────────────────────────────
styles = getSampleStyleSheet()

def style(name, **kwargs):
    return ParagraphStyle(name, parent=styles["Normal"], **kwargs)

TITLE_STYLE    = style("Title",   fontSize=20, fontName="Helvetica-Bold",
                        textColor=C_WHITE, alignment=TA_CENTER, spaceAfter=6)
SUBTITLE_STYLE = style("Sub",     fontSize=12, fontName="Helvetica",
                        textColor=C_BLUE,  alignment=TA_CENTER, spaceAfter=4)
META_STYLE     = style("Meta",    fontSize=9,  fontName="Helvetica",
                        textColor=C_GRAY,  alignment=TA_CENTER, spaceAfter=2)
SECTION_STYLE  = style("Section", fontSize=12, fontName="Helvetica-Bold",
                        textColor=C_BG,    spaceBefore=12, spaceAfter=4)
BODY_STYLE     = style("Body",    fontSize=9,  fontName="Helvetica",
                        textColor=C_TEXT,  spaceAfter=4, leading=14)
BULLET_STYLE   = style("Bullet",  fontSize=9,  fontName="Helvetica",
                        textColor=C_TEXT,  leftIndent=14, spaceAfter=3, leading=13)
MONO_STYLE     = style("Mono",    fontSize=8,  fontName="Courier",
                        textColor=C_BG,    backColor=C_LIGHT,
                        leftIndent=8, spaceAfter=2, leading=12)
FOOTER_STYLE   = style("Footer",  fontSize=7.5, fontName="Helvetica",
                        textColor=C_GRAY,  alignment=TA_CENTER)
LABEL_STYLE    = style("Label",   fontSize=9,  fontName="Helvetica-Bold",
                        textColor=C_BLUE,  spaceAfter=2)

# ── HELPERS ──────────────────────────────────────────────────────────────────
def section(text):
    return [
        Spacer(1, 8),
        Paragraph(text, SECTION_STYLE),
        HRFlowable(width="100%", thickness=1.5, color=C_BLUE, spaceAfter=6),
    ]

def bullet(text):
    return Paragraph(f"• {text}", BULLET_STYLE)

def body(text):
    return Paragraph(text, BODY_STYLE)

def sev_color_bg(sev):
    return {"CRITICAL": C_CRITICAL, "HIGH": C_HIGH,
            "MEDIUM": C_MEDIUM, "LOW": C_LOW}.get(sev, C_LIGHT)

def sev_color_text(sev):
    return {"CRITICAL": C_CRIT_TEXT, "HIGH": C_HIGH_TEXT,
            "MEDIUM": C_MED_TEXT, "LOW": C_LOW_TEXT}.get(sev, colors.black)

def make_table(data, col_widths):
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0,0), (-1,0), C_BG),
        ("TEXTCOLOR",      (0,0), (-1,0), C_WHITE),
        ("FONTNAME",       (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_LIGHT, C_LIGHTER]),
        ("GRID",           (0,0), (-1,-1), 0.4, colors.HexColor("#CCCCCC")),
        ("PADDING",        (0,0), (-1,-1), 5),
        ("VALIGN",         (0,0), (-1,-1), "TOP"),
        ("TEXTCOLOR",      (0,1), (-1,-1), C_TEXT),
    ]))
    return t

def load_report(filename):
    path = os.path.join(REPORTS_DIR, filename)
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return None

# ── PAGE BACKGROUNDS ─────────────────────────────────────────────────────────
def cover_page_bg(canvas, doc):
    canvas.saveState()
    # Full dark background
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    # Red top bar
    canvas.setFillColor(C_RED)
    canvas.rect(0, H - 8*mm, W, 8*mm, fill=1, stroke=0)
    # Blue bottom bar
    canvas.setFillColor(C_BLUE)
    canvas.rect(0, 0, W, 6*mm, fill=1, stroke=0)
    canvas.restoreState()

def normal_page(canvas, doc):
    canvas.saveState()
    # White background for entire page
    canvas.setFillColor(colors.white)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    # Dark top header bar
    canvas.setFillColor(C_BG)
    canvas.rect(0, H - 14*mm, W, 14*mm, fill=1, stroke=0)
    # Red accent line under header
    canvas.setFillColor(C_RED)
    canvas.rect(0, H - 15.5*mm, W, 1.5*mm, fill=1, stroke=0)
    # Header text
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(C_WHITE)
    canvas.drawString(20*mm, H - 10*mm, "IoT Firmware Vulnerability Scanner")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_BLUE)
    canvas.drawRightString(W - 20*mm, H - 10*mm, "CONFIDENTIAL — Security Research Report")
    # Dark bottom footer bar
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, W, 12*mm, fill=1, stroke=0)
    # Blue accent line above footer
    canvas.setFillColor(C_BLUE)
    canvas.rect(0, 11.5*mm, W, 0.5*mm, fill=1, stroke=0)
    # Footer text
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_GRAY)
    canvas.drawString(20*mm, 4*mm, "Srinidhi B Iyer — Security Engineering Portfolio")
    canvas.drawRightString(W - 20*mm, 4*mm, f"Page {doc.page}")
    canvas.restoreState()

# ── COVER PAGE ───────────────────────────────────────────────────────────────
def build_cover(ext, static, binary):
    story = []
    story.append(Spacer(1, 38*mm))
    story.append(Paragraph("IoT FIRMWARE", TITLE_STYLE))
    story.append(Paragraph("VULNERABILITY ASSESSMENT REPORT", TITLE_STYLE))
    story.append(Spacer(1, 5*mm))
    story.append(HRFlowable(width="55%", thickness=2, color=C_RED,
                             spaceAfter=5, hAlign="CENTER"))
    story.append(Spacer(1, 3*mm))

    firmware_name = ext.get("firmware_file", "Unknown") if ext else "Unknown"
    story.append(Paragraph(f"Target: {firmware_name}", SUBTITLE_STYLE))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}", META_STYLE))
    story.append(Paragraph(
        "Classification: CONFIDENTIAL — Research Purposes Only", META_STYLE))
    story.append(Spacer(1, 10*mm))

    summary  = static.get("summary", {}) if static else {}
    risk     = binary.get("risk_summary", {}) if binary else {}

    cover_data = [
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "VULN BINARIES"],
        [
            str(summary.get("CRITICAL", 0)),
            str(summary.get("HIGH", 0)),
            str(summary.get("MEDIUM", 0)),
            str(summary.get("LOW", 0)),
            str(risk.get("VULNERABLE", 0)),
        ]
    ]
    ct = Table(cover_data, colWidths=[30*mm]*5)
    ct.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), C_DARK),
        ("BACKGROUND",  (0,0), (0,0),  colors.HexColor("#3d0a0a")),
        ("TEXTCOLOR",   (0,0), (0,0),  C_CRIT_TEXT),
        ("TEXTCOLOR",   (1,0), (-1,0), C_GRAY),
        ("FONTNAME",    (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,0),  7),
        ("FONTSIZE",    (0,1), (-1,1),  20),
        ("TEXTCOLOR",   (0,1), (0,1),  C_CRIT_TEXT),
        ("TEXTCOLOR",   (1,1), (1,1),  C_HIGH_TEXT),
        ("TEXTCOLOR",   (2,1), (2,1),  C_MED_TEXT),
        ("TEXTCOLOR",   (3,1), (3,1),  C_LOW_TEXT),
        ("TEXTCOLOR",   (4,1), (4,1),  C_WHITE),
        ("BACKGROUND",  (0,1), (-1,1), C_DARK),
        ("ALIGN",       (0,0), (-1,-1), "CENTER"),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("PADDING",     (0,0), (-1,-1), 8),
        ("LINEABOVE",   (0,0), (-1,0),  2, C_RED),
        ("LINEBELOW",   (0,-1),(-1,-1), 2, C_BLUE),
    ]))
    story.append(ct)
    story.append(Spacer(1, 10*mm))

    author_data = [
        ["Prepared By",      "Tool",                   "Architecture",                                                         "Files Extracted"],
        ["Srinidhi B Iyer",  "IoT Firmware Scanner v1.0",
         ext.get("file_type", {}).get("description", "N/A")[:30] if ext else "N/A",
         f"{ext.get('total_files_extracted', 0)} files" if ext else "N/A"]
    ]
    at = Table(author_data, colWidths=[40*mm, 50*mm, 55*mm, 45*mm])
    at.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), C_DARK),
        ("TEXTCOLOR",  (0,0), (-1,0), C_BLUE),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTNAME",   (0,1), (-1,1), "Helvetica"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("TEXTCOLOR",  (0,1), (-1,1), C_WHITE),
        ("BACKGROUND", (0,1), (-1,1), colors.HexColor("#111827")),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("PADDING",    (0,0), (-1,-1), 7),
        ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#2a3a5c")),
    ]))
    story.append(at)
    story.append(PageBreak())
    return story

# ── EXECUTIVE SUMMARY ────────────────────────────────────────────────────────
def build_executive_summary(ext, static, binary):
    story = []
    story += section("1. Executive Summary")

    summary  = static.get("summary", {}) if static else {}
    risk     = binary.get("risk_summary", {}) if binary else {}
    total    = static.get("total_findings", 0) if static else 0
    fw_name  = ext.get("firmware_file", "Unknown") if ext else "Unknown"
    fw_size  = ext.get("firmware_size_kb", 0) if ext else 0
    files    = ext.get("total_files_extracted", 0) if ext else 0
    scanned  = static.get("files_scanned", 0) if static else 0
    binaries = binary.get("total_elf_binaries", 0) if binary else 0
    vuln_bin = risk.get("VULNERABLE", 0)

    story.append(body(
        f"This report presents the findings of an automated firmware security assessment "
        f"conducted on <b>{fw_name}</b> ({fw_size} KB). The assessment was performed using "
        f"the IoT Firmware Vulnerability Scanner, a custom-built security research tool "
        f"developed as part of a Security Engineering portfolio project."
    ))
    story.append(body(
        f"The firmware was successfully extracted yielding <b>{files} files</b> totaling "
        f"{ext.get('total_size_kb', 0) if ext else 0} KB. Static analysis was performed "
        f"across <b>{scanned} text files</b>, and binary security analysis was conducted "
        f"on <b>{binaries} ELF executables</b>."
    ))
    story.append(Spacer(1, 4))

    # Overall risk rating
    crit = summary.get("CRITICAL", 0)
    if crit > 0:
        overall, overall_color, rating_bg = "CRITICAL", C_CRIT_TEXT, colors.HexColor("#3d0a0a")
    elif summary.get("HIGH", 0) > 5:
        overall, overall_color, rating_bg = "HIGH", C_HIGH_TEXT, colors.HexColor("#3d2200")
    else:
        overall, overall_color, rating_bg = "MEDIUM", C_MED_TEXT, colors.HexColor("#0a1f3d")

    rt = Table([["OVERALL RISK RATING", overall]], colWidths=[120*mm, 60*mm])
    rt.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,0), C_DARK),
        ("BACKGROUND", (1,0), (1,0), rating_bg),
        ("TEXTCOLOR",  (0,0), (0,0), C_GRAY),
        ("TEXTCOLOR",  (1,0), (1,0), overall_color),
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (0,0),  9),
        ("FONTSIZE",   (1,0), (1,0),  14),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("PADDING",    (0,0), (-1,-1), 10),
        ("BOX",        (0,0), (-1,-1), 1.5, overall_color),
    ]))
    story.append(rt)
    story.append(Spacer(1, 6))

    story.append(Paragraph("Key Findings:", LABEL_STYLE))
    story.append(bullet(f"{summary.get('CRITICAL', 0)} Critical severity findings requiring immediate remediation"))
    story.append(bullet(f"{summary.get('HIGH', 0)} High severity findings including hardcoded IPs and debug shells"))
    story.append(bullet(f"{vuln_bin} of {binaries} binaries ({int(vuln_bin/binaries*100) if binaries else 0}%) lack ALL security mitigations"))
    story.append(bullet("SSLv3 usage detected — vulnerable to POODLE attack (CVE-2014-3566)"))
    story.append(bullet("Hardcoded admin credentials found in web administration panel source"))
    story.append(bullet("Debug shell spawning detected in CLI binary"))
    story.append(Spacer(1, 4))

    story += section("2. Assessment Scope & Methodology")
    scope_data = [
        ["Parameter",         "Details"],
        ["Firmware File",     fw_name],
        ["File Size",         f"{fw_size} KB"],
        ["File Type",         ext.get("file_type", {}).get("description", "N/A")[:60] if ext else "N/A"],
        ["Files Extracted",   f"{files} files ({ext.get('total_size_kb', 0) if ext else 0} KB)"],
        ["Files Scanned",     f"{scanned} text/config files"],
        ["Binaries Analyzed", f"{binaries} ELF executables"],
        ["Tool Used",         "IoT Firmware Scanner v1.0 (Custom)"],
        ["Scan Date",         datetime.now().strftime("%Y-%m-%d %H:%M")],
        ["Analyst",           "Srinidhi B Iyer"],
    ]
    story.append(make_table(scope_data, [60*mm, 120*mm]))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Methodology:", LABEL_STYLE))
    for step in [
        "Firmware extraction using 7-Zip with nested archive support",
        "File type detection via python-magic for format identification",
        "Static analysis using regex pattern matching across 570+ vulnerability signatures",
        "ELF binary analysis via manual header parsing (no external tools required)",
        "Security mitigation checks: NX bit, PIE, Stack Canary, RELRO",
    ]:
        story.append(bullet(step))

    return story

# ── STATIC ANALYSIS FINDINGS ─────────────────────────────────────────────────
def build_static_findings(static):
    story = []
    story += section("3. Static Analysis Findings")

    if not static:
        story.append(body("No static analysis report found."))
        return story

    summary  = static.get("summary", {})
    findings = static.get("findings", [])

    sev_data = [
        ["Severity", "Count", "Risk Level",  "Recommended Action"],
        ["CRITICAL", str(summary.get("CRITICAL", 0)), "Immediate",  "Fix before any deployment"],
        ["HIGH",     str(summary.get("HIGH", 0)),     "High",       "Fix within 24-48 hours"],
        ["MEDIUM",   str(summary.get("MEDIUM", 0)),   "Moderate",   "Schedule for patching"],
        ["LOW",      str(summary.get("LOW", 0)),       "Low",        "Review and document"],
    ]
    sev_bgs  = [C_CRITICAL, C_HIGH, C_MEDIUM, C_LOW]
    sev_tcs  = [C_CRIT_TEXT, C_HIGH_TEXT, C_MED_TEXT, C_LOW_TEXT]
    cmds = [
        ("BACKGROUND", (0,0), (-1,0), C_BG),
        ("TEXTCOLOR",  (0,0), (-1,0), C_WHITE),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("GRID",       (0,0), (-1,-1), 0.4, colors.HexColor("#CCCCCC")),
        ("PADDING",    (0,0), (-1,-1), 6),
        ("TEXTCOLOR",  (0,1), (-1,-1), C_TEXT),
    ]
    for i, (bg, tc) in enumerate(zip(sev_bgs, sev_tcs), start=1):
        cmds += [
            ("BACKGROUND", (0,i), (0,i), bg),
            ("TEXTCOLOR",  (0,i), (0,i), tc),
            ("FONTNAME",   (0,i), (0,i), "Helvetica-Bold"),
        ]
    st = Table(sev_data, colWidths=[35*mm, 25*mm, 35*mm, 85*mm])
    st.setStyle(TableStyle(cmds))
    story.append(st)
    story.append(Spacer(1, 8))

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_findings = [f for f in findings if f["severity"] == sev]
        if not sev_findings:
            continue

        story.append(Paragraph(
            f"{sev} Findings ({len(sev_findings)})",
            ParagraphStyle(f"sev_{sev}", parent=styles["Normal"],
                fontSize=10, fontName="Helvetica-Bold",
                textColor=sev_color_text(sev), spaceBefore=8, spaceAfter=4)
        ))

        fd = [["Pattern", "File", "Line", "Match"]]
        for f in sev_findings[:15]:
            fd.append([
                Paragraph(f["pattern"][:30], BODY_STYLE),
                Paragraph(f["file"][:40],    MONO_STYLE),
                str(f["line_number"]),
                Paragraph(str(f["matched_content"])[:50], BODY_STYLE),
            ])

        ft = Table(fd, colWidths=[45*mm, 55*mm, 12*mm, 68*mm], repeatRows=1)
        ft.setStyle(TableStyle([
            ("BACKGROUND",     (0,0), (-1,0), C_BG),
            ("TEXTCOLOR",      (0,0), (-1,0), C_WHITE),
            ("FONTNAME",       (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 7.5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [sev_color_bg(sev), C_LIGHTER]),
            ("GRID",           (0,0), (-1,-1), 0.3, colors.HexColor("#CCCCCC")),
            ("PADDING",        (0,0), (-1,-1), 4),
            ("VALIGN",         (0,0), (-1,-1), "TOP"),
            ("TEXTCOLOR",      (0,1), (-1,-1), C_TEXT),
        ]))
        story.append(ft)

        if len(sev_findings) > 15:
            story.append(Paragraph(
                f"  ... and {len(sev_findings) - 15} more {sev} findings in JSON report",
                FOOTER_STYLE
            ))
        story.append(Spacer(1, 4))

    return story

# ── BINARY ANALYSIS ──────────────────────────────────────────────────────────
def build_binary_findings(binary):
    story = []
    story += section("4. Binary Security Analysis")

    if not binary:
        story.append(body("No binary analysis report found."))
        return story

    risk     = binary.get("risk_summary", {})
    binaries = binary.get("binaries", [])
    total    = binary.get("total_elf_binaries", 0)

    story.append(body(
        f"Binary security analysis was performed on {total} ELF executables extracted "
        f"from the firmware. Each binary was inspected for the presence of four key security "
        f"mitigations: NX (No-Execute), PIE (Position Independent Executable), Stack Canary, "
        f"and RELRO (Relocation Read-Only). Absence of these protections significantly "
        f"increases exploitability."
    ))
    story.append(Spacer(1, 4))

    risk_data = [
        ["Risk Level", "Count", "% of Total", "Meaning"],
        ["VULNERABLE", str(risk.get("VULNERABLE", 0)),
         f"{int(risk.get('VULNERABLE',0)/total*100) if total else 0}%",
         "Score < 40 — No security mitigations"],
        ["PARTIAL",    str(risk.get("PARTIAL", 0)),
         f"{int(risk.get('PARTIAL',0)/total*100) if total else 0}%",
         "Score 40-74 — Some protections present"],
        ["SECURE",     str(risk.get("SECURE", 0)),
         f"{int(risk.get('SECURE',0)/total*100) if total else 0}%",
         "Score >= 75 — Strong mitigations"],
    ]
    rt = Table(risk_data, colWidths=[35*mm, 25*mm, 25*mm, 95*mm])
    rt.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), C_BG),
        ("TEXTCOLOR",  (0,0), (-1,0), C_WHITE),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("TEXTCOLOR",  (0,1), (0,1),  C_CRIT_TEXT),
        ("TEXTCOLOR",  (0,2), (0,2),  C_HIGH_TEXT),
        ("TEXTCOLOR",  (0,3), (0,3),  C_LOW_TEXT),
        ("BACKGROUND", (0,1), (-1,1), C_CRITICAL),
        ("BACKGROUND", (0,2), (-1,2), C_HIGH),
        ("BACKGROUND", (0,3), (-1,3), C_LOW),
        ("FONTNAME",   (0,1), (0,-1), "Helvetica-Bold"),
        ("TEXTCOLOR",  (1,1), (-1,-1), C_TEXT),
        ("GRID",       (0,0), (-1,-1), 0.4, colors.HexColor("#CCCCCC")),
        ("PADDING",    (0,0), (-1,-1), 6),
    ]))
    story.append(rt)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Security Mitigation Reference:", LABEL_STYLE))
    mit_data = [
        ["Mitigation",                   "Purpose & Impact if Missing"],
        ["NX (No-Execute)",              "Prevents execution of code on the stack/heap. Disabled = stack-based shellcode works."],
        ["PIE (Position Independent)",   "Randomizes binary load address. Disabled = fixed addresses, ROP chains trivial."],
        ["Stack Canary",                 "Detects stack buffer overflows before return. Disabled = BOF exploits undetected."],
        ["RELRO",                        "Makes GOT read-only after init. Disabled = GOT overwrite attacks possible."],
    ]
    mt = Table(mit_data, colWidths=[55*mm, 125*mm])
    mt.setStyle(TableStyle([
        ("BACKGROUND",     (0,0), (-1,0), C_BG),
        ("TEXTCOLOR",      (0,0), (-1,0), C_WHITE),
        ("FONTNAME",       (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_LIGHT, C_LIGHTER]),
        ("FONTNAME",       (0,1), (0,-1), "Helvetica-Bold"),
        ("TEXTCOLOR",      (0,1), (0,-1), C_BLUE),
        ("TEXTCOLOR",      (1,1), (1,-1), C_TEXT),
        ("GRID",           (0,0), (-1,-1), 0.3, colors.HexColor("#CCCCCC")),
        ("PADDING",        (0,0), (-1,-1), 6),
    ]))
    story.append(mt)
    story.append(Spacer(1, 8))

    story.append(Paragraph(f"Binary Analysis Results (showing 30 of {total}):", LABEL_STYLE))
    bd = [["Binary", "Arch", "NX", "PIE", "Canary", "RELRO", "Score", "Risk"]]
    for b in binaries[:30]:
        def flag(v):
            return "YES" if v == "ENABLED" else ("NO" if v == "DISABLED" else "?")
        bd.append([
            Paragraph(b["file"].split("/")[-1], MONO_STYLE),
            b["arch"],
            flag(b["nx"]),
            flag(b["pie"]),
            flag(b["canary"]),
            flag(b["relro"]),
            f"{b['score']}/100",
            b["risk"],
        ])

    bt = Table(bd, colWidths=[38*mm, 25*mm, 12*mm, 12*mm, 16*mm, 15*mm, 18*mm, 24*mm],
               repeatRows=1)
    bt_cmds = [
        ("BACKGROUND",  (0,0), (-1,0), C_BG),
        ("TEXTCOLOR",   (0,0), (-1,0), C_WHITE),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 7.5),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_LIGHT, C_LIGHTER]),
        ("GRID",        (0,0), (-1,-1), 0.3, colors.HexColor("#CCCCCC")),
        ("PADDING",     (0,0), (-1,-1), 4),
        ("ALIGN",       (2,0), (7,-1), "CENTER"),
        ("TEXTCOLOR",   (0,1), (-1,-1), C_TEXT),
    ]
    for i, b in enumerate(binaries[:30], start=1):
        if b["risk"] == "VULNERABLE":
            bt_cmds += [("TEXTCOLOR", (7,i), (7,i), C_CRIT_TEXT),
                        ("FONTNAME",  (7,i), (7,i), "Helvetica-Bold")]
        for col, key in [(2,"nx"),(3,"pie"),(4,"canary"),(5,"relro")]:
            if b[key] == "DISABLED":
                bt_cmds.append(("TEXTCOLOR", (col,i), (col,i), C_CRIT_TEXT))
            elif b[key] == "ENABLED":
                bt_cmds.append(("TEXTCOLOR", (col,i), (col,i), C_LOW_TEXT))
    bt.setStyle(TableStyle(bt_cmds))
    story.append(bt)
    return story

# ── RECOMMENDATIONS ──────────────────────────────────────────────────────────
def build_recommendations():
    story = []
    story += section("5. Recommendations & Remediation")

    recs = [
        ("CRITICAL", "Remove Hardcoded Credentials",
         "All hardcoded passwords, tokens, and default credentials must be removed from firmware. "
         "Implement runtime credential management with secure storage (e.g., TPM or encrypted NVRAM)."),
        ("CRITICAL", "Eliminate Debug Shells",
         "Remove or disable all debug shell spawning code (/bin/sh, /bin/ash) from production "
         "binaries. Debug interfaces should be compile-time disabled in release builds."),
        ("HIGH", "Enable Compiler Security Flags",
         "Recompile all binaries with: -fstack-protector-all (Canary), -fPIE -pie (PIE), "
         "-Wl,-z,relro,-z,now (RELRO), -D_FORTIFY_SOURCE=2 (NX). "
         "This alone would significantly raise the security score of all 119 binaries."),
        ("HIGH", "Upgrade Crypto Libraries",
         "Replace all MD5 usage with SHA-256. Disable SSLv3 and TLS 1.0/1.1 — "
         "enforce TLS 1.2 minimum. Update OpenSSL to latest stable version."),
        ("HIGH", "Remove Telnet / Enable SSH Only",
         "Telnet transmits credentials in plaintext. Disable telnetd and replace "
         "with SSH using key-based authentication."),
        ("MEDIUM", "Implement Secure Boot",
         "Add cryptographic verification of firmware integrity at boot time to prevent "
         "unauthorized firmware modification."),
        ("MEDIUM", "Network Hardening",
         "Remove hardcoded internal IP addresses. Implement proper network configuration "
         "management. Restrict management interfaces to dedicated VLANs."),
        ("LOW", "Remove Debug Artifacts",
         "Strip all debug symbols, build paths, developer emails, and TODO comments "
         "from production firmware before release."),
    ]

    for sev, title, desc in recs:
        color = sev_color_text(sev)
        bg    = sev_color_bg(sev)
        rec_data = [[
            Paragraph(f"[{sev}]\n{title}",
                ParagraphStyle("rt", parent=styles["Normal"],
                    fontSize=8, fontName="Helvetica-Bold", textColor=color)),
            Paragraph(desc, BODY_STYLE)
        ]]
        rec_t = Table(rec_data, colWidths=[45*mm, 130*mm])
        rec_t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (0,0), bg),
            ("BACKGROUND", (1,0), (1,0), colors.white),
            ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#CCCCCC")),
            ("PADDING",    (0,0), (-1,-1), 7),
            ("VALIGN",     (0,0), (-1,-1), "TOP"),
            ("LINEABOVE",  (0,0), (-1,0), 0.5, color),
        ]))
        story.append(rec_t)
        story.append(Spacer(1, 3))

    return story

# ── DISCLAIMER ───────────────────────────────────────────────────────────────
def build_disclaimer():
    story = []
    story += section("6. Disclaimer")
    story.append(body(
        "This security assessment was conducted for educational and portfolio demonstration "
        "purposes only. The firmware analyzed is publicly available legacy firmware. All findings "
        "are presented for research and learning purposes. This tool and its findings should not "
        "be used for unauthorized access to any systems. The author assumes no liability for "
        "misuse of this tool or its findings."
    ))
    story.append(Spacer(1, 4))
    story.append(body(
        "IoT Firmware Vulnerability Scanner is an open-source portfolio project by Srinidhi B Iyer, "
        "Electronics and Communication Engineering student, Vidyavardhaka College of Engineering, "
        "Mysuru. Built to demonstrate practical security engineering skills including firmware "
        "analysis, static code analysis, binary security assessment, and automated vulnerability "
        "detection."
    ))
    return story

# ── MAIN BUILD ───────────────────────────────────────────────────────────────
def generate_report():
    print("Loading reports...")
    ext    = load_report("extraction_report.json")
    static = load_report("static_analysis_report.json")
    binary = load_report("binary_analysis_report.json")

    if not any([ext, static, binary]):
        print("ERROR: No reports found in", REPORTS_DIR)
        print("Run main.py first to generate reports.")
        return

    print("Building PDF...")

    cover_frame  = Frame(0, 0, W, H,
                         leftPadding=25*mm, rightPadding=25*mm,
                         topPadding=20*mm,  bottomPadding=20*mm)
    normal_frame = Frame(0, 0, W, H,
                         leftPadding=20*mm, rightPadding=20*mm,
                         topPadding=20*mm,  bottomPadding=20*mm)

    doc = BaseDocTemplate(
        OUTPUT_PDF, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=18*mm,  bottomMargin=18*mm,
    )

    cover_template  = PageTemplate(id="cover",  frames=[cover_frame],  onPage=cover_page_bg)
    normal_template = PageTemplate(id="normal", frames=[normal_frame], onPage=normal_page)
    doc.addPageTemplates([cover_template, normal_template])

    story = []
    story += build_cover(ext, static, binary)
    story.append(NextPageTemplate("normal"))
    story += build_executive_summary(ext, static, binary)
    story.append(PageBreak())
    story += build_static_findings(static)
    story.append(PageBreak())
    story += build_binary_findings(binary)
    story.append(PageBreak())
    story += build_recommendations()
    story += build_disclaimer()

    doc.build(story)
    print(f"\n✔ PDF Report generated successfully!")
    print(f"✔ Location: {OUTPUT_PDF}")

if __name__ == "__main__":
    generate_report()