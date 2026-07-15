from flask import Flask, render_template_string, request, jsonify, redirect, url_for
import json
import os
import sys
import threading
import time
from datetime import datetime
from werkzeug.utils import secure_filename

# ── PATH SETUP ───────────────────────────────────────────────────────────────
BASE_DIR = r"D:\Srinidhi_Iyer\iot-firmware-scanner"
sys.path.insert(0, BASE_DIR)

from extractor.extractor      import extract_firmware
from analyzer.static_analyzer import analyze
from analyzer.binary_analyzer import analyze_binaries
from fuzzer.service_executor  import scan_target
from fuzzer.fuzzer            import run_fuzzer

app = Flask(__name__)

REPORTS_DIR   = os.path.join(BASE_DIR, "reports")
UPLOAD_DIR    = os.path.join(BASE_DIR, "uploads")
EXTRACTOR_OUT = os.path.join(BASE_DIR, "extractor", "extracted_output")
ALLOWED_EXT   = {".bin", ".img", ".fw", ".hex"}

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── GLOBAL SCAN STATE (single-scan-at-a-time, simple by design) ─────────────
scan_state = {
    "status":       "idle",   # idle | running | done | error
    "current_step": "",
    "progress":     0,        # 0-100
    "log":          [],
    "firmware":     "",
    "target_host":  "",
    "error":        "",
}
scan_lock = threading.Lock()

def reset_state():
    with scan_lock:
        scan_state.update({
            "status": "idle", "current_step": "", "progress": 0,
            "log": [], "firmware": "", "target_host": "", "error": ""
        })

def log_step(message, progress=None):
    with scan_lock:
        scan_state["log"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        scan_state["current_step"] = message
        if progress is not None:
            scan_state["progress"] = progress

# ── BACKGROUND PIPELINE RUNNER ───────────────────────────────────────────────
def run_pipeline_background(firmware_path, target_host):
    try:
        with scan_lock:
            scan_state["status"]      = "running"
            scan_state["firmware"]    = os.path.basename(firmware_path)
            scan_state["target_host"] = target_host or ""

        log_step("Starting firmware extraction...", 5)
        extract_firmware(firmware_path, EXTRACTOR_OUT)
        log_step("Extraction complete. Starting static analysis...", 30)

        analyze(EXTRACTOR_OUT)
        log_step("Static analysis complete. Starting binary analysis...", 55)

        analyze_binaries(EXTRACTOR_OUT)
        log_step("Binary analysis complete.", 75)

        if target_host:
            log_step(f"Scanning live services on {target_host}...", 80)
            service_result = scan_target(target_host)
            if service_result.get("total_open", 0) > 0:
                log_step("Open services found. Starting fuzzer...", 90)
                run_fuzzer(target_host)
            else:
                log_step("No open services found — skipping fuzzer.", 90)
        else:
            log_step("No target host provided — skipping live scan.", 90)

        log_step("Scan complete!", 100)
        with scan_lock:
            scan_state["status"] = "done"

    except Exception as e:
        with scan_lock:
            scan_state["status"] = "error"
            scan_state["error"]  = str(e)
        log_step(f"ERROR: {str(e)}")

def load_report(filename):
    path = os.path.join(REPORTS_DIR, filename)
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return None

# ── UPLOAD PAGE ───────────────────────────────────────────────────────────────
UPLOAD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IoT Firmware Scanner — Upload</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0a0e1a; color:#e0e0e0; font-family:'Segoe UI',sans-serif;
         min-height:100vh; display:flex; align-items:center; justify-content:center; }
  .card { background:#111827; border:1px solid #1e293b; border-radius:16px;
          padding:44px; width:520px; box-shadow: 0 20px 60px rgba(0,0,0,0.5); }
  .badge { color:#c0392b; font-size:0.8rem; font-weight:700; letter-spacing:2px; }
  h1 { font-size:1.5rem; margin:8px 0 4px; }
  .sub { color:#888; font-size:0.85rem; margin-bottom:28px; }
  .dropzone {
    border:2px dashed #2a3a5c; border-radius:12px; padding:40px 20px;
    text-align:center; cursor:pointer; transition:all 0.2s; margin-bottom:20px;
  }
  .dropzone:hover, .dropzone.dragover { border-color:#4a90d9; background:#0d1b2a; }
  .dropzone .icon { font-size:2.5rem; margin-bottom:10px; }
  .dropzone .text { color:#aaa; font-size:0.9rem; }
  .dropzone .filename { color:#4a90d9; font-weight:600; margin-top:8px; }
  input[type=file] { display:none; }
  label.field-label { display:block; font-size:0.78rem; color:#888;
        text-transform:uppercase; letter-spacing:1px; margin-bottom:6px; }
  input[type=text] {
    width:100%; background:#0d1b2a; border:1px solid #2a3a5c; border-radius:8px;
    color:#e0e0e0; padding:10px 14px; font-size:0.9rem; margin-bottom:20px; outline:none;
  }
  input[type=text]:focus { border-color:#4a90d9; }
  button {
    width:100%; background:#c0392b; color:#fff; border:none; border-radius:8px;
    padding:14px; font-size:0.95rem; font-weight:700; cursor:pointer; transition:background 0.2s;
  }
  button:hover { background:#a93226; }
  button:disabled { background:#444; cursor:not-allowed; }
  .hint { color:#555; font-size:0.75rem; margin-top:14px; text-align:center; }
</style>
</head>
<body>
<div class="card">
  <div class="badge">SECURITY RESEARCH TOOL</div>
  <h1>🔍 IoT Firmware Scanner</h1>
  <div class="sub">Upload a firmware image to begin automated vulnerability assessment</div>

  <form id="uploadForm" enctype="multipart/form-data">
    <div class="dropzone" id="dropzone" onclick="document.getElementById('fileInput').click()">
      <div class="icon">📦</div>
      <div class="text" id="dzText">Click or drag firmware file here (.bin, .img, .fw, .hex)</div>
      <div class="filename" id="fileName"></div>
    </div>
    <input type="file" id="fileInput" name="firmware" accept=".bin,.img,.fw,.hex">

    <label class="field-label">Target Device IP (optional — enables live fuzzing)</label>
    <input type="text" id="targetHost" name="target_host" placeholder="e.g. 192.168.1.1">

    <button type="submit" id="submitBtn">Start Security Scan</button>
    <div class="hint">Extraction → Static Analysis → Binary Audit → Live Fuzzing → Report</div>
  </form>
</div>

<script>
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');
const fileName = document.getElementById('fileName');
const dzText = document.getElementById('dzText');

['dragover','dragenter'].forEach(evt => dropzone.addEventListener(evt, e => {
  e.preventDefault(); dropzone.classList.add('dragover');
}));
['dragleave','drop'].forEach(evt => dropzone.addEventListener(evt, e => {
  e.preventDefault(); dropzone.classList.remove('dragover');
}));
dropzone.addEventListener('drop', e => {
  fileInput.files = e.dataTransfer.files;
  updateFileName();
});
fileInput.addEventListener('change', updateFileName);

function updateFileName() {
  if (fileInput.files.length > 0) {
    fileName.textContent = "✔ " + fileInput.files[0].name;
    dzText.textContent = "File ready:";
  }
}

document.getElementById('uploadForm').addEventListener('submit', function(e) {
  e.preventDefault();
  if (!fileInput.files.length) { alert('Please select a firmware file first.'); return; }

  const btn = document.getElementById('submitBtn');
  btn.disabled = true;
  btn.textContent = 'Uploading...';

  const formData = new FormData();
  formData.append('firmware', fileInput.files[0]);
  formData.append('target_host', document.getElementById('targetHost').value);

  fetch('/start_scan', { method: 'POST', body: formData })
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        window.location.href = '/scanning';
      } else {
        alert('Error: ' + data.error);
        btn.disabled = false;
        btn.textContent = 'Start Security Scan';
      }
    });
});
</script>
</body>
</html>
'''

# ── SCANNING / PROGRESS PAGE ─────────────────────────────────────────────────
SCANNING_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Scanning...</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0a0e1a; color:#e0e0e0; font-family:'Segoe UI',sans-serif;
         min-height:100vh; display:flex; align-items:center; justify-content:center; }
  .card { background:#111827; border:1px solid #1e293b; border-radius:16px;
          padding:44px; width:600px; }
  h1 { font-size:1.3rem; margin-bottom:6px; }
  .sub { color:#888; font-size:0.85rem; margin-bottom:24px; }
  .bar-bg { background:#0d1b2a; border-radius:10px; height:14px; overflow:hidden; margin-bottom:10px; }
  .bar-fill { background:linear-gradient(90deg,#c0392b,#4a90d9); height:100%;
              width:0%; transition:width 0.5s ease; }
  .pct { text-align:right; color:#4a90d9; font-weight:700; font-size:0.9rem; margin-bottom:20px; }
  .step { color:#e0e0e0; font-size:0.95rem; margin-bottom:16px; min-height:20px; }
  .log { background:#0d1b2a; border-radius:8px; padding:14px; height:200px;
         overflow-y:auto; font-family:monospace; font-size:0.78rem; color:#888; }
  .log div { margin-bottom:4px; }
  .spinner { display:inline-block; width:14px; height:14px; border:2px solid #2a3a5c;
             border-top-color:#4a90d9; border-radius:50%; animation:spin 0.8s linear infinite;
             margin-right:8px; vertical-align:middle; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="card">
  <h1><span class="spinner" id="spinner"></span>Scanning Firmware...</h1>
  <div class="sub" id="firmwareInfo">Loading...</div>
  <div class="bar-bg"><div class="bar-fill" id="barFill"></div></div>
  <div class="pct" id="pctText">0%</div>
  <div class="step" id="stepText">Initializing...</div>
  <div class="log" id="logBox"></div>
</div>

<script>
function poll() {
  fetch('/scan_status').then(r => r.json()).then(data => {
    document.getElementById('barFill').style.width = data.progress + '%';
    document.getElementById('pctText').textContent = data.progress + '%';
    document.getElementById('stepText').textContent = data.current_step;
    document.getElementById('firmwareInfo').textContent =
        data.firmware + (data.target_host ? ' → Target: ' + data.target_host : '');

    const logBox = document.getElementById('logBox');
    logBox.innerHTML = data.log.map(l => '<div>' + l + '</div>').join('');
    logBox.scrollTop = logBox.scrollHeight;

    if (data.status === 'done') {
      document.getElementById('spinner').style.display = 'none';
      setTimeout(() => window.location.href = '/results', 800);
    } else if (data.status === 'error') {
      document.getElementById('spinner').style.display = 'none';
      document.getElementById('stepText').innerHTML =
          '<span style="color:#e74c3c;">Error: ' + data.error + '</span>';
    } else {
      setTimeout(poll, 1000);
    }
  });
}
poll();
</script>
</body>
</html>
'''

# ── ROUTES ────────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    with scan_lock:
        status = scan_state["status"]
    if status == "running":
        return redirect(url_for('scanning_page'))
    if status == "done":
        return redirect(url_for('results'))
    return render_template_string(UPLOAD_HTML)

@app.route('/start_scan', methods=['POST'])
def start_scan():
    if 'firmware' not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"})

    file = request.files['firmware']
    if file.filename == '':
        return jsonify({"success": False, "error": "No file selected"})

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXT:
        return jsonify({"success": False, "error": f"File type {ext} not allowed. Use: {', '.join(ALLOWED_EXT)}"})

    filename = secure_filename(file.filename)
    save_path = os.path.join(UPLOAD_DIR, filename)
    file.save(save_path)

    target_host = request.form.get('target_host', '').strip()

    reset_state()
    thread = threading.Thread(target=run_pipeline_background, args=(save_path, target_host))
    thread.daemon = True
    thread.start()

    return jsonify({"success": True})

@app.route('/scanning')
def scanning_page():
    return render_template_string(SCANNING_HTML)

@app.route('/scan_status')
def scan_status():
    with scan_lock:
        return jsonify(dict(scan_state))

@app.route('/new_scan')
def new_scan():
    reset_state()
    return redirect(url_for('home'))

@app.route('/results')
def results():
    ext     = load_report('extraction_report.json')
    static  = load_report('static_analysis_report.json')
    binary  = load_report('binary_analysis_report.json')
    service = load_report('service_scan_report.json')
    fuzz    = load_report('fuzzing_report.json')
    return render_template_string(RESULTS_HTML, ext=ext, static=static, binary=binary,
                                   service=service, fuzz=fuzz)

# ── RESULTS DASHBOARD (same as before, + New Scan button) ──────────────────
RESULTS_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IoT Firmware Scanner — Results</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0a0e1a; color:#e0e0e0; font-family:'Segoe UI',sans-serif; }
  header { background:linear-gradient(135deg,#0d1b2a,#1a2a4a); border-bottom:2px solid #c0392b;
           padding:24px 40px; display:flex; align-items:center; gap:16px; }
  header h1 { font-size:1.6rem; color:#fff; }
  header span { font-size:0.9rem; color:#c0392b; font-weight:600; letter-spacing:2px; }
  .newscan-btn { margin-left:auto; background:#4a90d9; color:#fff; border:none;
        padding:10px 18px; border-radius:8px; font-size:0.85rem; font-weight:600;
        cursor:pointer; text-decoration:none; }
  .newscan-btn:hover { background:#357abd; }
  .container { max-width:1400px; margin:0 auto; padding:30px 40px; }
  .section-title { font-size:1.1rem; font-weight:700; color:#4a90d9; border-left:4px solid #4a90d9;
        padding-left:12px; margin:32px 0 16px; text-transform:uppercase; letter-spacing:1px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; }
  .card { background:#111827; border-radius:12px; padding:20px; border:1px solid #1e293b; text-align:center; }
  .card .number { font-size:2.4rem; font-weight:800; }
  .card .label { font-size:0.8rem; color:#888; margin-top:4px; text-transform:uppercase; letter-spacing:1px; }
  .card.critical .number { color:#e74c3c; } .card.high .number { color:#f39c12; }
  .card.medium .number { color:#3498db; } .card.low .number { color:#2ecc71; }
  .card.blue .number { color:#4a90d9; } .card.white .number { color:#fff; }
  .card.purple .number { color:#9b59b6; }
  .tab-bar { display:flex; gap:4px; margin-bottom:20px; border-bottom:2px solid #1e293b; flex-wrap:wrap; }
  .tab { padding:10px 22px; cursor:pointer; font-size:0.9rem; color:#888;
         border-bottom:2px solid transparent; margin-bottom:-2px; }
  .tab.active { color:#4a90d9; border-bottom-color:#4a90d9; font-weight:600; }
  .tab-content { display:none; } .tab-content.active { display:block; }
  .table-wrap { overflow-x:auto; border-radius:10px; border:1px solid #1e293b; }
  table { width:100%; border-collapse:collapse; font-size:0.88rem; }
  thead { background:#0d1b2a; }
  th { padding:12px 16px; text-align:left; color:#4a90d9; font-weight:600;
       text-transform:uppercase; letter-spacing:0.5px; font-size:0.78rem; }
  tbody tr { border-bottom:1px solid #1a2235; } tbody tr:hover { background:#131f35; }
  td { padding:10px 16px; vertical-align:top; }
  .sev { padding:3px 10px; border-radius:20px; font-size:0.75rem; font-weight:700; display:inline-block; }
  .sev-CRITICAL { background:#3d0a0a; color:#e74c3c; border:1px solid #e74c3c; }
  .sev-HIGH { background:#3d2200; color:#f39c12; border:1px solid #f39c12; }
  .sev-MEDIUM { background:#0a1f3d; color:#3498db; border:1px solid #3498db; }
  .sev-LOW { background:#0a2a1a; color:#2ecc71; border:1px solid #2ecc71; }
  .risk-VULNERABLE { color:#e74c3c; font-weight:700; } .risk-PARTIAL { color:#f39c12; font-weight:700; }
  .risk-SECURE { color:#2ecc71; font-weight:700; }
  .check-yes { color:#2ecc71; } .check-no { color:#e74c3c; } .check-unk { color:#888; }
  .filepath { color:#4a90d9; font-family:monospace; font-size:0.82rem; }
  .match { font-family:monospace; font-size:0.8rem; color:#aaa; max-width:300px;
           overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .filter-bar { display:flex; gap:10px; margin-bottom:12px; flex-wrap:wrap; }
  .filter-bar input { background:#111827; border:1px solid #2a3a5c; border-radius:6px;
        color:#e0e0e0; padding:8px 14px; font-size:0.88rem; flex:1; min-width:200px; outline:none; }
  .filter-btn { background:#111827; border:1px solid #2a3a5c; border-radius:6px;
        color:#e0e0e0; padding:8px 14px; font-size:0.82rem; cursor:pointer; }
  .filter-btn.active { background:#c0392b; border-color:#c0392b; }
  .payload-box { font-family:monospace; font-size:0.78rem; color:#f39c12; background:#1a1200;
        padding:2px 8px; border-radius:4px; }
  .reason-tag { display:inline-block; background:#3d0a0a; color:#e74c3c; padding:2px 8px;
        border-radius:10px; font-size:0.72rem; margin:1px; }
  footer { text-align:center; padding:30px; color:#444; font-size:0.82rem; border-top:1px solid #1e293b; margin-top:40px; }
</style>
</head>
<body>
<header>
  <div>
    <span>SECURITY RESEARCH TOOL</span>
    <h1>🔍 IoT Firmware Vulnerability Scanner</h1>
  </div>
  <a href="/new_scan" class="newscan-btn">+ New Scan</a>
</header>
<div class="container">
  <div class="tab-bar">
    <div class="tab active" onclick="switchTab('overview')">Overview</div>
    <div class="tab" onclick="switchTab('static')">Static Analysis</div>
    <div class="tab" onclick="switchTab('binary')">Binary Analysis</div>
    <div class="tab" onclick="switchTab('services')">Live Services</div>
    <div class="tab" onclick="switchTab('fuzzing')">Fuzzing</div>
  </div>

  <div id="tab-overview" class="tab-content active">
    <div class="section-title">Scan Summary</div>
    <div class="cards">
      <div class="card critical"><div class="number">{{ static.summary.CRITICAL if static else 0 }}</div><div class="label">Critical</div></div>
      <div class="card high"><div class="number">{{ static.summary.HIGH if static else 0 }}</div><div class="label">High</div></div>
      <div class="card medium"><div class="number">{{ static.summary.MEDIUM if static else 0 }}</div><div class="label">Medium</div></div>
      <div class="card low"><div class="number">{{ static.summary.LOW if static else 0 }}</div><div class="label">Low</div></div>
      <div class="card white"><div class="number">{{ binary.total_elf_binaries if binary else 0 }}</div><div class="label">Binaries</div></div>
      <div class="card blue"><div class="number">{{ binary.risk_summary.VULNERABLE if binary else 0 }}</div><div class="label">Vulnerable Binaries</div></div>
      {% if fuzz %}
      <div class="card critical"><div class="number">{{ fuzz.total_crashes }}</div><div class="label">Crashes</div></div>
      <div class="card high"><div class="number">{{ fuzz.total_timeouts }}</div><div class="label">Timeouts</div></div>
      {% endif %}
    </div>
  </div>

  <div id="tab-static" class="tab-content">
    {% if static %}
    <div class="filter-bar">
      <input type="text" oninput="filterTable('staticTable', this.value)" placeholder="Search...">
      <button class="filter-btn active" onclick="filterSeverity('ALL')">All</button>
      <button class="filter-btn" onclick="filterSeverity('CRITICAL')">Critical</button>
      <button class="filter-btn" onclick="filterSeverity('HIGH')">High</button>
    </div>
    <div class="table-wrap"><table id="staticTable">
      <thead><tr><th>Severity</th><th>Pattern</th><th>File</th><th>Line</th><th>Match</th></tr></thead>
      <tbody>
        {% for f in static.findings %}
        <tr data-severity="{{ f.severity }}">
          <td><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span></td>
          <td>{{ f.pattern }}</td><td class="filepath">{{ f.file }}</td>
          <td>{{ f.line_number }}</td><td class="match">{{ f.matched_content[:80] }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table></div>
    {% else %}<p style="color:#888;">No static analysis report.</p>{% endif %}
  </div>

  <div id="tab-binary" class="tab-content">
    {% if binary %}
    <div class="table-wrap"><table>
      <thead><tr><th>Binary</th><th>Arch</th><th>NX</th><th>PIE</th><th>Canary</th><th>RELRO</th><th>Score</th><th>Risk</th></tr></thead>
      <tbody>
        {% for b in binary.binaries %}
        <tr><td class="filepath">{{ b.file }}</td><td>{{ b.arch }}</td>
          <td>{% if b.nx=='ENABLED' %}<span class="check-yes">✔</span>{% elif b.nx=='DISABLED' %}<span class="check-no">✘</span>{% else %}?{% endif %}</td>
          <td>{% if b.pie=='ENABLED' %}<span class="check-yes">✔</span>{% elif b.pie=='DISABLED' %}<span class="check-no">✘</span>{% else %}?{% endif %}</td>
          <td>{% if b.canary=='ENABLED' %}<span class="check-yes">✔</span>{% elif b.canary=='DISABLED' %}<span class="check-no">✘</span>{% else %}?{% endif %}</td>
          <td>{% if b.relro=='ENABLED' %}<span class="check-yes">✔</span>{% elif b.relro=='DISABLED' %}<span class="check-no">✘</span>{% else %}?{% endif %}</td>
          <td>{{ b.score }}/100</td><td><span class="risk-{{ b.risk }}">{{ b.risk }}</span></td>
        </tr>
        {% endfor %}
      </tbody>
    </table></div>
    {% else %}<p style="color:#888;">No binary analysis report.</p>{% endif %}
  </div>

  <div id="tab-services" class="tab-content">
    {% if service %}
    <div class="table-wrap"><table>
      <thead><tr><th>Port</th><th>Service</th><th>Info</th></tr></thead>
      <tbody>
        {% for port, d in service.service_details.items() %}
        <tr><td>{{ d.port }}</td><td>{{ d.service }}</td>
          <td class="match">{% if d.http_info %}{{ d.http_info.status }} | {{ d.http_info.server }}{% else %}{{ d.banner[:80] }}{% endif %}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table></div>
    {% else %}<p style="color:#888;">No live service scan (no target IP was provided).</p>{% endif %}
  </div>

  <div id="tab-fuzzing" class="tab-content">
    {% if fuzz %}
    <div class="table-wrap"><table>
      <thead><tr><th>Severity</th><th>Payload</th><th>Size</th><th>Result</th><th>Reasons</th></tr></thead>
      <tbody>
        {% for f in fuzz.findings %}
        <tr><td><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span></td>
          <td><span class="payload-box">{{ f.payload_str[:40] }}</span></td>
          <td>{{ f.payload_size }}</td><td>{{ f.result_status }}</td>
          <td>{% for r in f.reasons %}<span class="reason-tag">{{ r }}</span>{% endfor %}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table></div>
    {% else %}<p style="color:#888;">No fuzzing report (no target IP was provided).</p>{% endif %}
  </div>
</div>
<footer>IoT Firmware Vulnerability Scanner — Srinidhi B Iyer</footer>
<script>
function switchTab(name) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
}
function filterTable(id, q) {
  document.querySelectorAll('#' + id + ' tbody tr').forEach(r => {
    r.style.display = r.textContent.toLowerCase().includes(q.toLowerCase()) ? '' : 'none';
  });
}
function filterSeverity(sev) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#staticTable tbody tr').forEach(r => {
    r.style.display = (sev === 'ALL' || r.dataset.severity === sev) ? '' : 'none';
  });
}
</script>
</body>
</html>
'''

if __name__ == '__main__':
    print("\n🚀 IoT Firmware Scanner — Web App starting...")
    print("📊 Open your browser at: http://localhost:5000")
    print("   Just upload a firmware file — no terminal commands needed!\n")
    app.run(debug=False, port=5000)