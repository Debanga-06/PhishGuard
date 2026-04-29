"""
app.py — Flask Web App & REST API for Phishing URL Detection.

Endpoints:
  GET  /                   → Web UI
  POST /predict            → JSON prediction
  GET  /history            → Recent scan history
  GET  /stats              → Aggregate stats
  GET  /health             → Health check
"""

import sys
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from flask import Flask, request, jsonify, render_template_string
from functools import wraps
import time
import json

from predict import predict, load_artifacts
from utils.logger import get_recent_scans, get_stats
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Pre-load model at startup
try:
    load_artifacts()
    print("✅ Model loaded successfully")
except FileNotFoundError as e:
    print(f"⚠️  {e}")


# ── Simple rate limiting (in-memory, per IP) ───────────────────────────────────
_rate_cache = {}
RATE_LIMIT = 30  # requests per minute

def rate_limit(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()
        window = _rate_cache.get(ip, [])
        window = [t for t in window if now - t < 60]
        if len(window) >= RATE_LIMIT:
            return jsonify({"error": "Rate limit exceeded. Max 30 requests/minute."}), 429
        window.append(now)
        _rate_cache[ip] = window
        return f(*args, **kwargs)
    return wrapper


# ── HTML Template ──────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhishGuard — URL Safety Analyzer</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Space+Grotesk:wght@400;600;700&display=swap');

  :root {
    --bg:       #0d1117;
    --surface:  #161b22;
    --border:   #30363d;
    --text:     #e6edf3;
    --muted:    #8b949e;
    --safe:     #3fb950;
    --danger:   #f85149;
    --warn:     #d29922;
    --accent:   #58a6ff;
    --red-dim:  rgba(248,81,73,0.12);
    --green-dim:rgba(63,185,80,0.12);
    --yellow-dim:rgba(210,153,34,0.1);
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Space Grotesk', sans-serif;
    min-height: 100vh;
    padding: 2rem 1rem;
  }

  .container { max-width: 860px; margin: 0 auto; }

  header {
    display: flex; align-items: center; gap: 1rem;
    margin-bottom: 2.5rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
  }

  .logo {
    width: 42px; height: 42px;
    background: linear-gradient(135deg, var(--danger), var(--accent));
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.4rem;
  }

  h1 { font-size: 1.6rem; font-weight: 700; letter-spacing: -0.5px; }
  h1 span { color: var(--accent); }
  .tagline { color: var(--muted); font-size: 0.85rem; }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.75rem;
    margin-bottom: 1.5rem;
  }

  .input-row { display: flex; gap: 0.75rem; }

  input[type="url"] {
    flex: 1;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.9rem;
    padding: 0.75rem 1rem;
    transition: border-color 0.2s;
    outline: none;
  }
  input[type="url"]:focus { border-color: var(--accent); }
  input[type="url"]::placeholder { color: var(--muted); }

  button {
    background: var(--accent);
    border: none;
    border-radius: 8px;
    color: #0d1117;
    cursor: pointer;
    font-family: 'Space Grotesk', sans-serif;
    font-size: 0.9rem;
    font-weight: 700;
    padding: 0.75rem 1.5rem;
    transition: opacity 0.2s, transform 0.1s;
    white-space: nowrap;
  }
  button:hover  { opacity: 0.9; }
  button:active { transform: scale(0.97); }
  button:disabled { opacity: 0.5; cursor: not-allowed; }

  .result { display: none; }
  .result.visible { display: block; }

  .verdict {
    display: flex;
    align-items: center;
    gap: 1.25rem;
    padding: 1.25rem 1.5rem;
    border-radius: 10px;
    margin-bottom: 1.25rem;
  }
  .verdict.safe    { background: var(--green-dim); border: 1px solid var(--safe); }
  .verdict.danger  { background: var(--red-dim);   border: 1px solid var(--danger); }
  .verdict.warn    { background: var(--yellow-dim); border: 1px solid var(--warn); }

  .verdict-icon { font-size: 2rem; }
  .verdict-label { font-size: 1.5rem; font-weight: 700; }
  .verdict.safe   .verdict-label { color: var(--safe); }
  .verdict.danger .verdict-label { color: var(--danger); }
  .verdict.warn   .verdict-label { color: var(--warn); }
  .verdict-url {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: var(--muted);
    word-break: break-all;
  }

  .metrics {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0.75rem;
    margin-bottom: 1.25rem;
  }
  .metric-box {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.85rem 1rem;
    text-align: center;
  }
  .metric-value { font-size: 1.5rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
  .metric-label { font-size: 0.72rem; color: var(--muted); margin-top: 2px; }

  .confidence-bar {
    height: 6px;
    background: var(--border);
    border-radius: 3px;
    overflow: hidden;
    margin-top: 6px;
  }
  .confidence-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.6s ease;
  }

  .section-title {
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.6rem;
  }

  .explanations { display: flex; flex-direction: column; gap: 0.5rem; }
  .explanation {
    display: flex;
    align-items: flex-start;
    gap: 0.6rem;
    padding: 0.6rem 0.9rem;
    border-radius: 6px;
    font-size: 0.83rem;
    background: var(--bg);
    border-left: 3px solid;
  }
  .explanation.high   { border-color: var(--danger); }
  .explanation.medium { border-color: var(--warn); }
  .explanation.low    { border-color: var(--accent); }
  .exp-badge {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    font-weight: 700;
    padding: 2px 5px;
    border-radius: 3px;
    flex-shrink: 0;
  }
  .high .exp-badge   { background: var(--red-dim);    color: var(--danger); }
  .medium .exp-badge { background: var(--yellow-dim); color: var(--warn); }
  .low .exp-badge    { background: rgba(88,166,255,0.1); color: var(--accent); }

  .blacklist-warning {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    background: var(--red-dim);
    border: 1px solid var(--danger);
    border-radius: 8px;
    padding: 0.85rem 1rem;
    margin-bottom: 1rem;
    font-size: 0.85rem;
  }

  .spinner {
    display: none;
    width: 18px; height: 18px;
    border: 2px solid rgba(255,255,255,0.2);
    border-top-color: var(--text);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  .history-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
  }
  .history-table th {
    text-align: left;
    color: var(--muted);
    font-weight: 600;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--border);
  }
  .history-table td {
    padding: 0.55rem 0.75rem;
    border-bottom: 1px solid rgba(48,54,61,0.5);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    max-width: 280px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .badge {
    font-size: 0.65rem;
    padding: 2px 7px;
    border-radius: 10px;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
  }
  .badge-safe    { background: var(--green-dim); color: var(--safe); }
  .badge-phish   { background: var(--red-dim);   color: var(--danger); }
  .badge-high    { background: var(--red-dim);   color: var(--danger); }
  .badge-medium  { background: var(--yellow-dim);color: var(--warn); }
  .badge-low     { background: rgba(88,166,255,0.1); color: var(--accent); }

  .stats-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; }
  .stat-box {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
    text-align: center;
  }
  .stat-value { font-size: 1.8rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; color: var(--accent); }
  .stat-label { font-size: 0.72rem; color: var(--muted); }

  .example-urls { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.75rem; }
  .example-url {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    padding: 3px 10px;
    border: 1px solid var(--border);
    border-radius: 4px;
    cursor: pointer;
    color: var(--muted);
    background: var(--bg);
    transition: all 0.15s;
  }
  .example-url:hover { border-color: var(--accent); color: var(--accent); }

  .error-box {
    background: var(--red-dim);
    border: 1px solid var(--danger);
    border-radius: 8px;
    padding: 0.85rem 1rem;
    color: var(--danger);
    font-size: 0.85rem;
  }

  @media (max-width: 600px) {
    .input-row  { flex-direction: column; }
    .metrics    { grid-template-columns: repeat(2, 1fr); }
    .stats-row  { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>
<div class="container">

  <header>
    <div class="logo">🛡</div>
    <div>
      <h1>Phish<span>Guard</span></h1>
      <div class="tagline">ML-powered phishing URL detection engine</div>
    </div>
  </header>

  <!-- Stats bar -->
  <div id="stats-bar" class="card" style="margin-bottom:1.5rem;"></div>

  <!-- Scanner card -->
  <div class="card">
    <div class="section-title" style="margin-bottom:0.85rem;">Analyze a URL</div>
    <div class="input-row">
      <input type="url" id="urlInput" placeholder="https://example.com/path?query=value" autocomplete="off" />
      <div class="spinner" id="spinner"></div>
      <button id="scanBtn" onclick="scan()">Scan URL</button>
    </div>
    <div class="example-urls">
      <span class="example-url" onclick="setUrl('https://google.com')">google.com</span>
      <span class="example-url" onclick="setUrl('https://github.com/login')">github.com/login</span>
      <span class="example-url" onclick="setUrl('http://paypa1-secure-verify.tk/login')">paypa1-secure.tk</span>
      <span class="example-url" onclick="setUrl('http://192.168.1.1/banking/login')">IP-based login</span>
      <span class="example-url" onclick="setUrl('http://apple.verify.account-secure.xyz/id/login')">apple subdomain abuse</span>
    </div>
  </div>

  <!-- Result -->
  <div id="result" class="result">
    <div class="card">
      <div id="blacklistWarning" class="blacklist-warning" style="display:none;">
        <span style="font-size:1.2rem">🚫</span>
        <span id="blacklistMsg"></span>
      </div>
      <div id="verdict" class="verdict">
        <div class="verdict-icon" id="verdictIcon"></div>
        <div>
          <div class="verdict-label" id="verdictLabel"></div>
          <div class="verdict-url" id="verdictUrl"></div>
        </div>
      </div>
      <div class="metrics">
        <div class="metric-box">
          <div class="metric-value" id="confVal">—</div>
          <div class="confidence-bar"><div class="confidence-fill" id="confBar"></div></div>
          <div class="metric-label">Confidence</div>
        </div>
        <div class="metric-box">
          <div class="metric-value" id="riskVal">—</div>
          <div class="metric-label">Risk Level</div>
        </div>
        <div class="metric-box">
          <div class="metric-value" id="timeVal">—</div>
          <div class="metric-label">Scan Time</div>
        </div>
      </div>
      <div id="explanationsSection" style="display:none;">
        <div class="section-title">Why this URL is suspicious</div>
        <div class="explanations" id="explanations"></div>
      </div>
    </div>
  </div>

  <!-- Error -->
  <div id="errorBox" class="error-box" style="display:none;margin-bottom:1.5rem;"></div>

  <!-- History -->
  <div class="card" id="historyCard">
    <div class="section-title" style="margin-bottom:1rem;">Recent Scans</div>
    <div id="historyContent"><div style="color:var(--muted);font-size:0.85rem">Loading...</div></div>
  </div>

</div>

<script>
function setUrl(u) {
  document.getElementById('urlInput').value = u;
  document.getElementById('urlInput').focus();
}

async function scan() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) { return; }

  const btn = document.getElementById('scanBtn');
  const spinner = document.getElementById('spinner');
  btn.disabled = true;
  spinner.style.display = 'block';
  document.getElementById('result').classList.remove('visible');
  document.getElementById('errorBox').style.display = 'none';

  try {
    const res = await fetch('/predict', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url})
    });
    const data = await res.json();

    if (data.error) throw new Error(data.error);

    renderResult(data);
    loadHistory();
    loadStats();
  } catch(e) {
    document.getElementById('errorBox').textContent = '⚠ ' + e.message;
    document.getElementById('errorBox').style.display = 'block';
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
  }
}

function renderResult(d) {
  const isPhish = d.prediction === 'phishing';
  const risk = d.risk_level;

  // Blacklist
  const blWarn = document.getElementById('blacklistWarning');
  if (d.blacklisted) {
    blWarn.style.display = 'flex';
    document.getElementById('blacklistMsg').textContent = '🚫 ' + d.blacklist_reason;
  } else {
    blWarn.style.display = 'none';
  }

  // Verdict
  const verdict = document.getElementById('verdict');
  verdict.className = 'verdict ' + (isPhish ? 'danger' : (risk === 'MEDIUM' ? 'warn' : 'safe'));
  document.getElementById('verdictIcon').textContent = isPhish ? '⚠️' : '✅';
  document.getElementById('verdictLabel').textContent = isPhish ? 'PHISHING URL' : 'LEGITIMATE URL';
  document.getElementById('verdictUrl').textContent = d.url;

  // Metrics
  const conf = Math.round(d.confidence * 100);
  document.getElementById('confVal').textContent = conf + '%';

  const bar = document.getElementById('confBar');
  bar.style.width = conf + '%';
  bar.style.background = isPhish ? 'var(--danger)' : 'var(--safe)';

  const riskEl = document.getElementById('riskVal');
  riskEl.textContent = risk;
  riskEl.style.color = risk === 'HIGH' ? 'var(--danger)' : risk === 'MEDIUM' ? 'var(--warn)' : 'var(--safe)';

  document.getElementById('timeVal').textContent = d.prediction_time_ms.toFixed(1) + 'ms';

  // Explanations
  const expSec  = document.getElementById('explanationsSection');
  const expList = document.getElementById('explanations');
  expList.innerHTML = '';
  if (d.explanations && d.explanations.length > 0) {
    expSec.style.display = 'block';
    d.explanations.forEach(e => {
      expList.innerHTML += `
        <div class="explanation ${e.severity}">
          <span class="exp-badge">${e.severity.toUpperCase()}</span>
          <span>${e.message}</span>
        </div>`;
    });
  } else {
    expSec.style.display = 'none';
  }

  document.getElementById('result').classList.add('visible');
  document.getElementById('result').scrollIntoView({behavior:'smooth', block:'start'});
}

async function loadHistory() {
  try {
    const res = await fetch('/history');
    const data = await res.json();
    const container = document.getElementById('historyContent');
    if (!data.scans || data.scans.length === 0) {
      container.innerHTML = '<div style="color:var(--muted);font-size:0.85rem">No scans yet.</div>';
      return;
    }
    let html = `<table class="history-table">
      <thead><tr><th>Timestamp</th><th>URL</th><th>Result</th><th>Confidence</th><th>Risk</th></tr></thead><tbody>`;
    data.scans.forEach(s => {
      const ts = new Date(s.timestamp).toLocaleTimeString();
      const isPhish = s.prediction === 'phishing';
      const badgeClass = isPhish ? 'badge-phish' : 'badge-safe';
      const riskClass  = 'badge-' + s.risk_level.toLowerCase();
      html += `<tr>
        <td style="color:var(--muted)">${ts}</td>
        <td title="${s.url}">${s.url}</td>
        <td><span class="badge ${badgeClass}">${s.prediction}</span></td>
        <td>${(s.confidence*100).toFixed(1)}%</td>
        <td><span class="badge ${riskClass}">${s.risk_level}</span></td>
      </tr>`;
    });
    html += '</tbody></table>';
    container.innerHTML = html;
  } catch {}
}

async function loadStats() {
  try {
    const res = await fetch('/stats');
    const d = await res.json();
    document.getElementById('stats-bar').innerHTML = `
      <div class="stats-row">
        <div class="stat-box"><div class="stat-value">${d.total}</div><div class="stat-label">Total Scans</div></div>
        <div class="stat-box"><div class="stat-value" style="color:var(--safe)">${d.legitimate}</div><div class="stat-label">Legitimate</div></div>
        <div class="stat-box"><div class="stat-value" style="color:var(--danger)">${d.phishing}</div><div class="stat-label">Phishing</div></div>
        <div class="stat-box"><div class="stat-value" style="color:var(--warn)">${d.phishing_rate}%</div><div class="stat-label">Phishing Rate</div></div>
      </div>`;
  } catch {}
}

// Enter key support
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('urlInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') scan();
  });
  loadStats();
  loadHistory();
});
</script>
</body>
</html>"""


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/predict", methods=["POST"])
@rate_limit
def predict_endpoint():
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL too long (max 2048 chars)"}), 400

    try:
        result = predict(url)
        return jsonify(result)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500


@app.route("/history")
def history():
    scans = get_recent_scans(limit=20)
    return jsonify({"scans": scans, "count": len(scans)})


@app.route("/stats")
def stats():
    return jsonify(get_stats())


@app.route("/health")
def health():
    try:
        load_artifacts()
        model_ok = True
    except Exception:
        model_ok = False
    return jsonify({"status": "ok" if model_ok else "degraded", "model_loaded": model_ok})


# ── Entry ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5180))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    print(f"\n🛡 PhishGuard running → http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=debug)