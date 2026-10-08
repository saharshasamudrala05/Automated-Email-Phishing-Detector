"""
app.py — Flask Web Interface for the Phishing Analyzer.

Run with:  python app.py
Then open: http://localhost:5000

Two routes:
  GET  /         → Analysis form
  POST /analyze  → Returns JSON result (consumed by the JS on the page)
  GET  /history  → Last 20 analyses as JSON
  GET  /stats    → Summary statistics
"""

import os
import json
from flask import Flask, request, jsonify, render_template_string

from config import validate_config, WEB_HOST, WEB_PORT, WEB_DEBUG
from analyzer import analyze_email
from utils import log_analysis, load_history, preprocess_email, ensure_dirs
from report_generator import generate_html_report

app = Flask(__name__)
ensure_dirs()


# ──────────────────────────────────────────────────────────────────────────────
# INLINE HTML TEMPLATE (no separate template file needed)
# ──────────────────────────────────────────────────────────────────────────────

WEB_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Phishing Analyzer</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a; color: #e2e8f0; min-height: 100vh;
    }

    /* NAV */
    nav {
      background: #1e293b; border-bottom: 1px solid #334155;
      padding: 14px 32px; display: flex; align-items: center; gap: 12px;
    }
    nav .logo { font-size: 1.2rem; font-weight: 800; color: #38bdf8; }
    nav .sub  { font-size: 0.75rem; color: #64748b; }
    nav a {
      margin-left: auto; color: #94a3b8; text-decoration: none;
      font-size: 0.85rem; padding: 6px 14px; border: 1px solid #334155;
      border-radius: 6px; transition: all .2s;
    }
    nav a:hover { background: #334155; color: #e2e8f0; }

    /* MAIN LAYOUT */
    .main { max-width: 900px; margin: 40px auto; padding: 0 16px; }
    h2 { font-size: 0.75rem; text-transform: uppercase; letter-spacing: .1em;
         color: #64748b; margin-bottom: 8px; }

    /* INPUT CARD */
    .card {
      background: #1e293b; border: 1px solid #334155;
      border-radius: 12px; padding: 24px; margin-bottom: 24px;
    }
    textarea {
      width: 100%; height: 240px; background: #0f172a; color: #e2e8f0;
      border: 1px solid #334155; border-radius: 8px; padding: 14px;
      font-family: "Courier New", monospace; font-size: 0.88rem;
      resize: vertical; outline: none; line-height: 1.5;
    }
    textarea:focus { border-color: #38bdf8; }
    textarea::placeholder { color: #475569; }

    .controls { display: flex; gap: 12px; margin-top: 14px; align-items: center; }
    select {
      background: #0f172a; color: #e2e8f0; border: 1px solid #334155;
      border-radius: 8px; padding: 10px 14px; font-size: 0.9rem; outline: none;
    }
    button.analyze-btn {
      background: #0ea5e9; color: white; border: none;
      border-radius: 8px; padding: 10px 28px; font-size: 0.95rem;
      font-weight: 700; cursor: pointer; transition: background .2s;
    }
    button.analyze-btn:hover { background: #0284c7; }
    button.analyze-btn:disabled { background: #334155; cursor: not-allowed; }
    .clear-btn {
      background: transparent; border: 1px solid #334155; color: #94a3b8;
      border-radius: 8px; padding: 10px 18px; cursor: pointer; font-size: 0.9rem;
    }
    .clear-btn:hover { border-color: #94a3b8; color: #e2e8f0; }
    .html-cb { margin-left: auto; display: flex; align-items: center; gap: 6px;
               font-size: 0.85rem; color: #94a3b8; cursor: pointer; }
    input[type=checkbox] { accent-color: #38bdf8; }

    /* LOADING */
    .spinner {
      display: none; width: 20px; height: 20px; border: 3px solid #334155;
      border-top-color: #38bdf8; border-radius: 50%;
      animation: spin .7s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .loading-text { display: none; color: #64748b; font-size: 0.85rem; }

    /* RESULT CARD */
    #result { display: none; }
    .verdict-hero {
      border-radius: 12px; padding: 24px; margin-bottom: 20px;
      border-left: 5px solid var(--accent);
      background: var(--bg);
    }
    .verdict-hero .v-title { font-size: 1.6rem; font-weight: 800; color: var(--accent); }
    .score-row { display: flex; align-items: center; gap: 24px; margin-top: 16px; }
    .ring {
      width: 88px; height: 88px; border-radius: 50%;
      border: 7px solid var(--accent); background: var(--ring-bg);
      display: flex; flex-direction: column; align-items: center;
      justify-content: center; flex-shrink: 0;
    }
    .ring .n { font-size: 1.8rem; font-weight: 900; color: var(--accent); }
    .ring .d { font-size: 0.65rem; color: #94a3b8; }
    .badges { display: flex; flex-wrap: wrap; gap: 8px; }
    .badge {
      background: var(--ring-bg); color: var(--accent);
      padding: 3px 12px; border-radius: 99px;
      font-size: 0.78rem; font-weight: 700;
    }
    .summary-text { margin-top: 14px; font-size: 0.92rem; color: #cbd5e1;
                    line-height: 1.6; }

    .result-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
    @media (max-width:600px) { .result-grid { grid-template-columns: 1fr; } }

    .r-card {
      background: #1e293b; border: 1px solid #334155;
      border-radius: 10px; padding: 16px;
    }
    .r-card h3 { font-size: 0.75rem; text-transform: uppercase; letter-spacing: .08em;
                 color: #64748b; margin-bottom: 10px; }
    .r-card ul { padding-left: 16px; }
    .r-card li { font-size: 0.88rem; margin-bottom: 5px; color: #cbd5e1; }
    .r-card.red   h3 { color: #f87171; }
    .r-card.amber h3 { color: #fbbf24; }
    .r-card.green h3 { color: #4ade80; }
    .r-card.purple h3 { color: #c084fc; }

    .action-box {
      background: var(--bg); border: 2px solid var(--accent);
      border-radius: 10px; padding: 16px; text-align: center; margin-top: 16px;
      margin-bottom: 16px;
    }
    .action-box .lbl { font-size: 0.7rem; color: #64748b; text-transform: uppercase;
                       letter-spacing: .1em; margin-bottom: 6px; }
    .action-box .act { font-size: 1.2rem; font-weight: 800; color: var(--accent); }

    .sender-table { width: 100%; border-collapse: collapse; }
    .sender-table td { padding: 5px 8px; font-size: 0.88rem; }
    .sender-table td:first-child { color: #64748b; font-weight: 600; width: 110px; }

    .report-link { display: block; text-align: center; margin-top: 12px;
                   color: #38bdf8; font-size: 0.85rem; }

    /* HISTORY */
    #history-section { display: none; }
    .hist-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    .hist-table th { text-align: left; padding: 8px 12px; color: #64748b;
                     border-bottom: 1px solid #334155; }
    .hist-table td { padding: 8px 12px; border-bottom: 1px solid #1e293b; }
    .pill-yes { background: #450a0a; color: #f87171; padding: 2px 8px;
                border-radius: 99px; font-size: 0.75rem; font-weight: 700; }
    .pill-no  { background: #052e16; color: #4ade80; padding: 2px 8px;
                border-radius: 99px; font-size: 0.75rem; font-weight: 700; }
  </style>
</head>
<body>

<nav>
  <div>
    <div class="logo">🔍 AI Phishing Analyzer</div>
    <div class="sub">Powered by Groq Llama 3.1 · Gemini 1.5 Flash</div>
  </div>
  <a href="#" onclick="toggleHistory()">📋 History</a>
</nav>

<div class="main">

  <!-- INPUT -->
  <div class="card">
    <h2>Paste Suspicious Email</h2>
    <textarea id="emailText" placeholder="Paste the full email here — including headers (From:, Subject:, Date:) and the body text...&#10;&#10;Example:&#10;From: security@paypa1.com&#10;Subject: URGENT: Your account has been suspended&#10;&#10;Dear Customer,&#10;Your PayPal account has been limited..."></textarea>
    <div class="controls">
      <select id="provider">
        <option value="groq">🚀 Groq (Llama 3.1 — Fast)</option>
        <option value="gemini">🌟 Gemini 1.5 Flash</option>
      </select>
      <button class="analyze-btn" onclick="analyze()" id="analyzeBtn">Analyze Threat</button>
      <button class="clear-btn" onclick="clearAll()">Clear</button>
      <label class="html-cb">
        <input type="checkbox" id="saveHtml"> Save HTML Report
      </label>
      <div class="spinner" id="spinner"></div>
      <span class="loading-text" id="loadingText">Analyzing...</span>
    </div>
  </div>

  <!-- RESULT -->
  <div id="result"></div>

  <!-- HISTORY -->
  <div id="history-section">
    <div class="card">
      <h2>Analysis History (Last 20)</h2>
      <div id="history-content"></div>
    </div>
  </div>

</div>

<script>
const RISK_COLOURS = {
  low:      { accent: '#22c55e', bg: '#052e16', ringBg: '#14532d' },
  medium:   { accent: '#eab308', bg: '#422006', ringBg: '#451a03' },
  high:     { accent: '#f97316', bg: '#431407', ringBg: '#431407' },
  critical: { accent: '#ef4444', bg: '#450a0a', ringBg: '#450a0a' },
};

function getRiskLevel(score) {
  if (score <= 30) return 'low';
  if (score <= 60) return 'medium';
  if (score <= 80) return 'high';
  return 'critical';
}

function getRiskLabel(score) {
  if (score <= 30) return 'LOW RISK';
  if (score <= 60) return 'SUSPICIOUS';
  if (score <= 80) return 'HIGH RISK';
  return 'CRITICAL — PHISHING';
}

function listItems(arr, fallback='None detected') {
  if (!arr || arr.length === 0) return `<li style="color:#475569">${fallback}</li>`;
  return arr.map(i => `<li>${i}</li>`).join('');
}

async function analyze() {
  const text = document.getElementById('emailText').value.trim();
  if (!text) { alert('Please paste an email first.'); return; }

  const provider = document.getElementById('provider').value;
  const saveHtml = document.getElementById('saveHtml').checked;

  document.getElementById('analyzeBtn').disabled = true;
  document.getElementById('spinner').style.display = 'block';
  document.getElementById('loadingText').style.display = 'block';
  document.getElementById('result').style.display = 'none';

  try {
    const resp = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: text, provider, save_html: saveHtml }),
    });

    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error || 'Analysis failed');
    }

    const data = await resp.json();
    renderResult(data);
  } catch (e) {
    document.getElementById('result').innerHTML = `
      <div class="card" style="border-color:#ef4444;color:#f87171">
        ❌ Error: ${e.message}
      </div>`;
    document.getElementById('result').style.display = 'block';
  } finally {
    document.getElementById('analyzeBtn').disabled = false;
    document.getElementById('spinner').style.display = 'none';
    document.getElementById('loadingText').style.display = 'none';
  }
}

function renderResult(r) {
  const score  = r.risk_score || 0;
  const level  = getRiskLevel(score);
  const label  = getRiskLabel(score);
  const colours = RISK_COLOURS[level];
  const isPhish = r.is_phishing;

  const verdictText  = isPhish ? '⚠ PHISHING DETECTED' : '✓ APPEARS LEGITIMATE';
  const verdictColor = isPhish ? '#ef4444' : '#22c55e';

  const senderSpoofed = r.sender_analysis?.appears_spoofed;

  const html = `
    <div class="verdict-hero" style="--accent:${colours.accent}; --bg:${colours.bg}; --ring-bg:${colours.ringBg}">
      <div class="v-title" style="color:${verdictColor}">${verdictText}</div>
      <div class="score-row">
        <div class="ring">
          <span class="n">${score}</span>
          <span class="d">/100</span>
        </div>
        <div>
          <div class="badges">
            <span class="badge">${label}</span>
            <span class="badge">${(r.confidence||'N/A').toUpperCase()}</span>
            <span class="badge">${(r.threat_category||'N/A').toUpperCase()}</span>
            <span class="badge">${r._provider?.toUpperCase()} / ${r._model}</span>
            <span class="badge">${r._latency_ms}ms</span>
          </div>
          <div class="summary-text">${r.summary || ''}</div>
        </div>
      </div>
    </div>

    <div class="action-box" style="--accent:${colours.accent}; --bg:${colours.bg}">
      <div class="lbl">Recommended Action</div>
      <div class="act">► ${(r.recommended_action||'N/A').toUpperCase().replace(/_/g,' ')}</div>
    </div>

    <div class="result-grid">
      <div class="r-card red">
        <h3>🚩 Red Flags (${(r.red_flags||[]).length})</h3>
        <ul>${listItems(r.red_flags)}</ul>
      </div>
      <div class="r-card amber">
        <h3>⚡ Urgency Tactics</h3>
        <ul>${listItems(r.urgency_indicators)}</ul>
      </div>
      <div class="r-card purple">
        <h3>🔗 Suspicious URLs</h3>
        <ul>${listItems(r.suspicious_urls)}</ul>
      </div>
      <div class="r-card red">
        <h3>🎭 Social Engineering</h3>
        <ul>${listItems(r.social_engineering_tactics)}</ul>
      </div>
      <div class="r-card green">
        <h3>✅ Legitimate Indicators</h3>
        <ul>${listItems(r.legitimate_indicators)}</ul>
      </div>
      <div class="r-card">
        <h3>📧 Sender Analysis</h3>
        <table class="sender-table">
          <tr><td>Spoofed</td><td style="color:${senderSpoofed?'#f87171':'#4ade80'}">
            ${senderSpoofed ? '⚠ YES' : '✓ No'}</td></tr>
          <tr><td>Technique</td><td>${r.sender_analysis?.spoofing_technique||'N/A'}</td></tr>
          <tr><td>Details</td><td>${r.sender_analysis?.sender_details||'N/A'}</td></tr>
        </table>
      </div>
    </div>

    ${r._html_report ? `<a class="report-link" href="/reports/${r._html_report}" target="_blank">
      📄 Open Full HTML Report ↗</a>` : ''}
  `;

  const el = document.getElementById('result');
  el.innerHTML = html;
  el.style.display = 'block';
  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function toggleHistory() {
  const sec = document.getElementById('history-section');
  if (sec.style.display === 'block') {
    sec.style.display = 'none'; return;
  }
  const resp = await fetch('/history');
  const data = await resp.json();
  const rows = data.map(h => `
    <tr>
      <td>${(h.timestamp||'').substring(0,19).replace('T',' ')}</td>
      <td><span class="${h.is_phishing?'pill-yes':'pill-no'}">${h.is_phishing?'YES':'NO'}</span></td>
      <td>${h.risk_score}</td>
      <td>${h.threat_category||'?'}</td>
      <td style="color:#94a3b8;font-size:0.8em">${(h.email_snippet||'').substring(0,60)}…</td>
    </tr>`).join('');

  document.getElementById('history-content').innerHTML = `
    <table class="hist-table">
      <tr><th>Timestamp</th><th>Phishing</th><th>Score</th><th>Category</th><th>Preview</th></tr>
      ${rows || '<tr><td colspan=5 style="color:#475569;padding:12px">No history yet.</td></tr>'}
    </table>`;
  sec.style.display = 'block';
}

function clearAll() {
  document.getElementById('emailText').value = '';
  document.getElementById('result').style.display = 'none';
}

document.getElementById('emailText').addEventListener('keydown', function(e) {
  if (e.ctrlKey && e.key === 'Enter') analyze();
});
</script>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(WEB_TEMPLATE)


@app.route("/analyze", methods=["POST"])
def analyze_route():
    data       = request.get_json(force=True)
    email_text = data.get("email", "").strip()
    provider   = data.get("provider", None)
    save_html  = data.get("save_html", False)

    if not email_text:
        return jsonify({"error": "No email text provided."}), 400

    email_text = preprocess_email(email_text)

    try:
        report = analyze_email(email_text, provider=provider)
    except (EnvironmentError, RuntimeError) as e:
        return jsonify({"error": str(e)}), 500
    except TimeoutError as e:
        return jsonify({"error": str(e)}), 504

    log_analysis(email_text, report)

    # Optionally generate HTML report
    if save_html:
        path = generate_html_report(email_text, report)
        report["_html_report"] = os.path.basename(path)

    # Don't send raw response back to browser
    report.pop("_raw_response", None)
    return jsonify(report)


@app.route("/history")
def history_route():
    history = load_history()
    return jsonify(history[-20:])


@app.route("/stats")
def stats_route():
    history = load_history()
    if not history:
        return jsonify({"total": 0})
    total    = len(history)
    phishing = sum(1 for h in history if h.get("is_phishing"))
    avg_score = sum(h.get("risk_score", 0) for h in history) / total
    return jsonify({
        "total":           total,
        "phishing_count":  phishing,
        "legitimate_count":total - phishing,
        "phishing_rate":   round(phishing / total * 100, 1),
        "avg_risk_score":  round(avg_score, 1),
    })


@app.route("/reports/<filename>")
def serve_report(filename):
    """Serve a generated HTML report."""
    from flask import send_from_directory
    return send_from_directory(
        os.path.abspath("reports"),
        filename,
        mimetype="text/html"
    )


# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        validate_config()
    except EnvironmentError as e:
        print(e)
        exit(1)

    print(f"\n  🔍 Phishing Analyzer Web UI")
    print(f"  Running at: http://localhost:{WEB_PORT}")
    print(f"  Press Ctrl+C to stop.\n")

    app.run(host=WEB_HOST, port=WEB_PORT, debug=WEB_DEBUG)
