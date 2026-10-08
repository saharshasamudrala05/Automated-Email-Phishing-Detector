"""
report_generator.py — Generates HTML and JSON reports from analysis results.

The HTML report is fully self-contained (no external CDN requests),
styled with inline CSS, and can be opened directly in a browser.
"""

import os
import json
import datetime
from config import OUTPUT_DIR
from utils import risk_label, risk_colour


def generate_html_report(email_text: str, report: dict) -> str:
    """
    Build a self-contained HTML report.
    Returns the path to the saved file.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    timestamp   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename    = f"threat_report_{timestamp}.html"
    filepath    = os.path.join(OUTPUT_DIR, filename)

    score       = report.get("risk_score", 0)
    is_phishing = report.get("is_phishing", False)
    label       = risk_label(score)

    # Colour palette based on risk
    if score <= 30:
        accent = "#22c55e"; bg_accent = "#f0fdf4"; badge_bg = "#dcfce7"
    elif score <= 60:
        accent = "#eab308"; bg_accent = "#fefce8"; badge_bg = "#fef9c3"
    elif score <= 80:
        accent = "#f97316"; bg_accent = "#fff7ed"; badge_bg = "#ffedd5"
    else:
        accent = "#ef4444"; bg_accent = "#fef2f2"; badge_bg = "#fee2e2"

    verdict_text   = "⚠ PHISHING DETECTED" if is_phishing else "✓ APPEARS LEGITIMATE"
    verdict_colour = "#ef4444" if is_phishing else "#22c55e"

    def list_items(items: list, colour: str = "#374151") -> str:
        if not items:
            return '<li style="color:#9ca3af">None detected</li>'
        return "".join(
            f'<li style="color:{colour}; margin-bottom:6px">{item}</li>'
            for item in items
        )

    red_flags    = report.get("red_flags", [])
    urgency      = report.get("urgency_indicators", [])
    sus_urls     = report.get("suspicious_urls", [])
    legit        = report.get("legitimate_indicators", [])
    se_tactics   = report.get("social_engineering_tactics", [])
    target_data  = report.get("target_data_sought", [])
    sender       = report.get("sender_analysis", {})
    action       = report.get("recommended_action", "N/A").upper().replace("_", " ")
    summary      = report.get("summary", "")
    provider     = report.get("_provider", "")
    model        = report.get("_model", "")
    latency      = report.get("_latency_ms", 0)

    email_safe = email_text[:1500].replace("<", "&lt;").replace(">", "&gt;")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Threat Report — {timestamp}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f3f4f6; color: #111827; line-height: 1.6;
    }}
    .header {{
      background: #0f172a; color: #f8fafc; padding: 24px 32px;
      display: flex; justify-content: space-between; align-items: center;
    }}
    .header h1 {{ font-size: 1.3rem; font-weight: 700; letter-spacing: 0.05em; }}
    .header .meta {{ font-size: 0.8rem; color: #94a3b8; text-align: right; }}
    .container {{ max-width: 960px; margin: 32px auto; padding: 0 16px; }}

    /* Verdict hero card */
    .verdict-card {{
      background: white; border-radius: 12px; padding: 32px;
      margin-bottom: 24px; border-left: 6px solid {accent};
      box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    }}
    .verdict-title {{ color: {verdict_colour}; font-size: 1.8rem; font-weight: 800; }}
    .score-ring-container {{ display: flex; align-items: center; gap: 32px; margin-top: 20px; }}
    .score-ring {{
      width: 100px; height: 100px; border-radius: 50%;
      border: 8px solid {accent}; background: {badge_bg};
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      flex-shrink: 0;
    }}
    .score-ring .num {{ font-size: 2rem; font-weight: 900; color: {accent}; }}
    .score-ring .den {{ font-size: 0.7rem; color: #6b7280; }}
    .verdict-meta p {{ margin-bottom: 6px; font-size: 0.95rem; }}
    .badge {{
      display: inline-block; padding: 3px 10px; border-radius: 99px;
      background: {badge_bg}; color: {accent};
      font-size: 0.8rem; font-weight: 600; margin-left: 6px;
    }}

    /* Summary */
    .summary-box {{
      background: #f8fafc; border: 1px solid #e2e8f0;
      border-radius: 8px; padding: 16px; margin-top: 16px;
      font-size: 0.95rem; color: #374151;
    }}

    /* Grid of cards */
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }}
    @media (max-width: 640px) {{ .grid {{ grid-template-columns: 1fr; }} }}
    .card {{
      background: white; border-radius: 10px; padding: 20px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.07);
    }}
    .card h3 {{ font-size: 0.85rem; font-weight: 700; text-transform: uppercase;
                letter-spacing: 0.08em; color: #6b7280; margin-bottom: 12px; }}
    .card ul {{ padding-left: 18px; }}
    .card li {{ font-size: 0.9rem; }}

    /* Sender block */
    .sender-grid {{ display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px;
                   font-size: 0.9rem; }}
    .sender-label {{ color: #6b7280; font-weight: 600; }}

    /* Action */
    .action-card {{
      background: {badge_bg}; border: 2px solid {accent};
      border-radius: 10px; padding: 20px; text-align: center; margin-bottom: 24px;
    }}
    .action-card h3 {{ font-size: 0.8rem; color: #6b7280; text-transform: uppercase;
                       letter-spacing: 0.08em; margin-bottom: 8px; }}
    .action-card .action-text {{ font-size: 1.3rem; font-weight: 800; color: {accent}; }}

    /* Raw email */
    .email-box {{
      background: #1e293b; color: #94a3b8; font-family: monospace;
      font-size: 0.8rem; padding: 20px; border-radius: 10px;
      white-space: pre-wrap; word-break: break-word; max-height: 300px;
      overflow-y: auto; margin-bottom: 24px;
    }}

    /* Footer */
    .footer {{ text-align: center; font-size: 0.75rem; color: #9ca3af; padding: 24px; }}
    .spoofed {{ color: #ef4444; font-weight: 700; }}
    .clean {{ color: #22c55e; font-weight: 600; }}
  </style>
</head>
<body>

<div class="header">
  <h1>🔍 AI PHISHING & THREAT ANALYZER</h1>
  <div class="meta">
    Generated: {datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC<br>
    Engine: {provider.upper()} / {model}<br>
    Analysis time: {latency}ms
  </div>
</div>

<div class="container">

  <!-- VERDICT CARD -->
  <div class="verdict-card">
    <div class="verdict-title">{verdict_text}</div>
    <div class="score-ring-container">
      <div class="score-ring">
        <span class="num">{score}</span>
        <span class="den">/100</span>
      </div>
      <div class="verdict-meta">
        <p><strong>Risk Level:</strong> <span class="badge">{label}</span></p>
        <p><strong>Confidence:</strong> <span class="badge">{report.get('confidence','N/A').upper()}</span></p>
        <p><strong>Category:</strong> <span class="badge">{report.get('threat_category','N/A').upper()}</span></p>
        <p><strong>Target Data:</strong> {', '.join(target_data) if target_data else 'None identified'}</p>
      </div>
    </div>
    <div class="summary-box">{summary}</div>
  </div>

  <!-- RECOMMENDED ACTION -->
  <div class="action-card">
    <h3>Recommended Action</h3>
    <div class="action-text">► {action}</div>
  </div>

  <!-- DETAIL GRID -->
  <div class="grid">

    <div class="card">
      <h3>🚩 Red Flags ({len(red_flags)})</h3>
      <ul>{list_items(red_flags, '#ef4444')}</ul>
    </div>

    <div class="card">
      <h3>⚡ Urgency / Pressure Tactics</h3>
      <ul>{list_items(urgency, '#d97706')}</ul>
    </div>

    <div class="card">
      <h3>🔗 Suspicious URLs / Domains</h3>
      <ul>{list_items(sus_urls, '#7c3aed')}</ul>
    </div>

    <div class="card">
      <h3>🎭 Social Engineering Tactics</h3>
      <ul>{list_items(se_tactics, '#dc2626')}</ul>
    </div>

    <div class="card">
      <h3>✅ Legitimate Indicators</h3>
      <ul>{list_items(legit, '#16a34a')}</ul>
    </div>

    <div class="card">
      <h3>📧 Sender Analysis</h3>
      <div class="sender-grid">
        <span class="sender-label">Spoofed:</span>
        <span class="{'spoofed' if sender.get('appears_spoofed') else 'clean'}">
          {'YES' if sender.get('appears_spoofed') else 'No'}
        </span>
        <span class="sender-label">Technique:</span>
        <span>{sender.get('spoofing_technique', 'N/A')}</span>
        <span class="sender-label">Details:</span>
        <span>{sender.get('sender_details', 'N/A')}</span>
      </div>
    </div>

  </div>

  <!-- RAW EMAIL -->
  <div class="card" style="margin-bottom:16px">
    <h3 style="margin-bottom:12px">📄 Analyzed Email Content (Preview)</h3>
  </div>
  <div class="email-box">{email_safe}{"..." if len(email_text) > 1500 else ""}</div>

</div>

<div class="footer">
  AI Phishing Analyzer · Report generated {datetime.datetime.utcnow().strftime("%Y-%m-%d")} ·
  For educational and security research purposes only.
</div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath


def generate_json_report(email_text: str, report: dict) -> str:
    """Save the raw analysis result as a JSON file. Returns file path."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filepath  = os.path.join(OUTPUT_DIR, f"threat_report_{timestamp}.json")

    output = {
        "meta": {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "email_length": len(email_text),
            "provider":     report.get("_provider"),
            "model":        report.get("_model"),
            "latency_ms":   report.get("_latency_ms"),
        },
        "analysis": {k: v for k, v in report.items() if not k.startswith("_")},
        "email_snippet": email_text[:500],
    }

    with open(filepath, "w") as f:
        json.dump(output, f, indent=2)

    return filepath
