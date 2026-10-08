"""
utils.py — Utility helpers for the Phishing Analyzer.

Covers:
  - Email pre-processing and header extraction
  - URL extraction from raw text
  - Risk score → label/colour mapping
  - Console pretty-printing (coloured output)
  - Analysis history logging (JSON append)
"""

import re
import json
import os
import datetime
from config import (
    RISK_LOW, RISK_MEDIUM, RISK_HIGH,
    LOG_FILE, LOG_DIR, OUTPUT_DIR,
)

# ──────────────────────────────────────────────────────────────────────────────
# COLOUR CODES  (ANSI — work on all terminals; Windows needs colorama)
# ──────────────────────────────────────────────────────────────────────────────
try:
    import colorama
    colorama.init(autoreset=True)
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"
    ORANGE = "\033[38;5;208m"
except ImportError:
    RED = YELLOW = GREEN = CYAN = BOLD = DIM = RESET = ORANGE = ""


# ──────────────────────────────────────────────────────────────────────────────
# RISK HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def risk_label(score: int) -> str:
    """Convert numeric risk score to text label."""
    if score <= RISK_LOW:
        return "LOW RISK"
    elif score <= RISK_MEDIUM:
        return "SUSPICIOUS"
    elif score <= RISK_HIGH:
        return "HIGH RISK"
    else:
        return "CRITICAL — PHISHING"


def risk_colour(score: int) -> str:
    """Return ANSI colour code matching the risk level."""
    if score <= RISK_LOW:
        return GREEN
    elif score <= RISK_MEDIUM:
        return YELLOW
    elif score <= RISK_HIGH:
        return ORANGE
    else:
        return RED


def risk_emoji(score: int) -> str:
    if score <= RISK_LOW:
        return "✅"
    elif score <= RISK_MEDIUM:
        return "⚠️"
    elif score <= RISK_HIGH:
        return "🔶"
    else:
        return "🚨"


# ──────────────────────────────────────────────────────────────────────────────
# EMAIL PRE-PROCESSING
# ──────────────────────────────────────────────────────────────────────────────

def extract_urls_from_text(text: str) -> list[str]:
    """
    Pull all URLs from raw text using regex.
    Returns a deduplicated list of found URLs.
    """
    pattern = r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+'
    urls = re.findall(pattern, text, re.IGNORECASE)
    return list(dict.fromkeys(urls))  # preserve order, deduplicate


def extract_email_addresses(text: str) -> list[str]:
    """Extract all email addresses found in text."""
    pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    return list(set(re.findall(pattern, text)))


def extract_headers(email_text: str) -> dict:
    """
    Parse simple email headers (From, To, Subject, Date, Reply-To).
    Works on raw email paste — not MIME parsing.
    """
    headers = {}
    header_patterns = {
        "from":     r'^From:\s*(.+)$',
        "to":       r'^To:\s*(.+)$',
        "subject":  r'^Subject:\s*(.+)$',
        "date":     r'^Date:\s*(.+)$',
        "reply_to": r'^Reply-To:\s*(.+)$',
        "x_mailer": r'^X-Mailer:\s*(.+)$',
    }
    for key, pattern in header_patterns.items():
        match = re.search(pattern, email_text, re.MULTILINE | re.IGNORECASE)
        if match:
            headers[key] = match.group(1).strip()
    return headers


def preprocess_email(raw_text: str) -> str:
    """
    Light cleaning of email text before sending to AI:
      - Strip excessive whitespace
      - Preserve structure (headers + body)
    """
    # Normalise line endings
    text = raw_text.replace('\r\n', '\n').replace('\r', '\n')
    # Collapse 3+ consecutive blank lines → 2
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


# ──────────────────────────────────────────────────────────────────────────────
# CONSOLE DISPLAY
# ──────────────────────────────────────────────────────────────────────────────

def print_banner():
    banner = f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════╗
║        AI-POWERED PHISHING EMAIL & THREAT ANALYZER       ║
║        Powered by Groq (Llama 3.1) / Gemini Flash        ║
╚══════════════════════════════════════════════════════════╝
{RESET}"""
    print(banner)


def print_report(report: dict):
    """Pretty-print the analysis report to the terminal."""
    score  = report.get("risk_score", 0)
    colour = risk_colour(score)
    label  = risk_label(score)
    emoji  = risk_emoji(score)

    sep = f"{DIM}{'─' * 60}{RESET}"

    print(f"\n{sep}")
    print(f"{BOLD}  THREAT ANALYSIS REPORT{RESET}")
    print(sep)

    # ── Verdict block ──
    verdict = "PHISHING" if report.get("is_phishing") else "LEGITIMATE"
    verdict_colour = RED if report.get("is_phishing") else GREEN
    print(f"  Verdict        : {verdict_colour}{BOLD}{verdict}{RESET}  {emoji}")
    print(f"  Risk Score     : {colour}{BOLD}{score}/100  [{label}]{RESET}")
    print(f"  Confidence     : {report.get('confidence', 'N/A').upper()}")
    print(f"  Threat Category: {report.get('threat_category', 'N/A').upper()}")
    print(f"  AI Provider    : {report.get('_provider', 'N/A')} / {report.get('_model', 'N/A')}")
    print(f"  Response Time  : {report.get('_latency_ms', 0)}ms")
    print(sep)

    # ── Summary ──
    summary = report.get("summary", "")
    if summary:
        print(f"\n{BOLD}  EXECUTIVE SUMMARY{RESET}")
        print(f"  {summary}")

    # ── Red Flags ──
    flags = report.get("red_flags", [])
    if flags:
        print(f"\n{RED}{BOLD}  RED FLAGS DETECTED ({len(flags)}){RESET}")
        for f in flags:
            print(f"  {RED}✗{RESET} {f}")

    # ── Urgency Indicators ──
    urgency = report.get("urgency_indicators", [])
    if urgency:
        print(f"\n{YELLOW}{BOLD}  URGENCY/PRESSURE TACTICS{RESET}")
        for u in urgency:
            print(f"  {YELLOW}⚡{RESET} {u}")

    # ── Suspicious URLs ──
    urls = report.get("suspicious_urls", [])
    if urls:
        print(f"\n{ORANGE}{BOLD}  SUSPICIOUS URLs/DOMAINS{RESET}")
        for u in urls:
            print(f"  {ORANGE}🔗{RESET} {u}")

    # ── Sender Analysis ──
    sender = report.get("sender_analysis", {})
    if sender:
        spoofed = sender.get("appears_spoofed", False)
        spoofed_str = f"{RED}YES — SPOOFED{RESET}" if spoofed else f"{GREEN}No{RESET}"
        print(f"\n{BOLD}  SENDER ANALYSIS{RESET}")
        print(f"  Appears Spoofed : {spoofed_str}")
        print(f"  Technique       : {sender.get('spoofing_technique', 'none')}")
        print(f"  Details         : {sender.get('sender_details', 'N/A')}")

    # ── Social Engineering ──
    se = report.get("social_engineering_tactics", [])
    if se:
        print(f"\n{BOLD}  SOCIAL ENGINEERING TACTICS{RESET}")
        for t in se:
            print(f"  ◆ {t}")

    # ── Legitimate Indicators ──
    legit = report.get("legitimate_indicators", [])
    if legit:
        print(f"\n{GREEN}{BOLD}  LEGITIMATE INDICATORS{RESET}")
        for l in legit:
            print(f"  {GREEN}✓{RESET} {l}")

    # ── Recommended Action ──
    action = report.get("recommended_action", "N/A")
    action_colour = RED if "delete" in action or "quarantine" in action else (
        YELLOW if "report" in action or "verify" in action else GREEN
    )
    print(f"\n{sep}")
    print(f"  {BOLD}RECOMMENDED ACTION:{RESET}")
    print(f"  {action_colour}{BOLD}  ► {action.upper().replace('_', ' ')}{RESET}")
    print(f"{sep}\n")


# ──────────────────────────────────────────────────────────────────────────────
# HISTORY LOGGING
# ──────────────────────────────────────────────────────────────────────────────

def log_analysis(email_text: str, report: dict):
    """
    Append an analysis result to the JSON log file.
    Creates the log file if it doesn't exist.
    Each entry: timestamp, snippet, verdict, score, provider.
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    entry = {
        "timestamp":      datetime.datetime.utcnow().isoformat() + "Z",
        "email_snippet":  email_text[:200].replace('\n', ' '),
        "is_phishing":    report.get("is_phishing"),
        "risk_score":     report.get("risk_score"),
        "confidence":     report.get("confidence"),
        "threat_category":report.get("threat_category"),
        "red_flags_count":len(report.get("red_flags", [])),
        "recommended_action": report.get("recommended_action"),
        "provider":       report.get("_provider"),
        "model":          report.get("_model"),
        "latency_ms":     report.get("_latency_ms"),
    }

    history = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                history = json.load(f)
        except (json.JSONDecodeError, IOError):
            history = []

    history.append(entry)

    with open(LOG_FILE, "w") as f:
        json.dump(history, f, indent=2)

    return entry


def load_history() -> list:
    """Load and return full analysis history."""
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return json.load(f)


def ensure_dirs():
    """Create output directories if they don't exist."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
