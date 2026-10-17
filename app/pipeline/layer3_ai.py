"""
Layer 3: Constrained AI Threat Scoring

CRITICAL DESIGN PRINCIPLE:
  The AI receives the VIOLATION REPORT from Layers 1 & 2 — NOT the raw email.

Why this matters:
  1. Prevents prompt injection (attacker can't hide instructions in email body)
  2. Constrains AI to confirming protocol violations, not guessing independently
  3. AI adds value only where rules can't: psychological tactics, intent analysis
  4. Subject line is passed (low-risk) for urgency/context analysis only

The AI cannot independently declare something phishing if Layers 1 & 2 found nothing.
"""
import json
import re
import requests

from app.config import Config


# ─── Constrained System Prompt ───────────────────────────────────────────────
# NOTE: This prompt deliberately gives the AI LIMITED context.
# It sees security violations — not the actual email content.

SYSTEM_PROMPT = """You are a Cybersecurity Threat Intelligence Analyst working in a SOC (Security Operations Centre).

You are given a STRUCTURED SECURITY VIOLATION REPORT produced by automated protocol-checking layers — NOT the raw email itself.

Your constraints:
1. You CANNOT independently declare an email as phishing without protocol violations being present
2. You MUST base your assessment on the violation report provided
3. You MAY analyse the email subject line for psychological manipulation tactics
4. You MUST return ONLY a valid JSON object — no preamble, no markdown

Your task:
- Evaluate the severity and combination of reported violations
- Identify psychological coercion tactics from the subject line
- Assign a content risk score (0-100) for social engineering indicators
- Write a 2-sentence SOC advisory for the security team
- Classify the threat type

Return EXACTLY this JSON schema:
{
  "content_risk_score": <integer 0-100>,
  "threat_category": "<credential_harvesting|business_email_compromise|malware_delivery|account_takeover|spam|legitimate>",
  "psychological_tactics": ["<tactic1>", "<tactic2>"],
  "attack_vector": "<email_spoofing|domain_lookalike|social_engineering|malware_link|unknown|none>",
  "soc_advisory": "<2-sentence advisory summarising threat and recommended action>",
  "confidence": "<low|medium|high>"
}"""


def analyze(violation_report: dict, subject: str = "", sanitized_snippet: str = "") -> dict:
    """
    Run Layer 3 constrained AI analysis.

    Args:
        violation_report: Dict with L1 and L2 flags and scores
        subject:          Email subject line (safe to pass — short, inspected for urgency)
        sanitized_snippet: First 300 chars of body, HTML-stripped (optional context)

    Returns:
        Layer 3 result dict
    """
    if not Config.GROQ_API_KEY:
        return _fallback_result(violation_report)

    user_message = _build_violation_message(violation_report, subject, sanitized_snippet)

    try:
        result = _call_groq(user_message)
        result["passed"] = result.get("content_risk_score", 0) < 30
        return result
    except Exception as e:
        return _fallback_result(violation_report, error=str(e))


# ─── Message Builder ──────────────────────────────────────────────────────────

def _build_violation_message(report: dict, subject: str, snippet: str) -> str:
    """
    Construct the structured message sent to AI.
    Deliberately minimal — only security-relevant data.
    """
    l1_flags = report.get("l1_flags", [])
    l2_flags = report.get("l2_flags", [])
    l1_score = report.get("l1_risk_score", 0)
    l2_score = report.get("l2_risk_score", 0)

    def fmt_flags(flags: list) -> str:
        if not flags:
            return "  → No violations detected"
        lines = []
        for f in flags:
            if isinstance(f, dict):
                lines.append(f"  → [{f.get('severity','?').upper()}] {f.get('label','?')}: {f.get('detail','')}")
            else:
                lines.append(f"  → {f}")
        return "\n".join(lines)

    msg = f"""SECURITY VIOLATION REPORT
══════════════════════════════════════════════

EMAIL SUBJECT (for psychological tactic analysis only):
  "{subject[:200]}"

BODY PREVIEW (HTML-stripped, first 300 chars):
  "{snippet[:300]}"

──────────────────────────────────────────────
LAYER 1 — CRYPTOGRAPHIC AUTHENTICATION
Risk Score: {l1_score}/100
Violations:
{fmt_flags(l1_flags)}

──────────────────────────────────────────────
LAYER 2 — DOMAIN & URL ANALYSIS
Risk Score: {l2_score}/100
Violations:
{fmt_flags(l2_flags)}

──────────────────────────────────────────────
Combined Protocol Risk: {min(l1_score + l2_score, 100)}/100

Assess the above and return your JSON response now."""

    return msg


# ─── API Call ─────────────────────────────────────────────────────────────────

def _call_groq(user_message: str) -> dict:
    headers = {
        "Authorization": f"Bearer {Config.GROQ_API_KEY}",
        "Content-Type":  "application/json",
    }
    payload = {
        "model":    Config.GROQ_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_message},
        ],
        "temperature": 0.1,
        "max_tokens":  800,
    }
    resp = requests.post(Config.GROQ_API_URL, headers=headers, json=payload, timeout=Config.AI_TIMEOUT)
    resp.raise_for_status()

    raw = resp.json()["choices"][0]["message"]["content"]
    return _parse_json(raw)


def _parse_json(raw: str) -> dict:
    cleaned = re.sub(r"```(?:json)?\s*|\s*```", "", raw).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", cleaned)
        if match:
            return json.loads(match.group())
        raise ValueError(f"Could not parse AI JSON: {raw[:200]}")


# ─── Fallback ─────────────────────────────────────────────────────────────────

def _fallback_result(violation_report: dict, error: str = "") -> dict:
    """
    Return a rule-based fallback if AI call fails.
    Ensures pipeline never fully breaks on AI outage.
    """
    combined = violation_report.get("l1_risk_score", 0) + violation_report.get("l2_risk_score", 0)
    score    = min(int(combined * 0.25), 40)   # Conservative — L1+L2 carry the weight

    return {
        "content_risk_score":  score,
        "threat_category":     "unknown",
        "psychological_tactics": [],
        "attack_vector":       "unknown",
        "soc_advisory":        f"AI analysis unavailable{': ' + error[:80] if error else ''}. "
                               f"Assessment based on protocol checks only.",
        "confidence":          "low",
        "passed":              score < 30,
        "fallback":            True,
    }
