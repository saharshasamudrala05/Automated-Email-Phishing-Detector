"""
orchestrator.py — 4-Layer Pipeline Runner

Executes all layers in sequence, computes the weighted final score,
and returns a complete ThreatReport dict ready for database storage.

Scoring weights (security analyst rationale):
  Layer 1 (SPF/DKIM/DMARC): 40% — Hard cryptographic facts, non-repudiable
  Layer 2 (Domain/URL):      35% — Deterministic rule checks, high precision
  Layer 3 (AI content):      25% — Probabilistic, adds value on social engineering
"""
import time
import re
import datetime

from app.pipeline import layer1_auth, layer2_domain, layer3_ai, layer4_actions
from app.config import Config


# Scoring weights must sum to 1.0
W_L1 = 0.40
W_L2 = 0.35
W_L3 = 0.25

# Multi-layer agreement boosts (defense-in-depth confirmation)
MULTI_LAYER_BOOST_2 = 1.20   # 20% boost if 2+ layers agree
MULTI_LAYER_BOOST_3 = 1.35   # 35% boost if all 3 layers flag


def run(email_data: dict, gmail_client=None) -> dict:
    """
    Execute the full 4-layer analysis pipeline on one email.

    Args:
        email_data:   Dict from GmailClient._fetch_full_message()
        gmail_client: Authenticated GmailClient (for Layer 4 labeling)

    Returns:
        Complete ThreatReport dict
    """
    t_start = time.time()

    # ── Metadata ─────────────────────────────────────────────────
    sender        = email_data.get("sender", "")
    subject       = email_data.get("subject", "")
    body          = email_data.get("body", "")
    headers       = email_data.get("headers", {})
    message_id    = email_data.get("id", "")

    # Sanitize body before any AI layer sees it
    sanitized_snippet = _sanitize_body_snippet(body)

    # ── Layer 1: Cryptographic Authentication ─────────────────────
    l1 = layer1_auth.check(headers)

    # ── Layer 2: Domain & URL Analysis ───────────────────────────
    l2 = layer2_domain.check(sender, subject, body)

    # ── Layer 3: Constrained AI (sees violations, not raw email) ──
    violation_report = {
        "l1_flags":      l1["flags"],
        "l1_risk_score": l1["risk_contribution"],
        "l2_flags":      l2["flags"],
        "l2_risk_score": l2["risk_contribution"],
    }
    l3 = layer3_ai.analyze(violation_report, subject, sanitized_snippet)

    # ── Score Aggregation ─────────────────────────────────────────
    final_score = _compute_final_score(l1, l2, l3)
    verdict     = _score_to_verdict(final_score)

    # ── Layer 4: Automated Actions ───────────────────────────────
    l4 = {"label_applied": None, "telegram_sent": False, "actions_taken": [], "errors": []}
    if gmail_client:
        try:
            l4 = layer4_actions.execute(
                gmail_client    = gmail_client,
                gmail_message_id= message_id,
                verdict         = verdict,
                final_score     = final_score,
                sender          = sender,
                subject         = subject,
                soc_advisory    = l3.get("soc_advisory", ""),
                threat_category = l3.get("threat_category", ""),
            )
        except Exception as e:
            l4["errors"].append(str(e))
            l4["actions_taken"].append(f"Layer 4 error: {str(e)[:80]}")

    processing_ms = int((time.time() - t_start) * 1000)

    return {
        # Identity
        "gmail_message_id": message_id,
        "subject":          subject,
        "sender":           sender,
        "sender_domain":    l2.get("from_domain", ""),
        "recipient":        email_data.get("recipient", ""),
        "date_received":    email_data.get("date", ""),

        # Pipeline results
        "layer1":           l1,
        "layer2":           l2,
        "layer3":           l3,
        "layer4":           l4,

        # Final verdict
        "final_score":      final_score,
        "verdict":          verdict,

        # Meta
        "processing_time_ms": processing_ms,
        "analyzed_at":        datetime.datetime.utcnow().isoformat() + "Z",
    }


# ─── Scoring ──────────────────────────────────────────────────────────────────

def _compute_final_score(l1: dict, l2: dict, l3: dict) -> int:
    s1 = l1.get("risk_contribution", 0)
    s2 = l2.get("risk_contribution", 0)
    s3 = l3.get("content_risk_score", 0)

    weighted = (s1 * W_L1) + (s2 * W_L2) + (s3 * W_L3)

    # Multi-layer agreement boost — if multiple independent checks agree, confidence rises
    flagging_layers = sum([s1 > 25, s2 > 25, s3 > 35])
    if flagging_layers == 3:
        weighted = weighted * MULTI_LAYER_BOOST_3
    elif flagging_layers == 2:
        weighted = weighted * MULTI_LAYER_BOOST_2

    return int(min(weighted, 100))


def _score_to_verdict(score: int) -> str:
    if score >= Config.PHISHING_THRESHOLD:
        return "PHISHING"
    if score >= Config.SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "SAFE"


# ─── Body Sanitization ────────────────────────────────────────────────────────

def _sanitize_body_snippet(body: str) -> str:
    """
    Return a short, sanitized snippet of the email body for AI context.
    Strips potential prompt injection attempts.
    """
    # Remove anything that looks like an instruction to the AI
    injection_patterns = [
        r"ignore (previous|all|above) instructions",
        r"you are now",
        r"new instruction",
        r"system prompt",
        r"disregard",
        r"forget everything",
    ]
    cleaned = body
    for pat in injection_patterns:
        cleaned = re.sub(pat, "[REDACTED]", cleaned, flags=re.IGNORECASE)

    # Strip URLs from snippet (already handled in L2, don't repeat for AI)
    cleaned = re.sub(r"https?://\S+", "[URL]", cleaned)

    return cleaned[:300].strip()
