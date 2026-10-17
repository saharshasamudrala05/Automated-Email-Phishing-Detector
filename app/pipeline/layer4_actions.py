"""
Layer 4: Automated Inbox Remediation & SOC Alerts

Actions triggered based on final verdict:
  PHISHING  (score ≥ 70): Apply ⚠️ PHISHING label + remove from INBOX + Telegram alert
  SUSPICIOUS(score ≥ 40): Apply 🔶 SUSPICIOUS label + Telegram alert
  SAFE      (score < 40): No action (preserve normal inbox flow)
"""
import requests
from app.config import Config


def execute(
    gmail_client,
    gmail_message_id: str,
    verdict: str,
    final_score: int,
    sender: str,
    subject: str,
    soc_advisory: str = "",
    threat_category: str = "",
) -> dict:
    """
    Execute all Layer 4 automated responses.

    Args:
        gmail_client:       Authenticated GmailClient instance
        gmail_message_id:   Gmail message ID to label
        verdict:            'PHISHING', 'SUSPICIOUS', or 'SAFE'
        final_score:        0-100 risk score
        sender, subject:    For alert content
        soc_advisory:       AI-generated advisory text
        threat_category:    Threat classification

    Returns:
        dict with actions_taken list and status flags
    """
    actions  = []
    label    = None
    telegram = False
    errors   = []

    # ── Gmail Labeling ───────────────────────────────────────────
    try:
        if verdict == "PHISHING":
            gmail_client.apply_phishing_label(gmail_message_id)
            label = "⚠️ PHISHING"
            actions.append("Applied label '⚠️ PHISHING' and removed from INBOX")

        elif verdict == "SUSPICIOUS":
            gmail_client.apply_suspicious_label(gmail_message_id)
            label = "🔶 SUSPICIOUS"
            actions.append("Applied label '🔶 SUSPICIOUS'")

    except Exception as e:
        errors.append(f"Gmail label error: {str(e)[:100]}")

    # ── Telegram Alert ───────────────────────────────────────────
    if verdict in ("PHISHING", "SUSPICIOUS") and Config.TELEGRAM_BOT_TOKEN and Config.TELEGRAM_CHAT_ID:
        try:
            _send_telegram_alert(
                verdict=verdict,
                score=final_score,
                sender=sender,
                subject=subject,
                category=threat_category,
                advisory=soc_advisory,
            )
            telegram = True
            actions.append("Telegram SOC alert dispatched")
        except Exception as e:
            errors.append(f"Telegram alert error: {str(e)[:100]}")

    if verdict == "SAFE":
        actions.append("No action required — email cleared all security checks")

    if errors:
        actions.extend([f"⚠ Error: {e}" for e in errors])

    return {
        "label_applied":  label,
        "telegram_sent":  telegram,
        "actions_taken":  actions,
        "errors":         errors,
    }


# ─── Telegram ─────────────────────────────────────────────────────────────────

def _send_telegram_alert(
    verdict: str,
    score: int,
    sender: str,
    subject: str,
    category: str,
    advisory: str,
):
    """Send a structured Telegram alert to the security team."""
    icon   = "🚨" if verdict == "PHISHING" else "⚠️"
    colour = "RED ALERT" if verdict == "PHISHING" else "ORANGE ALERT"

    message = (
        f"{icon} <b>PHISHGUARD — {colour}</b>\n\n"
        f"<b>Verdict:</b> {verdict}\n"
        f"<b>Risk Score:</b> {score}/100\n"
        f"<b>Category:</b> {category or 'Unknown'}\n\n"
        f"<b>From:</b> <code>{_safe(sender[:80])}</code>\n"
        f"<b>Subject:</b> <code>{_safe(subject[:100])}</code>\n\n"
        f"<b>Advisory:</b> {_safe(advisory[:300])}\n\n"
        f"<i>Check your PhishGuard dashboard for full report.</i>"
    )

    url = f"https://api.telegram.org/bot{Config.TELEGRAM_BOT_TOKEN}/sendMessage"
    resp = requests.post(url, json={
        "chat_id":    Config.TELEGRAM_CHAT_ID,
        "text":       message,
        "parse_mode": "HTML",
    }, timeout=10)
    resp.raise_for_status()


def _safe(text: str) -> str:
    """Escape HTML special chars for Telegram."""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))
