"""
Layer 1: Cryptographic Email Authentication

Parses Gmail's Authentication-Results headers to extract hard
cryptographic verdicts for SPF, DKIM, and DMARC.

Design principle: these are FACTS, not heuristics. A DMARC fail
is a protocol-level violation — no AI opinion needed here.
"""
import re


# Status weight for risk scoring
SPF_WEIGHTS   = {"pass": 0, "neutral": 5, "softfail": 15, "fail": 25, "none": 10, "permerror": 20, "temperror": 10}
DKIM_WEIGHTS  = {"pass": 0, "fail": 25, "none": 10, "permerror": 20, "temperror": 10}
DMARC_WEIGHTS = {"pass": 0, "fail": 35, "none": 15, "quarantine": 20}


def check(headers: dict) -> dict:
    """
    Run Layer 1 authentication analysis.

    Args:
        headers: Dict of email headers (name → value)

    Returns:
        Layer 1 report dict with flags and risk_contribution (0-100)
    """
    # Gmail appends Authentication-Results; ARC is a secondary source
    auth_str = (
        headers.get("Authentication-Results", "") +
        " " +
        headers.get("ARC-Authentication-Results", "")
    )

    spf   = _parse_result(auth_str, r"spf=(\S+)")
    dkim  = _parse_result(auth_str, r"dkim=(\S+)")
    dmarc = _parse_result(auth_str, r"dmarc=(\S+)")

    # Header consistency checks
    from_header  = headers.get("From", "")
    return_path  = headers.get("Return-Path", "")
    reply_to     = headers.get("Reply-To", "")

    from_domain   = _extract_domain(_extract_email(from_header))
    return_domain = _extract_domain(_extract_email(return_path))
    reply_domain  = _extract_domain(_extract_email(reply_to))

    header_mismatch  = bool(
        return_domain and from_domain and
        from_domain != return_domain
    )
    reply_to_mismatch = bool(
        reply_domain and from_domain and
        from_domain != reply_domain
    )

    # Build flags list
    flags = []
    score = 0

    # SPF
    spf_clean = _clean_status(spf)
    spf_w = SPF_WEIGHTS.get(spf_clean, 10)
    if spf_w > 0:
        flags.append({
            "code":    "SPF_FAIL",
            "label":   f"SPF {spf_clean.upper()}",
            "detail":  f"Sender IP is {'not ' if spf_clean != 'pass' else ''}authorized by domain's SPF record.",
            "severity": "high" if spf_w >= 20 else "medium",
        })
        score += spf_w

    # DKIM
    dkim_clean = _clean_status(dkim)
    dkim_w = DKIM_WEIGHTS.get(dkim_clean, 10)
    if dkim_w > 0:
        flags.append({
            "code":    "DKIM_FAIL",
            "label":   f"DKIM {dkim_clean.upper()}",
            "detail":  f"Email {'cryptographic signature invalid or missing' if dkim_clean != 'pass' else 'signature valid'}.",
            "severity": "high" if dkim_w >= 20 else "medium",
        })
        score += dkim_w

    # DMARC
    dmarc_clean = _clean_status(dmarc)
    dmarc_w = DMARC_WEIGHTS.get(dmarc_clean, 15)
    if dmarc_w > 0:
        flags.append({
            "code":    "DMARC_FAIL",
            "label":   f"DMARC {dmarc_clean.upper()}",
            "detail":  f"Domain authentication policy {'failed' if dmarc_clean != 'pass' else 'passed'}. Domain owner has {'not ' if dmarc_clean != 'pass' else ''}authorised this sender.",
            "severity": "critical" if dmarc_w >= 30 else "high",
        })
        score += dmarc_w

    # Header mismatch
    if header_mismatch:
        flags.append({
            "code":    "HEADER_MISMATCH",
            "label":   "Return-Path Mismatch",
            "detail":  f"From: domain '{from_domain}' ≠ Return-Path domain '{return_domain}'. Classic spoofing indicator.",
            "severity": "high",
        })
        score += 20

    if reply_to_mismatch:
        flags.append({
            "code":    "REPLY_TO_MISMATCH",
            "label":   "Reply-To Hijack Attempt",
            "detail":  f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}'. Replies would go to attacker.",
            "severity": "high",
        })
        score += 15

    return {
        "spf":               spf_clean,
        "dkim":              dkim_clean,
        "dmarc":             dmarc_clean,
        "header_mismatch":   header_mismatch,
        "reply_to_mismatch": reply_to_mismatch,
        "from_domain":       from_domain,
        "return_domain":     return_domain,
        "flags":             flags,
        "risk_contribution": min(score, 100),
        "passed":            score == 0,
    }


# ─── Parsers ──────────────────────────────────────────────────────────────────

def _parse_result(auth_str: str, pattern: str) -> str:
    m = re.search(pattern, auth_str, re.IGNORECASE)
    return m.group(1) if m else "none"


def _clean_status(raw: str) -> str:
    """Normalise to lowercase base word, stripping extra context."""
    return raw.split(";")[0].split()[0].lower().strip()


def _extract_email(header_val: str) -> str:
    """Extract email address from 'Display Name <email@domain.com>' format."""
    m = re.search(r"<([^>]+)>", header_val)
    if m:
        return m.group(1).strip().lower()
    bare = re.search(r"[\w.+-]+@[\w.-]+\.\w+", header_val)
    return bare.group(0).lower() if bare else ""


def _extract_domain(email: str) -> str:
    parts = email.split("@")
    return parts[-1].lower().strip() if len(parts) == 2 else ""
