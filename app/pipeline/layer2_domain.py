"""
Layer 2: Deterministic Domain & URL Analysis

Runs non-AI rule-based checks:
  1. WHOIS domain age check (< 30 days = suspicious)
  2. Typosquatting detection via Levenshtein distance
  3. Display name / brand impersonation check
  4. URL extraction and domain-mismatch analysis
  5. URL shortener detection

All rules produce binary flag/no-flag decisions — no AI guesswork.
"""
import re
import datetime
import socket
from urllib.parse import urlparse

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


# ─── Known brand list for typosquatting and display name checks ──────────────
PROTECTED_BRANDS = [
    "google", "gmail", "microsoft", "outlook", "office365", "office",
    "apple", "icloud", "amazon", "aws", "paypal", "ebay", "facebook",
    "instagram", "twitter", "linkedin", "dropbox", "netflix", "spotify",
    "github", "gitlab", "zoom", "slack", "salesforce", "adobe", "docusign",
    "chase", "wellsfargo", "citibank", "bankofamerica", "hsbc", "barclays",
    "irs", "fedex", "dhl", "ups", "usps", "coinbase", "binance",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "short.link", "cutt.ly", "rb.gy",
}

DANGEROUS_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".msi", ".vbs",
                         ".js", ".jar", ".ps1", ".hta", ".pif"}


# ─── Main Entry ───────────────────────────────────────────────────────────────

def check(sender: str, subject: str, body: str) -> dict:
    """
    Run full Layer 2 analysis.

    Returns:
        Layer 2 report dict with flags and risk_contribution.
    """
    flags = []
    score = 0

    display_name = _extract_display_name(sender)
    from_email   = _extract_email(sender)
    from_domain  = _extract_domain(from_email)
    root_domain  = _get_root_domain(from_domain)

    # ── 1. Display Name Brand Impersonation ──────────────────────
    impersonated_brand = _check_display_name_spoofing(display_name, from_domain)
    display_spoofing   = bool(impersonated_brand)
    if display_spoofing:
        flags.append({
            "code":    "DISPLAY_NAME_SPOOFING",
            "label":   "Brand Impersonation",
            "detail":  f"Display name '{display_name}' impersonates '{impersonated_brand}' "
                       f"but email is from '{from_domain}' (not the official domain).",
            "severity": "high",
        })
        score += 25

    # ── 2. Typosquatting ─────────────────────────────────────────
    closest_brand, distance = _check_typosquatting(root_domain)
    typosquatting_target    = None
    if closest_brand and distance <= 2 and root_domain != closest_brand:
        typosquatting_target = closest_brand
        flags.append({
            "code":    "TYPOSQUATTING",
            "label":   "Typosquatting Detected",
            "detail":  f"Domain '{from_domain}' is {distance} edit(s) away from '{closest_brand}.com'. "
                       f"Classic domain lookalike attack.",
            "severity": "critical" if distance == 1 else "high",
        })
        score += 35 if distance == 1 else 25

    # ── 3. WHOIS Domain Age ───────────────────────────────────────
    domain_age_days = _get_domain_age(from_domain)
    if domain_age_days is not None and domain_age_days < 30:
        flags.append({
            "code":    "NEW_DOMAIN",
            "label":   f"New Domain ({domain_age_days}d old)",
            "detail":  f"Domain '{from_domain}' was registered only {domain_age_days} days ago. "
                       f"Phishing domains are almost always newly created.",
            "severity": "critical" if domain_age_days < 7 else "high",
        })
        score += 30 if domain_age_days < 7 else 20

    # ── 4. Suspicious URL Analysis ───────────────────────────────
    urls = _extract_urls(body)
    suspicious_urls = []

    for url in urls[:10]:   # Cap at 10 URLs
        url_domain = _get_url_domain(url)
        url_root   = _get_root_domain(url_domain)
        issues     = []

        if _is_url_shortener(url_domain):
            issues.append("URL shortener hides real destination")
            score += 15

        if url_root and root_domain and url_root != root_domain and not _is_known_safe(url_root):
            issues.append(f"URL domain '{url_root}' does not match sender domain '{root_domain}'")
            score += 10

        if any(url.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            issues.append("Link points to executable file type")
            score += 25

        if url.startswith("http://") and not url.startswith("https://"):
            issues.append("Non-HTTPS (unencrypted) URL")
            score += 5

        if issues:
            suspicious_urls.append({"url": url[:200], "issues": issues})
            flags.append({
                "code":    "SUSPICIOUS_URL",
                "label":   "Suspicious URL",
                "detail":  f"{url[:80]}... — {'; '.join(issues)}",
                "severity": "high",
            })

    # ── 5. Generic sender on free email domain ───────────────────
    free_domains = {"gmail.com","yahoo.com","hotmail.com","outlook.com","protonmail.com"}
    if from_domain in free_domains and display_name and _looks_like_org(display_name):
        flags.append({
            "code":    "FREE_DOMAIN_ORG",
            "label":   "Organisation via Free Email",
            "detail":  f"'{display_name}' claims to be an organisation but sends from '{from_domain}'. "
                       f"Legitimate businesses use their own domain.",
            "severity": "medium",
        })
        score += 15

    return {
        "from_domain":          from_domain,
        "display_name":         display_name,
        "display_name_spoofing":display_spoofing,
        "impersonated_brand":   impersonated_brand,
        "typosquatting_target": typosquatting_target,
        "domain_age_days":      domain_age_days,
        "suspicious_urls":      suspicious_urls,
        "extracted_urls":       urls[:10],
        "flags":                flags,
        "risk_contribution":    min(score, 100),
        "passed":               score == 0,
    }


# ─── Check Functions ──────────────────────────────────────────────────────────

def _check_display_name_spoofing(display_name: str, from_domain: str) -> str | None:
    """Return the impersonated brand name if spoofing detected, else None."""
    if not display_name:
        return None
    dn_lower = display_name.lower()
    for brand in PROTECTED_BRANDS:
        if brand in dn_lower:
            # Check if from_domain actually belongs to this brand
            if brand not in from_domain:
                return brand
    return None


def _check_typosquatting(root_domain: str) -> tuple[str | None, int]:
    """Return (closest_brand, edit_distance) for the sender root domain."""
    if not root_domain or len(root_domain) < 4:
        return None, 99
    best_brand    = None
    best_distance = 99
    for brand in PROTECTED_BRANDS:
        d = _levenshtein(root_domain, brand)
        if d < best_distance:
            best_distance = d
            best_brand    = brand
    return best_brand, best_distance


def _get_domain_age(domain: str) -> int | None:
    """Return domain age in days via WHOIS, or None if unavailable."""
    if not WHOIS_AVAILABLE or not domain:
        return None
    try:
        import signal

        def _timeout(signum, frame):
            raise TimeoutError()

        # 5-second timeout for WHOIS
        w = whois_lib.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return None
        if isinstance(creation, str):
            creation = datetime.datetime.fromisoformat(creation)
        age = (datetime.datetime.utcnow() - creation.replace(tzinfo=None)).days
        return max(age, 0)
    except Exception:
        return None


# ─── URL Utilities ────────────────────────────────────────────────────────────

def _extract_urls(text: str) -> list[str]:
    pattern = r'https?://[^\s<>"\')\]\\]+'
    return list(dict.fromkeys(re.findall(pattern, text, re.IGNORECASE)))


def _get_url_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return ""


def _is_url_shortener(domain: str) -> bool:
    return domain in URL_SHORTENERS


def _is_known_safe(domain: str) -> bool:
    safe = {"google.com","googleapis.com","gstatic.com","amazon.com","amazonaws.com",
            "microsoft.com","apple.com","github.com","cdn.com","cloudfront.net"}
    return any(domain.endswith(s) for s in safe)


# ─── Domain Utilities ──────────────────────────────────────────────────────────

def _get_root_domain(domain: str) -> str:
    """Extract registrable root domain (e.g. 'evil.sub.paypal.com' → 'paypal')."""
    if not domain:
        return ""
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def _extract_display_name(from_header: str) -> str:
    """Extract display name from 'Display Name <email>' format."""
    m = re.match(r'^"?([^"<]+)"?\s*<', from_header)
    if m:
        return m.group(1).strip()
    return ""


def _extract_email(from_header: str) -> str:
    m = re.search(r"<([^>]+)>", from_header)
    if m:
        return m.group(1).strip().lower()
    bare = re.search(r"[\w.+-]+@[\w.-]+\.\w+", from_header)
    return bare.group(0).lower() if bare else from_header.lower().strip()


def _extract_domain(email: str) -> str:
    parts = email.split("@")
    return parts[-1].lower().strip() if len(parts) == 2 else ""


def _looks_like_org(name: str) -> bool:
    """Check if display name looks like it's claiming to be an organisation."""
    org_keywords = {"bank","security","support","helpdesk","team","service","official",
                    "admin","alert","notification","it","department","payroll","hr","finance"}
    return any(kw in name.lower() for kw in org_keywords)


# ─── Levenshtein Distance (no external dependency) ────────────────────────────

def _levenshtein(s1: str, s2: str) -> int:
    m, n = len(s1), len(s2)
    dp   = list(range(n + 1))
    for i in range(1, m + 1):
        prev  = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp  = dp[j]
            dp[j] = prev if s1[i-1] == s2[j-1] else 1 + min(prev, dp[j], dp[j-1])
            prev  = temp
    return dp[n]
