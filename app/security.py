"""
security.py — Application Security Layer

Implements:
  - In-memory sliding-window rate limiter
  - Security response headers (CSP, HSTS, etc.)
  - Request audit logging
  - Input sanitization helpers
"""
import time
import re
import html
from collections import defaultdict
from functools import wraps
from flask import request, jsonify, g

from app.config import Config


# ─── Rate Limiter ─────────────────────────────────────────────────────────────

class SlidingWindowRateLimiter:
    """
    Simple in-memory sliding window rate limiter.
    For multi-process production, replace with Redis-backed limiter.
    """
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window       = window_seconds
        self._store: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now    = time.time()
        cutoff = now - self.window
        calls  = self._store[key]

        # Remove expired timestamps
        self._store[key] = [t for t in calls if t > cutoff]

        if len(self._store[key]) >= self.max_requests:
            return False

        self._store[key].append(now)
        return True

    def remaining(self, key: str) -> int:
        now    = time.time()
        cutoff = now - self.window
        active = [t for t in self._store.get(key, []) if t > cutoff]
        return max(0, self.max_requests - len(active))


# Module-level limiter instance
_limiter = SlidingWindowRateLimiter(
    max_requests=Config.RATE_LIMIT_PER_MINUTE,
    window_seconds=60
)


def rate_limit(f):
    """Route decorator: enforce rate limit per IP."""
    @wraps(f)
    def decorated(*args, **kwargs):
        ip  = _get_client_ip()
        key = f"rl:{ip}"
        if not _limiter.is_allowed(key):
            return jsonify({
                "error": "Rate limit exceeded. Try again in 60 seconds.",
                "code":  429,
            }), 429
        return f(*args, **kwargs)
    return decorated


def _get_client_ip() -> str:
    """Safely extract client IP, respecting reverse proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


# ─── Security Headers ─────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "X-Content-Type-Options":    "nosniff",
    "X-Frame-Options":           "DENY",
    "X-XSS-Protection":          "1; mode=block",
    "Referrer-Policy":           "strict-origin-when-cross-origin",
    "Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    ),
}


def apply_security_headers(response):
    """Flask after_request hook — adds security headers to every response."""
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    # HSTS only on HTTPS
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ─── Input Sanitization ───────────────────────────────────────────────────────

def sanitize_text(text: str, max_length: int = 10000) -> str:
    """
    Sanitize arbitrary text input:
      - Truncate to max_length
      - Remove null bytes
      - Strip leading/trailing whitespace
    Does NOT HTML-escape (that's done at render time by Jinja2 auto-escaping).
    """
    if not isinstance(text, str):
        text = str(text)
    text = text.replace("\x00", "")              # Remove null bytes
    text = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f]", "", text)  # Control chars
    return text[:max_length].strip()


def sanitize_email_address(email: str) -> str:
    """Validate and normalise an email address string."""
    email = email.strip().lower()
    if not re.match(r"^[\w.+-]+@[\w.-]+\.\w{2,}$", email):
        return ""
    return email[:254]   # RFC 5321 max length


# ─── Audit Logging ────────────────────────────────────────────────────────────

def log_request(action: str, details: str = ""):
    """Log a security-relevant event. Writes to DB via database module."""
    try:
        from app import database
        database.audit(
            action=action,
            details=details,
            ip=_get_client_ip(),
        )
    except Exception:
        pass   # Audit failure must never break the main request


# ─── CSRF Token (simple session-based) ───────────────────────────────────────

import secrets

def generate_csrf_token() -> str:
    from flask import session
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf(token: str) -> bool:
    from flask import session
    expected = session.get("csrf_token", "")
    return expected and secrets.compare_digest(expected, token)
