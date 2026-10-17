"""
config.py — PhishGuard Production Configuration
All secrets loaded from environment variables. Never hardcoded.
"""
import os
import json
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ── Flask Core ──────────────────────────────────────────────
    SECRET_KEY      = os.getenv("SECRET_KEY", os.urandom(32).hex())
    DEBUG           = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    BASE_URL        = os.getenv("BASE_URL", "http://localhost:5000")

    # ── Database ─────────────────────────────────────────────────
    DATABASE_PATH   = os.getenv("DATABASE_PATH", "phishguard.db")

    # ── Groq AI ──────────────────────────────────────────────────
    GROQ_API_KEY    = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL      = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
    GROQ_API_URL    = "https://api.groq.com/openai/v1/chat/completions"
    AI_TIMEOUT      = 30

    # ── Gmail OAuth 2.0 ──────────────────────────────────────────
    # Store credentials.json content as env var on cloud deployments
    GOOGLE_CREDENTIALS_JSON = os.getenv("GOOGLE_CREDENTIALS_JSON", "")
    GMAIL_TOKEN_FILE        = os.getenv("GMAIL_TOKEN_FILE", "gmail_token.json")
    GMAIL_SCOPES = [
        "https://www.googleapis.com/auth/gmail.modify",   # read + label
    ]

    # ── Polling ───────────────────────────────────────────────────
    POLL_INTERVAL_MINUTES   = int(os.getenv("POLL_INTERVAL_MINUTES", "5"))
    MAX_EMAILS_PER_POLL     = int(os.getenv("MAX_EMAILS_PER_POLL", "10"))

    # ── Telegram Alerts ───────────────────────────────────────────
    TELEGRAM_BOT_TOKEN      = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID        = os.getenv("TELEGRAM_CHAT_ID", "")

    # ── Pipeline Thresholds ───────────────────────────────────────
    PHISHING_THRESHOLD      = int(os.getenv("PHISHING_THRESHOLD", "70"))
    SUSPICIOUS_THRESHOLD    = int(os.getenv("SUSPICIOUS_THRESHOLD", "40"))
    DOMAIN_AGE_DAYS_FLAG    = int(os.getenv("DOMAIN_AGE_DAYS_FLAG", "30"))

    # ── Security ──────────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE   = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
    MAX_EMAIL_BODY_CHARS    = 8000   # Truncate before sending to AI

    @classmethod
    def get_google_credentials_dict(cls) -> dict | None:
        """Return credentials dict from env var or local file."""
        if cls.GOOGLE_CREDENTIALS_JSON:
            try:
                return json.loads(cls.GOOGLE_CREDENTIALS_JSON)
            except json.JSONDecodeError:
                return None
        if os.path.exists("credentials.json"):
            with open("credentials.json") as f:
                return json.load(f)
        return None

    @classmethod
    def validate(cls):
        errors = []
        if not cls.GROQ_API_KEY:
            errors.append("GROQ_API_KEY is not set")
        if errors:
            raise EnvironmentError("Configuration errors:\n  " + "\n  ".join(errors))
