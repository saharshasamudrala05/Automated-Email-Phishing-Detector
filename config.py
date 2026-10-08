"""
config.py — Centralized configuration for Phishing Analyzer
All secrets are loaded from .env file. Never hardcode API keys.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ──────────────────────────────────────────────
# API PROVIDER SELECTION
# Set AI_PROVIDER in .env to "groq" or "gemini"
# ──────────────────────────────────────────────
AI_PROVIDER = os.getenv("AI_PROVIDER", "groq").lower()

# ──────────────────────────────────────────────
# GROQ (Primary — Free, Fast, No CC Required)
# Sign up: https://console.groq.com
# ──────────────────────────────────────────────
GROQ_API_KEY    = os.getenv("GROQ_API_KEY", "")
GROQ_API_URL    = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL      = "openai/gpt-oss-20b"   # Free tier — extremely fast
GROQ_MODEL_ALT  = "qwen/qwen3.8-27b"     # Alternative free model

# ──────────────────────────────────────────────
# GOOGLE GEMINI (Backup — Free Tier)
# Sign up: https://aistudio.google.com/app/apikey
# ──────────────────────────────────────────────
GEMINI_API_KEY  = os.getenv("GEMINI_API_KEY", "")
GEMINI_API_URL  = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

# ──────────────────────────────────────────────
# APPLICATION SETTINGS
# ──────────────────────────────────────────────
MAX_EMAIL_LENGTH    = 12000      # Characters — keep under model context limits
REQUEST_TIMEOUT     = 45         # Seconds before API call is abandoned
OUTPUT_DIR          = "reports"  # Where HTML/JSON reports are saved
LOG_DIR             = "logs"     # Where analysis history is stored
LOG_FILE            = os.path.join(LOG_DIR, "analysis_history.json")
WEB_HOST            = "0.0.0.0"
WEB_PORT            = 5000
WEB_DEBUG           = False

# Risk score thresholds for colour-coded output
RISK_LOW    = 30   # 0–30   → green (safe)
RISK_MEDIUM = 60   # 31–60  → yellow (suspicious)
RISK_HIGH   = 80   # 61–80  → orange (likely phishing)
               #  81–100 → red   (confirmed phishing)

# Validate config on import
def validate_config():
    """Check that at least one API key is available."""
    if AI_PROVIDER == "groq" and not GROQ_API_KEY:
        raise EnvironmentError(
            "\n[ERROR] GROQ_API_KEY is not set.\n"
            "  1. Get a free key at https://console.groq.com\n"
            "  2. Copy .env.example to .env and paste your key.\n"
        )
    if AI_PROVIDER == "gemini" and not GEMINI_API_KEY:
        raise EnvironmentError(
            "\n[ERROR] GEMINI_API_KEY is not set.\n"
            "  1. Get a free key at https://aistudio.google.com/app/apikey\n"
            "  2. Copy .env.example to .env and paste your key.\n"
        )
