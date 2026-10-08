"""
analyzer.py — Core AI threat analysis engine.

Responsibilities:
  1. Build the security-analyst prompt
  2. Call Groq or Gemini API via raw HTTP (no SDKs required)
  3. Parse and validate the structured JSON verdict
  4. Return a clean ThreatReport dict

Design choice: raw `requests` instead of vendor SDKs keeps the
dependency footprint tiny and makes provider-switching trivial.
"""

import json
import re
import time
import requests

from config import (
    AI_PROVIDER,
    GROQ_API_KEY, GROQ_API_URL, GROQ_MODEL,
    GEMINI_API_KEY, GEMINI_API_URL,
    REQUEST_TIMEOUT, MAX_EMAIL_LENGTH,
)

# ──────────────────────────────────────────────────────────────────────────────
# SYSTEM PROMPT  ← the entire intelligence of the tool lives here
# Written as a role + task + strict output-format contract.
# Temperature is set to 0.1 so the model stays factual, not creative.
# ──────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a Senior Incident Response Analyst and Email Security Expert with 15 years of experience in phishing detection, social engineering analysis, and threat intelligence.

Your ONLY task is to analyze the provided email text and return a structured JSON security verdict.

ANALYSIS CHECKLIST:
- Urgency / fear / pressure tactics (account suspended, act now, limited time)
- Sender spoofing (display name ≠ actual domain, lookalike domains like paypa1.com)
- Suspicious links (URL shorteners, mismatched anchor text vs href, non-HTTPS)
- Credential harvesting patterns (fake login pages, "verify your account")
- Generic salutations ("Dear Customer") vs personalised
- Grammar and spelling quality
- Attachment threats
- Brand impersonation markers
- Legitimate trust signals (DKIM headers, known sending domain, personalisation)

STRICT OUTPUT RULES:
1. Return ONLY a single valid JSON object. No preamble, no explanation, no markdown fences.
2. All string values must be properly escaped.
3. risk_score must be an integer 0-100.
4. is_phishing must be a boolean true or false (not a string).

JSON SCHEMA TO FOLLOW EXACTLY:
{
  "is_phishing": <true|false>,
  "risk_score": <integer 0-100>,
  "confidence": "<low|medium|high>",
  "threat_category": "<phishing|spear_phishing|spam|malware_delivery|legitimate|suspicious>",
  "red_flags": ["<specific red flag 1>", "<specific red flag 2>"],
  "legitimate_indicators": ["<legitimate signal 1>"],
  "urgency_indicators": ["<urgency/pressure tactic found>"],
  "suspicious_urls": ["<url or domain found in text>"],
  "sender_analysis": {
    "appears_spoofed": <true|false>,
    "spoofing_technique": "<none|display_name_spoofing|domain_lookalike|unicode_homograph|subdomain_trick|header_mismatch>",
    "sender_details": "<analysis of the from address/name>"
  },
  "social_engineering_tactics": ["<tactic 1>", "<tactic 2>"],
  "target_data_sought": ["<credential|financial|personal_info|corporate_access|none>"],
  "recommended_action": "<delete_immediately|report_to_it_security|quarantine|verify_with_sender_via_phone|safe_to_proceed>",
  "summary": "<2-3 sentence executive summary of findings and risk level>"
}"""


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC INTERFACE
# ──────────────────────────────────────────────────────────────────────────────

def analyze_email(email_text: str, provider: str = None) -> dict:
    """
    Analyze an email for phishing indicators.

    Args:
        email_text: Raw email content (headers + body).
        provider:   Override AI_PROVIDER from config ('groq' or 'gemini').

    Returns:
        A dict matching the JSON schema above, plus meta fields:
          - '_provider'      : which API was used
          - '_model'         : model name
          - '_latency_ms'    : response time in milliseconds
          - '_raw_response'  : original AI response string (for debugging)
    """
    provider = (provider or AI_PROVIDER).lower()

    # Truncate oversized input gracefully
    if len(email_text) > MAX_EMAIL_LENGTH:
        email_text = email_text[:MAX_EMAIL_LENGTH] + "\n\n[TRUNCATED — content exceeded limit]"

    t0 = time.time()

    if provider == "groq":
        result, raw, model = _call_groq(email_text)
    elif provider == "gemini":
        result, raw, model = _call_gemini(email_text)
    else:
        raise ValueError(f"Unknown provider '{provider}'. Choose 'groq' or 'gemini'.")

    latency = int((time.time() - t0) * 1000)

    # Inject meta fields
    result["_provider"]     = provider
    result["_model"]        = model
    result["_latency_ms"]   = latency
    result["_raw_response"] = raw

    return result


# ──────────────────────────────────────────────────────────────────────────────
# PROVIDER IMPLEMENTATIONS
# ──────────────────────────────────────────────────────────────────────────────

def _call_groq(email_text: str):
    """Call Groq's OpenAI-compatible chat endpoint."""
    if not GROQ_API_KEY:
        raise EnvironmentError(
            "GROQ_API_KEY is missing. Set it in your .env file.\n"
            "Get a free key at https://console.groq.com"
        )

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type":  "application/json",
    }

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": f"Analyze this email for phishing threats:\n\n{email_text}"},
        ],
        "temperature":  0.1,   # Low temp = factual, consistent
        "max_tokens":   1500,
        # "response_format": {"type": "json_object"},  # Force JSON mode
    }

    try:
        resp = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        raise TimeoutError(f"Groq API timed out after {REQUEST_TIMEOUT}s. Check your internet connection.")
    except requests.exceptions.HTTPError as e:
        _handle_http_error(e, "Groq")

    raw = resp.json()["choices"][0]["message"]["content"]
    return _parse_json(raw), raw, GROQ_MODEL


def _call_gemini(email_text: str):
    """Call Google Gemini 1.5 Flash REST endpoint."""
    if not GEMINI_API_KEY:
        raise EnvironmentError(
            "GEMINI_API_KEY is missing. Set it in your .env file.\n"
            "Get a free key at https://aistudio.google.com/app/apikey"
        )

    url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"

    combined_prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"Email to analyze:\n\n{email_text}"
    )

    payload = {
        "contents": [{"parts": [{"text": combined_prompt}]}],
        "generationConfig": {
            "temperature":      0.1,
            "maxOutputTokens":  1500,
            "responseMimeType": "application/json",  # Force JSON output
        },
    }

    try:
        resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        raise TimeoutError(f"Gemini API timed out after {REQUEST_TIMEOUT}s.")
    except requests.exceptions.HTTPError as e:
        _handle_http_error(e, "Gemini")

    raw = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    return _parse_json(raw), raw, "gemini-1.5-flash"


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _parse_json(raw: str) -> dict:
    """
    Robustly parse JSON from an LLM response.

    Strategy:
      1. Strip markdown code fences (```json ... ```)
      2. Direct json.loads
      3. Regex fallback to extract the first {...} block
      4. Raise with useful context if all else fails
    """
    # Remove markdown fences
    cleaned = re.sub(r"```(?:json)?\s*|\s*```", "", raw).strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Fallback: grab first balanced JSON object
    match = re.search(r"\{[\s\S]*\}", cleaned)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    raise ValueError(
        f"Could not parse JSON from AI response.\n"
        f"First 300 chars: {raw[:300]}"
    )


def _handle_http_error(error, provider):
    """Translate HTTP errors into human-readable messages."""
    status = None
    if hasattr(error, "response") and error.response is not None:
        status = error.response.status_code

    if status == 401:
        msg = provider + ": Invalid API key. Check your .env file."
    elif status == 403:
        msg = provider + ": Access forbidden. Your key may lack permissions."
    elif status == 404:
        msg = (
            provider + ": Model not found (404).\n"
            "  The model name in config.py is probably deprecated.\n"
            "  Run check_models.py to see your available models,\n"
            "  then update GROQ_MODEL in config.py with a valid name."
        )
    elif status == 429:
        msg = provider + ": Rate limit hit. Wait 60 seconds and retry."
    elif status == 503:
        msg = provider + ": Service unavailable. Try again shortly."
    else:
        msg = provider + " HTTP " + str(status) + ": " + str(error)

    raise RuntimeError(msg)