# 🔍 AI-Powered Phishing Email & Threat Analyzer

A production-ready security tool that uses free AI APIs (Groq / Google Gemini) to
analyze suspicious emails, detect phishing attempts, and produce structured threat
intelligence reports — with both a CLI and a browser-based web interface.

---

## 📋 TABLE OF CONTENTS
1. [Quick Start](#quick-start)
2. [Architecture](#architecture)
3. [How It Works](#how-it-works)
4. [Free API Setup](#free-api-setup)
5. [CLI Usage](#cli-usage)
6. [Web UI Usage](#web-ui-usage)
7. [Output Format](#output-format)
8. [Project Structure](#project-structure)
9. [Interview Talking Points](#interview-talking-points)
10. [Extension Ideas](#extension-ideas)

---

## ⚡ Quick Start

```bash
# 1. Clone / unzip the project
cd phishing_analyzer

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure your free API key
cp .env.example .env
# Open .env and paste your Groq API key (see Free API Setup below)

# 5a. Run CLI — analyze a sample email
python main.py -f sample_emails/phishing_bank.txt --html

# 5b. OR run the Web UI
python app.py
# Then open http://localhost:5000
```

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    USER INTERFACES                           │
│                                                              │
│   CLI (main.py)              Web UI (app.py + Flask)        │
│   ├── Single email            ├── POST /analyze              │
│   ├── File input              ├── GET  /history              │
│   └── Batch folder mode       └── GET  /stats                │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   CORE ANALYSIS ENGINE                       │
│                    (analyzer.py)                             │
│                                                              │
│   1. Email pre-processing (utils.py)                        │
│   2. Prompt engineering (SYSTEM_PROMPT)                     │
│   3. HTTP API call (requests — no vendor SDK)               │
│   4. JSON parsing + validation                              │
│   5. Return structured ThreatReport dict                    │
└─────────────┬──────────────────────────────────────────────┘
              │
     ┌────────┴────────┐
     ▼                 ▼
┌─────────┐      ┌──────────┐
│  GROQ   │      │  GEMINI  │
│  FREE   │      │  FREE    │
│  TIER   │      │  TIER    │
│Llama 3.1│      │1.5 Flash │
└─────────┘      └──────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────┐
│                     OUTPUT LAYER                             │
│                                                              │
│   report_generator.py           utils.py                    │
│   ├── HTML report (self-cont.)  ├── Console pretty-print    │
│   └── JSON report               └── History logging         │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Decisions
| Decision | Rationale |
|----------|-----------|
| Raw `requests` (no SDK) | Fewer dependencies, easier to switch providers |
| JSON mode on API call | Forces structured output, eliminates parsing surprises |
| Temperature = 0.1 | Security analysis needs consistency, not creativity |
| Regex fallback JSON parser | Handles edge cases where model adds markdown fences |
| Dual interface (CLI + Web) | Demonstrates both scripting and service deployment |
| `.env` for secrets | Security best practice — never hardcode API keys |

---

## 🔄 How It Works

```
Email Text Input
       │
       ▼
┌─────────────────┐
│ Pre-processing  │  → strip whitespace, truncate if >12,000 chars
│ (utils.py)      │  → extract headers (From, Subject, Date)
│                 │  → extract URLs for pre-analysis
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│ SECURITY PROMPT (analyst role + JSON schema)        │
│                                                     │
│ "You are a Senior Incident Response Analyst..."    │
│ "Analyze for: urgency tactics, sender spoofing,   │
│  suspicious URLs, social engineering..."           │
│ "Return ONLY valid JSON matching this schema:"    │
│    { is_phishing, risk_score, red_flags, ... }    │
└─────────────────────────────────────────────────────┘
         │
         ▼  HTTP POST with JSON body
┌────────────────┐
│  AI API Call   │  → Groq (llama-3.1-8b-instant, ~1-2s response)
│  (analyzer.py) │  → OR Gemini (gemini-1.5-flash, ~2-3s response)
└────────┬───────┘
         │
         ▼
┌───────────────────────────────┐
│ Response Parsing              │
│ 1. Strip markdown fences      │
│ 2. json.loads()               │
│ 3. Regex fallback if needed   │
└────────────────────┬──────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │   ThreatReport Dict   │
         │  + _provider meta     │
         │  + _latency_ms        │
         └───────────┬───────────┘
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       Console    HTML       JSON
       Output     Report     Report
```

### The Prompt Engineering Strategy
The most critical design element is the **system prompt**. It uses three techniques:
1. **Role priming**: "You are a Senior Incident Response Analyst" — improves analysis quality
2. **Explicit checklist**: tells the model exactly what phishing signals to check
3. **Schema contract**: provides the exact JSON structure — combined with `response_format: json_object`, this eliminates free-text responses

---

## 🆓 Free API Setup

### Option A: Groq (Recommended)
- **Speed**: ~1-2 seconds response time (fastest free LLM inference)
- **Model**: Llama 3.1 8B Instant
- **Rate Limit**: 30 requests/minute, 14,400/day (very generous)
- **Steps**:
  1. Go to [https://console.groq.com](https://console.groq.com)
  2. Sign in with Google/GitHub
  3. Click **API Keys** → **Create API Key**
  4. Copy the key to your `.env` file as `GROQ_API_KEY=...`

### Option B: Google Gemini
- **Model**: Gemini 1.5 Flash
- **Rate Limit**: 15 requests/minute, 1,500/day
- **Steps**:
  1. Go to [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
  2. Sign in with Google
  3. Click **Create API Key**
  4. Copy to `.env` as `GEMINI_API_KEY=...` and set `AI_PROVIDER=gemini`

### Why NOT a local LLM on your hardware?
- Intel i3-3110M (2013, dual-core) + 3.82GB usable RAM
- Minimum viable local model: TinyLlama 1.1B (~637MB) — but response quality
  for security analysis is poor compared to Llama 3.1 8B via Groq
- Recommended minimum for quality local inference: 8GB RAM + modern CPU/GPU
- **Verdict**: Free cloud APIs are objectively better for your hardware setup

---

## 💻 CLI Usage

```bash
# Interactive mode — paste email manually
python main.py

# Analyze a file
python main.py -f email.txt

# Analyze + save HTML report
python main.py -f email.txt --html

# Analyze + save both HTML and JSON reports
python main.py -f email.txt --html --json

# Force Gemini instead of Groq
python main.py -f email.txt --provider gemini

# Batch analyze all .txt files in a folder
python main.py --batch sample_emails/ --html

# View analysis history
python main.py --history

# Skip logging this analysis
python main.py -f email.txt --no-log
```

---

## 🌐 Web UI Usage

```bash
python app.py
# → http://localhost:5000
```

**Endpoints:**
| Method | URL | Description |
|--------|-----|-------------|
| `GET`  | `/` | Web interface |
| `POST` | `/analyze` | JSON API: send email, get threat report |
| `GET`  | `/history` | Last 20 analyses as JSON array |
| `GET`  | `/stats` | Phishing rate and score statistics |
| `GET`  | `/reports/<file>` | Serve generated HTML reports |

**POST /analyze payload:**
```json
{
  "email": "From: attacker@evil.com\nSubject: ...",
  "provider": "groq",
  "save_html": true
}
```

---

## 📊 Output Format

The AI returns (and the tool returns to you) a structured JSON object:

```json
{
  "is_phishing": true,
  "risk_score": 92,
  "confidence": "high",
  "threat_category": "phishing",
  "red_flags": [
    "Domain 'bancofamerica-secure.com' does not match legitimate domain 'bankofamerica.com'",
    "Requests Social Security Number and banking PIN — legitimate banks never do this",
    "Generic salutation 'Dear Valued Customer' instead of account holder name",
    "24-hour ultimatum creates artificial urgency"
  ],
  "legitimate_indicators": [],
  "urgency_indicators": [
    "Account will be PERMANENTLY CLOSED within 24 HOURS",
    "Aggressive use of capitalization to create panic"
  ],
  "suspicious_urls": [
    "bancofamerica-secure.com"
  ],
  "sender_analysis": {
    "appears_spoofed": true,
    "spoofing_technique": "domain_lookalike",
    "sender_details": "From domain 'bancofamerica-secure.com' mimics legitimate 'bankofamerica.com' using hyphenated subdomain trick"
  },
  "social_engineering_tactics": [
    "Fear appeal: threat of permanent account closure",
    "Artificial deadline: 24-hour countdown",
    "Authority impersonation: masquerading as bank security team",
    "Credential harvesting: requesting SSN, account number, and PIN"
  ],
  "target_data_sought": ["credential", "financial", "personal_info"],
  "recommended_action": "delete_immediately",
  "summary": "This is a high-confidence bank impersonation phishing attack targeting credential and financial data. The domain lookalike 'bancofamerica-secure.com' is the primary indicator, combined with requests for SSN and banking credentials that no legitimate bank ever solicits via email. Immediate deletion is recommended.",

  "_provider": "groq",
  "_model": "llama-3.1-8b-instant",
  "_latency_ms": 1247
}
```

---

## 📁 Project Structure

```
phishing_analyzer/
│
├── main.py                    # CLI entry point (argparse)
├── app.py                     # Flask web UI
├── analyzer.py                # Core AI engine (API calls + JSON parsing)
├── config.py                  # All configuration (reads from .env)
├── utils.py                   # Helpers: display, logging, URL extraction
├── report_generator.py        # HTML + JSON report generation
│
├── sample_emails/
│   ├── phishing_bank.txt      # Bank impersonation example
│   ├── phishing_ceo_fraud.txt # BEC / CEO fraud example
│   └── legitimate_github.txt  # Legitimate email for comparison
│
├── reports/                   # Generated reports (created at runtime)
├── logs/
│   └── analysis_history.json  # Persistent analysis log (created at runtime)
│
├── requirements.txt
├── .env.example               # Template — copy to .env and add your keys
└── README.md
```

---

## 🎤 Interview Talking Points

### "Walk me through the architecture"
> "The project has three layers. The presentation layer handles input — either a CLI
> built with argparse for scripting workflows, or a Flask REST API serving a
> single-page web UI. The core analysis layer in `analyzer.py` builds a structured
> security prompt using role-priming and schema contracts, calls the Groq or Gemini
> API via raw `requests`, then robustly parses the JSON verdict with a fallback
> regex extractor. The output layer generates colour-coded terminal output,
> self-contained HTML reports, and JSON files, and logs every analysis to a
> persistent history file."

### "Why Groq? Why not OpenAI or a local model?"
> "Three reasons: free tier with no credit card, best-in-class inference speed
> (~1-2s for Llama 3.1 8B), and an OpenAI-compatible API so switching to GPT-4
> later requires changing two lines. Local LLMs were evaluated but the target
> hardware — an i3-3110M with 4GB RAM — cannot run a model large enough to produce
> quality security analysis without quantization artifacts that reduce detection
> accuracy."

### "How did you engineer the prompt?"
> "I used three prompt engineering techniques: role priming (tell the model it's a
> Senior IR Analyst), an explicit analysis checklist covering the OWASP Email
> Security Top 10 indicators, and a strict output schema. Combined with temperature
> 0.1 and the `response_format: json_object` API parameter, this produces
> deterministic structured output across repeated calls."

### "What security concepts does this cover?"
> "It detects: phishing and spear-phishing, Business Email Compromise (BEC/CEO
> fraud), domain lookalike attacks, display name spoofing, URL obfuscation,
> credential harvesting, and social engineering tactics including fear appeals,
> artificial urgency, and authority impersonation."

### "What are the limitations?"
> "Three main ones: it can't analyze email attachments or follow hyperlinks to
> inspect the actual landing page. It also has no access to real-time threat
> intelligence feeds like VirusTotal or IPQS. And the LLM can occasionally
> hallucinate red flags on legitimate emails — a production version would combine
> AI scoring with rule-based checks for higher precision."

### "How would you scale this for production?"
> "Replace Flask with FastAPI for async request handling. Add a Redis queue (Celery)
> for batch processing. Integrate VirusTotal API for URL/attachment scanning.
> Add DKIM/SPF/DMARC header validation (currently only text-based analysis). Store
> results in PostgreSQL instead of a JSON file. Add user authentication and a
> dashboard for security teams. Deploy on a VM with nginx as reverse proxy."

---

## 🚀 Extension Ideas (for interview discussion)

1. **Attachment Scanning** — Extract text from PDF/DOCX attachments, analyze them too
2. **VirusTotal Integration** — Check extracted URLs against VT's free API (4 requests/min free)
3. **DKIM/SPF Validation** — Verify email authentication headers using `dnspython`
4. **Slack/Teams Alert** — Send webhook notification when phishing is detected
5. **Chrome Extension** — Wrap the `/analyze` endpoint for in-browser email scanning
6. **Feedback Loop** — Let users mark verdicts as correct/incorrect to track accuracy
7. **Custom Rules Engine** — Add regex-based pre-filter rules before the AI call to
   reduce API calls for obvious spam
8. **Multi-language Support** — Groq handles non-English emails natively
