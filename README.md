# 🛡️ PhishGuard — AI-Powered Phishing Detection Platform

A production-grade email security platform that protects your Gmail inbox using a
**4-layer hybrid security pipeline** — cryptographic protocol verification first,
constrained AI analysis second. Built for cybersecurity teams.

---

## ⚡ Quick Start (Local)

```bash
git clone <repo> && cd PhishGuard
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # Then fill in your keys (see Setup below)
python run.py
# → http://localhost:5000
```

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PHISHGUARD PLATFORM                                   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  PRESENTATION LAYER                                                   │   │
│  │  Flask Web App (Jinja2 templates)  │  REST API (/api/*)              │   │
│  │  SOC Dashboard  │  Threat Detail   │  Audit Log  │  Health Check     │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                │                                             │
│  ┌─────────────────────────────▼────────────────────────────────────────┐   │
│  │  APPLICATION LAYER                                                    │   │
│  │  APScheduler (polls every 5 min)  │  Manual Scan Trigger             │   │
│  │  GmailClient (OAuth 2.0)          │  Security Middleware              │   │
│  └─────────────────────────────┬────────────────────────────────────────┘   │
│                                │                                             │
│  ┌─────────────────────────────▼────────────────────────────────────────┐   │
│  │  4-LAYER SECURITY PIPELINE  (orchestrator.py)                        │   │
│  │                                                                       │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │   │
│  │  │  LAYER 1    │  │  LAYER 2    │  │  LAYER 3    │  │  LAYER 4   │ │   │
│  │  │ Auth Check  │→ │ Domain/URL  │→ │Constrained  │→ │ Automated  │ │   │
│  │  │ SPF/DKIM/   │  │ WHOIS Age   │  │    AI       │  │  Actions   │ │   │
│  │  │ DMARC       │  │ Typosquat   │  │(sees report │  │ Gmail Label│ │   │
│  │  │ Hdr Mismatch│  │ Display Spf │  │ NOT email)  │  │ Telegram   │ │   │
│  │  │ Weight: 40% │  │ Weight: 35% │  │ Weight: 25% │  │ Audit Log  │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘ │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                │                                             │
│  ┌─────────────────────────────▼────────────────────────────────────────┐   │
│  │  DATA LAYER                                                           │   │
│  │  SQLite (phishguard.db)  →  upgrade path: PostgreSQL                 │   │
│  │  scanned_emails  │  audit_log  │  system_config                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  EXTERNAL SERVICES:  Gmail API  │  Groq API  │  Telegram API               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Data Flow (End-to-End)

```
Gmail Inbox (unread emails)
        │
        │ OAuth 2.0 (gmail.modify scope — read + label)
        ▼
APScheduler polls every 5 minutes
        │
        ▼ For each new email:
┌───────────────────────────────────────────────────────────┐
│ LAYER 1 — Cryptographic Authentication                     │
│  Parse Authentication-Results header (set by Gmail MTA)   │
│  Extract: SPF result, DKIM result, DMARC result           │
│  Check:   From ≠ Return-Path (header mismatch)            │
│           From ≠ Reply-To  (reply hijack attempt)         │
│  Output:  flags[], risk_contribution (0-100), weight 40%  │
└───────────────────────┬───────────────────────────────────┘
                        │
┌───────────────────────▼───────────────────────────────────┐
│ LAYER 2 — Deterministic Domain & URL Analysis              │
│  WHOIS:        Domain age check (< 30 days = high risk)   │
│  Levenshtein:  Typosquatting detection vs 30 brand list   │
│  Display Name: Brand impersonation check                   │
│  URL scan:     Shorteners, domain mismatch, exe links     │
│  Output:       flags[], risk_contribution (0-100), 35%    │
└───────────────────────┬───────────────────────────────────┘
                        │
┌───────────────────────▼───────────────────────────────────┐
│ LAYER 3 — Constrained AI Threat Scoring  ← KEY DESIGN     │
│  INPUT: L1 flags + L2 flags + Subject line only           │
│         AI NEVER receives the full email body              │
│  Groq API (Llama/GPT-OSS): evaluates violation report     │
│  Outputs: content_risk_score, threat_category,            │
│           psychological_tactics, soc_advisory             │
│  Weight: 25% (AI confirms rules; can't override them)     │
└───────────────────────┬───────────────────────────────────┘
                        │
        Final Score = (L1×0.40) + (L2×0.35) + (L3×0.25)
        Multi-layer boost if 2+ layers agree (+20% / +35%)
        Verdict: PHISHING ≥70 │ SUSPICIOUS ≥40 │ SAFE <40
                        │
┌───────────────────────▼───────────────────────────────────┐
│ LAYER 4 — Automated Inbox Remediation                      │
│  PHISHING:   Apply "⚠️ PHISHING" label, remove from INBOX  │
│  SUSPICIOUS: Apply "🔶 SUSPICIOUS" label                   │
│  Both:       Send Telegram SOC alert card                  │
│  All:        Save full report to SQLite + Audit log        │
└───────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Architecture (Cybersecurity Principles Applied)

| Principle | Implementation |
|-----------|---------------|
| **Least Privilege** | Gmail OAuth scope: `gmail.modify` only (read + label — no delete, no send) |
| **Defense in Depth** | 3 independent detection layers before AI; each can catch what others miss |
| **Zero Trust** | Every API call re-validated; tokens refreshed automatically |
| **Prompt Injection Prevention** | AI receives violation REPORT, not raw email body; body sanitized and truncated to 300 chars |
| **Input Validation** | All text sanitized; null bytes stripped; control chars removed |
| **Audit Trail** | Every action (scan, label, alert, login, error) written to immutable audit log |
| **No Password Storage** | OAuth 2.0 only — credentials.json never stored in DB |
| **SQL Injection Prevention** | All queries parameterized (never string-concatenated) |
| **CSRF Protection** | Session-based token validated on all state-changing POST requests |
| **Security Headers** | CSP, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy on every response |
| **Rate Limiting** | Sliding window per-IP limiter on all API endpoints |
| **Secret Management** | All secrets in env vars; `.env` gitignored; never in source code |
| **HTTPS** | Enforced by Render; HSTS header added when `request.is_secure` |

---

## 📁 Project Structure

```
PhishGuard/
│
├── run.py                          ← Entry point (dev + prod)
├── Procfile                        ← Render/Heroku deploy command
├── render.yaml                     ← Render cloud config
├── requirements.txt
├── .env.example                    ← Template (copy to .env)
├── .gitignore
│
└── app/
    ├── __init__.py                 ← Flask app factory
    ├── config.py                   ← All settings (reads from .env)
    ├── database.py                 ← SQLite schema + CRUD
    ├── gmail_client.py             ← Gmail API OAuth 2.0 integration
    ├── poller.py                   ← APScheduler background polling
    ├── security.py                 ← Rate limiter, headers, CSRF, audit
    │
    ├── pipeline/
    │   ├── layer1_auth.py          ← SPF/DKIM/DMARC parsing
    │   ├── layer2_domain.py        ← WHOIS, Levenshtein, URL analysis
    │   ├── layer3_ai.py            ← Constrained Groq AI scoring
    │   ├── layer4_actions.py       ← Gmail labeling + Telegram
    │   └── orchestrator.py         ← Ties all 4 layers together
    │
    ├── routes/
    │   ├── auth.py                 ← OAuth routes (/auth/*)
    │   ├── dashboard.py            ← Web UI routes
    │   └── api.py                  ← REST API (/api/*)
    │
    └── templates/
        ├── base.html               ← Navigation, CSS, JS utilities
        ├── dashboard.html          ← Main SOC dashboard
        ├── threat_detail.html      ← 4-layer threat breakdown
        └── audit_log.html          ← Audit trail view
```

---

## ⚙️ Complete Setup Guide

### Step 1 — Groq API Key (2 minutes, free)
1. Go to https://console.groq.com → Sign in with Google
2. Click **API Keys** → **Create API Key**
3. Copy key → paste in `.env` as `GROQ_API_KEY=gsk_...`

### Step 2 — Google Cloud + Gmail API (10 minutes, free)

```
1. Go to https://console.cloud.google.com
2. Create new project: "PhishGuard"
3. APIs & Services → Enable APIs → search "Gmail API" → Enable
4. APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client ID
5. Application type: Web application
   Name: PhishGuard
   Authorised redirect URIs:
     → http://localhost:5000/auth/callback        (local dev)
     → https://your-app.onrender.com/auth/callback (production)
6. Download credentials.json → place in PhishGuard/ project root
   OR paste its contents into GOOGLE_CREDENTIALS_JSON in .env
7. OAuth Consent Screen → Add your email as a Test User
   (required while app is in "testing" mode)
```

### Step 3 — Telegram Bot (5 minutes, optional)
```
1. Open Telegram → search @BotFather → /newbot
2. Choose a name (e.g. "PhishGuard SOC") and username
3. Copy the bot token → TELEGRAM_BOT_TOKEN in .env
4. Start a chat with your bot
5. Get your chat_id:
   curl https://api.telegram.org/bot<TOKEN>/getUpdates
   → look for "chat":{"id": 123456789}
6. Paste chat_id → TELEGRAM_CHAT_ID in .env
```

### Step 4 — Local Run
```bash
cp .env.example .env
# Edit .env with your keys
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python run.py
# → http://localhost:5000
# Click "Connect Gmail" → complete OAuth → done
```

---

## 🚀 Deploy to Render (Free, Public URL)

```
1. Push code to GitHub (credentials.json must be in .gitignore!)
2. Go to https://render.com → New Web Service → Connect your repo
3. Build command:  pip install -r requirements.txt
4. Start command:  gunicorn run:app --workers 1 --threads 4 --bind 0.0.0.0:$PORT
5. Add environment variables (from your .env):
      GROQ_API_KEY
      GOOGLE_CREDENTIALS_JSON  ← paste full JSON string
      SECRET_KEY               ← generate random one
      BASE_URL                 ← https://your-app.onrender.com
      TELEGRAM_BOT_TOKEN       (optional)
      TELEGRAM_CHAT_ID         (optional)
6. Deploy → get your public URL
7. Add that URL to Google Cloud Console → Authorised redirect URIs
8. Visit your URL → Connect Gmail → live!

KEEP-ALIVE (prevents Render free tier sleep):
  → Sign up at https://uptimerobot.com (free)
  → Add HTTP monitor → URL: https://your-app.onrender.com/health
  → Interval: 14 minutes
  → This keeps the poller running 24/7
```

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | SOC Dashboard |
| `GET` | `/threats/<id>` | Full 4-layer threat report |
| `GET` | `/audit-log` | Immutable audit trail |
| `GET` | `/health` | Health check (UptimeRobot target) |
| `POST`| `/scan-now` | Trigger immediate inbox scan |
| `GET` | `/api/stats` | Dashboard statistics JSON |
| `GET` | `/api/threats?limit=20` | Recent phishing/suspicious emails |
| `GET` | `/api/scans?limit=25&offset=0` | Paginated scan history |
| `GET` | `/api/scans/<id>` | Single scan full JSON report |
| `GET` | `/api/charts/risk-distribution` | Risk score distribution data |
| `GET` | `/api/charts/categories` | Threat category breakdown |
| `GET` | `/api/charts/trend` | 7-day daily scan trend |
| `GET` | `/api/poller/status` | Background poller status |
| `GET` | `/auth/login` | Start Gmail OAuth flow |
| `GET` | `/auth/callback` | OAuth callback (Google redirects here) |
| `GET` | `/auth/logout` | Disconnect Gmail |
| `GET` | `/auth/status` | Gmail connection status JSON |

---

## 🎤 Interview: Technical Talking Points

### "Walk me through the architecture"
> "PhishGuard has four distinct layers before making any verdict. Layer 1 parses
> Gmail's `Authentication-Results` header — which is set by Google's own MTA — to
> extract hard SPF, DKIM, and DMARC verdicts. These are cryptographic facts, not
> opinions. Layer 2 runs deterministic rules: WHOIS domain age check, Levenshtein
> distance typosquatting detection against a curated brand list, display name
> impersonation detection, and URL analysis. Layer 3 is where AI enters — but
> critically, the AI receives only the violation report from Layers 1 and 2, never
> the raw email. This prevents prompt injection. Layer 4 executes automated responses:
> applying Gmail labels, sending Telegram alerts, and writing an immutable audit log."

### "Why does the AI only see the violation report?"
> "Two reasons. First, security: if an attacker embeds `ignore all previous
> instructions` in an email body, and that body goes directly to the AI, the AI
> might be manipulated. By passing only the structured violation report, the attack
> surface is eliminated — the AI has no email content to be poisoned by. Second,
> architectural: AI should confirm what rules found, not make independent guesses.
> A DMARC fail is a fact. Levenshtein distance to 'paypal' is math. AI adds value
> in scoring psychological manipulation tactics and generating plain-English
> advisories for SOC analysts — that's the right use of probabilistic inference."

### "Explain the scoring weights"
> "Layer 1 carries 40% weight because cryptographic authentication is non-repudiable.
> A DMARC fail means the domain owner explicitly did not authorise this sender —
> that's not a guess. Layer 2 is 35% — domain age and typosquatting are deterministic
> rules with very low false-positive rates. Layer 3 AI gets 25% — it's valuable for
> social engineering analysis but probabilistic. There's also a multi-layer boost:
> if two independent layers both flag an email, the final score gets a 20% boost,
> and if all three agree, 35%. This models the security analyst intuition that when
> independent evidence converges, confidence should rise significantly."

### "What cybersecurity principles does this embody?"
> "Least privilege: OAuth `gmail.modify` scope only — can't delete, can't send.
> Defense in depth: three independent detection mechanisms. Zero trust: every API
> call re-authenticated. Input validation: all text sanitized, null bytes stripped,
> body truncated before AI sees it. Audit logging: every action is written to an
> immutable log with timestamp and IP. CSRF protection on all state-changing routes.
> Security headers on every HTTP response including CSP, X-Frame-Options DENY.
> Rate limiting per IP. And no password storage anywhere — pure OAuth 2.0."

### "What are the limitations?"
> "Three main ones. One: we can't validate attachments — a malicious PDF attachment
> isn't analysed. Production fix: integrate a sandbox like Any.run or VirusTotal
> Sandbox API. Two: WHOIS is slow and unreliable for some TLDs, so we give benefit
> of the doubt on lookup failures. Production fix: use a commercial domain
> intelligence feed like PassiveTotal. Three: the AI layer can be slow on Groq's
> free tier — but since it's Layer 3 and the poller runs async in the background,
> latency doesn't affect the user. Production fix: cache AI results for repeated
> sender domains."

### "How would you scale this?"
> "Replace the embedded APScheduler with a Celery worker backed by Redis — this
> lets you run the web app on multiple instances while the poller stays as one
> process. Migrate SQLite to PostgreSQL for concurrent writes. Add a VirusTotal
> integration for URL and attachment scanning. Add DNSBL (DNS Block List) checks
> in Layer 2 for sender IP reputation. Wrap the REST API behind an API gateway
> with JWT authentication for multi-tenant SOC use. Deploy on Kubernetes with
> horizontal pod autoscaling for the web tier."

---

## 🔍 Key Design Decisions Explained

| Decision | Why |
|----------|-----|
| Raw `requests` for Groq | No vendor SDK lock-in; trivial to swap to OpenAI, Anthropic, or local Ollama |
| SQLite not PostgreSQL | Zero-config for demo; identical SQL syntax for easy migration |
| APScheduler in-process | Single Procfile, no Redis needed for free-tier deployment |
| Single gunicorn worker | Prevents duplicate polling; scale by extracting Celery for background jobs |
| Levenshtein implemented locally | No `python-levenshtein` C dependency to build; simpler deployment |
| Gmail MTA auth headers | More reliable than self-validating SPF/DKIM (Google's infrastructure does it) |
| Flask app factory pattern | Testability; clean separation of config, DB init, blueprint registration |

---

## 🚀 Extension Ideas (For Interview Discussion)

1. **VirusTotal Integration** — Check every extracted URL against VT's free API (4 req/min)
2. **Attachment Sandbox** — Extract text from PDF/DOCX attachments, run through pipeline
3. **DNSBL Checks** — Query Spamhaus, SORBS for sender IP reputation in Layer 2
4. **Microsoft 365 Support** — Replace Gmail client with Microsoft Graph API
5. **Multi-tenant** — JWT auth, per-organisation threat feeds and thresholds
6. **Analyst Feedback Loop** — "Mark as wrong" button feeds back to scoring calibration
7. **Threat Intelligence Export** — Export IOCs (domains, IPs, URLs) in STIX format
8. **Slack Integration** — Alternative to Telegram for enterprise SOC alerting
9. **Browser Extension** — Wrap the `/api/scans` endpoint for webmail scanning
10. **Real-time WebSocket** — Replace JS polling with Server-Sent Events for instant alerts
