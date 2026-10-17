# PhishGuard: AI-Powered Phishing Detection Platform

A production-grade email security platform that protects your Gmail inbox using a
**4-layer hybrid security pipeline** — cryptographic protocol verification first,
constrained AI analysis second. Built for cybersecurity teams.

---

## System Architecture

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

## Data Flow (End-to-End)

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
│  PHISHING:   Apply " PHISHING" label, remove from INBOX  │
│  SUSPICIOUS: Apply " SUSPICIOUS" label                   │
│  Both:       Send Telegram SOC alert card                  │
│  All:        Save full report to SQLite + Audit log        │
└───────────────────────────────────────────────────────────┘
```

---

## Security Architecture (Cybersecurity Principles Applied)

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

---

---

## REST API Reference

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

---

##  Key Design Decisions Explained

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

## Extension Ideas

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
