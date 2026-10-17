"""
database.py — PhishGuard Data Layer

Schema stores full 4-layer pipeline results per email.
All queries are parameterized (no SQL injection).
SQLite for portability; swap connection string for PostgreSQL in prod.
"""
import sqlite3
import json
import datetime
import os
from contextlib import contextmanager
from app.config import Config


# ─── Schema ──────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS scanned_emails (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    gmail_message_id    TEXT    UNIQUE NOT NULL,
    subject             TEXT,
    sender              TEXT,
    sender_domain       TEXT,
    recipient           TEXT,
    date_received       TEXT,

    -- Layer 1: Cryptographic Authentication
    l1_spf              TEXT,
    l1_dkim             TEXT,
    l1_dmarc            TEXT,
    l1_header_mismatch  INTEGER DEFAULT 0,
    l1_flags            TEXT    DEFAULT '[]',
    l1_risk_score       INTEGER DEFAULT 0,

    -- Layer 2: Domain & URL Analysis
    l2_domain_age_days  INTEGER,
    l2_typosquatting    TEXT,
    l2_display_spoofing INTEGER DEFAULT 0,
    l2_suspicious_urls  TEXT    DEFAULT '[]',
    l2_flags            TEXT    DEFAULT '[]',
    l2_risk_score       INTEGER DEFAULT 0,

    -- Layer 3: Constrained AI Scoring
    l3_content_risk     INTEGER DEFAULT 0,
    l3_threat_category  TEXT,
    l3_psych_tactics    TEXT    DEFAULT '[]',
    l3_soc_advisory     TEXT,
    l3_confidence       TEXT,

    -- Final Verdict
    final_score         INTEGER DEFAULT 0,
    verdict             TEXT    NOT NULL DEFAULT 'PENDING',

    -- Layer 4: Actions
    l4_label_applied    TEXT,
    l4_telegram_sent    INTEGER DEFAULT 0,
    l4_actions          TEXT    DEFAULT '[]',

    -- Meta
    scanned_at          TEXT    NOT NULL,
    processing_time_ms  INTEGER DEFAULT 0,
    full_report         TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    action      TEXT    NOT NULL,
    details     TEXT,
    email_id    INTEGER,
    ip_address  TEXT,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS system_config (
    key         TEXT    PRIMARY KEY,
    value       TEXT,
    updated_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_emails_verdict    ON scanned_emails(verdict);
CREATE INDEX IF NOT EXISTS idx_emails_scanned_at ON scanned_emails(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_emails_score      ON scanned_emails(final_score DESC);
CREATE INDEX IF NOT EXISTS idx_audit_created     ON audit_log(created_at DESC);
"""


# ─── Connection ──────────────────────────────────────────────────────────────

def get_db_path() -> str:
    return Config.DATABASE_PATH


@contextmanager
def get_conn():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # Better concurrent read/write
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(app=None):
    """Create all tables. Called at startup."""
    with get_conn() as conn:
        conn.executescript(SCHEMA)


# ─── Scanned Emails CRUD ─────────────────────────────────────────────────────

def save_scan_result(report: dict) -> int:
    """Insert a completed pipeline report. Returns new row ID."""
    now = datetime.datetime.utcnow().isoformat() + "Z"
    l1  = report.get("layer1", {})
    l2  = report.get("layer2", {})
    l3  = report.get("layer3", {})
    l4  = report.get("layer4", {})

    with get_conn() as conn:
        cur = conn.execute("""
            INSERT OR REPLACE INTO scanned_emails (
                gmail_message_id, subject, sender, sender_domain,
                recipient, date_received,
                l1_spf, l1_dkim, l1_dmarc, l1_header_mismatch,
                l1_flags, l1_risk_score,
                l2_domain_age_days, l2_typosquatting, l2_display_spoofing,
                l2_suspicious_urls, l2_flags, l2_risk_score,
                l3_content_risk, l3_threat_category, l3_psych_tactics,
                l3_soc_advisory, l3_confidence,
                final_score, verdict,
                l4_label_applied, l4_telegram_sent, l4_actions,
                scanned_at, processing_time_ms, full_report
            ) VALUES (
                ?,?,?,?,?,?,
                ?,?,?,?,?,?,
                ?,?,?,?,?,?,
                ?,?,?,?,?,
                ?,?,
                ?,?,?,
                ?,?,?
            )""", (
            report.get("gmail_message_id"),
            report.get("subject"),
            report.get("sender"),
            report.get("sender_domain"),
            report.get("recipient"),
            report.get("date_received"),
            l1.get("spf"), l1.get("dkim"), l1.get("dmarc"),
            1 if l1.get("header_mismatch") else 0,
            json.dumps(l1.get("flags", [])),
            l1.get("risk_contribution", 0),
            l2.get("domain_age_days"),
            l2.get("typosquatting_target"),
            1 if l2.get("display_name_spoofing") else 0,
            json.dumps(l2.get("suspicious_urls", [])),
            json.dumps(l2.get("flags", [])),
            l2.get("risk_contribution", 0),
            l3.get("content_risk_score", 0),
            l3.get("threat_category"),
            json.dumps(l3.get("psychological_tactics", [])),
            l3.get("soc_advisory"),
            l3.get("confidence"),
            report.get("final_score", 0),
            report.get("verdict", "SAFE"),
            l4.get("label_applied"),
            1 if l4.get("telegram_sent") else 0,
            json.dumps(l4.get("actions_taken", [])),
            now,
            report.get("processing_time_ms", 0),
            json.dumps(report),
        ))
        return cur.lastrowid


def get_scan_by_id(scan_id: int) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scanned_emails WHERE id=?", (scan_id,)
        ).fetchone()
    return _row_to_dict(row) if row else None


def get_recent_scans(limit: int = 50, offset: int = 0) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM scanned_emails
            ORDER BY scanned_at DESC LIMIT ? OFFSET ?
        """, (limit, offset)).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_threats(limit: int = 20) -> list[dict]:
    """Return only PHISHING and SUSPICIOUS emails, most recent first."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM scanned_emails
            WHERE verdict IN ('PHISHING','SUSPICIOUS')
            ORDER BY final_score DESC, scanned_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [_row_to_dict(r) for r in rows]


def is_already_scanned(gmail_message_id: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id FROM scanned_emails WHERE gmail_message_id=?",
            (gmail_message_id,)
        ).fetchone()
    return row is not None


def get_stats() -> dict:
    """Dashboard statistics."""
    with get_conn() as conn:
        total     = conn.execute("SELECT COUNT(*) FROM scanned_emails").fetchone()[0]
        phishing  = conn.execute("SELECT COUNT(*) FROM scanned_emails WHERE verdict='PHISHING'").fetchone()[0]
        suspicious= conn.execute("SELECT COUNT(*) FROM scanned_emails WHERE verdict='SUSPICIOUS'").fetchone()[0]
        safe      = conn.execute("SELECT COUNT(*) FROM scanned_emails WHERE verdict='SAFE'").fetchone()[0]
        avg_score = conn.execute("SELECT ROUND(AVG(final_score),1) FROM scanned_emails").fetchone()[0] or 0

        # Risk distribution (buckets)
        buckets = {}
        for label, lo, hi in [("0-20",0,20),("21-40",21,40),("41-60",41,60),("61-80",61,80),("81-100",81,100)]:
            c = conn.execute(
                "SELECT COUNT(*) FROM scanned_emails WHERE final_score BETWEEN ? AND ?", (lo, hi)
            ).fetchone()[0]
            buckets[label] = c

        # Category breakdown
        cats = conn.execute("""
            SELECT l3_threat_category, COUNT(*) as cnt
            FROM scanned_emails
            WHERE l3_threat_category IS NOT NULL
            GROUP BY l3_threat_category
        """).fetchall()

        # Daily trend (last 7 days)
        trend = conn.execute("""
            SELECT DATE(scanned_at) as day, COUNT(*) as total,
                   SUM(CASE WHEN verdict='PHISHING' THEN 1 ELSE 0 END) as threats
            FROM scanned_emails
            WHERE scanned_at >= DATE('now','-7 days')
            GROUP BY DATE(scanned_at)
            ORDER BY day
        """).fetchall()

    return {
        "total": total,
        "phishing": phishing,
        "suspicious": suspicious,
        "safe": safe,
        "avg_score": avg_score,
        "detection_rate": round((phishing + suspicious) / total * 100, 1) if total else 0,
        "risk_distribution": buckets,
        "categories": {r["l3_threat_category"]: r["cnt"] for r in cats},
        "daily_trend": [{"day": r["day"], "total": r["total"], "threats": r["threats"]} for r in trend],
    }


# ─── Audit Log ───────────────────────────────────────────────────────────────

def audit(action: str, details: str = "", email_id: int = None, ip: str = None):
    now = datetime.datetime.utcnow().isoformat() + "Z"
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_log(action,details,email_id,ip_address,created_at) VALUES(?,?,?,?,?)",
            (action, details, email_id, ip, now)
        )


def get_audit_log(limit: int = 100) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ─── System Config ────────────────────────────────────────────────────────────

def set_config(key: str, value: str):
    now = datetime.datetime.utcnow().isoformat() + "Z"
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO system_config(key,value,updated_at) VALUES(?,?,?)",
            (key, value, now)
        )


def get_config(key: str, default: str = None) -> str | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT value FROM system_config WHERE key=?", (key,)
        ).fetchone()
    return row["value"] if row else default


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    # Deserialize JSON columns
    for col in ("l1_flags","l2_suspicious_urls","l2_flags","l3_psych_tactics","l4_actions"):
        if col in d and d[col]:
            try:
                d[col] = json.loads(d[col])
            except (json.JSONDecodeError, TypeError):
                d[col] = []
    if "full_report" in d and d["full_report"]:
        try:
            d["full_report"] = json.loads(d["full_report"])
        except (json.JSONDecodeError, TypeError):
            pass
    return d
