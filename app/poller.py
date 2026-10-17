"""
poller.py — Background Email Polling Service

Uses APScheduler to poll Gmail every N minutes.
Runs in a daemon thread inside the Flask process.
"""
import logging
import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.config import Config
from app import database

log = logging.getLogger("phishguard.poller")

_scheduler = None
_last_poll: datetime.datetime | None = None
_poll_count: int = 0
_is_polling: bool = False


def start_poller(app):
    """Initialise and start the background scheduler."""
    global _scheduler
    if _scheduler and _scheduler.running:
        return

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        func       = lambda: _poll_with_context(app),
        trigger    = IntervalTrigger(minutes=Config.POLL_INTERVAL_MINUTES),
        id         = "gmail_poll",
        name       = "Gmail Inbox Poll",
        replace_existing=True,
        max_instances=1,         # Never run overlapping polls
    )
    _scheduler.start()
    log.info(f"Poller started — interval: {Config.POLL_INTERVAL_MINUTES} min")


def trigger_manual_poll(app):
    """Trigger an immediate poll (called from dashboard 'Scan Now' button)."""
    _poll_with_context(app)


def get_poller_status() -> dict:
    return {
        "running":       _scheduler.running if _scheduler else False,
        "last_poll":     _last_poll.isoformat() + "Z" if _last_poll else None,
        "poll_count":    _poll_count,
        "is_polling":    _is_polling,
        "interval_min":  Config.POLL_INTERVAL_MINUTES,
        "next_run":      _get_next_run(),
    }


def _get_next_run() -> str | None:
    if not _scheduler or not _scheduler.running:
        return None
    job = _scheduler.get_job("gmail_poll")
    if job and job.next_run_time:
        return job.next_run_time.isoformat()
    return None


def _poll_with_context(app):
    """Run poll inside Flask application context (needed for DB access)."""
    with app.app_context():
        _poll_inbox()


def _poll_inbox():
    """Core polling logic: fetch → pipeline → save → action."""
    global _last_poll, _poll_count, _is_polling

    if _is_polling:
        log.warning("Poll already in progress — skipping")
        return

    _is_polling = True
    try:
        from app.gmail_client import GmailClient, is_connected
        from app.pipeline.orchestrator import run as run_pipeline

        if not is_connected():
            log.info("Gmail not connected — skipping poll")
            return

        gmail = GmailClient()
        emails = gmail.get_unread_inbox_messages(max_results=Config.MAX_EMAILS_PER_POLL)
        log.info(f"Poll: {len(emails)} unread email(s) fetched")

        new_threats = 0
        for email_data in emails:
            msg_id = email_data.get("id")

            # Skip already-scanned emails
            if database.is_already_scanned(msg_id):
                continue

            try:
                report = run_pipeline(email_data, gmail_client=gmail)
                row_id = database.save_scan_result(report)
                verdict = report.get("verdict", "SAFE")
                score   = report.get("final_score", 0)

                database.audit(
                    action  = f"EMAIL_SCANNED_{verdict}",
                    details = f"Score:{score} Subject:'{email_data.get('subject','')[:60]}' "
                              f"From:{email_data.get('sender','')[:60]}",
                    email_id= row_id,
                )

                if verdict in ("PHISHING", "SUSPICIOUS"):
                    new_threats += 1
                    log.warning(f"THREAT DETECTED [{verdict}] score={score} — {email_data.get('subject','')[:60]}")
                else:
                    log.info(f"Safe email cleared — {email_data.get('subject','')[:60]}")

            except Exception as e:
                log.error(f"Pipeline error for message {msg_id}: {e}")
                database.audit(action="PIPELINE_ERROR", details=str(e)[:200])

        _last_poll  = datetime.datetime.utcnow()
        _poll_count += 1
        log.info(f"Poll #{_poll_count} complete — {new_threats} threat(s) found")
        database.set_config("last_poll", _last_poll.isoformat() + "Z")

    except Exception as e:
        log.error(f"Poller error: {e}")
        database.audit(action="POLLER_ERROR", details=str(e)[:200])
    finally:
        _is_polling = False
