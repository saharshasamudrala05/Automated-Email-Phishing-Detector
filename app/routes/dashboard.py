"""
routes/dashboard.py — Dashboard & Threat Detail Views
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app
from app import database
from app.gmail_client import is_connected, get_connected_email
from app.poller import get_poller_status, trigger_manual_poll
from app.security import log_request, generate_csrf_token, validate_csrf

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    connected   = is_connected()
    email       = get_connected_email() if connected else None
    stats       = database.get_stats()
    threats     = database.get_threats(limit=8)
    recent      = database.get_recent_scans(limit=15)
    poller      = get_poller_status()
    csrf_token  = generate_csrf_token()

    return render_template(
        "dashboard.html",
        connected   = connected,
        gmail_email = email,
        stats       = stats,
        threats     = threats,
        recent      = recent,
        poller      = poller,
        csrf_token  = csrf_token,
    )


@dashboard_bp.route("/threats/<int:scan_id>")
def threat_detail(scan_id: int):
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        flash("Scan record not found.", "error")
        return redirect(url_for("dashboard.index"))
    log_request("VIEW_THREAT", f"scan_id={scan_id}")
    return render_template("threat_detail.html", scan=scan)


@dashboard_bp.route("/scan-now", methods=["POST"])
def scan_now():
    token = request.form.get("csrf_token", "")
    if not validate_csrf(token):
        flash("Invalid CSRF token.", "error")
        return redirect(url_for("dashboard.index"))
    if not is_connected():
        flash("Gmail not connected.", "error")
        return redirect(url_for("dashboard.index"))

    log_request("MANUAL_SCAN_TRIGGERED")
    trigger_manual_poll(current_app._get_current_object())
    flash("Manual scan triggered — results will appear shortly.", "success")
    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/audit-log")
def audit_log():
    logs = database.get_audit_log(limit=100)
    return render_template("audit_log.html", logs=logs)


@dashboard_bp.route("/health")
def health():
    """Health check endpoint — used by UptimeRobot to keep Render alive."""
    from flask import jsonify
    return jsonify({"status": "ok", "service": "PhishGuard"})
