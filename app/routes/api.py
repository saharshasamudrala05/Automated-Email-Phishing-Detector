"""
routes/api.py — REST API for the PhishGuard frontend

All endpoints return JSON.
Rate-limited via the @rate_limit decorator.
"""
from flask import Blueprint, jsonify, request, current_app
from app import database
from app.gmail_client import is_connected, get_connected_email
from app.poller import get_poller_status
from app.security import rate_limit, log_request

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/stats")
@rate_limit
def stats():
    """Dashboard statistics snapshot."""
    return jsonify(database.get_stats())


@api_bp.route("/threats")
@rate_limit
def threats():
    """Recent phishing/suspicious emails."""
    limit  = min(int(request.args.get("limit", 20)), 100)
    data   = database.get_threats(limit=limit)
    return jsonify(data)


@api_bp.route("/scans")
@rate_limit
def scans():
    """Paginated scan history."""
    limit  = min(int(request.args.get("limit", 25)), 100)
    offset = int(request.args.get("offset", 0))
    data   = database.get_recent_scans(limit=limit, offset=offset)
    return jsonify(data)


@api_bp.route("/scans/<int:scan_id>")
@rate_limit
def scan_detail(scan_id: int):
    """Single scan full report."""
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    return jsonify(scan)


@api_bp.route("/poller/status")
@rate_limit
def poller_status():
    """Background poller status."""
    return jsonify(get_poller_status())


@api_bp.route("/connection")
@rate_limit
def connection():
    """Gmail connection status."""
    connected = is_connected()
    return jsonify({
        "connected": connected,
        "email":     get_connected_email() if connected else None,
    })


@api_bp.route("/charts/risk-distribution")
@rate_limit
def risk_distribution():
    stats  = database.get_stats()
    dist   = stats.get("risk_distribution", {})
    return jsonify({
        "labels": list(dist.keys()),
        "data":   list(dist.values()),
    })


@api_bp.route("/charts/categories")
@rate_limit
def categories():
    stats  = database.get_stats()
    cats   = stats.get("categories", {})
    return jsonify({
        "labels": list(cats.keys()),
        "data":   list(cats.values()),
    })


@api_bp.route("/charts/trend")
@rate_limit
def trend():
    stats = database.get_stats()
    trend = stats.get("daily_trend", [])
    return jsonify(trend)
