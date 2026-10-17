"""
routes/auth.py — Gmail OAuth 2.0 Authentication Routes

/auth/login    → Start OAuth flow (redirect to Google)
/auth/callback → Handle Google's redirect, exchange code for tokens
/auth/logout   → Revoke and delete stored tokens
/auth/status   → JSON status for the frontend
"""
import os
from flask import (
    Blueprint, redirect, request, session,
    url_for, flash, current_app, jsonify
)
from app.gmail_client import (
    get_oauth_flow, save_credentials_from_flow,
    is_connected, get_connected_email, Config
)
from app import database
from app.security import log_request

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/login")
def login():
    """Initiate Gmail OAuth 2.0 flow."""
    creds_dict = Config.get_google_credentials_dict()
    if not creds_dict:
        return (
            "<h2>Setup Error</h2>"
            "<p>Google credentials not found. "
            "See README → Step 2: Google Cloud Setup.</p>", 400
        )

    redirect_uri = _get_redirect_uri()
    flow         = get_oauth_flow(redirect_uri)

    auth_url, state = flow.authorization_url(
        access_type    = "offline",   # Get refresh_token for background polling
        include_granted_scopes = "true",
        prompt         = "consent",   # Force consent screen to always get refresh_token
    )
    session["oauth_state"] = state
    log_request("OAUTH_INITIATED")
    return redirect(auth_url)


@auth_bp.route("/callback")
def callback():
    """Handle Google OAuth redirect and exchange code for tokens."""
    error = request.args.get("error")
    if error:
        flash(f"OAuth error: {error}", "error")
        return redirect(url_for("dashboard.index"))

    code  = request.args.get("code")
    state = request.args.get("state")

    if not code:
        flash("No authorisation code received from Google.", "error")
        return redirect(url_for("dashboard.index"))

    try:
        redirect_uri = _get_redirect_uri()
        flow         = get_oauth_flow(redirect_uri)
        flow.oauth2session.state = state or session.get("oauth_state", "")
        save_credentials_from_flow(flow, code)

        email = get_connected_email()
        database.set_config("connected_email", email or "unknown")
        database.audit(action="GMAIL_CONNECTED", details=f"Account: {email}")
        log_request("OAUTH_SUCCESS", f"Account: {email}")
        flash(f"✅ Gmail connected: {email}", "success")

    except Exception as e:
        flash(f"OAuth callback error: {str(e)[:200]}", "error")
        log_request("OAUTH_FAILURE", str(e)[:200])

    return redirect(url_for("dashboard.index"))


@auth_bp.route("/logout")
def logout():
    """Disconnect Gmail — delete stored tokens."""
    token_file = Config.GMAIL_TOKEN_FILE
    if os.path.exists(token_file):
        os.remove(token_file)

    database.audit(action="GMAIL_DISCONNECTED")
    log_request("GMAIL_DISCONNECTED")
    flash("Gmail disconnected.", "info")
    return redirect(url_for("dashboard.index"))


@auth_bp.route("/status")
def status():
    """JSON endpoint: Gmail connection status."""
    connected = is_connected()
    email     = get_connected_email() if connected else None
    return jsonify({
        "connected": connected,
        "email":     email,
    })


def _get_redirect_uri() -> str:
    """Build the OAuth callback URL for this environment."""
    base = Config.BASE_URL.rstrip("/")
    return f"{base}/auth/callback"
