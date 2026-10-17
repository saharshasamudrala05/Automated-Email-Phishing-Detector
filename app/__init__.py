"""
app/__init__.py — PhishGuard Flask Application Factory

Uses the Application Factory pattern for:
  - Testability (create multiple isolated app instances)
  - Deferred initialisation (DB, scheduler start after config is loaded)
  - Clean blueprint registration
"""
import logging
from flask import Flask
from app.config import Config
from app import database
from app.security import apply_security_headers


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)
    app.secret_key = Config.SECRET_KEY

    # ── Logging ───────────────────────────────────────────────────
    logging.basicConfig(
        level   = logging.INFO,
        format  = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # ── Database ──────────────────────────────────────────────────
    database.init_db(app)

    # ── Security Headers (every response) ────────────────────────
    app.after_request(apply_security_headers)

    # ── Blueprints ────────────────────────────────────────────────
    from app.routes.auth      import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.api       import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp)

    # ── Background Poller ─────────────────────────────────────────
    # Only start in main process (not during Flask reloader's child proc)
    import os
    if os.environ.get("WERKZEUG_RUN_MAIN") != "true" or not Config.DEBUG:
        from app.poller import start_poller
        start_poller(app)

    # ── Template Utilities ────────────────────────────────────────
    @app.template_filter("risk_colour")
    def risk_colour(score):
        if score >= 70: return "danger"
        if score >= 40: return "warning"
        return "success"

    @app.template_filter("verdict_icon")
    def verdict_icon(verdict):
        icons = {"PHISHING": "🚨", "SUSPICIOUS": "⚠️", "SAFE": "✅", "PENDING": "⏳"}
        return icons.get(verdict, "❓")

    @app.context_processor
    def inject_globals():
        from app.gmail_client import is_connected
        return {"gmail_connected": is_connected()}

    return app
