"""
gmail_client.py — Gmail API Integration (OAuth 2.0)

Security principles applied:
  - OAuth 2.0 only (no password storage)
  - Minimal scope: gmail.modify (read + label, NOT full access)
  - Token refreshed automatically; never expose raw tokens to frontend
  - All Gmail label ops isolated here (single point of control)
"""
import os
import json
import base64
import re
import datetime
from email import message_from_bytes

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from app.config import Config


# ─── OAuth Flow ──────────────────────────────────────────────────────────────

def get_oauth_flow(redirect_uri: str) -> Flow:
    """Build the OAuth 2.0 authorisation flow object."""
    creds_dict = Config.get_google_credentials_dict()
    if not creds_dict:
        raise FileNotFoundError(
            "Google credentials not found.\n"
            "Set GOOGLE_CREDENTIALS_JSON env var or place credentials.json in project root."
        )
    flow = Flow.from_client_config(
        creds_dict,
        scopes=Config.GMAIL_SCOPES,
        redirect_uri=redirect_uri,
    )
    return flow


def load_credentials() -> Credentials | None:
    """Load stored OAuth tokens. Refresh if expired."""
    token_file = Config.GMAIL_TOKEN_FILE
    if not os.path.exists(token_file):
        return None

    with open(token_file) as f:
        token_data = json.load(f)

    creds = Credentials.from_authorized_user_info(token_data, Config.GMAIL_SCOPES)

    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            _save_credentials(creds)
        except Exception:
            return None

    return creds if creds.valid else None


def save_credentials_from_flow(flow: Flow, code: str):
    """Exchange auth code for tokens and persist."""
    flow.fetch_token(code=code)
    _save_credentials(flow.credentials)


def _save_credentials(creds: Credentials):
    token_data = {
        "token":         creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri":     creds.token_uri,
        "client_id":     creds.client_id,
        "client_secret": creds.client_secret,
        "scopes":        list(creds.scopes) if creds.scopes else Config.GMAIL_SCOPES,
    }
    with open(Config.GMAIL_TOKEN_FILE, "w") as f:
        json.dump(token_data, f, indent=2)


def is_connected() -> bool:
    return load_credentials() is not None


def get_connected_email() -> str | None:
    """Return the email address of the connected account."""
    creds = load_credentials()
    if not creds:
        return None
    try:
        service = build("gmail", "v1", credentials=creds)
        profile = service.users().getProfile(userId="me").execute()
        return profile.get("emailAddress")
    except Exception:
        return None


# ─── Gmail API Client ─────────────────────────────────────────────────────────

class GmailClient:
    """
    Thin wrapper around Gmail API.
    All methods raise RuntimeError on unrecoverable API errors.
    """

    def __init__(self):
        creds = load_credentials()
        if not creds:
            raise RuntimeError("Gmail not authenticated. Visit /auth/login to connect.")
        self._service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        self._label_cache: dict[str, str] = {}   # label_name → label_id

    # ── Email Fetching ──────────────────────────────────────────

    def get_unread_inbox_messages(self, max_results: int = 10) -> list[dict]:
        """
        Return list of raw email dicts (headers + body) for unread INBOX emails.
        Does NOT mark them as read — that's a separate decision.
        """
        try:
            result = self._service.users().messages().list(
                userId="me",
                labelIds=["INBOX", "UNREAD"],
                maxResults=max_results,
            ).execute()
        except HttpError as e:
            raise RuntimeError(f"Gmail list error: {e}")

        messages = result.get("messages", [])
        emails = []
        for msg_ref in messages:
            email_data = self._fetch_full_message(msg_ref["id"])
            if email_data:
                emails.append(email_data)
        return emails

    def _fetch_full_message(self, message_id: str) -> dict | None:
        """Fetch and parse a single Gmail message into a flat dict."""
        try:
            msg = self._service.users().messages().get(
                userId="me",
                id=message_id,
                format="full",
            ).execute()
        except HttpError:
            return None

        payload  = msg.get("payload", {})
        headers  = {h["name"]: h["value"] for h in payload.get("headers", [])}

        subject  = headers.get("Subject", "(no subject)")
        sender   = headers.get("From", "")
        recipient= headers.get("To", "")
        date_str = headers.get("Date", "")

        body     = _extract_body(payload)

        return {
            "id":           message_id,
            "subject":      subject,
            "sender":       sender,
            "recipient":    recipient,
            "date":         date_str,
            "headers":      headers,
            "body":         body,
            "snippet":      msg.get("snippet", ""),
            "label_ids":    msg.get("labelIds", []),
        }

    # ── Label Management ────────────────────────────────────────

    def apply_phishing_label(self, message_id: str):
        """Apply ⚠️ PHISHING label and remove from INBOX."""
        label_id = self._get_or_create_label("⚠️ PHISHING", "#ff3333", "#ffffff")
        self._service.users().messages().modify(
            userId="me",
            id=message_id,
            body={
                "addLabelIds":    [label_id],
                "removeLabelIds": ["INBOX"],
            }
        ).execute()

    def apply_suspicious_label(self, message_id: str):
        """Apply 🔶 SUSPICIOUS label."""
        label_id = self._get_or_create_label("🔶 SUSPICIOUS", "#ff8800", "#ffffff")
        self._service.users().messages().modify(
            userId="me",
            id=message_id,
            body={"addLabelIds": [label_id]},
        ).execute()

    def _get_or_create_label(self, name: str, bg_color: str, text_color: str) -> str:
        """Return label ID, creating the label first if it doesn't exist."""
        if name in self._label_cache:
            return self._label_cache[name]

        # List existing labels
        labels = self._service.users().labels().list(userId="me").execute()
        for lbl in labels.get("labels", []):
            if lbl["name"] == name:
                self._label_cache[name] = lbl["id"]
                return lbl["id"]

        # Create new label
        new_label = self._service.users().labels().create(
            userId="me",
            body={
                "name": name,
                "labelListVisibility":   "labelShow",
                "messageListVisibility": "show",
                "color": {"backgroundColor": bg_color, "textColor": text_color},
            }
        ).execute()
        self._label_cache[name] = new_label["id"]
        return new_label["id"]


# ─── Body Extraction ──────────────────────────────────────────────────────────

def _extract_body(payload: dict) -> str:
    """
    Recursively extract plaintext body from Gmail payload.
    Prefers text/plain; falls back to stripping text/html.
    """
    mime = payload.get("mimeType", "")

    if mime == "text/plain":
        data = payload.get("body", {}).get("data", "")
        return _b64_decode(data)

    if mime == "text/html":
        data = payload.get("body", {}).get("data", "")
        html = _b64_decode(data)
        return _strip_html(html)

    # multipart — recurse into parts
    for part in payload.get("parts", []):
        text = _extract_body(part)
        if text:
            return text

    return ""


def _b64_decode(data: str) -> str:
    if not data:
        return ""
    try:
        return base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
    except Exception:
        return ""


def _strip_html(html: str) -> str:
    """Very simple HTML tag stripper — preserves text content."""
    text = re.sub(r"<style[^>]*>.*?</style>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<script[^>]*>.*?</script>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"\s{2,}", " ", text)
    return text.strip()
