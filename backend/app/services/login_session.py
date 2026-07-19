import secrets
import time
from html.parser import HTMLParser
from threading import Lock
from urllib.parse import urljoin, urlsplit

import requests

from app.services.credential_vault import open_test_account
from app.utils.domain import clean_domain
from app.utils.safe_http import safe_get, validate_request_url


_sessions = {}
_session_lock = Lock()


class LoginSessionError(ValueError):
    pass


def clear_login_sessions():
    """Close all volatile sessions. Used by shutdown code and tests."""
    with _session_lock:
        records = list(_sessions.values())
        _sessions.clear()
    for record in records:
        record["session"].close()


def delete_login_session(session_id, engagement_payload):
    with _session_lock:
        record = _sessions.get(str(session_id))
        if not record:
            raise LoginSessionError("The authenticated session was not found.")
        if record["engagement_id"] != engagement_payload.get("engagement_id"):
            raise LoginSessionError(
                "This authenticated session belongs to a different engagement."
            )
        del _sessions[str(session_id)]
    record["session"].close()
    return {"session_id": str(session_id), "deleted": True}


def get_login_session(session_id, engagement_payload, now=None):
    current_time = int(now if now is not None else time.time())
    with _session_lock:
        record = _sessions.get(str(session_id))
        if not record:
            raise LoginSessionError("The authenticated session was not found.")
        if record["engagement_id"] != engagement_payload.get("engagement_id"):
            raise LoginSessionError(
                "This authenticated session belongs to a different engagement."
            )
        if current_time > int(record["expires_at"]):
            del _sessions[str(session_id)]
            expired_session = record["session"]
        else:
            return record["session"]
    expired_session.close()
    raise LoginSessionError("The authenticated session has expired.")


class LoginFormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag.lower() == "form":
            self.current = {
                "action": str(attrs.get("action", "")),
                "method": str(attrs.get("method", "get")).lower(),
                "fields": [],
            }
        elif tag.lower() == "input" and self.current is not None:
            self.current["fields"].append({
                "name": str(attrs.get("name", "")),
                "type": str(attrs.get("type", "text")).lower(),
                "value": str(attrs.get("value", "")),
            })

    def handle_endtag(self, tag):
        if tag.lower() == "form" and self.current is not None:
            self.forms.append(self.current)
            self.current = None


def _select_login_form(html):
    parser = LoginFormParser()
    parser.feed(html)
    candidates = [
        form for form in parser.forms
        if any(field["type"] == "password" for field in form["fields"])
    ]
    if len(candidates) != 1:
        raise LoginSessionError(
            "WebShield requires exactly one recognizable password login form."
        )
    form = candidates[0]
    if form["method"] != "post":
        raise LoginSessionError("WebShield will not send credentials using a GET form.")
    password_fields = [f for f in form["fields"] if f["type"] == "password" and f["name"]]
    username_fields = [
        f for f in form["fields"]
        if f["type"] in {"text", "email"} and f["name"]
    ]
    if len(password_fields) != 1 or len(username_fields) != 1:
        raise LoginSessionError(
            "The login fields are ambiguous; WebShield stopped without submitting."
        )
    return form, username_fields[0]["name"], password_fields[0]["name"]


def create_login_session(
    credential_id,
    engagement_payload,
    vault_secret,
    session_factory=requests.Session,
):
    account = open_test_account(
        credential_id, engagement_payload, vault_secret
    )
    login_url = account["login_url"]
    domain = clean_domain(account["domain"])
    session = session_factory()

    try:
        login_page = safe_get(login_url, session=session, max_bytes=1_000_000)
        if login_page.status_code >= 400:
            raise LoginSessionError("The login page could not be loaded.")
        form, username_name, password_name = _select_login_form(login_page.text)
        action_url = urljoin(login_page.url, form["action"] or login_page.url)
        validate_request_url(action_url)
        action = urlsplit(action_url)
        if action.scheme.lower() != "https" or clean_domain(action.hostname or "") != domain:
            raise LoginSessionError("The login form submits outside the signed domain scope.")

        form_data = {
            field["name"]: field["value"]
            for field in form["fields"]
            if field["name"] and field["type"] == "hidden"
        }
        form_data[username_name] = account["username"]
        form_data[password_name] = account["password"]

        response = session.post(
            action_url,
            data=form_data,
            timeout=10,
            allow_redirects=False,
            headers={"User-Agent": "WebShield/0.1 authorized assessment"},
        )
        if response.status_code >= 500:
            raise LoginSessionError("The login service returned a server error.")

        cookie_names = sorted(cookie.name for cookie in session.cookies)
        if not cookie_names:
            raise LoginSessionError(
                "No authenticated session cookie was observed after the login attempt."
            )

        session_id = secrets.token_urlsafe(18)
        record = {
            "session_id": session_id,
            "engagement_id": engagement_payload["engagement_id"],
            "domain": domain,
            "session": session,
            "credential_id": credential_id,
            "expires_at": account["expires_at"],
        }
        with _session_lock:
            _sessions[session_id] = record

        return {
            "session_id": session_id,
            "domain": domain,
            "status": "Session Cookie Observed",
            "confidence": "Medium",
            "cookie_names": cookie_names,
            "cookie_values_returned": False,
            "credential_values_returned": False,
            "expires_at": account["expires_at"],
            "message": (
                "A session cookie was observed after one authorized login attempt. "
                "Authenticated access still needs verification on a protected page."
            ),
        }
    except Exception:
        session.close()
        raise
