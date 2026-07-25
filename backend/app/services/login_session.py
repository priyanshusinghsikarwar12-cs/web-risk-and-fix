import secrets
import time
import re
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


COOKIE_NAME_PATTERN = re.compile(
    r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$"
)
MAX_COOKIE_HEADER_BYTES = 16_384
MAX_COOKIE_COUNT = 50
SESSION_COOKIE_HINTS = {
    "access_token",
    "auth",
    "auth_token",
    "connect.sid",
    "id_token",
    "jsessionid",
    "jwt",
    "phpsessid",
    "session",
    "session_id",
    "sessionid",
    "sid",
}


def _cookie_snapshot(cookie_jar):
    snapshot = {}
    for cookie in cookie_jar:
        name = str(getattr(cookie, "name", "") or "")
        value = str(getattr(cookie, "value", "") or "")
        if name:
            snapshot[name] = value
    return snapshot


def _looks_like_session_cookie(name):
    normalized = str(name or "").strip().lower()
    compact = normalized.replace("-", "_")
    return (
        normalized in SESSION_COOKIE_HINTS
        or compact in SESSION_COOKIE_HINTS
        or "session" in compact
        or compact.endswith("_sid")
    )


def analyze_session_rotation(before_login, after_login):
    before = {
        name: value
        for name, value in (before_login or {}).items()
        if _looks_like_session_cookie(name)
    }
    after = {
        name: value
        for name, value in (after_login or {}).items()
        if _looks_like_session_cookie(name)
    }
    comparable = sorted(set(before) & set(after))
    rotated = [
        name for name in comparable
        if before[name] != after[name]
    ]
    unchanged = [
        name for name in comparable
        if before[name] == after[name]
    ]
    checks = []

    if unchanged and not rotated:
        status = "Needs Attention"
        confidence = "Medium"
        message = (
            "A likely session identifier remained unchanged across the "
            "authorized login. Confirm whether the server rotates its "
            "authenticated session state."
        )
        checks.append({
            "name": "Session Identifier Was Not Rotated After Login",
            "status": "Needs Attention",
            "severity": "High",
            "confidence": "Medium",
            "validation": "Requires Confirmation",
            "category": "Authentication Failures",
            "message": message,
            "remediation": (
                "Create a new server-side session identifier immediately "
                "after authentication and invalidate the anonymous identifier."
            ),
            "evidence": {
                "comparable_session_cookie_count": len(comparable),
                "unchanged_session_cookie_count": len(unchanged),
                "rotated_session_cookie_count": 0,
                "cookie_values_returned": False,
            },
        })
    elif rotated and not unchanged:
        status = "Protected"
        confidence = "High"
        message = (
            "The likely session identifier changed during the authorized "
            "login, which is the expected session-fixation protection."
        )
    elif rotated and unchanged:
        status = "Inconclusive"
        confidence = "Medium"
        message = (
            "Some likely session identifiers changed while another remained "
            "unchanged. The application must identify which cookie controls "
            "the authenticated session."
        )
    elif not before and after:
        status = "Protected"
        confidence = "Medium"
        message = (
            "A likely session identifier appeared only after login. No "
            "reusable pre-login identifier was available for comparison."
        )
    else:
        status = "Not Observable"
        confidence = "Low"
        message = (
            "WebShield could not identify the same likely session cookie "
            "before and after login, so session rotation was not measurable."
        )

    return {
        "name": "Session Fixation Protection",
        "status": status,
        "confidence": confidence,
        "message": message,
        "checks": checks,
        "finding_count": len(checks),
        "comparable_cookie_count": len(comparable),
        "rotated_cookie_count": len(rotated),
        "unchanged_cookie_count": len(unchanged),
        "cookie_names_returned": False,
        "cookie_values_returned": False,
        "login_attempts": 1,
    }


def _parse_cookie_header(cookie_header):
    if not isinstance(cookie_header, str):
        raise LoginSessionError("The browser Cookie header is required.")
    if len(cookie_header.encode("utf-8")) > MAX_COOKIE_HEADER_BYTES:
        raise LoginSessionError("The browser Cookie header exceeds 16 KB.")
    if "\r" in cookie_header or "\n" in cookie_header:
        raise LoginSessionError("The browser Cookie header contains unsafe line breaks.")

    cookies = []
    seen_names = set()
    for part in cookie_header.split(";"):
        item = part.strip()
        if not item:
            continue
        name, separator, value = item.partition("=")
        name = name.strip()
        value = value.strip()
        if not separator or not COOKIE_NAME_PATTERN.fullmatch(name):
            raise LoginSessionError(
                "Paste only the Cookie request-header value as name=value pairs."
            )
        if len(value) > 4096:
            raise LoginSessionError("One browser cookie exceeds the safe size limit.")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise LoginSessionError("A browser cookie contains unsafe control characters.")
        if name in seen_names:
            raise LoginSessionError("The browser Cookie header repeats a cookie name.")
        seen_names.add(name)
        cookies.append((name, value))

    if not cookies:
        raise LoginSessionError("No browser cookies were provided.")
    if len(cookies) > MAX_COOKIE_COUNT:
        raise LoginSessionError("The browser session contains too many cookies.")
    return cookies


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
        cookies_before_login = _cookie_snapshot(session.cookies)
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

        if engagement_payload.get("assessment_mode") == "bug_bounty":
            time.sleep(
                max(
                    0.5,
                    float(
                        engagement_payload.get(
                            "request_delay_seconds",
                            0.5,
                        )
                    ),
                )
            )

        response = session.post(
            action_url,
            data=form_data,
            timeout=10,
            allow_redirects=False,
            headers={"User-Agent": "WebShield/0.1 authorized assessment"},
        )
        if response.status_code >= 500:
            raise LoginSessionError("The login service returned a server error.")

        cookies_after_login = _cookie_snapshot(session.cookies)
        session_fixation = analyze_session_rotation(
            cookies_before_login,
            cookies_after_login,
        )
        setattr(
            session,
            "_webshield_session_fixation",
            session_fixation,
        )
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
            "session_fixation": session_fixation,
            "expires_at": account["expires_at"],
            "message": (
                "A session cookie was observed after one authorized login attempt. "
                "Authenticated access still needs verification on a protected page."
            ),
        }
    except Exception:
        session.close()
        raise


def create_browser_session(
    cookie_header,
    engagement_payload,
    ttl_seconds=900,
    session_factory=requests.Session,
    now=None,
):
    if engagement_payload.get("purpose") != "verified_engagement":
        raise LoginSessionError("A signed Engagement Profile is required.")
    if engagement_payload.get("researcher_owned_accounts_only") is not True:
        raise LoginSessionError(
            "Browser session handoff requires a researcher-owned test account."
        )
    if not 300 <= int(ttl_seconds) <= 3600:
        raise LoginSessionError(
            "Browser session access must expire between 5 and 60 minutes."
        )

    cookies = _parse_cookie_header(cookie_header)
    domain = clean_domain(engagement_payload.get("domain"))
    current_time = int(now if now is not None else time.time())
    session = session_factory()

    try:
        if hasattr(session, "headers"):
            session.headers.update({
                "User-Agent": "WebShield/0.1 authorized read-only assessment"
            })
        for name, value in cookies:
            session.cookies.set(
                name,
                value,
                domain=domain,
                path="/",
                secure=True,
            )

        session_id = secrets.token_urlsafe(18)
        expires_at = current_time + int(ttl_seconds)
        record = {
            "session_id": session_id,
            "engagement_id": engagement_payload["engagement_id"],
            "domain": domain,
            "session": session,
            "credential_id": None,
            "source": "Browser Session Handoff",
            "expires_at": expires_at,
        }
        setattr(
            session,
            "_webshield_session_fixation",
            {
                "name": "Session Fixation Protection",
                "status": "Not Observable",
                "confidence": "Low",
                "message": (
                    "A browser session was supplied after login, so WebShield "
                    "did not observe the anonymous-to-authenticated rotation."
                ),
                "checks": [],
                "finding_count": 0,
                "comparable_cookie_count": 0,
                "rotated_cookie_count": 0,
                "unchanged_cookie_count": 0,
                "cookie_names_returned": False,
                "cookie_values_returned": False,
                "login_attempts": 0,
            },
        )
        with _session_lock:
            _sessions[session_id] = record

        return {
            "session_id": session_id,
            "domain": domain,
            "status": "Browser Session Stored",
            "confidence": "Unverified",
            "cookie_count": len(cookies),
            "cookie_names_returned": False,
            "cookie_values_returned": False,
            "expires_at": expires_at,
            "message": (
                "The browser session is held only in volatile memory. "
                "Protected-page access must still be verified."
            ),
        }
    except Exception:
        session.close()
        raise
