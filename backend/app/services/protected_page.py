import hashlib
from html.parser import HTMLParser
from urllib.parse import urlsplit

from app.services.login_session import get_login_session
from app.utils.domain import clean_domain
from app.utils.safe_http import safe_get


class ProtectedPageError(ValueError):
    pass


class PasswordFormDetector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.has_password_field = False

    def handle_starttag(self, tag, attributes):
        if tag.lower() != "input":
            return
        values = dict(attributes)
        if str(values.get("type", "")).lower() == "password":
            self.has_password_field = True


def _has_password_form(html):
    detector = PasswordFormDetector()
    detector.feed(str(html or ""))
    return detector.has_password_field


def _validate_protected_url(url, engagement_payload):
    value = str(url or "").strip()
    try:
        parsed = urlsplit(value)
        hostname = clean_domain(parsed.hostname or "")
    except (TypeError, ValueError) as error:
        raise ProtectedPageError("The protected-page URL is invalid.") from error
    if parsed.scheme.lower() != "https":
        raise ProtectedPageError("Protected-page verification requires HTTPS.")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ProtectedPageError("The protected-page URL contains unsafe authority data.")
    scope = {clean_domain(item) for item in engagement_payload.get("scope", [])}
    if hostname not in scope:
        raise ProtectedPageError(
            "The protected-page URL is outside the signed engagement scope."
        )
    return value


def _response_evidence(response):
    content = response.content or b""
    return {
        "status_code": response.status_code,
        "final_url": response.url,
        "content_length": len(content),
        "fingerprint": hashlib.sha256(content).hexdigest(),
        "has_password_form": _has_password_form(response.text),
    }


def verify_protected_page(
    session_id,
    protected_url,
    engagement_payload,
    fetcher=safe_get,
):
    safe_url = _validate_protected_url(protected_url, engagement_payload)
    authenticated_session = get_login_session(session_id, engagement_payload)

    anonymous_response = fetcher(safe_url, max_bytes=1_000_000)
    authenticated_response = fetcher(
        safe_url,
        max_bytes=1_000_000,
        session=authenticated_session,
    )
    anonymous = _response_evidence(anonymous_response)
    authenticated = _response_evidence(authenticated_response)

    strong_access_change = (
        anonymous["status_code"] in {401, 403}
        and 200 <= authenticated["status_code"] < 400
    ) or (
        anonymous["has_password_form"]
        and not authenticated["has_password_form"]
        and 200 <= authenticated["status_code"] < 400
    )
    meaningful_change = (
        anonymous["status_code"] != authenticated["status_code"]
        or anonymous["final_url"] != authenticated["final_url"]
        or anonymous["fingerprint"] != authenticated["fingerprint"]
    )

    if strong_access_change:
        status = "Verified"
        confidence = "High"
        message = (
            "The protected page changed from an anonymous login/denial response "
            "to an authenticated page response."
        )
    elif (
        meaningful_change
        and 200 <= authenticated["status_code"] < 400
        and not authenticated["has_password_form"]
    ):
        status = "Likely Authenticated"
        confidence = "Medium"
        message = (
            "The authenticated response differs from the anonymous response, "
            "but WebShield cannot prove access control from this page alone."
        )
    else:
        status = "Not Verified"
        confidence = "Low"
        message = (
            "WebShield could not confirm that the session reached protected content."
        )

    return {
        "name": "Protected Page Verification",
        "domain": engagement_payload["domain"],
        "protected_url": safe_url,
        "status": status,
        "confidence": confidence,
        "message": message,
        "anonymous": {
            "status_code": anonymous["status_code"],
            "final_url": anonymous["final_url"],
            "login_form_observed": anonymous["has_password_form"],
        },
        "authenticated": {
            "status_code": authenticated["status_code"],
            "final_url": authenticated["final_url"],
            "login_form_observed": authenticated["has_password_form"],
        },
        "page_content_returned": False,
        "cookie_values_returned": False,
    }
