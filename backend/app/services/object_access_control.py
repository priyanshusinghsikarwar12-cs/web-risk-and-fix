import hashlib
import re
import time
from urllib.parse import parse_qsl, urlsplit

import requests

from app.services.login_session import get_login_session
from app.utils.domain import clean_domain
from app.utils.safe_http import safe_get_once, validate_request_url


OBJECT_PLACEHOLDER = "{object_id}"
OBJECT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DENIED_STATUS_CODES = {401, 403, 404}
SENSITIVE_QUERY_PARTS = {
    "auth",
    "cookie",
    "csrf",
    "key",
    "otp",
    "password",
    "secret",
    "session",
    "signature",
    "token",
}
STATE_CHANGING_PATH_PARTS = {
    "book",
    "buy",
    "cancel",
    "create",
    "delete",
    "logout",
    "pay",
    "purchase",
    "remove",
    "save",
    "submit",
    "transfer",
    "update",
    "upload",
    "withdraw",
}


class ObjectAccessControlError(ValueError):
    pass


def _validate_template(endpoint_template, engagement_payload):
    template = str(endpoint_template or "").strip()
    if template.count(OBJECT_PLACEHOLDER) != 1:
        raise ObjectAccessControlError(
            "The read-only endpoint must contain {object_id} exactly once."
        )

    parsed = urlsplit(template)
    domain = clean_domain(engagement_payload.get("domain"))
    if (
        parsed.scheme.lower() != "https"
        or clean_domain(parsed.hostname or "") != domain
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.fragment
    ):
        raise ObjectAccessControlError(
            "The object endpoint must be same-host HTTPS without credentials, "
            "a custom port, or a fragment."
        )

    path = parsed.path.lower()
    if any(part in path for part in STATE_CHANGING_PATH_PARTS):
        raise ObjectAccessControlError(
            "The endpoint path looks state-changing, so WebShield stopped."
        )
    for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
        normalized = name.lower().replace("-", "_")
        if any(part in normalized for part in SENSITIVE_QUERY_PARTS):
            raise ObjectAccessControlError(
                "The endpoint contains a secret-like query parameter."
            )

    validation_url = template.replace(OBJECT_PLACEHOLDER, "webshield-object")
    validate_request_url(validation_url)
    return template, domain


def _validate_object_id(value, label):
    cleaned = str(value or "").strip()
    if not OBJECT_ID_PATTERN.fullmatch(cleaned) or ".." in cleaned:
        raise ObjectAccessControlError(
            f"{label} must be a simple identifier containing 1 to 128 safe characters."
        )
    return cleaned


def _response_evidence(response):
    content_type = str(response.headers.get("Content-Type", "")).lower()
    content = bytes(response.content or b"")
    return {
        "status_code": int(response.status_code),
        "content_type": content_type.split(";", 1)[0].strip(),
        "is_json": "application/json" in content_type,
        "body_length": len(content),
        "fingerprint": hashlib.sha256(content).hexdigest(),
    }


def _collect(fetcher, url, session, domain):
    try:
        response = fetcher(
            url,
            session=session,
            allowed_host=domain,
            max_bytes=1_000_000,
        )
    except requests.RequestException as error:
        raise ObjectAccessControlError(
            "One bounded object request could not be completed."
        ) from error
    return _response_evidence(response)


def check_object_access_control(
    session_a_id,
    session_b_id,
    endpoint_template,
    object_a_id,
    object_b_id,
    engagement_payload,
    *,
    read_only_get_confirmed=False,
    test_accounts_own_objects_confirmed=False,
    fetcher=safe_get_once,
    sleeper=time.sleep,
):
    if engagement_payload.get("assessment_mode") != "owner_verified":
        raise ObjectAccessControlError(
            "Object access testing currently requires an owner-verified engagement."
        )
    if read_only_get_confirmed is not True:
        raise ObjectAccessControlError(
            "Confirm that the endpoint performs a read-only GET operation."
        )
    if test_accounts_own_objects_confirmed is not True:
        raise ObjectAccessControlError(
            "Confirm that both identifiers belong to the two authorized test accounts."
        )
    if str(session_a_id) == str(session_b_id):
        raise ObjectAccessControlError("Two different test-account sessions are required.")

    template, domain = _validate_template(endpoint_template, engagement_payload)
    object_a = _validate_object_id(object_a_id, "Account A object ID")
    object_b = _validate_object_id(object_b_id, "Account B object ID")
    if object_a == object_b:
        raise ObjectAccessControlError("The two test objects must use different identifiers.")

    session_a = get_login_session(session_a_id, engagement_payload)
    session_b = get_login_session(session_b_id, engagement_payload)
    url_a = template.replace(OBJECT_PLACEHOLDER, object_a)
    url_b = template.replace(OBJECT_PLACEHOLDER, object_b)
    delay = max(
        0.5,
        float(engagement_payload.get("request_delay_seconds", 0.5)),
    )

    own_a = _collect(fetcher, url_a, session_a, domain)
    sleeper(delay)
    own_b = _collect(fetcher, url_b, session_b, domain)
    requests_made = 2

    baseline_usable = (
        200 <= own_a["status_code"] < 300
        and 200 <= own_b["status_code"] < 300
        and own_a["is_json"]
        and own_b["is_json"]
        and own_a["body_length"] > 2
        and own_b["body_length"] > 2
        and own_a["fingerprint"] != own_b["fingerprint"]
    )
    if not baseline_usable:
        return {
            "name": "Object Access Control",
            "status": "Inconclusive",
            "message": (
                "The two owner baselines were not distinct successful JSON objects, "
                "so WebShield stopped before cross-account requests."
            ),
            "checks": [],
            "requests_made": requests_made,
            "request_limit": 4,
            "objects_enumerated": 0,
            "values_returned": False,
            "forms_submitted": 0,
            "state_changing_requests_sent": 0,
        }

    sleeper(delay)
    a_reads_b = _collect(fetcher, url_b, session_a, domain)
    sleeper(delay)
    b_reads_a = _collect(fetcher, url_a, session_b, domain)
    requests_made = 4

    matches = []
    if (
        200 <= a_reads_b["status_code"] < 300
        and a_reads_b["is_json"]
        and a_reads_b["fingerprint"] == own_b["fingerprint"]
    ):
        matches.append("Account A received Account B's exact object response.")
    if (
        200 <= b_reads_a["status_code"] < 300
        and b_reads_a["is_json"]
        and b_reads_a["fingerprint"] == own_a["fingerprint"]
    ):
        matches.append("Account B received Account A's exact object response.")

    checks = []
    if matches:
        checks.append({
            "name": "Cross-Account Object Access Candidate",
            "status": "Needs Attention",
            "severity": "High",
            "confidence": "High",
            "validation": "Requires Confirmation",
            "category": "Broken Access Control",
            "message": (
                "A dedicated test account received the exact private JSON object "
                "baseline belonging to the other dedicated test account."
            ),
            "evidence": {
                "cross_account_exact_matches": len(matches),
                "owner_baselines_distinct": True,
                "response_values_returned": False,
                "identifiers_returned": False,
            },
            "remediation": (
                "Authorize every object request on the server using the current "
                "user and object ownership; never rely only on an object ID."
            ),
        })

    denied = (
        a_reads_b["status_code"] in DENIED_STATUS_CODES
        and b_reads_a["status_code"] in DENIED_STATUS_CODES
    )
    if checks:
        status = "Needs Attention"
        message = "WebShield observed an exact cross-account object response match."
    elif denied:
        status = "Protected"
        message = "Both cross-account object requests were denied."
    else:
        status = "Inconclusive"
        message = (
            "Cross-account responses did not exactly match the other owner baseline, "
            "but both were not clearly denied. Manual review is required."
        )

    return {
        "name": "Object Access Control",
        "status": status,
        "message": message,
        "checks": checks,
        "finding_count": len(checks),
        "requests_made": requests_made,
        "request_limit": 4,
        "objects_enumerated": 0,
        "values_returned": False,
        "forms_submitted": 0,
        "state_changing_requests_sent": 0,
        "cross_request_statuses": {
            "account_a_to_b": a_reads_b["status_code"],
            "account_b_to_a": b_reads_a["status_code"],
        },
        "scope": "Two client-owned accounts and two client-owned objects only",
    }


def check_api_authentication_boundary(
    session_id,
    endpoint_template,
    object_id,
    engagement_payload,
    *,
    read_only_get_confirmed=False,
    private_test_object_confirmed=False,
    fetcher=safe_get_once,
    sleeper=time.sleep,
    anonymous_session_factory=requests.Session,
):
    if engagement_payload.get("assessment_mode") != "owner_verified":
        raise ObjectAccessControlError(
            "API authentication testing currently requires an owner-verified engagement."
        )
    if read_only_get_confirmed is not True:
        raise ObjectAccessControlError(
            "Confirm that the endpoint performs a read-only GET operation."
        )
    if private_test_object_confirmed is not True:
        raise ObjectAccessControlError(
            "Confirm that this private object belongs to the authorized test account."
        )

    template, domain = _validate_template(endpoint_template, engagement_payload)
    safe_object_id = _validate_object_id(object_id, "Test object ID")
    object_url = template.replace(OBJECT_PLACEHOLDER, safe_object_id)
    authenticated_session = get_login_session(session_id, engagement_payload)
    delay = max(
        0.5,
        float(engagement_payload.get("request_delay_seconds", 0.5)),
    )

    authenticated = _collect(
        fetcher,
        object_url,
        authenticated_session,
        domain,
    )
    baseline_usable = (
        200 <= authenticated["status_code"] < 300
        and authenticated["is_json"]
        and authenticated["body_length"] > 2
    )
    if not baseline_usable:
        return {
            "name": "API Authentication Boundary",
            "status": "Inconclusive",
            "message": (
                "The authenticated request did not return a usable private JSON "
                "baseline, so WebShield stopped before the anonymous request."
            ),
            "checks": [],
            "finding_count": 0,
            "requests_made": 1,
            "request_limit": 2,
            "values_returned": False,
            "forms_submitted": 0,
            "state_changing_requests_sent": 0,
        }

    sleeper(delay)
    anonymous_session = anonymous_session_factory()
    try:
        anonymous = _collect(fetcher, object_url, anonymous_session, domain)
    finally:
        anonymous_session.close()

    exact_private_match = (
        200 <= anonymous["status_code"] < 300
        and anonymous["is_json"]
        and anonymous["fingerprint"] == authenticated["fingerprint"]
    )
    checks = []
    if exact_private_match:
        checks.append({
            "name": "Private API Object Available Without Authentication",
            "status": "Needs Attention",
            "severity": "High",
            "confidence": "High",
            "validation": "Requires Confirmation",
            "category": "Broken Access Control",
            "message": (
                "The logged-out request received the exact private JSON object "
                "baseline returned to the authorized test account."
            ),
            "evidence": {
                "anonymous_exact_match": True,
                "authenticated_status_code": authenticated["status_code"],
                "anonymous_status_code": anonymous["status_code"],
                "response_values_returned": False,
                "identifier_returned": False,
            },
            "remediation": (
                "Require authentication before resolving the object and enforce "
                "authorization again on every API request."
            ),
        })

    if checks:
        status = "Needs Attention"
        message = "WebShield observed the exact private object without a session."
    elif anonymous["status_code"] in DENIED_STATUS_CODES:
        status = "Protected"
        message = "The anonymous request was denied."
    else:
        status = "Inconclusive"
        message = (
            "The anonymous response did not match the private baseline exactly, "
            "but it was not clearly denied. Manual review is required."
        )

    return {
        "name": "API Authentication Boundary",
        "status": status,
        "message": message,
        "checks": checks,
        "finding_count": len(checks),
        "requests_made": 2,
        "request_limit": 2,
        "values_returned": False,
        "forms_submitted": 0,
        "state_changing_requests_sent": 0,
        "anonymous_status_code": anonymous["status_code"],
        "scope": "One client-owned account and one private client-owned object only",
    }
