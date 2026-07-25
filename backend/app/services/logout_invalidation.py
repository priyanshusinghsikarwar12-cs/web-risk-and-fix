import hashlib
import json
import re
import secrets
import time
from threading import Lock
from urllib.parse import parse_qsl, urlsplit

import requests

from app.services.login_session import (
    delete_login_session,
    get_login_session,
)
from app.services.protected_page import (
    ProtectedPageError,
    _has_password_form,
    _validate_protected_url,
    verify_protected_page,
)
from app.utils.safe_http import safe_get, safe_post_json


EMAIL_PATTERN = re.compile(
    r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
)
MAX_LOGOUT_TESTS = 50
LOGOUT_TEST_TTL_SECONDS = 900

_records = {}
_record_lock = Lock()


class LogoutInvalidationError(ValueError):
    pass


SENSITIVE_QUERY_KEY_PARTS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "code",
    "credential",
    "jwt",
    "password",
    "secret",
    "session",
    "signature",
    "token",
}
SENSITIVE_JSON_KEY_MARKERS = {
    "cookie",
    "credential",
    "csrf",
    "cvv",
    "jwt",
    "otp",
    "passwd",
    "password",
    "secret",
    "session",
    "signature",
    "token",
}
SENSITIVE_JSON_EXACT_KEYS = {
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "pin",
}
SENSITIVE_CODE_QUALIFIERS = {
    "auth",
    "authorization",
    "login",
    "oauth",
    "otp",
    "password",
    "recovery",
    "reset",
    "verification",
}
READ_ONLY_ACTION_PREFIXES = (
    "check",
    "fetch",
    "get",
    "list",
    "lookup",
    "query",
    "read",
    "search",
    "view",
)
MAX_POST_BODY_BYTES = 16_384
MAX_POST_BODY_DEPTH = 5


def _validate_verification_endpoint(url, engagement_payload):
    try:
        safe_url = _validate_protected_url(url, engagement_payload)
        parsed = urlsplit(safe_url)
    except ProtectedPageError as error:
        raise LogoutInvalidationError(str(error)) from error
    if parsed.fragment:
        raise LogoutInvalidationError(
            "The verification endpoint must not contain a URL fragment."
        )
    for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
        normalized = str(name).strip().lower().replace("-", "_")
        if any(part in normalized for part in SENSITIVE_QUERY_KEY_PARTS):
            raise LogoutInvalidationError(
                "The verification endpoint contains a sensitive-looking query "
                "parameter. Use a read-only URL without tokens or credentials."
            )
    return safe_url


def _validate_json_value(value, depth=0):
    if depth > MAX_POST_BODY_DEPTH:
        raise LogoutInvalidationError(
            "The read-only POST JSON body is nested too deeply."
        )
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, str):
        if len(value) > 2_048:
            raise LogoutInvalidationError(
                "A read-only POST JSON value is too long."
            )
        return
    if isinstance(value, list):
        if len(value) > 100:
            raise LogoutInvalidationError(
                "The read-only POST JSON array is too large."
            )
        for item in value:
            _validate_json_value(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 100:
            raise LogoutInvalidationError(
                "The read-only POST JSON object has too many fields."
            )
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            compact = re.sub(r"[^a-z0-9]", "", normalized)
            secret_marker = any(
                marker in compact
                for marker in SENSITIVE_JSON_KEY_MARKERS
            )
            sensitive_code = (
                "code" in compact
                and any(
                    qualifier in compact
                    for qualifier in SENSITIVE_CODE_QUALIFIERS
                )
            )
            sensitive_pin = (
                compact.endswith("pin")
                and compact.startswith(("card", "payment", "security"))
            )
            if (
                normalized in SENSITIVE_JSON_EXACT_KEYS
                or secret_marker
                or sensitive_code
                or sensitive_pin
            ):
                raise LogoutInvalidationError(
                    "The read-only POST JSON body contains a secret-like field. "
                    "Remove tokens, passwords, cookies, OTPs, and credentials."
                )
            _validate_json_value(item, depth + 1)
        return
    raise LogoutInvalidationError(
        "The read-only POST body contains an unsupported JSON value."
    )


def _validate_read_only_post(url, json_body, confirmed):
    if confirmed is not True:
        raise LogoutInvalidationError(
            "Confirm that the POST operation only reads your own test account."
        )
    action = urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1].lower()
    if not action.startswith(READ_ONLY_ACTION_PREFIXES):
        raise LogoutInvalidationError(
            "The POST endpoint action is not recognizably read-only. Use an "
            "endpoint beginning with get, query, list, fetch, read, view, check, "
            "lookup, or search."
        )
    if not isinstance(json_body, dict):
        raise LogoutInvalidationError(
            "The read-only POST body must be one JSON object."
        )
    _validate_json_value(json_body)
    serialized = json.dumps(
        json_body,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(serialized.encode("utf-8")) > MAX_POST_BODY_BYTES:
        raise LogoutInvalidationError(
            "The read-only POST JSON body exceeds 16 KB."
        )
    return json.loads(serialized)


def _fetch_verification_response(
    method,
    url,
    json_body,
    session,
    domain,
    fetcher,
    post_fetcher,
    delay,
):
    if method == "POST":
        return post_fetcher(
            url,
            json_body,
            max_bytes=1_000_000,
            session=session,
            allowed_host=domain,
        )
    return fetcher(
        url,
        max_bytes=1_000_000,
        session=session,
        allowed_redirect_host=domain,
        redirect_delay_seconds=delay,
    )


def _fingerprint(content):
    return hashlib.sha256(content or b"").hexdigest()


def _indicator_hashes(text, salt):
    return {
        hashlib.sha256(
            salt + value.lower().encode("utf-8")
        ).hexdigest()
        for value in EMAIL_PATTERN.findall(str(text or ""))
    }


def _delete_session_safely(session_id, engagement_id):
    try:
        delete_login_session(
            session_id,
            {"engagement_id": engagement_id},
        )
    except Exception:
        pass


def _cleanup_expired(now):
    expired = []
    with _record_lock:
        for test_id, record in list(_records.items()):
            if int(record["expires_at"]) < int(now):
                expired.append(_records.pop(test_id))
    for record in expired:
        _delete_session_safely(
            record["session_id"],
            record["engagement_id"],
        )


def clear_logout_tests():
    with _record_lock:
        records = list(_records.values())
        _records.clear()
    for record in records:
        _delete_session_safely(
            record["session_id"],
            record["engagement_id"],
        )


def prepare_logout_invalidation_test(
    session_id,
    protected_url,
    engagement_payload,
    anonymous_access_denial_confirmed=False,
    verification_endpoint_url=None,
    verification_method="GET",
    verification_json_body=None,
    read_only_post_confirmed=False,
    verifier=verify_protected_page,
    fetcher=safe_get,
    post_fetcher=safe_post_json,
    sleeper=time.sleep,
    now=None,
):
    current_time = int(now if now is not None else time.time())
    _cleanup_expired(current_time)
    with _record_lock:
        capacity_reached = len(_records) >= MAX_LOGOUT_TESTS
    if capacity_reached:
        raise LogoutInvalidationError(
            "Too many logout tests are waiting; cancel or complete an existing test."
        )
    safe_url = _validate_protected_url(protected_url, engagement_payload)
    endpoint_mode = bool(str(verification_endpoint_url or "").strip())
    method = str(verification_method or "GET").strip().upper()
    if method not in {"GET", "POST"}:
        raise LogoutInvalidationError(
            "Verification method must be GET or read-only POST."
        )
    if method == "POST" and not endpoint_mode:
        raise LogoutInvalidationError(
            "Read-only POST verification requires an endpoint URL."
        )
    test_url = (
        _validate_verification_endpoint(
            verification_endpoint_url,
            engagement_payload,
        )
        if endpoint_mode
        else safe_url
    )
    json_body = None
    if method == "POST":
        json_body = _validate_read_only_post(
            test_url,
            verification_json_body,
            read_only_post_confirmed,
        )
    verification = verifier(session_id, safe_url, engagement_payload)
    verified = verification.get("status") == "Verified"
    accepted_medium = (
        verification.get("status") == "Likely Authenticated"
        and anonymous_access_denial_confirmed is True
    )
    if not verified and not accepted_medium:
        raise LogoutInvalidationError(
            "Logout testing requires verified protected-page access or the "
            "confirmed logged-out private-window boundary."
        )

    session = get_login_session(session_id, engagement_payload)
    delay = float(engagement_payload.get("request_delay_seconds", 0.5))
    if delay:
        sleeper(delay)
    try:
        anonymous_response = None
        if endpoint_mode:
            anonymous_response = _fetch_verification_response(
                method,
                test_url,
                json_body,
                None,
                engagement_payload["domain"],
                fetcher,
                post_fetcher,
                delay,
            )
            if delay:
                sleeper(delay)
        response = _fetch_verification_response(
            method if endpoint_mode else "GET",
            test_url,
            json_body,
            session,
            engagement_payload["domain"],
            fetcher,
            post_fetcher,
            delay,
        )
    except requests.RequestException as error:
        raise LogoutInvalidationError(
            "The authenticated logout baseline could not be collected."
        ) from error
    if not 200 <= response.status_code < 400:
        raise LogoutInvalidationError(
            "The authenticated logout baseline did not return a usable response."
        )

    endpoint_access_proven = False
    if endpoint_mode:
        endpoint_access_proven = (
            anonymous_response.status_code in {401, 403}
            and 200 <= response.status_code < 400
        )
        endpoint_changed = (
            anonymous_response.status_code != response.status_code
            or _fingerprint(anonymous_response.content)
            != _fingerprint(response.content)
        )
        if not endpoint_access_proven and not (
            endpoint_changed and anonymous_access_denial_confirmed is True
        ):
            raise LogoutInvalidationError(
                "The endpoint did not provide a clear authenticated-versus-anonymous "
                "boundary. Choose a read-only account endpoint that denies logged-out "
                "access or confirm its logged-out behavior first."
            )

    salt = secrets.token_bytes(16)
    test_id = secrets.token_urlsafe(18)
    expires_at = current_time + LOGOUT_TEST_TTL_SECONDS
    record = {
        "test_id": test_id,
        "engagement_id": engagement_payload["engagement_id"],
        "domain": engagement_payload["domain"],
        "session_id": str(session_id),
        "protected_url": safe_url,
        "test_url": test_url,
        "endpoint_mode": endpoint_mode,
        "verification_method": method if endpoint_mode else "GET",
        "verification_json_body": json_body,
        "endpoint_access_proven": endpoint_access_proven,
        "baseline_fingerprint": _fingerprint(response.content),
        "baseline_indicators": _indicator_hashes(response.text, salt),
        "salt": salt,
        "expires_at": expires_at,
    }
    with _record_lock:
        _records[test_id] = record

    return {
        "test_id": test_id,
        "status": "Waiting for Manual Logout",
        "confidence": verification.get("confidence", "Medium"),
        "protected_url": safe_url,
        "verification_mode": (
            f"Read-only {method} Account Endpoint"
            if endpoint_mode
            else "Protected Page"
        ),
        "baseline_requests_made": 2 if endpoint_mode else 1,
        "expires_at": expires_at,
        "baseline_personal_indicator_count": len(record["baseline_indicators"]),
        "personal_values_returned": False,
        "cookie_values_returned": False,
        "message": (
            "Log out normally in the browser, then ask WebShield to replay the "
            "old session once before this test expires."
        ),
    }


def check_logout_invalidation_test(
    test_id,
    engagement_payload,
    logout_completed_confirmed,
    fetcher=safe_get,
    post_fetcher=safe_post_json,
    sleeper=time.sleep,
    now=None,
):
    if logout_completed_confirmed is not True:
        raise LogoutInvalidationError(
            "Confirm that manual logout completed before replaying the old session."
        )
    current_time = int(now if now is not None else time.time())
    _cleanup_expired(current_time)
    with _record_lock:
        record = _records.pop(str(test_id), None)
    if not record:
        raise LogoutInvalidationError("The logout test was not found or has expired.")
    if record["engagement_id"] != engagement_payload.get("engagement_id"):
        with _record_lock:
            _records[str(test_id)] = record
        raise LogoutInvalidationError(
            "This logout test belongs to a different signed engagement."
        )

    try:
        session = get_login_session(record["session_id"], engagement_payload)
        delay = float(engagement_payload.get("request_delay_seconds", 0.5))
        if delay:
            sleeper(delay)
        anonymous = _fetch_verification_response(
            record["verification_method"],
            record["test_url"],
            record["verification_json_body"],
            None,
            record["domain"],
            fetcher,
            post_fetcher,
            delay,
        )
        if delay:
            sleeper(delay)
        old_session = _fetch_verification_response(
            record["verification_method"],
            record["test_url"],
            record["verification_json_body"],
            session,
            record["domain"],
            fetcher,
            post_fetcher,
            delay,
        )

        anonymous_fingerprint = _fingerprint(anonymous.content)
        old_fingerprint = _fingerprint(old_session.content)
        anonymous_indicators = _indicator_hashes(anonymous.text, record["salt"])
        old_indicators = _indicator_hashes(old_session.text, record["salt"])
        persistent_private_indicators = (
            record["baseline_indicators"]
            & old_indicators
            - anonymous_indicators
        )
        strong_access = (
            anonymous.status_code in {401, 403}
            and 200 <= old_session.status_code < 400
        ) or (
            _has_password_form(anonymous.text)
            and not _has_password_form(old_session.text)
            and 200 <= old_session.status_code < 400
        )
        appears_invalidated = (
            old_session.status_code in {401, 403}
            or _has_password_form(old_session.text)
            or (
                old_fingerprint == anonymous_fingerprint
                and not persistent_private_indicators
            )
        )
        exact_baseline_persisted = (
            old_fingerprint == record["baseline_fingerprint"]
            and old_fingerprint != anonymous_fingerprint
        )

        finding = None
        if strong_access or persistent_private_indicators:
            status = "Needs Attention"
            message = (
                "The old authenticated session still reached protected evidence "
                "after manual logout."
            )
            finding = {
                "title": "Old Session May Remain Valid After Logout",
                "severity": "High",
                "confidence": "High",
                "validation": "Potential Broken Session Invalidation",
                "category": "Identification and Authentication Failures",
                "message": message,
                "remediation": (
                    "Invalidate the server-side session during logout, expire the "
                    "session cookie, and confirm every protected endpoint rejects it."
                ),
            }
        elif exact_baseline_persisted:
            status = "Review"
            message = (
                "The old session returned the same protected-page fingerprint after "
                "logout, but WebShield did not retain enough personal evidence to "
                "confirm continued account access."
            )
            finding = {
                "title": "Old Session Response Persisted After Logout",
                "severity": "Medium",
                "confidence": "Medium",
                "validation": "Requires Confirmation",
                "category": "Identification and Authentication Failures",
                "message": message,
                "remediation": (
                    "Confirm logout invalidation against a clearly protected endpoint "
                    "and revoke the server-side session immediately on logout."
                ),
            }
        elif appears_invalidated:
            status = "Protected"
            message = "The old session no longer reproduced protected access after logout."
        else:
            status = "Inconclusive"
            message = (
                "The old response changed after logout, but the tested page did not "
                "provide enough evidence to prove or disprove session invalidation."
            )

        return {
            "name": "Logout Session Invalidation",
            "status": status,
            "message": message,
            "finding": finding,
            "requests_made": 2,
            "verification_mode": (
                f"Read-only {record['verification_method']} Account Endpoint"
                if record["endpoint_mode"]
                else "Protected Page"
            ),
            "forms_submitted": 0,
            "state_changing_requests_sent": 0,
            "old_session_deleted": True,
            "personal_values_returned": False,
            "cookie_values_returned": False,
            "evidence": {
                "anonymous_status_code": anonymous.status_code,
                "old_session_status_code": old_session.status_code,
                "exact_baseline_fingerprint_persisted": exact_baseline_persisted,
                "private_indicator_count": len(persistent_private_indicators),
                "indicator_values_returned": False,
            },
        }
    except requests.RequestException as error:
        raise LogoutInvalidationError(
            "The one-time post-logout comparison could not be completed."
        ) from error
    finally:
        _delete_session_safely(
            record["session_id"],
            record["engagement_id"],
        )


def cancel_logout_invalidation_test(test_id, engagement_payload):
    with _record_lock:
        record = _records.get(str(test_id))
        if not record:
            raise LogoutInvalidationError("The logout test was not found or has expired.")
        if record["engagement_id"] != engagement_payload.get("engagement_id"):
            raise LogoutInvalidationError(
                "This logout test belongs to a different signed engagement."
            )
        del _records[str(test_id)]
    _delete_session_safely(record["session_id"], record["engagement_id"])
    return {
        "test_id": str(test_id),
        "cancelled": True,
        "old_session_deleted": True,
    }
