import re
import time
from urllib.parse import parse_qsl, urlsplit

import requests

from app.services.login_session import get_login_session
from app.services.protected_page import _validate_protected_url
from app.utils.safe_http import safe_get


TEST_ORIGIN = "https://webshield.invalid"
SENSITIVE_QUERY_NAMES = {
    "access_token",
    "api_key",
    "auth",
    "authorization",
    "jwt",
    "password",
    "session",
    "sessionid",
    "ticket",
    "token",
}
EMAIL_PATTERN = re.compile(
    r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
)


class AuthenticatedSecurityError(ValueError):
    pass


def _header(response, name):
    return str(response.headers.get(name, "")).strip()


def _cache_observation(response, personal_data_observed):
    cache_control = _header(response, "Cache-Control")
    cache_directives = {
        item.strip().lower()
        for item in cache_control.split(",")
        if item.strip()
    }
    shared_cache_header = (
        _header(response, "CF-Cache-Status")
        or _header(response, "X-Cache")
        or _header(response, "X-Proxy-Cache")
    )
    shared_cache_hit = "hit" in shared_cache_header.lower()
    explicitly_shared = (
        "public" in cache_directives
        or any(item.startswith("s-maxage=") for item in cache_directives)
    )
    protected = (
        "no-store" in cache_directives
        or "private" in cache_directives
    )
    checks = []

    if (explicitly_shared or shared_cache_hit) and personal_data_observed:
        checks.append({
            "name": "Authenticated Account Response May Reach a Shared Cache",
            "status": "Needs Attention",
            "severity": "Medium",
            "confidence": "Medium",
            "validation": "Requires Confirmation",
            "category": "Cryptographic and Data Protection Failures",
            "message": (
                "An authenticated response contained personal-data indicators "
                "and was marked for shared caching or appeared to be served as "
                "a cache hit. Indicators can include non-user addresses, so "
                "manual confirmation is required. Actual values were not retained."
            ),
            "remediation": (
                "Prevent shared caching of personalized responses, use an "
                "appropriate private or no-store policy, and verify CDN rules."
            ),
            "evidence": {
                "cache_control_present": bool(cache_control),
                "explicitly_shared": explicitly_shared,
                "shared_cache_hit": shared_cache_hit,
                "personal_data_indicators": True,
                "sensitive_values_returned": False,
            },
        })
    elif explicitly_shared or shared_cache_hit:
        checks.append({
            "name": "Authenticated Response Uses Shared-Cache Signals",
            "status": "Review",
            "severity": "Medium",
            "confidence": "Medium",
            "validation": "Requires Confirmation",
            "category": "Data Protection Review",
            "message": (
                "The authenticated response used a shared-cache directive or "
                "cache-hit signal. WebShield did not retain evidence of personal "
                "data in the response."
            ),
            "remediation": (
                "Confirm that the response is not personalized and review CDN "
                "cache-key and bypass rules before treating this as a vulnerability."
            ),
            "evidence": {
                "cache_control_present": bool(cache_control),
                "explicitly_shared": explicitly_shared,
                "shared_cache_hit": shared_cache_hit,
                "personal_data_indicators": False,
            },
        })

    return {
        "status": (
            "Needs Attention" if checks else "Protected" if protected else "Review"
        ),
        "cache_control_present": bool(cache_control),
        "private_or_no_store": protected,
        "shared_cache_signal": explicitly_shared or shared_cache_hit,
        "checks": checks,
    }


def run_authenticated_security_checks(
    session_id,
    protected_url,
    engagement_payload,
    fetcher=safe_get,
    sleeper=time.sleep,
):
    safe_url = _validate_protected_url(protected_url, engagement_payload)
    session = get_login_session(session_id, engagement_payload)
    delay = (
        float(engagement_payload.get("request_delay_seconds", 0.5))
        if engagement_payload.get("assessment_mode") == "bug_bounty"
        else 0.3
    )
    if delay:
        sleeper(delay)

    try:
        response = fetcher(
            safe_url,
            max_bytes=1_000_000,
            session=session,
            headers={"Origin": TEST_ORIGIN, "Accept": "text/html,*/*"},
            allowed_redirect_host=engagement_payload["domain"],
            redirect_delay_seconds=delay,
        )
    except requests.RequestException as error:
        raise AuthenticatedSecurityError(
            "The authenticated security response could not be collected."
        ) from error

    if response.status_code >= 500:
        raise AuthenticatedSecurityError(
            "The protected page returned a server error, so checks stopped."
        )

    allowed_origin = _header(response, "Access-Control-Allow-Origin")
    credentials_allowed = (
        _header(response, "Access-Control-Allow-Credentials").lower() == "true"
    )
    cors_checks = []
    if allowed_origin == TEST_ORIGIN and credentials_allowed:
        cors_checks.append({
            "name": "Authenticated Response Trusts an Unrelated Origin",
            "status": "Needs Attention",
            "severity": "High",
            "confidence": "High",
            "validation": "Potential Cross-Origin Data Exposure",
            "category": "Broken Access Control",
            "message": (
                "The protected response reflected an unrelated Origin while "
                "allowing browser credentials. An external website may be able "
                "to read the authenticated response."
            ),
            "remediation": (
                "Use a strict allowlist for trusted origins, reject unknown "
                "origins, and enable credentialed CORS only where required."
            ),
            "evidence": {
                "origin_reflected": True,
                "credentials_allowed": True,
                "response_body_returned": False,
            },
        })
    cors_result = {
        "name": "Authenticated CORS",
        "status": "Needs Attention" if cors_checks else "Protected",
        "message": (
            "The protected response trusted an unrelated credentialed origin."
            if cors_checks
            else "The protected response did not grant credentialed access to the test origin."
        ),
        "checks": cors_checks,
        "requests_made": 1,
        "credentials_sent": True,
        "response_contents_returned": False,
    }

    html = str(response.text or "")
    personal_indicator_count = len(EMAIL_PATTERN.findall(html))
    parsed_url = urlsplit(response.url)
    sensitive_query_names = sorted({
        name.lower()
        for name, _ in parse_qsl(parsed_url.query, keep_blank_values=True)
        if name.lower() in SENSITIVE_QUERY_NAMES
    })
    transport_checks = []
    if sensitive_query_names:
        transport_checks.append({
            "name": "Sensitive-Looking Value Is Carried in the Page URL",
            "status": "Needs Attention",
            "severity": "Medium",
            "confidence": "High",
            "validation": "Confirmed Transport Pattern",
            "category": "Sensitive Data Exposure",
            "message": (
                "The protected page URL contains a query parameter commonly "
                "used for credentials or session material. Values were redacted."
            ),
            "remediation": (
                "Move secrets and session material out of URLs and into secure "
                "cookies or authorization headers, then invalidate exposed values."
            ),
            "evidence": {
                "sensitive_parameter_names": sensitive_query_names,
                "parameter_values_returned": False,
            },
        })

    cache_result = _cache_observation(
        response,
        personal_data_observed=personal_indicator_count > 0,
    )
    transport_checks.extend(cache_result["checks"])
    transport_result = {
        "name": "Authenticated Data Transport and Caching",
        "status": (
            "Needs Attention" if transport_checks else cache_result["status"]
        ),
        "message": (
            "WebShield found an authenticated transport or caching condition "
            "that requires review."
            if transport_checks
            else "No confirmed authenticated transport or shared-cache exposure was observed."
        ),
        "checks": transport_checks,
        "cache": cache_result,
        "personal_data_indicator_count": personal_indicator_count,
        "sensitive_values_returned": False,
        "response_body_returned": False,
    }

    return {
        "name": "Authenticated Vulnerability Suite",
        "status": (
            "Needs Attention"
            if cors_checks or transport_checks
            else "Protected"
        ),
        "message": (
            "WebShield found authenticated security evidence that requires review."
            if cors_checks or transport_checks
            else "No authenticated CORS, sensitive-URL, or shared-cache finding was confirmed."
        ),
        "cors": cors_result,
        "data_transport": transport_result,
        "requests_made": 1,
        "forms_submitted": 0,
        "state_changing_requests_sent": 0,
        "scope": "One signed protected-page URL on the exact hostname",
    }
