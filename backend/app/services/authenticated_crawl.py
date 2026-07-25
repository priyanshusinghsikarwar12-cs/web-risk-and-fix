from app.deep_scanners.crawler import crawl_verified_site
from app.services.login_session import get_login_session
from app.services.protected_page import verify_protected_page
from app.services.vulnerability_report import build_vulnerability_report
from app.services.authenticated_security import (
    AuthenticatedSecurityError,
    run_authenticated_security_checks,
)


class AuthenticatedCrawlError(ValueError):
    pass


def run_authenticated_crawl(
    session_id,
    protected_url,
    engagement_payload,
    max_pages=15,
    max_depth=2,
    accept_medium_confidence=False,
    anonymous_access_denial_confirmed=False,
    verifier=verify_protected_page,
    crawler=crawl_verified_site,
    security_scanner=run_authenticated_security_checks,
):
    bug_bounty_mode = engagement_payload.get("assessment_mode") == "bug_bounty"
    page_limit = 5 if bug_bounty_mode else 25
    depth_limit = 1 if bug_bounty_mode else 2

    if bug_bounty_mode:
        if engagement_payload.get("authenticated_testing_approved") is not True:
            raise AuthenticatedCrawlError(
                "Authenticated testing is not approved by this signed profile."
            )
        if engagement_payload.get("researcher_owned_accounts_only") is not True:
            raise AuthenticatedCrawlError(
                "Bug bounty authentication requires a researcher-owned account."
            )
        if (
            accept_medium_confidence
            and anonymous_access_denial_confirmed is not True
        ):
            raise AuthenticatedCrawlError(
                "Medium-confidence bug bounty authentication requires explicit "
                "confirmation that the protected URL denied access in a logged-out "
                "private browser window."
            )

    if not 1 <= int(max_pages) <= page_limit:
        raise AuthenticatedCrawlError(
            f"Authenticated crawling supports between 1 and {page_limit} pages "
            "for this profile."
        )
    if not 0 <= int(max_depth) <= depth_limit:
        raise AuthenticatedCrawlError(
            f"Authenticated crawling supports a maximum depth of {depth_limit} "
            "for this profile."
        )

    verification = verifier(
        session_id,
        protected_url,
        engagement_payload,
    )
    verified = verification.get("status") == "Verified"
    accepted_medium = (
        verification.get("status") == "Likely Authenticated"
        and accept_medium_confidence is True
        and (
            not bug_bounty_mode
            or anonymous_access_denial_confirmed is True
        )
    )
    if not verified and not accepted_medium:
        raise AuthenticatedCrawlError(
            "Authenticated crawling stopped because protected-page access "
            "was not sufficiently verified."
        )

    session = get_login_session(session_id, engagement_payload)
    result = crawler(
        engagement_payload["domain"],
        max_pages=int(max_pages),
        max_depth=int(max_depth),
        delay_seconds=(
            float(engagement_payload.get("request_delay_seconds", 0.5))
            if bug_bounty_mode
            else 0.3
        ),
        start_url=protected_url,
        session=session,
        authenticated=True,
    )
    result["name"] = "Read-Only Authenticated Crawler"
    result["authentication_verification"] = verification
    result["forms_submitted"] = 0
    result["state_changing_requests_sent"] = 0
    result["scope"] = "Same signed HTTPS hostname only"
    result["assessment_mode"] = engagement_payload.get(
        "assessment_mode", "owner_verified"
    )
    result["request_delay_seconds"] = (
        float(engagement_payload.get("request_delay_seconds", 0.5))
        if bug_bounty_mode
        else 0.3
    )
    result["anonymous_access_denial_confirmed"] = (
        anonymous_access_denial_confirmed is True
    )
    result["session_fixation"] = getattr(
        session,
        "_webshield_session_fixation",
        {
            "name": "Session Fixation Protection",
            "status": "Not Observable",
            "confidence": "Low",
            "message": (
                "The authenticated session did not contain pre-login "
                "rotation evidence."
            ),
            "checks": [],
            "finding_count": 0,
            "cookie_names_returned": False,
            "cookie_values_returned": False,
        },
    )
    try:
        authenticated_security = security_scanner(
            session_id,
            protected_url,
            engagement_payload,
        )
    except AuthenticatedSecurityError as error:
        authenticated_security = {
            "name": "Authenticated Vulnerability Suite",
            "status": "Unavailable",
            "message": str(error),
            "cors": {"status": "Unavailable", "checks": []},
            "data_transport": {
                "status": "Unavailable",
                "checks": [],
                "cache": {"status": "Unavailable"},
            },
            "requests_made": 0,
            "forms_submitted": 0,
            "state_changing_requests_sent": 0,
        }
    result["authenticated_security"] = authenticated_security
    empty_result = {"status": "Not Applicable", "checks": []}
    result["vulnerability_report"] = build_vulnerability_report(
        result,
        authenticated_security["data_transport"],
        authenticated_security["cors"],
        empty_result,
        empty_result,
        empty_result,
        excluded_finding_types=engagement_payload.get(
            "excluded_finding_types",
            [],
        ),
    )
    return result
