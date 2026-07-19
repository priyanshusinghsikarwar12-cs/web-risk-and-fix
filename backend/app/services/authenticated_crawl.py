from app.deep_scanners.crawler import crawl_verified_site
from app.services.login_session import get_login_session
from app.services.protected_page import verify_protected_page
from app.services.vulnerability_report import build_vulnerability_report


class AuthenticatedCrawlError(ValueError):
    pass


def run_authenticated_crawl(
    session_id,
    protected_url,
    engagement_payload,
    max_pages=15,
    max_depth=2,
    accept_medium_confidence=False,
    verifier=verify_protected_page,
    crawler=crawl_verified_site,
):
    if not 1 <= int(max_pages) <= 25:
        raise AuthenticatedCrawlError(
            "Authenticated crawling supports between 1 and 25 pages."
        )
    if not 0 <= int(max_depth) <= 2:
        raise AuthenticatedCrawlError(
            "Authenticated crawling supports a maximum depth of 2."
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
        delay_seconds=0.3,
        start_url=protected_url,
        session=session,
        authenticated=True,
    )
    result["name"] = "Read-Only Authenticated Crawler"
    result["authentication_verification"] = verification
    result["forms_submitted"] = 0
    result["state_changing_requests_sent"] = 0
    result["scope"] = "Same verified HTTPS hostname only"
    empty_result = {"status": "Not Applicable", "checks": []}
    result["vulnerability_report"] = build_vulnerability_report(
        result,
        empty_result,
        empty_result,
        empty_result,
        empty_result,
        empty_result,
    )
    return result
