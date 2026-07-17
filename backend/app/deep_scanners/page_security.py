from app.scanners.cookies import (
    analyze_set_cookie_headers,
    get_set_cookie_headers,
)
from app.scanners.headers import (
    validate_security_headers,
)
from app.scanners.mixed_content import (
    analyze_mixed_content,
)


def analyze_page_security(response):
    header_checks = validate_security_headers(
        response.headers
    )

    cookie_headers = get_set_cookie_headers(
        response
    )

    cookie_checks = analyze_set_cookie_headers(
        cookie_headers
    )

    mixed_content = analyze_mixed_content(
        response.text,
        getattr(
            response,
            "webshield_content_truncated",
            False,
        ),
    )

    statuses = [
        check["status"]
        for check in header_checks
    ]

    statuses.extend(
        check["status"]
        for check in cookie_checks
    )

    statuses.append(
        mixed_content["status"]
    )

    if "Needs Attention" in statuses:
        status = "Needs Attention"

    elif "Review" in statuses:
        status = "Review"

    else:
        status = "Protected"

    return {
        "url": response.url,
        "status": status,
        "header_checks": header_checks,
        "cookie_checks": cookie_checks,
        "cookies_observed": bool(
            cookie_headers
        ),
        "mixed_content": mixed_content,
    }


def summarize_page_security(
    page_results: list,
):
    if not page_results:
        return {
            "name": "Crawled Page Security",
            "status": "Not Applicable",
            "message": (
                "No crawled HTML page was available "
                "for page-level security analysis."
            ),
            "pages_analyzed": 0,
            "header_coverage": [],
            "cookie_findings": [],
            "mixed_content_findings": [],
            "score_eligible": False,
        }

    header_coverage = {}
    cookie_findings = []
    mixed_content_findings = []

    for page in page_results:
        page_url = page["url"]

        for check in page["header_checks"]:
            technical_name = check[
                "technical_name"
            ]

            coverage = header_coverage.setdefault(
                technical_name,
                {
                    "technical_name": technical_name,
                    "name": check["name"],
                    "protected_pages": 0,
                    "attention_pages": 0,
                    "affected_pages": [],
                },
            )

            if check["status"] == "Protected":
                coverage["protected_pages"] += 1
            else:
                coverage["attention_pages"] += 1

                if (
                    len(coverage["affected_pages"])
                    < 20
                ):
                    coverage[
                        "affected_pages"
                    ].append(page_url)

        for cookie in page["cookie_checks"]:
            if cookie["status"] in {
                "Needs Attention",
                "Review",
            }:
                cookie_findings.append({
                    **cookie,
                    "page_url": page_url,
                })

        mixed_result = page["mixed_content"]

        for finding in mixed_result.get(
            "checks",
            [],
        ):
            mixed_content_findings.append({
                **finding,
                "page_url": page_url,
            })

    coverage_results = []

    for coverage in header_coverage.values():
        coverage_results.append({
            **coverage,
            "status": (
                "Needs Attention"
                if coverage[
                    "attention_pages"
                ]
                else "Protected"
            ),
        })

    attention_exists = (
        any(
            item["status"] == "Needs Attention"
            for item in coverage_results
        )
        or any(
            item["status"] == "Needs Attention"
            for item in cookie_findings
        )
        or bool(mixed_content_findings)
    )

    review_exists = any(
        item["status"] == "Review"
        for item in cookie_findings
    )

    if attention_exists:
        status = "Needs Attention"
        message = (
            "WebShield found inconsistent or missing "
            "protections across crawled pages."
        )

    elif review_exists:
        status = "Review"
        message = (
            "Page protections were generally present, "
            "but some cookie settings need review."
        )

    else:
        status = "Protected"
        message = (
            "No obvious page-level header, cookie, or "
            "mixed-content problem was observed."
        )

    return {
        "name": "Crawled Page Security",
        "status": status,
        "message": message,
        "pages_analyzed": len(page_results),
        "header_coverage": sorted(
            coverage_results,
            key=lambda item: item[
                "technical_name"
            ],
        ),
        "cookie_findings": cookie_findings[
            :100
        ],
        "cookie_finding_count": len(
            cookie_findings
        ),
        "mixed_content_findings": (
            mixed_content_findings[:100]
        ),
        "mixed_content_finding_count": len(
            mixed_content_findings
        ),
        "results_limited": (
            len(cookie_findings) > 100
            or len(mixed_content_findings) > 100
        ),
        "scope": (
            "HTML responses downloaded by the "
            "verified controlled crawler"
        ),
        "score_eligible": False,
    }