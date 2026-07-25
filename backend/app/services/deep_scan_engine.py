from datetime import datetime, timezone
from app.deep_scanners.cors import (
    check_cors_configuration,
)
from time import perf_counter, sleep

from app.deep_scanners.crawler import (
    crawl_verified_site,
)
from app.deep_scanners.exposure_checks import (
    check_sensitive_exposures,
)
from app.deep_scanners.js_advisories import (
    check_javascript_advisories,
)
from app.deep_scanners.ports import (
    scan_open_ports,
)
from app.deep_scanners.subdomains import (
    discover_subdomains,
)
from app.deep_scanners.zap_baseline import (
    run_zap_baseline,
)
from app.utils.domain import clean_domain
from app.deep_scanners.http_methods import (
    check_http_method_exposure,
)
from app.deep_scanners.query_security import (
    check_query_input_security,
)
from app.scanners.hosting_context import (
    check_hosting_context,
)
from app.services.vulnerability_report import (
    build_vulnerability_report,
)


def unavailable_result(
    scanner_name: str,
):
    return {
        "name": scanner_name,
        "status": "Unavailable",
        "message": (
            "This scanner could not complete. "
            "The remaining deep scanners continued."
        ),
        "checks": [],
    }


def run_deep_scanner(
    scanner_name: str,
    scanner_function,
    *args,
    fallback=None,
    **kwargs,
):
    safe_fallback = (
        fallback.copy()
        if fallback is not None
        else unavailable_result(scanner_name)
    )

    try:
        result = scanner_function(
            *args,
            **kwargs,
        )

        if not isinstance(result, dict):
            raise TypeError(
                "Scanner results must be dictionaries."
            )

        return result, None

    except Exception as error:
        failure = {
            "scanner": scanner_name,
            "error_type": type(error).__name__,
            "message": (
                f"{scanner_name} could not complete."
            ),
        }

        return safe_fallback, failure


def not_requested_result(scanner_name: str):
    return {
        "name": scanner_name,
        "status": "Not Requested",
        "message": "This scanner was not approved for this engagement.",
        "checks": [],
        "finding_count": 0,
    }


def run_verified_deep_scan(
    domain: str,
    max_pages: int = 25,
    max_depth: int = 2,
    include_zap: bool = False,
    zap_spider_minutes: int = 1,
    zap_maximum_minutes: int = 5,
    scanner_overrides=None,
    approved_scanners=None,
    excluded_finding_types=None,
    request_delay_seconds=None,
    sleep_function=sleep,
    allow_invalid_tls: bool = False,
    baseline_scanner=None,
):
    safe_domain = clean_domain(domain)

    if not 1 <= max_pages <= 50:
        raise ValueError(
            "Deep crawling supports between "
            "1 and 50 pages."
        )

    if not 0 <= max_depth <= 3:
        raise ValueError(
            "Deep crawling supports a maximum "
            "depth between 0 and 3."
        )

    if not 1 <= zap_spider_minutes <= 3:
        raise ValueError(
            "ZAP spider time must be between "
            "1 and 3 minutes."
        )

    if not 2 <= zap_maximum_minutes <= 10:
        raise ValueError(
            "ZAP maximum time must be between "
            "2 and 10 minutes."
        )

    supported_scanners = {
        "crawler",
        "exposure_checks",
        "cors",
        "http_methods",
        "subdomains",
        "ports",
        "javascript_advisories",
        "query_input_security",
        "zap_baseline",
    }
    requested_scanners = (
        set(approved_scanners)
        if approved_scanners is not None
        else supported_scanners - {"query_input_security"}
    )
    if requested_scanners - supported_scanners:
        raise ValueError(
            "The engagement approved an unsupported scanner."
        )
    if request_delay_seconds is not None and not 0.5 <= float(
        request_delay_seconds
    ) <= 5:
        raise ValueError(
            "The enforced request delay must be between 0.5 and 5 seconds."
        )

    enforced_delay = (
        float(request_delay_seconds)
        if request_delay_seconds is not None
        else None
    )

    def scanner_enabled(name):
        return name in requested_scanners

    def pause_between_scanners():
        if enforced_delay:
            sleep_function(enforced_delay)

    scanner_functions = {
        "crawler": crawl_verified_site,
        "exposures": check_sensitive_exposures,
        "cors": check_cors_configuration,
        "http_methods": check_http_method_exposure,
        "subdomains": discover_subdomains,
        "ports": scan_open_ports,
        "hosting_context": check_hosting_context,
        "javascript_advisories": (
            check_javascript_advisories
        ),
        "query_input_security": check_query_input_security,
        "zap": run_zap_baseline,
    }

    if scanner_overrides:
        scanner_functions.update(
            scanner_overrides
        )

    started_at = datetime.now(timezone.utc)
    start_timer = perf_counter()

    failures = []
    baseline_report = None
    if baseline_scanner is not None:
        baseline_report, failure = run_deep_scanner(
            "Passive Security Baseline",
            baseline_scanner,
            safe_domain,
            fallback={
                "domain": safe_domain,
                "scan_status": "Unavailable",
                "overall_status": "Unavailable",
            },
        )
        if failure:
            failures.append(failure)

    def run_approved(permission, scanner_name, function, *args, **kwargs):
        if not scanner_enabled(permission):
            return not_requested_result(scanner_name), None
        result, failure = run_deep_scanner(
            scanner_name, function, *args, **kwargs
        )
        pause_between_scanners()
        return result, failure

    crawler, failure = run_approved(
        "crawler",
        "Verified Application Crawler",
        scanner_functions["crawler"],
        safe_domain,
        max_pages=max_pages,
        max_depth=max_depth,
        delay_seconds=enforced_delay or 0.2,
        allow_invalid_tls=allow_invalid_tls,
    )
    if failure:
        failures.append(failure)

    exposures, failure = run_approved(
        "exposure_checks",
        "Sensitive Exposure Checks",
        scanner_functions["exposures"],
        safe_domain,
        delay_seconds=enforced_delay or 0.15,
        allow_invalid_tls=allow_invalid_tls,
    )
    if failure:
        failures.append(failure)

    cors_options = (
        {"delay_seconds": enforced_delay}
        if enforced_delay
        else {}
    )
    cors_options["allow_invalid_tls"] = allow_invalid_tls
    cors_configuration, failure = run_approved(
        "cors",
        "CORS Configuration",
        scanner_functions["cors"],
        safe_domain,
        **cors_options,
    )
    if failure:
        failures.append(failure)

    http_method_exposure, failure = run_approved(
        "http_methods",
        "HTTP Method Exposure",
        scanner_functions["http_methods"],
        safe_domain,
        allow_invalid_tls=allow_invalid_tls,
    )
    if failure:
        failures.append(failure)

    subdomains, failure = run_approved(
        "subdomains",
        "Subdomain Discovery",
        scanner_functions["subdomains"],
        safe_domain,
    )
    if failure:
        failures.append(failure)

    hosting_context, failure = run_approved(
        "ports",
        "Hosting and Infrastructure Context",
        scanner_functions["hosting_context"],
        safe_domain,
    )
    if failure:
        failures.append(failure)

    ports, failure = run_approved(
        "ports",
        "Open Ports and Services",
        scanner_functions["ports"],
        safe_domain,
        timeout=0.75,
        max_workers=1 if enforced_delay else 20,
        hosting_context=hosting_context,
    )
    if failure:
        failures.append(failure)

    javascript_advisories, failure = run_approved(
        "javascript_advisories",
        "JavaScript Known Vulnerabilities",
        scanner_functions["javascript_advisories"],
        safe_domain,
        same_host_only=bool(enforced_delay),
        allow_invalid_tls=allow_invalid_tls,
    )
    if failure:
        failures.append(failure)

    query_input_security, failure = run_approved(
        "query_input_security",
        "Application Input Security",
        scanner_functions["query_input_security"],
        safe_domain,
        crawler,
        max_requests=6,
        delay_seconds=enforced_delay or 0.5,
        allow_invalid_tls=allow_invalid_tls,
    )
    if failure:
        failures.append(failure)

    if include_zap and scanner_enabled("zap_baseline"):
        zap_baseline, failure = run_approved(
            "zap_baseline",
            "OWASP ZAP Baseline",
            scanner_functions["zap"],
            safe_domain,
            spider_minutes=zap_spider_minutes,
            maximum_minutes=zap_maximum_minutes,
        )
        if failure:
            failures.append(failure)
    else:
        zap_baseline = not_requested_result("OWASP ZAP Baseline")
        zap_baseline["active_attack_payloads"] = False

    finished_at = datetime.now(timezone.utc)
    duration_seconds = round(
        perf_counter() - start_timer,
        3,
    )

    pages_crawled = crawler.get("pages_scanned", 0)
    crawler_requested = scanner_enabled("crawler")
    coverage_incomplete = (
        crawler_requested
        and pages_crawled == 0
    )
    scan_status = (
        "Incomplete"
        if coverage_incomplete
        else "Complete"
        if not failures
        else "Partial"
    )

    coverage = {
        "complete": not coverage_incomplete,
        "crawler_requested": crawler_requested,
        "pages_tested": pages_crawled,
        "tls_verification_bypassed": (
            allow_invalid_tls and pages_crawled > 0
        ),
        "message": (
            "The application crawler inspected no pages. Zero findings "
            "must not be interpreted as a secure result."
            if coverage_incomplete
            else (
                (
                    f"The application crawler inspected {pages_crawled} "
                    "page(s) after owner-authorized certificate bypass. "
                    "The certificate problem remains a security finding."
                )
                if allow_invalid_tls and pages_crawled > 0
                else f"The application crawler inspected {pages_crawled} page(s)."
                if crawler_requested
                else "The application crawler was not requested."
            )
        ),
    }

    vulnerability_report = build_vulnerability_report(
        crawler,
        exposures,
        cors_configuration,
        http_method_exposure,
        javascript_advisories,
        zap_baseline,
        input_security=query_input_security,
        excluded_finding_types=excluded_finding_types,
        coverage=coverage,
        baseline=baseline_report,
    )

    finding_summary = {
        "vulnerabilities": vulnerability_report[
            "summary"
        ]["total"],
        "critical": vulnerability_report["summary"][
            "critical"
        ],
        "high": vulnerability_report["summary"]["high"],
        "medium": vulnerability_report["summary"]["medium"],
        "low": vulnerability_report["summary"]["low"],
        "pages_crawled": pages_crawled,
        "sensitive_exposures": exposures.get(
            "finding_count",
            0,
        ),
        "cors_findings": cors_configuration.get(
            "finding_count",
            0,
        ),
        "http_method_findings": (
            http_method_exposure.get(
                "finding_count",
                0,
            )
        ),
        "subdomains_discovered": subdomains.get(
            "discovered_count",
            0,
        ),
        "open_ports": ports.get(
            "open_port_count",
            0,
        ),
        "javascript_advisories": (
            javascript_advisories.get(
                "vulnerability_match_count",
                0,
            )
        ),
        "zap_findings": zap_baseline.get(
            "finding_count",
            0,
        ),
        "query_input_findings": query_input_security.get(
            "finding_count",
            0,
        ),
    }    

    return {
        "name": "WebShield Verified Deep Scan",
        "domain": safe_domain,
        "scan_status": scan_status,
        "message": (
            "All requested deep scanners completed."
            if scan_status == "Complete"
            else (
                "The assessment is incomplete because no application "
                "page could be inspected. Review the connection or "
                "certificate problem before interpreting the findings."
                if scan_status == "Incomplete"
                else (
                    "Some deep scanners could not finish, "
                    "but WebShield preserved the remaining "
                    "results."
                )
            )
        ),
        "authorization_required": True,
        "approved_scanners": sorted(requested_scanners),
        "request_delay_seconds": enforced_delay,
        "max_concurrency": 1 if enforced_delay else None,
        "zap_requested": include_zap,
        "finding_summary": finding_summary,
        "coverage": coverage,
        "passive_baseline": baseline_report,
        "vulnerability_report": vulnerability_report,
        "crawler": crawler,
        "sensitive_exposures": exposures,
        "cors_configuration": cors_configuration,
        "http_method_exposure": http_method_exposure,
        "subdomains": subdomains,
        "hosting_context": hosting_context,
        "open_ports": ports,
        "javascript_advisories": (
            javascript_advisories
        ),
        "query_input_security": query_input_security,
        "zap_baseline": zap_baseline,
        "scan_failures": failures,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": duration_seconds,
    }
