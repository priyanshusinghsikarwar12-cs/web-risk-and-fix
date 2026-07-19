from datetime import datetime, timezone
from app.deep_scanners.cors import (
    check_cors_configuration,
)
from time import perf_counter

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


def run_verified_deep_scan(
    domain: str,
    max_pages: int = 25,
    max_depth: int = 2,
    include_zap: bool = False,
    zap_spider_minutes: int = 1,
    zap_maximum_minutes: int = 5,
    scanner_overrides=None,
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
        "zap": run_zap_baseline,
    }

    if scanner_overrides:
        scanner_functions.update(
            scanner_overrides
        )

    started_at = datetime.now(timezone.utc)
    start_timer = perf_counter()

    failures = []

    crawler, failure = run_deep_scanner(
        "Verified Application Crawler",
        scanner_functions["crawler"],
        safe_domain,
        max_pages=max_pages,
        max_depth=max_depth,
        delay_seconds=0.2,
    )

    if failure:
        failures.append(failure)

    exposures, failure = run_deep_scanner(
        "Sensitive Exposure Checks",
        scanner_functions["exposures"],
        safe_domain,
        delay_seconds=0.15,
    )

    if failure:
        failures.append(failure)
    cors_configuration, failure = run_deep_scanner(
        "CORS Configuration",
        scanner_functions["cors"],
        safe_domain,
    )       
    if failure:
        failures.append(failure)

    http_method_exposure, failure = (
        run_deep_scanner(
            "HTTP Method Exposure",
            scanner_functions["http_methods"],
            safe_domain,
        )
    )

    if failure:
        failures.append(failure)            

    subdomains, failure = run_deep_scanner(
        "Subdomain Discovery",
        scanner_functions["subdomains"],
        safe_domain,
    )

    if failure:
        failures.append(failure)

    hosting_context, failure = run_deep_scanner(
        "Hosting and Infrastructure Context",
        scanner_functions["hosting_context"],
        safe_domain,
        fallback={
            "name": "Hosting and Infrastructure Context",
            "domain": safe_domain,
            "status": "Unavailable",
            "message": (
                "Hosting context could not be refreshed for "
                "this deep scan."
            ),
            "provider": {
                "name": None,
                "category": "Not identified",
                "confidence": "None",
                "evidence": [],
            },
            "addresses": [],
            "address_count": 0,
            "shared_infrastructure": {
                "status": "Not Determined",
                "message": (
                    "Infrastructure sharing was not determined."
                ),
                "confidence": "None",
            },
            "score_eligible": False,
        },
    )

    if failure:
        failures.append(failure)

    ports, failure = run_deep_scanner(
        "Open Ports and Services",
        scanner_functions["ports"],
        safe_domain,
        timeout=0.75,
        max_workers=20,
        hosting_context=hosting_context,
    )

    if failure:
        failures.append(failure)

    javascript_advisories, failure = (
        run_deep_scanner(
            "JavaScript Known Vulnerabilities",
            scanner_functions[
                "javascript_advisories"
            ],
            safe_domain,
        )
    )

    if failure:
        failures.append(failure)

    if include_zap:
        zap_baseline, failure = run_deep_scanner(
            "OWASP ZAP Baseline",
            scanner_functions["zap"],
            safe_domain,
            spider_minutes=zap_spider_minutes,
            maximum_minutes=zap_maximum_minutes,
        )

        if failure:
            failures.append(failure)

    else:
        zap_baseline = {
            "name": "OWASP ZAP Baseline",
            "domain": safe_domain,
            "status": "Not Requested",
            "message": (
                "The optional ZAP passive scan "
                "was not requested."
            ),
            "checks": [],
            "finding_count": 0,
            "active_attack_payloads": False,
        }

    finished_at = datetime.now(timezone.utc)
    duration_seconds = round(
        perf_counter() - start_timer,
        3,
    )

    scan_status = (
        "Complete"
        if not failures
        else "Partial"
    )

    vulnerability_report = build_vulnerability_report(
        crawler,
        exposures,
        cors_configuration,
        http_method_exposure,
        javascript_advisories,
        zap_baseline,
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
        "pages_crawled": crawler.get(
            "pages_scanned",
            0,
        ),
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
    }    

    return {
        "name": "WebShield Verified Deep Scan",
        "domain": safe_domain,
        "scan_status": scan_status,
        "message": (
            "All requested deep scanners completed."
            if scan_status == "Complete"
            else (
                "Some deep scanners could not finish, "
                "but WebShield preserved the remaining "
                "results."
            )
        ),
        "authorization_required": True,
        "zap_requested": include_zap,
        "finding_summary": finding_summary,
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
        "zap_baseline": zap_baseline,
        "scan_failures": failures,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": duration_seconds,
    }
