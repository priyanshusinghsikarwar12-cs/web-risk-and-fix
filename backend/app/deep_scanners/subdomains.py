import json
import secrets
from urllib.parse import quote

import dns.exception
import dns.resolver
import requests

from app.utils.domain import (
    DomainValidationError,
    clean_domain,
)
from app.utils.safe_http import safe_get


MAX_CT_RESULTS = 200
DNS_RECORD_TYPES = (
    "A",
    "AAAA",
    "CNAME",
)


def extract_certificate_names(
    records: list,
    parent_domain: str,
) -> list:
    safe_parent = clean_domain(parent_domain)
    discovered_names = set()

    for record in records:
        values = []

        for field_name in (
            "name_value",
            "common_name",
        ):
            value = record.get(field_name)

            if value:
                values.extend(
                    str(value).splitlines()
                )

        for value in values:
            candidate = (
                value.strip()
                .lower()
                .rstrip(".")
            )

            if candidate.startswith("*."):
                candidate = candidate[2:]

            try:
                safe_candidate = clean_domain(
                    candidate
                )
            except DomainValidationError:
                continue

            if (
                safe_candidate != safe_parent
                and safe_candidate.endswith(
                    f".{safe_parent}"
                )
            ):
                discovered_names.add(
                    safe_candidate
                )

    return sorted(discovered_names)


def resolve_dns_records(
    hostname: str,
    resolver,
) -> dict:
    records = {}

    for record_type in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(
                hostname,
                record_type,
            )

            values = sorted({
                answer.to_text()
                .strip('"')
                .rstrip(".")
                for answer in answers
            })

            if values:
                records[record_type] = values

        except dns.exception.DNSException:
            continue

    return records


def _flatten_records(records: dict) -> set:
    return {
        f"{record_type}:{value}"
        for record_type, values in records.items()
        for value in values
    }


def discover_subdomains(
    domain: str,
    resolver=None,
):
    safe_domain = clean_domain(domain)

    active_resolver = resolver

    if active_resolver is None:
        active_resolver = dns.resolver.Resolver()
        active_resolver.timeout = 3
        active_resolver.lifetime = 5

    wildcard_name = (
        f"webshield-{secrets.token_hex(10)}."
        f"{safe_domain}"
    )

    wildcard_records = resolve_dns_records(
        wildcard_name,
        active_resolver,
    )

    encoded_query = quote(
        f"%.{safe_domain}",
        safe="",
    )

    source_url = (
        f"https://crt.sh/?q={encoded_query}"
        f"&output=json"
    )

    try:
        response = safe_get(
            source_url,
            timeout=20,
            max_bytes=3_000_000,
        )

    except requests.RequestException as error:
        return {
            "name": "Subdomain Discovery",
            "domain": safe_domain,
            "status": "Unavailable",
            "message": (
                "Certificate Transparency records "
                "could not be downloaded."
            ),
            "checks": [],
            "discovered_count": 0,
            "dns_confirmed_count": 0,
            "wildcard_dns": bool(
                wildcard_records
            ),
            "source": "Certificate Transparency",
            "source_url": source_url,
            "error_type": type(error).__name__,
            "score_eligible": False,
        }

    if response.status_code != 200:
        return {
            "name": "Subdomain Discovery",
            "domain": safe_domain,
            "status": "Unavailable",
            "message": (
                "The Certificate Transparency provider "
                "did not return a successful response."
            ),
            "checks": [],
            "discovered_count": 0,
            "dns_confirmed_count": 0,
            "wildcard_dns": bool(
                wildcard_records
            ),
            "source": "Certificate Transparency",
            "source_url": source_url,
            "provider_status_code": (
                response.status_code
            ),
            "score_eligible": False,
        }

    try:
        certificate_records = json.loads(
            response.content.decode(
                "utf-8",
                errors="strict",
            )
        )

        if not isinstance(
            certificate_records,
            list,
        ):
            raise ValueError(
                "Expected a list of records."
            )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        return {
            "name": "Subdomain Discovery",
            "domain": safe_domain,
            "status": "Unavailable",
            "message": (
                "The Certificate Transparency response "
                "could not be safely interpreted."
            ),
            "checks": [],
            "discovered_count": 0,
            "dns_confirmed_count": 0,
            "wildcard_dns": bool(
                wildcard_records
            ),
            "source": "Certificate Transparency",
            "source_url": source_url,
            "error_type": type(error).__name__,
            "score_eligible": False,
        }

    discovered_names = extract_certificate_names(
        certificate_records,
        safe_domain,
    )

    results_limited = (
        len(discovered_names) > MAX_CT_RESULTS
    )

    inspected_names = discovered_names[
        :MAX_CT_RESULTS
    ]

    wildcard_values = _flatten_records(
        wildcard_records
    )

    checks = []
    confirmed_count = 0

    for hostname in inspected_names:
        dns_records = resolve_dns_records(
            hostname,
            active_resolver,
        )

        confirmed = bool(dns_records)
        wildcard_match = (
            bool(wildcard_values)
            and _flatten_records(dns_records)
            == wildcard_values
        )

        if confirmed:
            confirmed_count += 1

        checks.append({
            "name": hostname,
            "hostname": hostname,
            "status": (
                "DNS Confirmed"
                if confirmed
                else "Certificate Observed"
            ),
            "confidence": (
                "High"
                if confirmed and not wildcard_match
                else "Review"
                if wildcard_match
                else "Medium"
            ),
            "dns_records": dns_records,
            "wildcard_match": wildcard_match,
            "message": (
                "This subdomain currently resolves "
                "through DNS."
                if confirmed and not wildcard_match
                else
                "This name resolves like the random "
                "wildcard DNS test and needs review."
                if wildcard_match
                else
                "This name appeared in certificate "
                "records but did not currently resolve."
            ),
        })

    provider_truncated = getattr(
        response,
        "webshield_content_truncated",
        False,
    )

    if checks:
        status = (
            "Partial"
            if provider_truncated
            or results_limited
            else "Completed"
        )

        message = (
            f"WebShield found {len(discovered_names)} "
            "unique subdomain name(s) in certificate "
            f"records and confirmed {confirmed_count} "
            "through DNS."
        )
    else:
        status = (
            "Partial"
            if provider_truncated
            else "No Results"
        )

        message = (
            "No subdomain names were found in the "
            "available Certificate Transparency response."
        )

    return {
        "name": "Subdomain Discovery",
        "domain": safe_domain,
        "status": status,
        "message": message,
        "checks": checks,
        "discovered_count": len(
            discovered_names
        ),
        "inspected_count": len(
            inspected_names
        ),
        "dns_confirmed_count": confirmed_count,
        "wildcard_dns": bool(wildcard_records),
        "wildcard_test_name": wildcard_name,
        "results_limited": results_limited,
        "provider_response_truncated": (
            provider_truncated
        ),
        "source": "Certificate Transparency",
        "source_url": source_url,
        "scope": (
            "Certificate records and DNS confirmation "
            "for names below the verified parent domain"
        ),
        "score_eligible": False,
        "safety": {
            "brute_force_used": False,
            "subdomain_websites_requested": False,
            "dns_record_types": list(
                DNS_RECORD_TYPES
            ),
        },
    }