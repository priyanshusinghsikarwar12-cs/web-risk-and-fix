from datetime import datetime, timezone
from urllib.parse import quote, urljoin

import requests

from app.utils.domain import clean_domain
from app.utils.safe_http import safe_get


IANA_RDAP_BOOTSTRAP_URL = (
    "https://data.iana.org/rdap/dns.json"
)


def parse_rdap_date(value):
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed_date = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )
    except ValueError:
        return None

    if parsed_date.tzinfo is None:
        parsed_date = parsed_date.replace(
            tzinfo=timezone.utc
        )

    return parsed_date.astimezone(timezone.utc)


def find_event_date(rdap_data, event_action):
    events = rdap_data.get("events", [])

    for event in events:
        action = str(
            event.get("eventAction", "")
        ).strip().lower()

        if action != event_action.lower():
            continue

        parsed_date = parse_rdap_date(
            event.get("eventDate")
        )

        if parsed_date is not None:
            return parsed_date

    return None


def find_rdap_server(domain, bootstrap_data):
    top_level_domain = domain.rsplit(".", 1)[-1].lower()

    services = bootstrap_data.get("services", [])

    for service in services:
        if (
            not isinstance(service, list)
            or len(service) != 2
        ):
            continue

        supported_domains = service[0]
        server_urls = service[1]

        normalized_domains = {
            str(item).lower()
            for item in supported_domains
        }

        if (
            top_level_domain in normalized_domains
            and server_urls
        ):
            return str(server_urls[0])

    return None


def build_rdap_domain_url(base_url, domain):
    normalized_base_url = base_url.rstrip("/") + "/"

    return urljoin(
        normalized_base_url,
        f"domain/{quote(domain, safe='')}",
    )


def analyze_rdap_domain(rdap_data, now=None):
    if now is None:
        now = datetime.now(timezone.utc)

    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    now = now.astimezone(timezone.utc)

    domain = (
        rdap_data.get("unicodeName")
        or rdap_data.get("ldhName")
        or "Unknown domain"
    )

    registration_date = find_event_date(
        rdap_data,
        "registration",
    )

    expiration_date = find_event_date(
        rdap_data,
        "expiration",
    )

    last_changed_date = find_event_date(
        rdap_data,
        "last changed",
    )

    result = {
        "name": "Domain Registration",
        "domain": domain,
        "source": "RDAP registry data",
        "confidence": "High",
        "registration_date": (
            registration_date.isoformat()
            if registration_date
            else None
        ),
        "expiration_date": (
            expiration_date.isoformat()
            if expiration_date
            else None
        ),
        "last_changed_date": (
            last_changed_date.isoformat()
            if last_changed_date
            else None
        ),
        "days_left": None,
    }

    if expiration_date is None:
        result.update({
            "status": "Unknown",
            "message": (
                "The domain registry did not publish an "
                "expiration date through RDAP."
            ),
            "confidence": "Limited",
        })

        return result

    days_left = (
        expiration_date.date() - now.date()
    ).days

    result["days_left"] = days_left

    if days_left < 0:
        result.update({
            "status": "Expired",
            "message": (
                "The published domain expiration date "
                "has already passed."
            ),
        })

    elif days_left <= 30:
        result.update({
            "status": "Needs Attention",
            "message": (
                f"The domain is expected to expire in "
                f"{days_left} days."
            ),
        })

    elif days_left <= 90:
        result.update({
            "status": "Review",
            "message": (
                f"The domain is expected to expire in "
                f"{days_left} days. Confirm that automatic "
                f"renewal is enabled."
            ),
        })

    else:
        result.update({
            "status": "Healthy",
            "message": (
                f"The domain registration is expected to "
                f"remain active for {days_left} more days."
            ),
        })

    return result


def unavailable_result(domain, message):
    return {
        "name": "Domain Registration",
        "domain": domain,
        "status": "Unavailable",
        "message": message,
        "source": "RDAP registry data",
        "confidence": "Unavailable",
        "registration_date": None,
        "expiration_date": None,
        "last_changed_date": None,
        "days_left": None,
    }


def check_domain_registration(domain):
    clean_name = clean_domain(domain)

    try:
        bootstrap_response = safe_get(
            IANA_RDAP_BOOTSTRAP_URL,
            timeout=10,
        )

        bootstrap_response.raise_for_status()

        if getattr(
            bootstrap_response,
            "webshield_content_truncated",
            False,
        ):
            return unavailable_result(
                clean_name,
                "The IANA RDAP directory response was too large.",
            )

        bootstrap_data = bootstrap_response.json()

        rdap_server = find_rdap_server(
            clean_name,
            bootstrap_data,
        )

        if rdap_server is None:
            return unavailable_result(
                clean_name,
                (
                    "No official RDAP server was listed for "
                    "this domain extension."
                ),
            )

        rdap_url = build_rdap_domain_url(
            rdap_server,
            clean_name,
        )

        rdap_response = safe_get(
            rdap_url,
            timeout=12,
        )

        if rdap_response.status_code == 404:
            return unavailable_result(
                clean_name,
                (
                    "The registry did not return an RDAP "
                    "record for this domain."
                ),
            )

        rdap_response.raise_for_status()

        if getattr(
            rdap_response,
            "webshield_content_truncated",
            False,
        ):
            return unavailable_result(
                clean_name,
                "The RDAP registry response was too large.",
            )

        rdap_data = rdap_response.json()

        if rdap_data.get("objectClassName") != "domain":
            return unavailable_result(
                clean_name,
                (
                    "The registry returned an unexpected "
                    "RDAP response."
                ),
            )

        result = analyze_rdap_domain(rdap_data)
        result["rdap_server"] = rdap_server

        return result

    except (
        requests.RequestException,
        ValueError,
    ):
        return unavailable_result(
            clean_name,
            (
                "The domain registration check could not "
                "be completed."
            ),
        )