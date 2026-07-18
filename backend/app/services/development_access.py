import hmac
import os

from app.utils.domain import (
    DomainValidationError,
    clean_domain,
)


LOOPBACK_HOSTS = {
    "127.0.0.1",
    "::1",
    "localhost",
    "testclient",
}


class DevelopmentAccessError(ValueError):
    pass


def read_allowed_domains(value: str):
    allowed_domains = set()

    for item in value.split(","):
        candidate = item.strip()

        if not candidate:
            continue

        try:
            allowed_domains.add(
                clean_domain(candidate)
            )
        except DomainValidationError as error:
            raise DevelopmentAccessError(
                "The development domain allowlist "
                "contains an invalid domain."
            ) from error

    return allowed_domains


def validate_development_admin_access(
    domain: str,
    supplied_token: str | None,
    client_host: str | None,
    environment=None,
):
    active_environment = (
        environment
        if environment is not None
        else os.environ
    )

    if (
        active_environment.get(
            "WEBSHIELD_ENV",
            "",
        ).strip().lower()
        != "development"
    ):
        raise DevelopmentAccessError(
            "Development admin access is disabled."
        )

    if client_host not in LOOPBACK_HOSTS:
        raise DevelopmentAccessError(
            "Development admin access is available "
            "only from the local computer."
        )

    expected_token = active_environment.get(
        "WEBSHIELD_DEV_ADMIN_TOKEN",
        "",
    )

    if len(expected_token) < 32:
        raise DevelopmentAccessError(
            "The development admin token is not "
            "configured securely."
        )

    if (
        not supplied_token
        or not hmac.compare_digest(
            supplied_token,
            expected_token,
        )
    ):
        raise DevelopmentAccessError(
            "The development admin token is invalid."
        )

    safe_domain = clean_domain(domain)

    allowed_domains = read_allowed_domains(
        active_environment.get(
            "WEBSHIELD_DEV_SCAN_ALLOWLIST",
            "",
        )
    )

    if safe_domain not in allowed_domains:
        raise DevelopmentAccessError(
            "This domain is not included in the "
            "development scan allowlist."
        )

    return {
        "authorized": True,
        "domain": safe_domain,
        "scope": [safe_domain],
        "method": "Development Admin",
        "development_bypass": True,
    }