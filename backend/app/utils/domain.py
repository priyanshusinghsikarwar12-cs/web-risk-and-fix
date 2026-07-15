import ipaddress
import re
import socket
from urllib.parse import urlparse


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9]"
    r"(?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$",
    re.IGNORECASE,
)


class DomainValidationError(ValueError):
    pass


def clean_domain(value: str) -> str:
    value = value.strip()

    if not value:
        raise DomainValidationError(
            "Enter a website domain."
        )

    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"

    parsed = urlparse(value)

    if parsed.scheme not in {"http", "https"}:
        raise DomainValidationError(
            "Only HTTP and HTTPS website addresses are supported."
        )

    if parsed.username or parsed.password:
        raise DomainValidationError(
            "Website addresses containing credentials are not allowed."
        )

    try:
        port = parsed.port
    except ValueError as error:
        raise DomainValidationError(
            "The website address contains an invalid port."
        ) from error

    if port not in {None, 80, 443}:
        raise DomainValidationError(
            "Only standard website ports are allowed."
        )

    hostname = parsed.hostname

    if not hostname:
        raise DomainValidationError(
            "The website domain is invalid."
        )

    try:
        hostname = (
            hostname
            .encode("idna")
            .decode("ascii")
            .rstrip(".")
            .lower()
        )
    except UnicodeError as error:
        raise DomainValidationError(
            "The website domain contains invalid characters."
        ) from error

    if (
        hostname == "localhost"
        or hostname.endswith(".localhost")
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
    ):
        raise DomainValidationError(
            "Local or internal websites cannot be scanned."
        )

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise DomainValidationError(
            "Enter a public domain name instead of an IP address."
        )

    if not DOMAIN_PATTERN.fullmatch(hostname):
        raise DomainValidationError(
            "Enter a valid public website domain."
        )

    return hostname


def ensure_public_addresses(addresses):
    if not addresses:
        raise DomainValidationError(
            "The website domain did not resolve to an address."
        )

    for address in addresses:
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError as error:
            raise DomainValidationError(
                "The website resolved to an invalid address."
            ) from error

        if not parsed_address.is_global:
            raise DomainValidationError(
                "The website resolves to a private or unsafe address."
            )


def validate_public_domain(value: str) -> str:
    domain = clean_domain(value)

    try:
        address_info = socket.getaddrinfo(
            domain,
            443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as error:
        raise DomainValidationError(
            "The website domain could not be found."
        ) from error

    addresses = {
        item[4][0]
        for item in address_info
    }

    ensure_public_addresses(addresses)

    return domain