from urllib.parse import urlparse


def clean_domain(domain: str) -> str:
    value = domain.strip()

    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"

    parsed = urlparse(value)

    return parsed.netloc.lower()