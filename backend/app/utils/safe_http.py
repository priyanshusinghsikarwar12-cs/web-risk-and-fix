from urllib.parse import urljoin

import requests

from app.utils.domain import (
    DomainValidationError,
    validate_public_domain,
)


REDIRECT_STATUS_CODES = {
    301,
    302,
    303,
    307,
    308,
}


class UnsafeTargetError(requests.RequestException):
    pass


def validate_request_url(url: str):
    try:
        validate_public_domain(url)
    except DomainValidationError as error:
        raise UnsafeTargetError(str(error)) from error


def safe_get(
    url: str,
    timeout: int = 10,
    max_redirects: int = 5,
    max_bytes: int = 2_000_000,
    session=None,
):
    http_session = session or requests.Session()
    owns_session = session is None

    current_url = url
    redirect_count = 0

    request_headers = {
        "User-Agent": (
            "WebShield/0.1 website security assessment"
        )
    }

    try:
        while True:
            validate_request_url(current_url)

            response = http_session.get(
                current_url,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
                headers=request_headers,
            )

            if (
                response.status_code in REDIRECT_STATUS_CODES
                and response.headers.get("Location")
            ):
                if redirect_count >= max_redirects:
                    response.close()

                    raise requests.TooManyRedirects(
                        "The website redirected too many times."
                    )

                next_url = urljoin(
                    response.url,
                    response.headers["Location"],
                )

                # Validate before following the redirect.
                validate_request_url(next_url)

                response.close()

                current_url = next_url
                redirect_count += 1
                continue

            content = bytearray()
            content_truncated = False

            for chunk in response.iter_content(
                chunk_size=65_536
            ):
                if not chunk:
                    continue

                remaining = max_bytes - len(content)

                if remaining <= 0:
                    content_truncated = True
                    break

                if len(chunk) > remaining:
                    content.extend(chunk[:remaining])
                    content_truncated = True
                    break

                content.extend(chunk)

            response._content = bytes(content)
            response._content_consumed = True
            response.webshield_content_truncated = (
                content_truncated
            )

            response.close()

            return response

    finally:
        if owns_session:
            http_session.close()