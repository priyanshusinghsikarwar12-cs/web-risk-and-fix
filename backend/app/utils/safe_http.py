from urllib.parse import urljoin, urlsplit
import time
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning

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

ALLOWED_CUSTOM_HEADERS = {
    "accept",
    "origin",
}


class UnsafeTargetError(requests.RequestException):
    pass


def _get_with_tls_warning_control(
    http_session,
    url,
    verify_tls,
    **request_options,
):
    # An unverified request is permitted only when an explicitly authorized
    # caller sets verify_tls=False. The certificate failure remains reportable;
    # this suppresses only urllib3's duplicate terminal warning.
    with warnings.catch_warnings():
        if verify_tls is False:
            warnings.simplefilter(
                "ignore",
                InsecureRequestWarning,
            )

        return http_session.get(
            url,
            verify=verify_tls,
            **request_options,
        )


def _read_limited_response(response, max_bytes):
    content = bytearray()
    content_truncated = False

    for chunk in response.iter_content(chunk_size=65_536):
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
    response.webshield_content_truncated = content_truncated
    response.close()
    return response


def validate_request_url(url: str):
    try:
        validate_public_domain(url)

    except DomainValidationError as error:
        raise UnsafeTargetError(str(error)) from error


def _build_request_headers(
    headers: dict | None,
) -> dict:
    request_headers = {
        "User-Agent": (
            "WebShield/0.1 website security assessment"
        )
    }

    for name, value in (headers or {}).items():
        clean_name = str(name).strip()
        clean_value = str(value).strip()

        if (
            clean_name.lower()
            not in ALLOWED_CUSTOM_HEADERS
        ):
            raise ValueError(
                "Custom header is not allowed: "
                f"{clean_name}"
            )

        if (
            "\r" in clean_name
            or "\n" in clean_name
            or "\r" in clean_value
            or "\n" in clean_value
        ):
            raise ValueError(
                "Custom headers cannot contain newlines."
            )

        request_headers[clean_name] = clean_value

    return request_headers


def safe_get(
    url: str,
    timeout: int = 10,
    max_redirects: int = 5,
    max_bytes: int = 2_000_000,
    session=None,
    headers: dict | None = None,
    allowed_redirect_host: str | None = None,
    redirect_delay_seconds: float = 0,
    verify_tls: bool = True,
):
    http_session = session or requests.Session()
    owns_session = session is None

    current_url = url
    redirect_count = 0

    request_headers = _build_request_headers(
        headers
    )
    if not 0 <= redirect_delay_seconds <= 5:
        raise ValueError(
            "The redirect delay must be between 0 and 5 seconds."
        )

    try:
        while True:
            validate_request_url(current_url)

            response = _get_with_tls_warning_control(
                http_session,
                current_url,
                verify_tls,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
                headers=request_headers,
            )

            if (
                response.status_code
                in REDIRECT_STATUS_CODES
                and response.headers.get("Location")
            ):
                if redirect_count >= max_redirects:
                    response.close()

                    raise requests.TooManyRedirects(
                        "The website redirected too many "
                        "times."
                    )

                next_url = urljoin(
                    response.url,
                    response.headers["Location"],
                )

                if allowed_redirect_host:
                    redirect_hostname = (
                        urlsplit(next_url).hostname or ""
                    ).lower()
                    if redirect_hostname != allowed_redirect_host.lower():
                        response.close()
                        raise UnsafeTargetError(
                            "The response redirected outside the approved hostname."
                        )

                # Prevent redirects to private or unsafe
                # network addresses.
                validate_request_url(next_url)

                response.close()

                if redirect_delay_seconds:
                    time.sleep(redirect_delay_seconds)

                current_url = next_url
                redirect_count += 1
                continue

            response = _read_limited_response(response, max_bytes)
            response.webshield_tls_verified = verify_tls
            return response

    finally:
        if owns_session:
            http_session.close()


def safe_post_json(
    url: str,
    json_body: dict,
    timeout: int = 10,
    max_bytes: int = 1_000_000,
    session=None,
    allowed_host: str | None = None,
):
    """Send one bounded JSON POST without following redirects."""
    validate_request_url(url)
    hostname = (urlsplit(url).hostname or "").lower()
    if allowed_host and hostname != allowed_host.lower():
        raise UnsafeTargetError(
            "The read-only POST endpoint is outside the approved hostname."
        )
    if not isinstance(json_body, dict):
        raise ValueError("The read-only POST body must be a JSON object.")

    http_session = session or requests.Session()
    owns_session = session is None
    try:
        response = http_session.post(
            url,
            json=json_body,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            headers=_build_request_headers({"accept": "application/json"}),
        )
        if response.status_code in REDIRECT_STATUS_CODES:
            response.close()
            raise UnsafeTargetError(
                "The read-only POST endpoint redirected, so WebShield stopped."
            )
        return _read_limited_response(response, max_bytes)
    finally:
        if owns_session:
            http_session.close()


def safe_get_once(
    url: str,
    timeout: int = 10,
    max_bytes: int = 500_000,
    session=None,
    allowed_host: str | None = None,
    verify_tls: bool = True,
):
    """Send one bounded GET and return redirects without following them."""
    validate_request_url(url)
    hostname = (urlsplit(url).hostname or "").lower()
    if allowed_host and hostname != allowed_host.lower():
        raise UnsafeTargetError(
            "The bounded GET target is outside the approved hostname."
        )
    http_session = session or requests.Session()
    owns_session = session is None
    try:
        response = _get_with_tls_warning_control(
            http_session,
            url,
            verify_tls,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            headers=_build_request_headers(None),
        )
        response = _read_limited_response(response, max_bytes)
        response.webshield_tls_verified = verify_tls
        return response
    finally:
        if owns_session:
            http_session.close()
