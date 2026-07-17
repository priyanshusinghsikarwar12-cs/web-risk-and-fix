from http.cookies import CookieError, SimpleCookie

import requests

from app.utils.safe_http import safe_get


def get_set_cookie_headers(response):
    raw_response = getattr(response, "raw", None)
    raw_headers = getattr(raw_response, "headers", None)

    if raw_headers is not None:
        if hasattr(raw_headers, "getlist"):
            values = raw_headers.getlist("Set-Cookie")

            if values:
                return list(values)

        if hasattr(raw_headers, "get_all"):
            values = raw_headers.get_all("Set-Cookie")

            if values:
                return list(values)

    combined_value = response.headers.get("Set-Cookie")

    if combined_value:
        return [combined_value]

    return []


def analyze_cookie(cookie_name, morsel):
    secure = bool(morsel["secure"])
    http_only = bool(morsel["httponly"])

    raw_same_site = str(
        morsel["samesite"] or ""
    ).strip()

    same_site = (
        raw_same_site.capitalize()
        if raw_same_site
        else None
    )

    domain_attribute = str(
        morsel["domain"] or ""
    ).strip()

    path_attribute = str(
        morsel["path"] or ""
    ).strip()

    warnings = []
    serious_problem = False

    if not secure:
        warnings.append(
            "The cookie can be sent without requiring HTTPS."
        )
        serious_problem = True

    if not http_only:
        warnings.append(
            "The cookie is accessible to JavaScript. "
            "Confirm that this is necessary."
        )

    if same_site is None:
        warnings.append(
            "The cookie does not explicitly declare a "
            "SameSite policy."
        )

    elif same_site.lower() not in {
        "strict",
        "lax",
        "none",
    }:
        warnings.append(
            "The cookie contains an unrecognized SameSite value."
        )
        serious_problem = True

    elif same_site.lower() == "none":
        if not secure:
            warnings.append(
                "SameSite=None requires the Secure attribute."
            )
            serious_problem = True
        else:
            warnings.append(
                "The cookie allows cross-site use. "
                "Confirm that this is intentional."
            )

    if cookie_name.startswith("__Secure-") and not secure:
        warnings.append(
            "Cookies beginning with __Secure- must use Secure."
        )
        serious_problem = True

    if cookie_name.startswith("__Host-"):
        if not secure:
            warnings.append(
                "Cookies beginning with __Host- must use Secure."
            )
            serious_problem = True

        if domain_attribute:
            warnings.append(
                "Cookies beginning with __Host- must not "
                "declare a Domain attribute."
            )
            serious_problem = True

        if path_attribute != "/":
            warnings.append(
                "Cookies beginning with __Host- must use Path=/."
            )
            serious_problem = True

    if serious_problem:
        status = "Needs Attention"
        message = (
            "This cookie has a security configuration problem."
        )

    elif warnings:
        status = "Review"
        message = (
            "This cookie may be valid, but its security "
            "settings should be reviewed."
        )

    else:
        status = "Protected"
        message = (
            "This cookie uses the expected security attributes."
        )

    return {
        "name": cookie_name,
        "status": status,
        "message": message,
        "flags": {
            "secure": secure,
            "http_only": http_only,
            "same_site": same_site,
        },
        "warnings": warnings,
    }


def analyze_set_cookie_headers(header_values):
    checks = []

    for header_value in header_values:
        parsed_cookies = SimpleCookie()

        try:
            parsed_cookies.load(header_value)
        except CookieError:
            parsed_cookies = SimpleCookie()

        if not parsed_cookies:
            checks.append({
                "name": "Unparsed cookie",
                "status": "Review",
                "message": (
                    "WebShield observed a cookie header but "
                    "could not safely interpret it."
                ),
                "flags": {
                    "secure": None,
                    "http_only": None,
                    "same_site": None,
                },
                "warnings": [
                    "Review the original Set-Cookie header manually."
                ],
            })

            continue

        for cookie_name, morsel in parsed_cookies.items():
            checks.append(
                analyze_cookie(
                    cookie_name,
                    morsel,
                )
            )

    return checks


def check_cookie_security(domain: str, response=None):
    url = f"https://{domain}"

    try:
        if response is None:
            response = safe_get(
                url,
            timeout=10,
        )

        header_values = get_set_cookie_headers(response)
        checks = analyze_set_cookie_headers(header_values)

        if not header_values:
            return {
                "name": "Cookie Security",
                "status": "Not Observed",
                "message": (
                    "The website homepage did not set cookies "
                    "in its initial HTTP response. Other pages "
                    "or JavaScript may still create cookies."
                ),
                "url": response.url,
                "checks": [],
            }

        if any(
            check["status"] == "Needs Attention"
            for check in checks
        ):
            status = "Needs Attention"

        elif any(
            check["status"] == "Review"
            for check in checks
        ):
            status = "Review"

        else:
            status = "Protected"

        return {
            "name": "Cookie Security",
            "status": status,
            "message": (
                f"WebShield inspected {len(checks)} cookie "
                "configuration(s) from the initial response."
            ),
            "url": response.url,
            "checks": checks,
        }

    except requests.RequestException as error:
        return {
            "name": "Cookie Security",
            "status": "Unavailable",
            "message": (
                "The cookie security check could not be completed."
            ),
            "url": url,
            "checks": [],
            "error": str(error),
        }