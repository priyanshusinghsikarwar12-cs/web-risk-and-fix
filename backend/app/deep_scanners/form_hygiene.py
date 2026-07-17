from urllib.parse import urlsplit


CSRF_FIELD_TERMS = {
    "__requestverificationtoken",
    "_csrf",
    "authenticity_token",
    "csrf",
    "csrf_token",
    "csrftoken",
    "xsrf",
    "xsrf_token",
}

PASSWORD_AUTOCOMPLETE_VALUES = {
    "current-password",
    "new-password",
}


def _has_csrf_field(form: dict) -> bool:
    for field in form.get("fields", []):
        field_name = str(
            field.get("name", "")
        ).strip().lower()

        if field_name in CSRF_FIELD_TERMS:
            return True

        if any(
            term in field_name
            for term in {
                "csrf",
                "xsrf",
                "authenticity",
                "requestverificationtoken",
            }
        ):
            return True

    return False


def _password_fields(form: dict) -> list:
    return [
        field
        for field in form.get("fields", [])
        if str(
            field.get("type", "")
        ).lower() == "password"
    ]


def analyze_form_hygiene(forms: list) -> dict:
    if not forms:
        return {
            "name": "Form and Login Hygiene",
            "status": "Not Applicable",
            "message": (
                "The controlled crawler did not observe "
                "any HTML forms."
            ),
            "checks": [],
            "form_count": 0,
            "password_form_count": 0,
            "csrf_signal_count": 0,
            "score_eligible": False,
        }

    findings = []
    password_form_count = 0
    csrf_signal_count = 0

    for index, form in enumerate(forms, start=1):
        method = str(
            form.get("method", "GET")
        ).upper()

        page_url = form.get("page_url")
        action_url = (
            form.get("action_url")
            or page_url
            or ""
        )

        action_scheme = urlsplit(
            action_url
        ).scheme.lower()

        internal_action = form.get(
            "internal_action",
            True,
        )

        password_fields = _password_fields(form)
        has_password = bool(password_fields)
        has_csrf_signal = _has_csrf_field(form)

        if has_password:
            password_form_count += 1

        if has_csrf_signal:
            csrf_signal_count += 1

        if action_scheme == "http":
            findings.append({
                "name": "Insecure Form Destination",
                "status": "Needs Attention",
                "message": (
                    "This form may send information through "
                    "an unencrypted HTTP connection."
                ),
                "form_number": index,
                "page_url": page_url,
                "action_url": action_url,
            })

        if has_password and method == "GET":
            findings.append({
                "name": "Password Form Uses GET",
                "status": "Needs Attention",
                "message": (
                    "This password form uses GET. Entered "
                    "values could appear in URLs, browser "
                    "history, logs, or analytics."
                ),
                "form_number": index,
                "page_url": page_url,
                "action_url": action_url,
            })

        if has_password and not internal_action:
            findings.append({
                "name": "External Password Destination",
                "status": "Needs Attention",
                "message": (
                    "This password form appears to submit "
                    "information to a different hostname."
                ),
                "form_number": index,
                "page_url": page_url,
                "action_url": action_url,
            })

        if method == "POST" and not has_csrf_signal:
            findings.append({
                "name": "CSRF Protection Needs Review",
                "status": "Review",
                "message": (
                    "No CSRF token field was visible in this "
                    "POST form. The application may still "
                    "protect requests through headers, "
                    "cookies, or JavaScript."
                ),
                "form_number": index,
                "page_url": page_url,
                "action_url": action_url,
            })

        for password_field in password_fields:
            autocomplete = str(
                password_field.get(
                    "autocomplete",
                    "",
                )
            ).strip().lower()

            if autocomplete not in (
                PASSWORD_AUTOCOMPLETE_VALUES
            ):
                findings.append({
                    "name": (
                        "Password Autocomplete Purpose "
                        "Needs Review"
                    ),
                    "status": "Review",
                    "message": (
                        "The password field does not clearly "
                        "declare whether it expects a current "
                        "or new password."
                    ),
                    "form_number": index,
                    "page_url": page_url,
                    "action_url": action_url,
                })

    if any(
        finding["status"] == "Needs Attention"
        for finding in findings
    ):
        status = "Needs Attention"
        message = (
            "WebShield observed a form configuration that "
            "could expose submitted information."
        )

    elif findings:
        status = "Review"
        message = (
            "WebShield found form protections that require "
            "manual confirmation."
        )

    else:
        status = "Protected"
        message = (
            "No obvious form transport or login hygiene "
            "problem was observed in the crawled HTML."
        )

    return {
        "name": "Form and Login Hygiene",
        "status": status,
        "message": message,
        "checks": findings,
        "form_count": len(forms),
        "password_form_count": password_form_count,
        "csrf_signal_count": csrf_signal_count,
        "score_eligible": False,
        "scope": (
            "HTML forms discovered by the verified crawler"
        ),
    }