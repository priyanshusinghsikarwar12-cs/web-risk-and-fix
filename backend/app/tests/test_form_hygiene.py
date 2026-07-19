from app.deep_scanners.form_hygiene import (
    analyze_form_hygiene,
)


def make_form(
    method="POST",
    action_url="https://example.com/login",
    internal_action=True,
    fields=None,
):
    return {
        "method": method,
        "page_url": "https://example.com/login",
        "action_url": action_url,
        "internal_action": internal_action,
        "fields": fields or [],
        "has_password_field": any(
            field.get("type") == "password"
            for field in (fields or [])
        ),
    }


def test_no_forms_are_not_applicable():
    result = analyze_form_hygiene([])

    assert result["status"] == "Not Applicable"


def test_password_get_form_needs_attention():
    form = make_form(
        method="GET",
        fields=[
            {
                "name": "password",
                "type": "password",
                "autocomplete": "current-password",
            },
        ],
    )

    result = analyze_form_hygiene([form])

    assert result["status"] == "Needs Attention"
    assert any(
        check["name"] == "Password Form Uses GET"
        for check in result["checks"]
    )


def test_http_destination_needs_attention():
    form = make_form(
        action_url="http://example.com/login",
    )

    result = analyze_form_hygiene([form])

    assert result["status"] == "Needs Attention"


def test_external_password_destination_is_found():
    form = make_form(
        action_url="https://external.example.org/login",
        internal_action=False,
        fields=[
            {
                "name": "password",
                "type": "password",
                "autocomplete": "current-password",
            },
        ],
    )

    result = analyze_form_hygiene([form])

    assert any(
        check["name"] == (
            "External Password Destination"
        )
        for check in result["checks"]
    )


def test_missing_csrf_signal_requires_review():
    form = make_form(method="POST")

    result = analyze_form_hygiene([form])

    assert result["status"] == "Review"
    assert any(
        "CSRF" in check["name"]
        for check in result["checks"]
    )
    csrf = next(
        check
        for check in result["checks"]
        if "CSRF" in check["name"]
    )
    assert csrf["severity"] == "Medium"
    assert csrf["confidence"] == "Low"
    assert csrf["vulnerability_confirmed"] is False
    assert result["csrf_review_count"] == 1


def test_csrf_field_is_recognized():
    form = make_form(
        fields=[
            {
                "name": "csrf_token",
                "type": "hidden",
                "autocomplete": "",
            },
        ],
    )

    result = analyze_form_hygiene([form])

    assert result["csrf_signal_count"] == 1
    assert result["protected_post_form_count"] == 1
    assert result["status"] == "Protected"


def test_password_autocomplete_requires_review():
    form = make_form(
        fields=[
            {
                "name": "password",
                "type": "password",
                "autocomplete": "",
            },
            {
                "name": "csrf_token",
                "type": "hidden",
                "autocomplete": "",
            },
        ],
    )

    result = analyze_form_hygiene([form])

    assert result["status"] == "Review"
    assert any(
        "Autocomplete" in check["name"]
        for check in result["checks"]
    )
