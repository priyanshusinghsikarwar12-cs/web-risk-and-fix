from app.deep_scanners.cors import (
    check_cors_configuration,
)


class FakeResponse:
    def __init__(
        self,
        headers=None,
        url="https://example.com/",
        status_code=200,
    ):
        self.headers = headers or {}
        self.url = url
        self.status_code = status_code


def make_getter(response_factory):
    def fake_get(url, **kwargs):
        origin = kwargs["headers"]["Origin"]
        return response_factory(origin)

    return fake_get


def test_no_cors_policy_is_not_observed():
    result = check_cors_configuration(
        "example.com",
        getter=make_getter(
            lambda origin: FakeResponse()
        ),
    )

    assert result["status"] == "Not Observed"
    assert result["finding_count"] == 0
    assert result["requests_made"] == 2


def test_reflected_origin_with_credentials_is_high_risk():
    def response_factory(origin):
        return FakeResponse({
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        })

    result = check_cors_configuration(
        "example.com",
        getter=make_getter(response_factory),
    )

    assert result["status"] == "Needs Attention"
    assert result["checks"][0]["severity"] == "High"


def test_multiple_reflected_origins_require_review():
    def response_factory(origin):
        return FakeResponse({
            "Access-Control-Allow-Origin": origin,
        })

    result = check_cors_configuration(
        "example.com",
        getter=make_getter(response_factory),
    )

    assert result["status"] == "Review"
    assert result["checks"][0]["severity"] == "Medium"


def test_wildcard_policy_requires_review():
    def response_factory(origin):
        return FakeResponse({
            "Access-Control-Allow-Origin": "*",
        })

    result = check_cors_configuration(
        "example.com",
        getter=make_getter(response_factory),
    )

    assert result["status"] == "Review"
    assert result["checks"][0]["severity"] == "Low"


def test_fixed_unrelated_policy_is_not_reported():
    def response_factory(origin):
        return FakeResponse({
            "Access-Control-Allow-Origin": (
                "https://trusted.example.com"
            ),
        })

    result = check_cors_configuration(
        "example.com",
        getter=make_getter(response_factory),
    )

    assert result["status"] == "Protected"
    assert result["finding_count"] == 0


def test_redirect_outside_verified_host_is_rejected():
    result = check_cors_configuration(
        "example.com",
        getter=make_getter(
            lambda origin: FakeResponse(
                url="https://other.example/"
            )
        ),
    )

    assert result["status"] == "Unavailable"
    assert len(result["errors"]) == 2