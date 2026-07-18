import requests

from app.deep_scanners.http_methods import (
    check_http_method_exposure,
    parse_methods,
)


class FakeResponse:
    def __init__(
        self,
        headers=None,
        status_code=200,
        url="https://example.com/",
    ):
        self.headers = headers or {}
        self.status_code = status_code
        self.url = url
        self.closed = False

    def close(self):
        self.closed = True


def allow_test_url(url):
    return None


def test_method_header_is_parsed():
    assert parse_methods(
        "GET, POST, OPTIONS"
    ) == {
        "GET",
        "POST",
        "OPTIONS",
    }


def test_expected_methods_are_protected():
    response = FakeResponse({
        "Allow": "GET, HEAD, OPTIONS, POST",
    })

    result = check_http_method_exposure(
        "example.com",
        requester=lambda *args, **kwargs: response,
        validator=allow_test_url,
    )

    assert result["status"] == "Protected"
    assert result["finding_count"] == 0
    assert response.closed is True


def test_put_and_delete_require_review():
    response = FakeResponse({
        "Allow": "GET, PUT, DELETE",
    })

    result = check_http_method_exposure(
        "example.com",
        requester=lambda *args, **kwargs: response,
        validator=allow_test_url,
    )

    assert result["status"] == "Review"
    assert result["finding_count"] == 2
    assert "PUT" in result["advertised_methods"]


def test_connect_needs_attention():
    response = FakeResponse({
        "Allow": "GET, CONNECT",
    })

    result = check_http_method_exposure(
        "example.com",
        requester=lambda *args, **kwargs: response,
        validator=allow_test_url,
    )

    assert result["status"] == "Needs Attention"
    assert result["checks"][0]["severity"] == "High"


def test_cors_methods_are_also_observed():
    response = FakeResponse({
        "Access-Control-Allow-Methods": (
            "GET, POST, PUT"
        ),
    })

    result = check_http_method_exposure(
        "example.com",
        requester=lambda *args, **kwargs: response,
        validator=allow_test_url,
    )

    assert result["status"] == "Review"
    assert result["cors_header_methods"] == [
        "GET",
        "POST",
        "PUT",
    ]


def test_missing_allow_header_is_not_observed():
    result = check_http_method_exposure(
        "example.com",
        requester=lambda *args, **kwargs: (
            FakeResponse()
        ),
        validator=allow_test_url,
    )

    assert result["status"] == "Not Observed"
    assert result["advertised_methods"] == []


def test_out_of_scope_response_is_rejected():
    result = check_http_method_exposure(
        "example.com",
        requester=lambda *args, **kwargs: (
            FakeResponse(
                url="https://other.example/"
            )
        ),
        validator=allow_test_url,
    )

    assert result["status"] == "Unavailable"


def test_network_failure_is_handled():
    def broken_requester(*args, **kwargs):
        raise requests.Timeout()

    result = check_http_method_exposure(
        "example.com",
        requester=broken_requester,
        validator=allow_test_url,
    )

    assert result["status"] == "Unavailable"
    assert result["error_type"] == "Timeout"