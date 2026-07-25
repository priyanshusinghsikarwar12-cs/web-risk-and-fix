from app.deep_scanners.query_security import check_query_input_security


class FakeResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html"}


def crawler_with(url):
    return {"pages": [{"url": url}]}


def test_no_existing_query_parameters_is_not_applicable():
    result = check_query_input_security(
        "example.com",
        crawler_with("https://example.com/page"),
        sleeper=lambda delay: None,
    )
    assert result["status"] == "Not Applicable"
    assert result["requests_made"] == 0


def test_open_redirect_location_is_observed_without_contacting_destination():
    calls = []

    def fetcher(url, **kwargs):
        calls.append(url)
        return FakeResponse(
            status_code=302,
            headers={
                "Location": "https://webshield.invalid/marker",
                "Content-Type": "text/html",
            },
        )

    result = check_query_input_security(
        "example.com",
        crawler_with("https://example.com/login?next=%2Faccount"),
        fetcher=fetcher,
        sleeper=lambda delay: None,
    )
    assert result["finding_count"] == 1
    assert result["checks"][0]["name"] == "Potential Open Redirect"
    assert result["checks"][0]["evidence"]["destination_contacted"] is False
    assert "webshield.invalid" in calls[0]


def test_unescaped_html_significant_marker_requires_confirmation():
    def fetcher(url, **kwargs):
        from urllib.parse import parse_qs, urlsplit

        marker = parse_qs(urlsplit(url).query)["q"][0]
        return FakeResponse(f"<p>Search: {marker}</p>")

    result = check_query_input_security(
        "example.com",
        crawler_with("https://example.com/search?q=hello"),
        fetcher=fetcher,
        sleeper=lambda delay: None,
    )
    assert result["finding_count"] == 1
    finding = result["checks"][0]
    assert finding["validation"] == "Requires Confirmation"
    assert finding["evidence"]["script_payload_sent"] is False


def test_encoded_or_absent_marker_is_not_a_finding():
    result = check_query_input_security(
        "example.com",
        crawler_with("https://example.com/search?q=hello"),
        fetcher=lambda *args, **kwargs: FakeResponse(
            "WSREFLECT-safe-&lt;&gt;&quot;&#x27;"
        ),
        sleeper=lambda delay: None,
    )
    assert result["status"] == "Not Observed"
    assert result["finding_count"] == 0


def test_sensitive_parameters_and_state_changing_paths_are_skipped():
    calls = []
    crawler = {
        "pages": [
            {"url": "https://example.com/search?token=secret"},
            {"url": "https://example.com/delete?id=1"},
        ]
    }
    result = check_query_input_security(
        "example.com",
        crawler,
        fetcher=lambda url, **kwargs: calls.append(url),
        sleeper=lambda delay: None,
    )
    assert result["status"] == "Not Applicable"
    assert calls == []


def test_request_count_is_strictly_limited_and_paced():
    delays = []
    result = check_query_input_security(
        "example.com",
        crawler_with("https://example.com/search?a=1&b=2&c=3"),
        max_requests=2,
        delay_seconds=0.75,
        fetcher=lambda *args, **kwargs: FakeResponse("No reflection"),
        sleeper=delays.append,
    )
    assert result["requests_made"] == 2
    assert delays == [0.75]
    assert result["forms_submitted"] == 0
    assert result["state_changing_requests_sent"] == 0


def test_new_database_error_family_becomes_review_candidate():
    responses = [
        FakeResponse("<p>Normal search response</p>"),
        FakeResponse(
            "You have an error in your SQL syntax near the supplied value",
            status_code=500,
            headers={"Content-Type": "text/plain"},
        ),
    ]

    result = check_query_input_security(
        "example.com",
        crawler_with("https://example.com/search?q=books"),
        fetcher=lambda *args, **kwargs: responses.pop(0),
        sleeper=lambda delay: None,
    )

    finding = next(
        item for item in result["checks"]
        if item["name"] == "Database Error Triggered by Query Input"
    )
    assert finding["severity"] == "High"
    assert finding["confidence"] == "Medium"
    assert finding["validation"] == "Requires Confirmation"
    assert finding["evidence"]["data_extraction_attempted"] is False
    assert result["database_error_tests"] == 1


def test_database_error_already_in_control_is_not_new_finding():
    error_text = "You have an error in your SQL syntax"
    result = check_query_input_security(
        "example.com",
        crawler_with("https://example.com/search?q=books"),
        fetcher=lambda *args, **kwargs: FakeResponse(error_text),
        sleeper=lambda delay: None,
    )

    assert not any(
        item["name"] == "Database Error Triggered by Query Input"
        for item in result["checks"]
    )
    assert result["database_error_tests"] == 1
