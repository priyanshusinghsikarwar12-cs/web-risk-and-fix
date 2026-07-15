from app.scanners.health import (
    classify_http_status,
    classify_response_time,
    evaluate_health,
)


def test_successful_status():
    assert classify_http_status(200) == "successful"


def test_client_error_status():
    assert classify_http_status(404) == "client_error"


def test_server_error_status():
    assert classify_http_status(500) == "server_error"


def test_fast_response():
    assert classify_response_time(500) == "Fast"


def test_http_connection_needs_attention():
    result = evaluate_health(
        200,
        500,
        "http://example.com",
    )

    assert result["status"] == "Needs Attention"
    assert result["https"] is False