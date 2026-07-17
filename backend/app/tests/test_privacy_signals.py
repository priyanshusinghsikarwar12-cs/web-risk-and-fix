from app.scanners.privacy_signals import (
    analyze_privacy_signals,
)


BASE_URL = "https://example.com/"


def test_detects_privacy_policy_link():
    html = """
    <a href="/privacy-policy">Privacy Policy</a>
    """

    result = analyze_privacy_signals(
        html,
        BASE_URL,
    )

    privacy_check = result["checks"][0]

    assert privacy_check["status"] == "Observed"
    assert (
        privacy_check["links"][0]["url"]
        == "https://example.com/privacy-policy"
    )


def test_detects_cookie_consent_text():
    html = """
    <div>Accept all cookies</div>
    """

    result = analyze_privacy_signals(
        html,
        BASE_URL,
    )

    consent_check = result["checks"][1]

    assert consent_check["status"] == "Observed"


def test_detects_cookie_banner_attribute():
    html = """
    <div id="cookie-consent"></div>
    """

    result = analyze_privacy_signals(
        html,
        BASE_URL,
    )

    assert result["consent_signal_count"] == 1


def test_both_signals_are_observed():
    html = """
    <a href="/privacy">Privacy Notice</a>
    <button>Manage cookies</button>
    """

    result = analyze_privacy_signals(
        html,
        BASE_URL,
    )

    assert result["status"] == "Observed"


def test_one_signal_is_partial():
    html = """
    <a href="/privacy">Privacy Notice</a>
    """

    result = analyze_privacy_signals(
        html,
        BASE_URL,
    )

    assert result["status"] == "Partial"


def test_no_signals_are_not_observed():
    html = """
    <html>
      <body>Welcome to our website.</body>
    </html>
    """

    result = analyze_privacy_signals(
        html,
        BASE_URL,
    )

    assert result["status"] == "Not Observed"


def test_truncated_page_requires_review():
    html = """
    <html>
      <body>Welcome to our website.</body>
    </html>
    """

    result = analyze_privacy_signals(
        html,
        BASE_URL,
        content_truncated=True,
    )

    assert result["status"] == "Review"