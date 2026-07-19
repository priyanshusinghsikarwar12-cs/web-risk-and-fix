from datetime import datetime, timedelta, timezone

import pytest

from app.services.engagement_profile import (
    EngagementProfileError,
    create_engagement_profile,
    validate_engagement_profile,
)


SECRET = "engagement-test-secret-that-is-long-enough"
NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)


def ownership_payload():
    return {
        "domain": "example.com",
        "scope": ["example.com"],
        "verification_method": "DNS TXT",
    }


def settings(**overrides):
    values = {
        "client_reference": "Example client assessment",
        "authorized_by": "Website owner",
        "environment": "production",
        "max_pages": 25,
        "max_depth": 2,
        "include_zap": False,
        "zap_spider_minutes": 1,
        "zap_maximum_minutes": 5,
        "approved_scanners": [
            "crawler",
            "exposure_checks",
            "cors",
            "http_methods",
            "subdomains",
            "ports",
            "javascript_advisories",
        ],
        "authorization_confirmed": True,
    }
    values.update(overrides)
    return values


def test_signed_engagement_round_trip():
    engagement = create_engagement_profile(
        "example.com",
        ownership_payload(),
        settings(),
        SECRET,
        now=NOW,
    )

    payload = validate_engagement_profile(
        engagement["receipt"],
        "example.com",
        SECRET,
        now=NOW + timedelta(minutes=5),
    )

    assert payload["purpose"] == "verified_engagement"
    assert payload["max_pages"] == 25
    assert payload["max_depth"] == 2
    assert payload["client_reference"] == "Example client assessment"
    assert payload["authorization_confirmed"] is True


def test_engagement_rejects_wrong_domain():
    engagement = create_engagement_profile(
        "example.com", ownership_payload(), settings(), SECRET, now=NOW
    )

    with pytest.raises(EngagementProfileError, match="different domain"):
        validate_engagement_profile(
            engagement["receipt"], "example.org", SECRET, now=NOW
        )


def test_engagement_rejects_modified_receipt():
    engagement = create_engagement_profile(
        "example.com", ownership_payload(), settings(), SECRET, now=NOW
    )
    parts = engagement["receipt"].split(".")
    replacement = "A" if parts[1][-1] != "A" else "B"
    parts[1] = parts[1][:-1] + replacement

    with pytest.raises(EngagementProfileError, match="signature"):
        validate_engagement_profile(".".join(parts), "example.com", SECRET, now=NOW)


def test_engagement_rejects_expired_receipt():
    engagement = create_engagement_profile(
        "example.com",
        ownership_payload(),
        settings(),
        SECRET,
        now=NOW,
        ttl_seconds=1800,
    )

    with pytest.raises(EngagementProfileError, match="expired"):
        validate_engagement_profile(
            engagement["receipt"],
            "example.com",
            SECRET,
            now=NOW + timedelta(minutes=31),
        )


def test_engagement_requires_explicit_authorization():
    with pytest.raises(EngagementProfileError, match="authorization"):
        create_engagement_profile(
            "example.com",
            ownership_payload(),
            settings(authorization_confirmed=False),
            SECRET,
            now=NOW,
        )


def test_engagement_rejects_unapproved_zap():
    with pytest.raises(EngagementProfileError, match="explicitly included"):
        create_engagement_profile(
            "example.com",
            ownership_payload(),
            settings(include_zap=True),
            SECRET,
            now=NOW,
        )


def test_engagement_rejects_excessive_page_limit():
    with pytest.raises(EngagementProfileError, match="page limit"):
        create_engagement_profile(
            "example.com",
            ownership_payload(),
            settings(max_pages=51),
            SECRET,
            now=NOW,
        )
