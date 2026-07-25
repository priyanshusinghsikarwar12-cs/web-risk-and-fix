from datetime import datetime, timedelta, timezone

import pytest

from app.services.engagement_profile import (
    EngagementProfileError,
    create_bug_bounty_engagement_profile,
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
            "query_input_security",
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


def bug_bounty_settings(**overrides):
    values = {
        "program_name": "Example Public Program",
        "program_url": "https://hackerone.com/example",
        "researcher_handle": "researcher_one",
        "scope_reference": "example.com domain scope row",
        "policy_saved_date": "2026-07-21",
        "asset_in_scope_confirmed": True,
        "program_rules_confirmed": True,
        "safe_harbor_confirmed": True,
        "researcher_owned_accounts_only": True,
    }
    values.update(overrides)
    return values


def test_bug_bounty_profile_has_fixed_safe_limits():
    engagement = create_bug_bounty_engagement_profile(
        "example.com",
        bug_bounty_settings(),
        SECRET,
        now=NOW,
    )

    payload = validate_engagement_profile(
        engagement["receipt"],
        "example.com",
        SECRET,
        now=NOW + timedelta(minutes=5),
    )

    assert payload["assessment_mode"] == "bug_bounty"
    assert payload["max_pages"] == 5
    assert payload["max_depth"] == 1
    assert payload["max_concurrency"] == 1
    assert payload["request_delay_seconds"] == 0.5
    assert payload["include_zap"] is False
    assert "ports" not in payload["approved_scanners"]
    assert "subdomains" not in payload["approved_scanners"]
    assert payload["authenticated_testing_approved"] is False


def test_bug_bounty_profile_signs_authenticated_testing_approval():
    engagement = create_bug_bounty_engagement_profile(
        "example.com",
        bug_bounty_settings(authenticated_testing_approved=True),
        SECRET,
        now=NOW,
    )

    payload = validate_engagement_profile(
        engagement["receipt"],
        "example.com",
        SECRET,
        now=NOW + timedelta(minutes=5),
    )

    assert payload["authenticated_testing_approved"] is True
    assert payload["researcher_owned_accounts_only"] is True
    assert payload["request_delay_seconds"] == 0.5


def test_bug_bounty_profile_requires_every_confirmation():
    with pytest.raises(
        EngagementProfileError,
        match="Every bug bounty safety confirmation",
    ):
        create_bug_bounty_engagement_profile(
            "example.com",
            bug_bounty_settings(safe_harbor_confirmed=False),
            SECRET,
            now=NOW,
        )


def test_bug_bounty_profile_rejects_non_hackerone_policy_url():
    with pytest.raises(
        EngagementProfileError,
        match="HTTPS HackerOne page",
    ):
        create_bug_bounty_engagement_profile(
            "example.com",
            bug_bounty_settings(
                program_url="https://example.com/program"
            ),
            SECRET,
            now=NOW,
        )


def test_bug_bounty_profile_signs_selected_safe_scanners_only():
    engagement = create_bug_bounty_engagement_profile(
        "example.com",
        bug_bounty_settings(
            approved_scanners=[
                "crawler",
                "cors",
            ]
        ),
        SECRET,
        now=NOW,
    )

    payload = validate_engagement_profile(
        engagement["receipt"],
        "example.com",
        SECRET,
        now=NOW + timedelta(minutes=5),
    )

    assert payload["approved_scanners"] == [
        "cors",
        "crawler",
    ]


def test_bug_bounty_profile_rejects_empty_scanner_selection():
    with pytest.raises(
        EngagementProfileError,
        match="At least one scanner",
    ):
        create_bug_bounty_engagement_profile(
            "example.com",
            bug_bounty_settings(approved_scanners=[]),
            SECRET,
            now=NOW,
        )


def test_bug_bounty_profile_rejects_unsafe_scanner_selection():
    with pytest.raises(
        EngagementProfileError,
        match="not allowed in safe mode",
    ):
        create_bug_bounty_engagement_profile(
            "example.com",
            bug_bounty_settings(
                approved_scanners=["crawler", "ports"]
            ),
            SECRET,
            now=NOW,
        )


def test_bug_bounty_profile_rejects_active_query_input_testing():
    with pytest.raises(
        EngagementProfileError,
        match="not allowed in safe mode",
    ):
        create_bug_bounty_engagement_profile(
            "example.com",
            bug_bounty_settings(
                approved_scanners=[
                    "crawler",
                    "query_input_security",
                ]
            ),
            SECRET,
            now=NOW,
        )


def test_bug_bounty_profile_signs_program_policy_exclusions():
    engagement = create_bug_bounty_engagement_profile(
        "example.com",
        bug_bounty_settings(
            excluded_finding_types=[
                "missing_security_headers",
                "cookie_attribute_observations",
            ]
        ),
        SECRET,
        now=NOW,
    )

    payload = validate_engagement_profile(
        engagement["receipt"],
        "example.com",
        SECRET,
        now=NOW + timedelta(minutes=5),
    )

    assert payload["excluded_finding_types"] == [
        "cookie_attribute_observations",
        "missing_security_headers",
    ]


def test_bug_bounty_profile_rejects_unknown_policy_exclusion():
    with pytest.raises(
        EngagementProfileError,
        match="unsupported finding exclusion",
    ):
        create_bug_bounty_engagement_profile(
            "example.com",
            bug_bounty_settings(
                excluded_finding_types=["ignore_everything"]
            ),
            SECRET,
            now=NOW,
        )
