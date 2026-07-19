import dns.resolver

from app.scanners.domain_trust import (
    check_domain_trust,
    lookup_dns_records,
    parse_caa_record,
)


def make_lookup(records=None, errors=None):
    records = records or {}
    errors = errors or {}

    def lookup(domain, record_type):
        return {
            "values": records.get(record_type, []),
            "error": errors.get(record_type, "no_answer"),
        }

    return lookup


def test_caa_record_is_parsed():
    result = parse_caa_record(
        '0 issue "letsencrypt.org"'
    )

    assert result == {
        "flags": 0,
        "tag": "issue",
        "value": "letsencrypt.org",
    }


def test_invalid_caa_record_is_ignored():
    assert parse_caa_record("invalid") is None


def test_dns_lookup_returns_text_evidence():
    class Answer:
        def to_text(self):
            return "12345 13 2 ABCDEF"

    result = lookup_dns_records(
        "example.com",
        "DS",
        resolver=lambda domain, record_type: [Answer()],
    )

    assert result == {
        "values": ["12345 13 2 ABCDEF"],
        "error": None,
    }


def test_dns_lookup_distinguishes_no_answer():
    def resolver(domain, record_type):
        raise dns.resolver.NoAnswer()

    result = lookup_dns_records(
        "example.com",
        "CAA",
        resolver=resolver,
    )

    assert result == {
        "values": [],
        "error": "no_answer",
    }


def test_dnssec_and_caa_are_protected():
    result = check_domain_trust(
        "example.com",
        lookup=make_lookup(
            records={
                "DS": ["12345 13 2 ABCDEF"],
                "DNSKEY": ["257 3 13 KEYDATA"],
                "CAA": [
                    '0 issue "letsencrypt.org"',
                ],
            },
            errors={
                "DS": None,
                "DNSKEY": None,
                "CAA": None,
            },
        ),
    )

    assert result["status"] == "Protected"
    assert result["score_eligible"] is False
    assert result["checks"][0]["status"] == (
        "Configured"
    )
    assert result["checks"][1]["evidence"][
        "authorized_authorities"
    ] == ["letsencrypt.org"]


def test_missing_records_are_not_called_vulnerable():
    result = check_domain_trust(
        "example.com",
        lookup=make_lookup(),
    )

    assert result["status"] == "Not Configured"
    assert result["checks"][0]["passed"] is None
    assert result["checks"][1]["passed"] is None


def test_partial_dnssec_chain_needs_review():
    result = check_domain_trust(
        "example.com",
        lookup=make_lookup(
            records={
                "DS": ["12345 13 2 ABCDEF"],
            },
            errors={"DS": None},
        ),
    )

    assert result["checks"][0]["status"] == (
        "Needs Review"
    )


def test_lookup_failures_limit_confidence():
    result = check_domain_trust(
        "example.com",
        lookup=make_lookup(
            errors={
                "DS": "lookup_timeout",
                "DNSKEY": "lookup_timeout",
                "CAA": "lookup_timeout",
            },
        ),
    )

    assert result["status"] == "Unavailable"
    assert result["confidence"] == "Limited"


def test_empty_issue_value_does_not_name_authority():
    result = check_domain_trust(
        "example.com",
        lookup=make_lookup(
            records={"CAA": ['0 issue ";"']},
            errors={"CAA": None},
        ),
    )

    caa = result["checks"][1]

    assert caa["status"] == "Configured"
    assert caa["evidence"][
        "authorized_authorities"
    ] == []
    assert caa["evidence"][
        "standard_certificate_policy"
    ] == "Issuance Blocked"
    assert caa["evidence"][
        "wildcard_certificate_policy"
    ] == "Follows Standard Policy"


def test_iodef_only_does_not_claim_issuance_control():
    result = check_domain_trust(
        "example.com",
        lookup=make_lookup(
            records={
                "CAA": [
                    '0 iodef "mailto:security@example.com"',
                ],
            },
            errors={"CAA": None},
        ),
    )

    caa = result["checks"][1]

    assert caa["status"] == (
        "Observed, Not Restrictive"
    )
    assert caa["passed"] is None
    assert caa["evidence"]["reporting_contacts"] == [
        "mailto:security@example.com"
    ]


def test_named_and_empty_issue_rules_are_additive():
    result = check_domain_trust(
        "example.com",
        lookup=make_lookup(
            records={
                "CAA": [
                    '0 issue ";"',
                    (
                        '0 issue "letsencrypt.org; '
                        'validationmethods=dns-01"'
                    ),
                ],
            },
            errors={"CAA": None},
        ),
    )

    caa = result["checks"][1]

    assert caa["evidence"][
        "standard_certificate_policy"
    ] == "Restricted"
    assert caa["evidence"][
        "standard_authorities"
    ] == ["letsencrypt.org"]


def test_issuewild_policy_is_reported_separately():
    result = check_domain_trust(
        "example.com",
        lookup=make_lookup(
            records={
                "CAA": [
                    '0 issue "letsencrypt.org"',
                    '0 issuewild ";"',
                ],
            },
            errors={"CAA": None},
        ),
    )

    caa = result["checks"][1]

    assert caa["evidence"][
        "standard_certificate_policy"
    ] == "Restricted"
    assert caa["evidence"][
        "wildcard_certificate_policy"
    ] == "Issuance Blocked"
