from datetime import (
    datetime,
    timedelta,
    timezone,
)
import pytest
from app.services.subdomain_scope import (
    SubdomainScopeError,
    build_authorized_subdomain_scope,
    create_scoped_authorization_receipt,
    is_child_subdomain,
    validate_scoped_authorization_receipt,
)


def confirmed_check(
    hostname,
    wildcard_match=False,
):
    return {
        "hostname": hostname,
        "status": "DNS Confirmed",
        "wildcard_match": wildcard_match,
        "dns_records": {
            "A": ["93.184.216.34"],
        },
    }


def test_child_subdomain_is_accepted():
    assert is_child_subdomain(
        "api.example.com",
        "example.com",
    ) is True


def test_parent_domain_is_not_a_child():
    assert is_child_subdomain(
        "example.com",
        "example.com",
    ) is False


def test_valid_confirmed_scope():
    result = build_authorized_subdomain_scope(
        "example.com",
        [
            "api.example.com",
            "shop.example.com",
        ],
        [
            confirmed_check(
                "api.example.com"
            ),
            confirmed_check(
                "shop.example.com"
            ),
        ],
        authority_attested=True,
    )

    assert result["status"] == (
        "Scope Validated"
    )

    assert result["scope"] == [
        "example.com",
        "api.example.com",
        "shop.example.com",
    ]


def test_authority_confirmation_is_required():
    with pytest.raises(
        SubdomainScopeError,
        match="authorized",
    ):
        build_authorized_subdomain_scope(
            "example.com",
            ["api.example.com"],
            [
                confirmed_check(
                    "api.example.com"
                )
            ],
            authority_attested=False,
        )


def test_outside_domain_is_rejected():
    with pytest.raises(
        SubdomainScopeError,
        match="not a subdomain",
    ):
        build_authorized_subdomain_scope(
            "example.com",
            ["api.other.com"],
            [],
            authority_attested=True,
        )


def test_undiscovered_subdomain_is_rejected():
    with pytest.raises(
        SubdomainScopeError,
        match="not present",
    ):
        build_authorized_subdomain_scope(
            "example.com",
            ["unknown.example.com"],
            [],
            authority_attested=True,
        )


def test_historical_name_is_rejected():
    with pytest.raises(
        SubdomainScopeError,
        match="historical or inactive",
    ):
        build_authorized_subdomain_scope(
            "example.com",
            ["old.example.com"],
            [{
                "hostname": "old.example.com",
                "status": (
                    "Certificate Observed"
                ),
                "wildcard_match": False,
                "dns_records": {},
            }],
            authority_attested=True,
        )


def test_wildcard_result_is_rejected():
    with pytest.raises(
        SubdomainScopeError,
        match="wildcard DNS",
    ):
        build_authorized_subdomain_scope(
            "example.com",
            ["random.example.com"],
            [
                confirmed_check(
                    "random.example.com",
                    wildcard_match=True,
                )
            ],
            authority_attested=True,
        )


def test_selection_limit_is_enforced():
    selected = [
        f"host{index}.example.com"
        for index in range(11)
    ]

    checks = [
        confirmed_check(hostname)
        for hostname in selected
    ]

    with pytest.raises(
        SubdomainScopeError,
        match="Too many",
    ):
        build_authorized_subdomain_scope(
            "example.com",
            selected,
            checks,
            authority_attested=True,
        )

SECRET = (
    "test-secret-that-is-at-least-32-characters"
)

NOW = datetime(
    2026,
    7,
    18,
    10,
    0,
    tzinfo=timezone.utc,
)


def validated_scope():
    return build_authorized_subdomain_scope(
        "example.com",
        [
            "api.example.com",
            "shop.example.com",
        ],
        [
            confirmed_check(
                "api.example.com"
            ),
            confirmed_check(
                "shop.example.com"
            ),
        ],
        authority_attested=True,
    )


def test_scoped_receipt_authorizes_selected_host():
    authorization = (
        create_scoped_authorization_receipt(
            validated_scope(),
            "DNS TXT",
            SECRET,
            now=NOW,
        )
    )

    result = (
        validate_scoped_authorization_receipt(
            authorization["receipt"],
            "api.example.com",
            SECRET,
            now=NOW,
        )
    )

    assert result["authorized_target"] == (
        "api.example.com"
    )

    assert result["scope"] == [
        "example.com",
        "api.example.com",
        "shop.example.com",
    ]


def test_scoped_receipt_authorizes_parent():
    authorization = (
        create_scoped_authorization_receipt(
            validated_scope(),
            "DNS TXT",
            SECRET,
            now=NOW,
        )
    )

    result = (
        validate_scoped_authorization_receipt(
            authorization["receipt"],
            "example.com",
            SECRET,
            now=NOW,
        )
    )

    assert result["authorized_target"] == (
        "example.com"
    )


def test_unselected_subdomain_is_rejected():
    authorization = (
        create_scoped_authorization_receipt(
            validated_scope(),
            "DNS TXT",
            SECRET,
            now=NOW,
        )
    )

    with pytest.raises(
        SubdomainScopeError,
        match="not included",
    ):
        validate_scoped_authorization_receipt(
            authorization["receipt"],
            "admin.example.com",
            SECRET,
            now=NOW,
        )


def test_modified_scoped_receipt_is_rejected():
    authorization = (
        create_scoped_authorization_receipt(
            validated_scope(),
            "DNS TXT",
            SECRET,
            now=NOW,
        )
    )

    version, payload, signature = (
        authorization["receipt"].split(".")
    )

    replacement_character = (
        "A"
        if signature[0] != "A"
        else "B"
    )

    modified_signature = (
        replacement_character
        + signature[1:]
    )

    modified_receipt = ".".join([
        version,
        payload,
        modified_signature,
    ])

    assert (
        modified_receipt
        != authorization["receipt"]
    )

    with pytest.raises(
        SubdomainScopeError,
        match="signature",
    ):
        validate_scoped_authorization_receipt(
            modified_receipt,
            "api.example.com",
            SECRET,
            now=NOW,
        )


def test_expired_scoped_receipt_is_rejected():
    authorization = (
        create_scoped_authorization_receipt(
            validated_scope(),
            "DNS TXT",
            SECRET,
            now=NOW,
            ttl_seconds=300,
        )
    )

    later = NOW + timedelta(
        seconds=301
    )

    with pytest.raises(
        SubdomainScopeError,
        match="expired",
    ):
        validate_scoped_authorization_receipt(
            authorization["receipt"],
            "api.example.com",
            SECRET,
            now=later,
        )


def test_unvalidated_scope_is_rejected():
    with pytest.raises(
        SubdomainScopeError,
        match="validated",
    ):
        create_scoped_authorization_receipt(
            {
                "parent_domain": "example.com",
                "scope": [
                    "example.com",
                    "api.example.com",
                ],
                "authority_attested": True,
                "status": "Pending",
            },
            "DNS TXT",
            SECRET,
            now=NOW,
        )