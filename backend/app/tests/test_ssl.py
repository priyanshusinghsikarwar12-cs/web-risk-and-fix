from app.scanners.ssl import classify_verification_error


def test_expired_certificate_classification():
    result = classify_verification_error(
        "certificate has expired"
    )

    assert result == "expired_certificate"


def test_hostname_mismatch_classification():
    result = classify_verification_error(
        "hostname mismatch"
    )

    assert result == "hostname_mismatch"


def test_self_signed_certificate_classification():
    result = classify_verification_error(
        "self-signed certificate"
    )

    assert result == "self_signed_certificate"


def test_untrusted_chain_classification():
    result = classify_verification_error(
        "unable to get local issuer certificate"
    )

    assert result == "untrusted_certificate_chain"


def test_unknown_verification_failure_classification():
    result = classify_verification_error(
        "certificate verification failed"
    )

    assert result == "certificate_verification_failed"