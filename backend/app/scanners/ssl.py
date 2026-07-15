import socket
import ssl
from datetime import datetime, timezone


def classify_verification_error(message: str) -> str:
    normalized = message.lower()

    if "expired" in normalized:
        return "expired_certificate"

    if (
        "hostname mismatch" in normalized
        or "not valid for" in normalized
    ):
        return "hostname_mismatch"

    if "self-signed" in normalized:
        return "self_signed_certificate"

    if (
        "unable to get local issuer" in normalized
        or "unable to verify" in normalized
        or "unknown ca" in normalized
    ):
        return "untrusted_certificate_chain"

    return "certificate_verification_failed"


def build_failure(
    error_type: str,
    message: str,
    technical_error: str,
    verify_code=None,
):
    return {
        "name": "Security Certificate",
        "status": "Needs Attention",
        "message": message,
        "days_left": None,
        "urgency": "Review certificate setup",
        "error_type": error_type,
        "advanced": {
            "technical_error": technical_error,
            "verify_code": verify_code,
        },
    }


def certificate_name_to_dict(name):
    return {
        key: value
        for group in name
        for key, value in group
    }


def evaluate_certificate(
    certificate: dict,
    tls_version: str,
    cipher,
):
    expires_text = certificate["notAfter"]
    valid_from_text = certificate["notBefore"]

    expires_timestamp = ssl.cert_time_to_seconds(expires_text)
    valid_from_timestamp = ssl.cert_time_to_seconds(valid_from_text)

    expires_on = datetime.fromtimestamp(
        expires_timestamp,
        timezone.utc,
    )

    valid_from = datetime.fromtimestamp(
        valid_from_timestamp,
        timezone.utc,
    )

    now = datetime.now(timezone.utc)
    days_left = (expires_on - now).days

    issuer = certificate_name_to_dict(
        certificate.get("issuer", ())
    )

    subject = certificate_name_to_dict(
        certificate.get("subject", ())
    )

    if days_left < 0:
        status = "Needs Attention"
        message = "Your website security certificate has expired."
        urgency = "Fix immediately"

    elif days_left <= 30:
        status = "Needs Attention"
        message = (
            "Your website security certificate is valid, "
            "but it will expire soon."
        )
        urgency = "Renew soon"

    else:
        status = "Protected"
        message = (
            "Your website security certificate is valid "
            "and trusted."
        )
        urgency = "No action needed"

    return {
        "name": "Security Certificate",
        "status": status,
        "message": message,
        "days_left": days_left,
        "urgency": urgency,
        "error_type": None,
        "advanced": {
            "valid_from": valid_from.isoformat(),
            "expires_on": expires_on.isoformat(),
            "issuer": issuer,
            "subject": subject,
            "tls_version": tls_version,
            "cipher": cipher[0] if cipher else None,
        },
    }


def check_ssl_certificate(domain: str):
    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (domain, 443),
            timeout=10,
        ) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=domain,
            ) as secure_sock:
                certificate = secure_sock.getpeercert()
                tls_version = secure_sock.version()
                cipher = secure_sock.cipher()

        return evaluate_certificate(
            certificate,
            tls_version,
            cipher,
        )

    except ssl.SSLCertVerificationError as error:
        error_type = classify_verification_error(
            error.verify_message
        )

        messages = {
            "expired_certificate": (
                "Your website security certificate has expired."
            ),
            "hostname_mismatch": (
                "The certificate does not match this website's domain."
            ),
            "self_signed_certificate": (
                "The website uses a self-signed certificate "
                "that browsers may not trust."
            ),
            "untrusted_certificate_chain": (
                "The certificate chain could not be trusted."
            ),
            "certificate_verification_failed": (
                "The security certificate could not be verified."
            ),
        }

        return build_failure(
            error_type,
            messages[error_type],
            error.verify_message,
            error.verify_code,
        )

    except socket.gaierror as error:
        return build_failure(
            "dns_resolution_failed",
            "WebShield could not find the website's server.",
            str(error),
        )

    except (socket.timeout, TimeoutError) as error:
        return build_failure(
            "connection_timeout",
            "The website took too long to respond.",
            str(error),
        )

    except ConnectionRefusedError as error:
        return build_failure(
            "connection_refused",
            "The website refused a secure connection.",
            str(error),
        )

    except ssl.SSLError as error:
        return build_failure(
            "tls_handshake_failed",
            "The website could not establish a secure connection.",
            str(error),
        )

    except OSError as error:
        return build_failure(
            "connection_failed",
            "WebShield could not connect to the certificate service.",
            str(error),
        )