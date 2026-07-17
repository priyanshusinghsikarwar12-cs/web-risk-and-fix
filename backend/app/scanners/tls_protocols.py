import socket
import ssl


PROTOCOLS = [
    {
        "name": "TLS 1.0",
        "version": ssl.TLSVersion.TLSv1,
        "modern": False,
    },
    {
        "name": "TLS 1.1",
        "version": ssl.TLSVersion.TLSv1_1,
        "modern": False,
    },
    {
        "name": "TLS 1.2",
        "version": ssl.TLSVersion.TLSv1_2,
        "modern": True,
    },
    {
        "name": "TLS 1.3",
        "version": ssl.TLSVersion.TLSv1_3,
        "modern": True,
    },
]


def create_protocol_context(version, modern):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = version
    context.maximum_version = version

    if not modern:
        try:
            context.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass

    return context


def probe_tls_protocol(
    domain: str,
    protocol_name: str,
    version,
    modern: bool,
):
    try:
        context = create_protocol_context(version, modern)

        with socket.create_connection(
            (domain, 443),
            timeout=5,
        ) as connection:
            with context.wrap_socket(
                connection,
                server_hostname=domain,
            ) as secure_connection:
                cipher = secure_connection.cipher()

        return {
            "name": protocol_name,
            "status": "Supported",
            "supported": True,
            "security": "Modern" if modern else "Obsolete",
            "cipher": cipher[0] if cipher else None,
            "message": (
                f"The website accepts {protocol_name} connections."
            ),
        }

    except ssl.SSLError as error:
        reason = str(
            getattr(error, "reason", "") or error
        ).upper()

        unsupported_reasons = (
            "TLSV1_ALERT_PROTOCOL_VERSION",
            "UNSUPPORTED_PROTOCOL",
            "WRONG_VERSION_NUMBER",
            "PROTOCOL_VERSION",
        )

        if any(item in reason for item in unsupported_reasons):
            return {
                "name": protocol_name,
                "status": "Not Supported",
                "supported": False,
                "security": "Modern" if modern else "Obsolete",
                "cipher": None,
                "message": (
                    f"The website does not accept "
                    f"{protocol_name} connections."
                ),
            }

        return {
            "name": protocol_name,
            "status": "Inconclusive",
            "supported": None,
            "security": "Modern" if modern else "Obsolete",
            "cipher": None,
            "message": (
                f"WebShield could not reliably determine "
                f"{protocol_name} support."
            ),
            "technical_error": str(error),
        }

    except (socket.timeout, TimeoutError) as error:
        return {
            "name": protocol_name,
            "status": "Unavailable",
            "supported": None,
            "security": "Modern" if modern else "Obsolete",
            "cipher": None,
            "message": (
                f"The {protocol_name} check timed out."
            ),
            "technical_error": str(error),
        }

    except OSError as error:
        return {
            "name": protocol_name,
            "status": "Unavailable",
            "supported": None,
            "security": "Modern" if modern else "Obsolete",
            "cipher": None,
            "message": (
                f"WebShield could not test {protocol_name}."
            ),
            "technical_error": str(error),
        }


def evaluate_tls_results(checks):
    obsolete_supported = any(
        check["supported"] is True
        and check["security"] == "Obsolete"
        for check in checks
    )

    modern_supported = any(
        check["supported"] is True
        and check["security"] == "Modern"
        for check in checks
    )

    obsolete_uncertain = any(
        check["supported"] is None
        and check["security"] == "Obsolete"
        for check in checks
    )

    if obsolete_supported:
        return {
            "status": "Needs Attention",
            "message": (
                "The website accepts an outdated TLS protocol "
                "that should be disabled."
            ),
            "confidence": "High",
        }

    if not modern_supported:
        return {
            "status": "Review",
            "message": (
                "WebShield could not confirm support for a "
                "modern TLS protocol."
            ),
            "confidence": "Medium",
        }

    if obsolete_uncertain:
        return {
            "status": "Review",
            "message": (
                "Modern TLS is supported, but some older "
                "protocol checks were inconclusive."
            ),
            "confidence": "Medium",
        }

    return {
        "status": "Protected",
        "message": (
            "The website supports modern TLS and rejected "
            "the outdated protocols tested."
        ),
        "confidence": "High",
    }


def check_tls_protocols(domain: str):
    checks = []

    for protocol in PROTOCOLS:
        checks.append(
            probe_tls_protocol(
                domain,
                protocol["name"],
                protocol["version"],
                protocol["modern"],
            )
        )

    result = evaluate_tls_results(checks)

    return {
        "name": "TLS Protocol Security",
        "domain": domain,
        "status": result["status"],
        "message": result["message"],
        "confidence": result["confidence"],
        "checks": checks,
        "score_eligible": False,
    }