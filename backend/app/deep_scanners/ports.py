import socket
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)

from app.utils.domain import (
    DomainValidationError,
    clean_domain,
    ensure_public_addresses,
)


CONTROLLED_PORTS = {
    21: {
        "service": "FTP",
        "status": "Review",
        "severity": "Medium",
        "message": (
            "FTP is exposed. Confirm that it is required "
            "and protected; prefer encrypted alternatives."
        ),
    },
    22: {
        "service": "SSH",
        "status": "Review",
        "severity": "Medium",
        "message": (
            "Remote administration through SSH is exposed. "
            "Restrict access and require strong authentication."
        ),
    },
    23: {
        "service": "Telnet",
        "status": "Needs Attention",
        "severity": "High",
        "message": (
            "Telnet is exposed and does not provide modern "
            "encrypted remote administration."
        ),
    },
    25: {
        "service": "SMTP",
        "status": "Review",
        "severity": "Low",
        "message": (
            "An email-transfer service is exposed. This may "
            "be expected for a mail server."
        ),
    },
    53: {
        "service": "DNS",
        "status": "Review",
        "severity": "Low",
        "message": (
            "A DNS service is exposed. Confirm that this "
            "system is intended to answer DNS requests."
        ),
    },
    80: {
        "service": "HTTP",
        "status": "Expected",
        "severity": "Informational",
        "message": (
            "A standard website service is exposed over HTTP."
        ),
    },
    110: {
        "service": "POP3",
        "status": "Needs Attention",
        "severity": "Medium",
        "message": (
            "A plaintext email retrieval service appears "
            "exposed. Prefer its encrypted alternative."
        ),
    },
    143: {
        "service": "IMAP",
        "status": "Needs Attention",
        "severity": "Medium",
        "message": (
            "A plaintext email access service appears "
            "exposed. Prefer its encrypted alternative."
        ),
    },
    443: {
        "service": "HTTPS",
        "status": "Expected",
        "severity": "Informational",
        "message": (
            "The standard encrypted website service "
            "is exposed."
        ),
    },
    445: {
        "service": "SMB",
        "status": "Needs Attention",
        "severity": "High",
        "message": (
            "Windows file sharing is exposed to the internet "
            "and should be reviewed immediately."
        ),
    },
    465: {
        "service": "SMTPS",
        "status": "Review",
        "severity": "Low",
        "message": (
            "An encrypted email submission service is exposed."
        ),
    },
    587: {
        "service": "SMTP Submission",
        "status": "Review",
        "severity": "Low",
        "message": (
            "An email submission service is exposed. This "
            "may be expected for a mail server."
        ),
    },
    993: {
        "service": "IMAPS",
        "status": "Review",
        "severity": "Low",
        "message": (
            "An encrypted IMAP email service is exposed."
        ),
    },
    995: {
        "service": "POP3S",
        "status": "Review",
        "severity": "Low",
        "message": (
            "An encrypted POP3 email service is exposed."
        ),
    },
    1433: {
        "service": "Microsoft SQL Server",
        "status": "Needs Attention",
        "severity": "High",
        "message": (
            "A database service appears internet-accessible. "
            "Restrict it unless public access is required."
        ),
    },
    1521: {
        "service": "Oracle Database",
        "status": "Needs Attention",
        "severity": "High",
        "message": (
            "An Oracle database listener appears exposed."
        ),
    },
    2049: {
        "service": "NFS",
        "status": "Needs Attention",
        "severity": "High",
        "message": (
            "Network file sharing appears exposed to "
            "the internet."
        ),
    },
    3306: {
        "service": "MySQL",
        "status": "Needs Attention",
        "severity": "High",
        "message": (
            "A MySQL database service appears "
            "internet-accessible."
        ),
    },
    3389: {
        "service": "Remote Desktop",
        "status": "Needs Attention",
        "severity": "High",
        "message": (
            "Remote Desktop appears exposed. Restrict it "
            "through a VPN, firewall, or trusted addresses."
        ),
    },
    5432: {
        "service": "PostgreSQL",
        "status": "Needs Attention",
        "severity": "High",
        "message": (
            "A PostgreSQL database service appears "
            "internet-accessible."
        ),
    },
    6379: {
        "service": "Redis",
        "status": "Needs Attention",
        "severity": "High",
        "message": (
            "A Redis service appears exposed to the internet."
        ),
    },
    8080: {
        "service": "Alternate HTTP",
        "status": "Review",
        "severity": "Medium",
        "message": (
            "An alternate web service is exposed. Confirm "
            "that it is intended for public access."
        ),
    },
    8443: {
        "service": "Alternate HTTPS",
        "status": "Review",
        "severity": "Medium",
        "message": (
            "An alternate encrypted web service is exposed."
        ),
    },
    9200: {
        "service": "Elasticsearch",
        "status": "Needs Attention",
        "severity": "High",
        "message": (
            "An Elasticsearch service appears exposed."
        ),
    },
    11211: {
        "service": "Memcached",
        "status": "Needs Attention",
        "severity": "High",
        "message": (
            "A Memcached service appears exposed."
        ),
    },
    27017: {
        "service": "MongoDB",
        "status": "Needs Attention",
        "severity": "High",
        "message": (
            "A MongoDB service appears internet-accessible."
        ),
    },
}


def resolve_public_addresses(
    domain: str,
    resolver=socket.getaddrinfo,
) -> list:
    safe_domain = clean_domain(domain)

    try:
        address_info = resolver(
            safe_domain,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as error:
        raise DomainValidationError(
            "The verified hostname could not be resolved."
        ) from error

    addresses = sorted({
        item[4][0]
        for item in address_info
    })

    ensure_public_addresses(addresses)

    return addresses[:4]


def test_tcp_connection(
    address: str,
    port: int,
    timeout: float,
    connector=socket.create_connection,
) -> bool:
    connection = None

    try:
        connection = connector(
            (address, port),
            timeout=timeout,
        )

        return True

    except (
        ConnectionError,
        OSError,
        TimeoutError,
    ):
        return False

    finally:
        if connection is not None:
            connection.close()


def build_port_attribution(hosting_context):
    hosting_context = hosting_context or {}
    sharing = hosting_context.get(
        "shared_infrastructure",
        {},
    )
    provider = hosting_context.get("provider", {})
    sharing_status = sharing.get("status")

    if sharing_status in {
        "Shared Edge Observed",
        "Likely Shared",
    }:
        provider_name = provider.get("name") or (
            "the detected hosting provider"
        )

        return {
            "status": "Provider Edge - Origin Unconfirmed",
            "origin_confirmed": False,
            "provider": provider.get("name"),
            "confidence": provider.get(
                "confidence",
                "Unavailable",
            ),
            "message": (
                f"The tested addresses appear to belong to "
                f"{provider_name}'s shared infrastructure. "
                "The responding service cannot yet be attributed "
                "to the website owner's origin server."
            ),
        }

    return {
        "status": "Origin Attribution Not Established",
        "origin_confirmed": False,
        "provider": provider.get("name"),
        "confidence": "None",
        "message": (
            "WebShield confirmed a TCP connection, but a connection "
            "alone does not prove who operates the responding service."
        ),
    }


def scan_open_ports(
    domain: str,
    timeout: float = 0.75,
    max_workers: int = 20,
    resolver=socket.getaddrinfo,
    connector=socket.create_connection,
    ports=None,
    hosting_context=None,
):
    safe_domain = clean_domain(domain)

    if not 0.2 <= timeout <= 3:
        raise ValueError(
            "The connection timeout must be between "
            "0.2 and 3 seconds."
        )

    if not 1 <= max_workers <= 30:
        raise ValueError(
            "The worker limit must be between 1 and 30."
        )

    selected_ports = (
        ports
        if ports is not None
        else CONTROLLED_PORTS
    )

    addresses = resolve_public_addresses(
        safe_domain,
        resolver=resolver,
    )

    tasks = {}
    open_results = {}

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:
        for address in addresses:
            for port in selected_ports:
                future = executor.submit(
                    test_tcp_connection,
                    address,
                    port,
                    timeout,
                    connector,
                )

                tasks[future] = (
                    address,
                    port,
                )

        for future in as_completed(tasks):
            address, port = tasks[future]

            if future.result():
                open_results.setdefault(
                    port,
                    [],
                ).append(address)

    checks = []
    attribution = build_port_attribution(
        hosting_context,
    )
    shared_provider_edge = (
        attribution["status"]
        == "Provider Edge - Origin Unconfirmed"
    )

    for port in sorted(open_results):
        definition = selected_ports[port]

        check_status = (
            "Attribution Required"
            if shared_provider_edge
            else definition["status"]
        )

        checks.append({
            "name": (
                f"{definition['service']} "
                f"on port {port}"
            ),
            "port": port,
            "service": definition["service"],
            "status": check_status,
            "service_status": definition["status"],
            "severity": definition["severity"],
            "message": definition["message"],
            "addresses": sorted(
                open_results[port]
            ),
            "connection_confirmed": True,
            "banner_collected": False,
            "vulnerability_confirmed": False,
            "attribution": attribution.copy(),
        })

    if checks and shared_provider_edge:
        status = "Attribution Required"
        message = (
            "WebShield confirmed network connections on shared "
            "provider-edge addresses. These are observations, "
            "not confirmed origin-server exposures."
        )

    elif any(
        check["status"] == "Needs Attention"
        for check in checks
    ):
        status = "Needs Attention"
        message = (
            "WebShield found an exposed network service "
            "that should be reviewed."
        )

    elif any(
        check["status"] == "Review"
        for check in checks
    ):
        status = "Review"
        message = (
            "WebShield found network services whose "
            "public exposure should be confirmed."
        )

    elif checks:
        status = "Observed"
        message = (
            "Only expected standard web services were "
            "observed in the controlled port list."
        )

    else:
        status = "Not Observed"
        message = (
            "No open service was confirmed from the "
            "controlled port list."
        )

    return {
        "name": "Open Ports and Services",
        "domain": safe_domain,
        "status": status,
        "message": message,
        "checks": checks,
        "open_port_count": len(checks),
        "ports_tested": len(selected_ports),
        "addresses_tested": addresses,
        "connection_attempt_count": (
            len(selected_ports) * len(addresses)
        ),
        "confidence": "Medium",
        "attribution": attribution,
        "scope": (
            "TCP connection checks against a fixed "
            "verified-only port list"
        ),
        "score_eligible": False,
        "important_note": attribution["message"],
        "safety": {
            "connection_only": True,
            "banner_grabbing": False,
            "authentication_attempted": False,
            "commands_sent": False,
            "exploitation_attempted": False,
        },
    }
