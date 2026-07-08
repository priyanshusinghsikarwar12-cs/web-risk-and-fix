import dns.resolver


DNS_RECORDS = {
    "A": "Website Address",
    "AAAA": "IPv6 Website Address",
    "MX": "Email Setup",
    "TXT": "Domain Verification & Email Protection",
}


def check_dns_records(domain: str):
    checks = []

    for record_type, friendly_name in DNS_RECORDS.items():
        try:
            answers = dns.resolver.resolve(domain, record_type)
            values = [answer.to_text() for answer in answers]

            checks.append({
                "name": friendly_name,
                "status": "Found",
                "message": f"{friendly_name} records were found.",
                "advanced": {
                    "record_type": record_type,
                    "values": values,
                },
            })

        except Exception:
            checks.append({
                "name": friendly_name,
                "status": "Missing",
                "message": f"{friendly_name} records were not found.",
                "advanced": {
                    "record_type": record_type,
                    "values": [],
                },
            })

    return {
        "name": "Domain Setup",
        "checks": checks,
    }