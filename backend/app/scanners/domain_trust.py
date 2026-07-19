import dns.exception
import dns.resolver


NO_RECORD_ERRORS = {
    "no_answer",
    "domain_not_found",
}


def lookup_dns_records(
    domain,
    record_type,
    resolver=dns.resolver.resolve,
):
    try:
        answers = resolver(domain, record_type)

        return {
            "values": [
                answer.to_text()
                for answer in answers
            ],
            "error": None,
        }

    except dns.resolver.NXDOMAIN:
        return {
            "values": [],
            "error": "domain_not_found",
        }

    except dns.resolver.NoAnswer:
        return {
            "values": [],
            "error": "no_answer",
        }

    except dns.resolver.LifetimeTimeout:
        return {
            "values": [],
            "error": "lookup_timeout",
        }

    except dns.resolver.NoNameservers:
        return {
            "values": [],
            "error": "resolver_failure",
        }

    except dns.exception.DNSException as error:
        return {
            "values": [],
            "error": str(error),
        }


def parse_caa_record(value):
    parts = value.strip().split(maxsplit=2)

    if len(parts) != 3:
        return None

    try:
        flags = int(parts[0])
    except ValueError:
        return None

    tag = parts[1].strip('"').lower()
    record_value = parts[2].strip().strip('"')

    return {
        "flags": flags,
        "tag": tag,
        "value": record_value,
    }


def build_dnssec_check(ds_result, dnskey_result):
    ds_records = ds_result["values"]
    dnskey_records = dnskey_result["values"]
    errors = [
        error
        for error in (
            ds_result["error"],
            dnskey_result["error"],
        )
        if error and error not in NO_RECORD_ERRORS
    ]

    if ds_records and dnskey_records:
        status = "Configured"
        passed = True
        message = (
            "A parent DNSSEC delegation and DNS signing keys "
            "were observed for this domain."
        )
    elif ds_records or dnskey_records:
        status = "Needs Review"
        passed = None
        message = (
            "Only part of the expected DNSSEC record chain was "
            "observed. Confirm the domain's DNSSEC configuration."
        )
    elif errors:
        status = "Unavailable"
        passed = None
        message = (
            "WebShield could not reliably complete the DNSSEC "
            "record lookup."
        )
    else:
        status = "Not Configured"
        passed = None
        message = (
            "No DNSSEC delegation or signing keys were observed. "
            "This is a missing protection, not proof of an attack."
        )

    return {
        "name": "DNS Authenticity Protection",
        "technical_name": "DNSSEC",
        "status": status,
        "message": message,
        "passed": passed,
        "evidence": {
            "ds_record_count": len(ds_records),
            "dnskey_record_count": len(dnskey_records),
            "ds_records": ds_records,
            "dnskey_records": dnskey_records,
            "lookup_errors": errors,
        },
        "limitation": (
            "This check observes public DS and DNSKEY records. "
            "It does not independently validate every signature "
            "from the DNS root to the domain."
        ),
    }


def build_caa_check(caa_result):
    records = [
        parsed
        for value in caa_result["values"]
        if (parsed := parse_caa_record(value)) is not None
    ]

    issue_records = [
        record
        for record in records
        if record["tag"] == "issue"
    ]
    issuewild_records = [
        record
        for record in records
        if record["tag"] == "issuewild"
    ]
    reporting_contacts = [
        record["value"]
        for record in records
        if record["tag"] == "iodef"
        and record["value"]
    ]

    standard_authorities = sorted(
        {
            record["value"].split(";", 1)[0].strip()
            for record in issue_records
            if record["value"].split(";", 1)[0].strip()
        }
    )
    wildcard_authorities = sorted(
        {
            record["value"].split(";", 1)[0].strip()
            for record in issuewild_records
            if record["value"].split(";", 1)[0].strip()
        }
    )
    authorities = sorted(
        set(standard_authorities)
        | set(wildcard_authorities)
    )

    if issue_records:
        standard_policy = (
            "Restricted"
            if standard_authorities
            else "Issuance Blocked"
        )
    else:
        standard_policy = "Not Restricted by CAA"

    if issuewild_records:
        wildcard_policy = (
            "Restricted"
            if wildcard_authorities
            else "Issuance Blocked"
        )
    elif issue_records:
        wildcard_policy = (
            "Follows Standard Policy"
        )
    else:
        wildcard_policy = "Not Restricted by CAA"

    restriction_records = (
        issue_records + issuewild_records
    )

    if restriction_records:
        status = "Configured"
        passed = True
        if authorities:
            policy_summary = (
                "Certificate issuance is restricted to the named "
                "certificate authorities."
            )
        elif issue_records and issuewild_records:
            policy_summary = (
                "The observed CAA rules request that no authority "
                "issue standard or wildcard certificates."
            )
        elif issue_records:
            policy_summary = (
                "The observed CAA rule requests that no authority "
                "issue standard certificates; wildcard handling "
                "follows that standard policy."
            )
        else:
            policy_summary = (
                "The observed CAA rule blocks wildcard certificate "
                "issuance but does not restrict standard certificates."
            )

        message = policy_summary
    elif records:
        status = "Observed, Not Restrictive"
        passed = None
        policy_summary = (
            "CAA records were observed, but none of them use the "
            "issue or issuewild tags that restrict issuance."
        )
        message = policy_summary
    elif caa_result["error"] in NO_RECORD_ERRORS:
        status = "Not Configured"
        passed = None
        policy_summary = (
            "No certificate-issuance restriction was observed."
        )
        message = (
            "No CAA rule was observed at this domain. Certificate "
            "authorities will rely on their normal validation rules."
        )
    elif caa_result["error"]:
        status = "Unavailable"
        passed = None
        policy_summary = "CAA policy could not be determined."
        message = (
            "WebShield could not reliably complete the CAA lookup."
        )
    else:
        status = "Not Configured"
        passed = None
        policy_summary = (
            "No certificate-issuance restriction was observed."
        )
        message = (
            "No CAA rule was observed at this domain. Certificate "
            "authorities will rely on their normal validation rules."
        )

    return {
        "name": "Certificate Issuance Control",
        "technical_name": "CAA",
        "status": status,
        "message": message,
        "passed": passed,
        "evidence": {
            "record_count": len(records),
            "restriction_record_count": len(
                restriction_records
            ),
            "records": records,
            "authorized_authorities": authorities,
            "standard_authorities": standard_authorities,
            "wildcard_authorities": wildcard_authorities,
            "standard_certificate_policy": standard_policy,
            "wildcard_certificate_policy": wildcard_policy,
            "reporting_contacts": reporting_contacts,
            "policy_summary": policy_summary,
            "lookup_error": caa_result["error"],
        },
        "limitation": (
            "This check reports CAA records returned for the scanned "
            "domain. It does not test certificate-authority behavior."
        ),
    }


def check_domain_trust(
    domain,
    lookup=lookup_dns_records,
):
    ds_result = lookup(domain, "DS")
    dnskey_result = lookup(domain, "DNSKEY")
    caa_result = lookup(domain, "CAA")

    dnssec_check = build_dnssec_check(
        ds_result,
        dnskey_result,
    )
    caa_check = build_caa_check(caa_result)
    checks = [dnssec_check, caa_check]

    configured_count = sum(
        check["status"] == "Configured"
        for check in checks
    )
    unavailable_count = sum(
        check["status"] == "Unavailable"
        for check in checks
    )

    if configured_count == 2:
        status = "Protected"
        message = (
            "DNS authenticity and certificate-issuance controls "
            "were both observed."
        )
    elif unavailable_count == 2:
        status = "Unavailable"
        message = (
            "The domain-trust DNS lookups could not be completed."
        )
    elif configured_count == 1:
        status = "Partially Configured"
        message = (
            "One of the two optional domain-trust protections was "
            "observed. Review the other check before making changes."
        )
    else:
        status = "Not Configured"
        message = (
            "DNSSEC and CAA protections were not fully observed. "
            "This does not mean the website is currently compromised."
        )

    return {
        "name": "Domain Trust",
        "domain": domain,
        "status": status,
        "message": message,
        "confidence": (
            "High"
            if unavailable_count == 0
            else "Limited"
        ),
        "checks": checks,
        "scope": "Public DS, DNSKEY, and CAA records only",
        "score_eligible": False,
    }
