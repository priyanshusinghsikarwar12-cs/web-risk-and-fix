import dns.exception
import dns.resolver


def make_check(
    name,
    status,
    message,
    record_type,
    values,
    passed=None,
    score_eligible=False,
    error=None,
):
    return {
        "name": name,
        "status": status,
        "message": message,
        "passed": passed,
        "score_eligible": score_eligible,
        "advanced": {
            "record_type": record_type,
            "values": values,
            "error": error,
        },
    }


def resolve_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(
            domain,
            record_type,
        )

        values = [
            answer.to_text()
            for answer in answers
        ]

        return values, None

    except dns.resolver.NXDOMAIN:
        return [], "domain_not_found"

    except dns.resolver.NoAnswer:
        return [], "no_answer"

    except dns.resolver.LifetimeTimeout:
        return [], "lookup_timeout"

    except dns.resolver.NoNameservers:
        return [], "resolver_failure"

    except dns.exception.DNSException as error:
        return [], str(error)


def resolve_txt_records(domain):
    try:
        answers = dns.resolver.resolve(
            domain,
            "TXT",
        )

        values = []

        for answer in answers:
            text = "".join(
                part.decode(
                    "utf-8",
                    errors="replace",
                )
                for part in answer.strings
            )

            values.append(text)

        return values, None

    except dns.resolver.NXDOMAIN:
        return [], "domain_not_found"

    except dns.resolver.NoAnswer:
        return [], "no_answer"

    except dns.resolver.LifetimeTimeout:
        return [], "lookup_timeout"

    except dns.resolver.NoNameservers:
        return [], "resolver_failure"

    except dns.exception.DNSException as error:
        return [], str(error)


def analyze_mx_records(values):
    exchanges = []

    for value in values:
        parts = value.split(maxsplit=1)

        if len(parts) != 2:
            continue

        exchange = parts[1].rstrip(".")
        exchanges.append(exchange)

    has_null_mx = "" in exchanges

    has_normal_mx = any(
        exchange
        for exchange in exchanges
    )

    if has_null_mx and has_normal_mx:
        return {
            "valid": False,
            "accepts_email": None,
            "type": "invalid_mixed_mx",
        }

    if has_null_mx:
        return {
            "valid": True,
            "accepts_email": False,
            "type": "null_mx",
        }

    if has_normal_mx:
        return {
            "valid": True,
            "accepts_email": True,
            "type": "mail_servers",
        }

    return {
        "valid": False,
        "accepts_email": None,
        "type": "no_usable_mx",
    }


def find_policy(values, prefix):
    normalized_prefix = prefix.lower()

    for value in values:
        normalized_value = value.strip().lower()

        if normalized_value.startswith(
            normalized_prefix
        ):
            return value

    return None


def check_dns_records(domain: str):
    checks = []

    # IPv4 website address
    a_values, a_error = resolve_records(domain, "A")

    checks.append(
        make_check(
            name="Website Address",
            status="Configured" if a_values else "Missing",
            message=(
                "Your domain points to a website server."
                if a_values
                else "No IPv4 website address was found."
            ),
            record_type="A",
            values=a_values,
            passed=bool(a_values),
            score_eligible=True,
            error=a_error,
        )
    )

    # Optional IPv6 website address
    aaaa_values, aaaa_error = resolve_records(domain, "AAAA")

    checks.append(
        make_check(
            name="IPv6 Website Address",
            status="Configured" if aaaa_values else "Optional",
            message=(
                "Your domain supports IPv6."
                if aaaa_values
                else "No IPv6 address was found. IPv6 is optional."
            ),
            record_type="AAAA",
            values=aaaa_values,
            passed=True if aaaa_values else None,
            score_eligible=False,
            error=aaaa_error,
        )
    )

    # Email receiving configuration
    mx_values, mx_error = resolve_records(domain, "MX")

    if mx_values:
        mx_result = analyze_mx_records(mx_values)

        if mx_result["type"] == "null_mx":
            mx_status = "Intentionally Disabled"
            mx_message = (
                "This domain intentionally declares that it "
                "does not receive email."
            )
            mx_passed = True

        elif mx_result["type"] == "mail_servers":
            mx_status = "Configured"
            mx_message = "Email receiving servers are configured."
            mx_passed = True

        else:
            mx_status = "Needs Attention"
            mx_message = (
                "The domain has an invalid or conflicting "
                "email configuration."
            )
            mx_passed = False

    else:
        mx_status = "Not Configured"
        mx_message = (
            "No email receiving configuration was found. "
            "This is acceptable if the domain does not use email."
        )
        mx_passed = None

    checks.append(
        make_check(
            name="Email Setup",
            status=mx_status,
            message=mx_message,
            record_type="MX",
            values=mx_values,
            passed=mx_passed,
            score_eligible=False,
            error=mx_error,
        )
    )

    # SPF email-sender policy
    txt_values, txt_error = resolve_txt_records(domain)
    spf_policy = find_policy(txt_values, "v=spf1")

    checks.append(
        make_check(
            name="Email Sender Protection",
            status="Configured" if spf_policy else "Not Configured",
            message=(
                "An SPF email-sender policy was found."
                if spf_policy
                else (
                    "No SPF policy was found. This matters only "
                    "if the domain sends email."
                )
            ),
            record_type="TXT (SPF)",
            values=[spf_policy] if spf_policy else [],
            passed=True if spf_policy else None,
            score_eligible=False,
            error=txt_error,
        )
    )

    # DMARC email-protection policy
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_values, dmarc_error = resolve_txt_records(dmarc_domain)
    dmarc_policy = find_policy(dmarc_values, "v=dmarc1")

    checks.append(
        make_check(
            name="Email Impersonation Protection",
            status="Configured" if dmarc_policy else "Not Configured",
            message=(
                "A DMARC email-protection policy was found."
                if dmarc_policy
                else (
                    "No DMARC policy was found. This matters only "
                    "if the domain uses email."
                )
            ),
            record_type="TXT (DMARC)",
            values=[dmarc_policy] if dmarc_policy else [],
            passed=True if dmarc_policy else None,
            score_eligible=False,
            error=dmarc_error,
        )
    )

    return {
        "status": "Completed",
        "checks": checks,
    }