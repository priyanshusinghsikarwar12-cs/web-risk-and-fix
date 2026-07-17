import base64
import re

from app.scanners.dns import resolve_txt_records
from app.utils.domain import clean_domain


SELECTOR_LABEL_PATTERN = re.compile(
    r"^[a-z0-9_]"
    r"(?:[a-z0-9_-]{0,61}[a-z0-9_])?$",
    re.IGNORECASE,
)

BASE64_PATTERN = re.compile(
    r"^[A-Za-z0-9+/]*={0,2}$"
)


class DKIMSelectorError(ValueError):
    pass


def clean_selector(selector):
    if not isinstance(selector, str):
        raise DKIMSelectorError(
            "Enter the DKIM selector used by the email provider."
        )

    clean_value = selector.strip().lower().rstrip(".")

    if not clean_value or len(clean_value) > 253:
        raise DKIMSelectorError(
            "The DKIM selector is invalid."
        )

    labels = clean_value.split(".")

    if any(
        not SELECTOR_LABEL_PATTERN.fullmatch(label)
        for label in labels
    ):
        raise DKIMSelectorError(
            "The DKIM selector contains invalid characters."
        )

    return clean_value


def build_dkim_record_name(domain, selector):
    clean_domain_name = clean_domain(domain)
    clean_selector_name = clean_selector(selector)

    return (
        f"{clean_selector_name}."
        f"_domainkey.{clean_domain_name}"
    )


def parse_dkim_tags(record):
    tags = {}
    tag_order = []

    for section in record.split(";"):
        section = section.strip()

        if not section:
            continue

        if "=" not in section:
            return None, "invalid_tag"

        name, value = section.split("=", 1)

        name = name.strip().lower()
        value = value.strip()

        if not name or name in tags:
            return None, "duplicate_or_empty_tag"

        tags[name] = value
        tag_order.append(name)

    return {
        "tags": tags,
        "tag_order": tag_order,
    }, None


def valid_public_key(value):
    normalized_value = re.sub(
        r"\s+",
        "",
        value,
    )

    if not normalized_value:
        return False

    if not BASE64_PATTERN.fullmatch(normalized_value):
        return False

    padded_value = normalized_value + (
        "=" * ((4 - len(normalized_value) % 4) % 4)
    )

    try:
        decoded_value = base64.b64decode(
            padded_value,
            validate=True,
        )
    except (ValueError, base64.binascii.Error):
        return False

    return bool(decoded_value)


def analyze_dkim_records(
    values,
    domain,
    selector,
    lookup_error=None,
):
    record_name = build_dkim_record_name(
        domain,
        selector,
    )

    base_result = {
        "name": "DKIM Email Signing",
        "domain": clean_domain(domain),
        "selector": clean_selector(selector),
        "record_name": record_name,
        "source": "DNS TXT record",
        "score_eligible": False,
    }

    if not values:
        if lookup_error in {
            "lookup_timeout",
            "resolver_failure",
        }:
            return {
                **base_result,
                "status": "Unavailable",
                "message": (
                    "The DKIM DNS lookup could not be "
                    "completed."
                ),
                "confidence": "Unavailable",
                "public_key_present": None,
                "key_type": None,
                "error": lookup_error,
            }

        return {
            **base_result,
            "status": "Not Found",
            "message": (
                "No DKIM record was found for this "
                "specific selector. The domain may use "
                "a different selector."
            ),
            "confidence": "High",
            "public_key_present": False,
            "key_type": None,
            "error": lookup_error,
        }

    if len(values) != 1:
        return {
            **base_result,
            "status": "Invalid",
            "message": (
                "Multiple TXT records were returned for "
                "this DKIM selector. DKIM expects one "
                "usable key record."
            ),
            "confidence": "High",
            "public_key_present": None,
            "key_type": None,
            "error": "multiple_records",
        }

    parsed_record, parsing_error = parse_dkim_tags(
        values[0]
    )

    if parsing_error:
        return {
            **base_result,
            "status": "Invalid",
            "message": (
                "The DKIM record contains invalid or "
                "duplicate tags."
            ),
            "confidence": "High",
            "public_key_present": None,
            "key_type": None,
            "error": parsing_error,
        }

    tags = parsed_record["tags"]
    tag_order = parsed_record["tag_order"]

    version = tags.get("v")

    if version is not None:
        if version != "DKIM1":
            return {
                **base_result,
                "status": "Invalid",
                "message": (
                    "The DKIM record uses an unsupported "
                    "version."
                ),
                "confidence": "High",
                "public_key_present": None,
                "key_type": None,
                "error": "invalid_version",
            }

        if tag_order[0] != "v":
            return {
                **base_result,
                "status": "Invalid",
                "message": (
                    "The DKIM version tag must appear "
                    "first in the record."
                ),
                "confidence": "High",
                "public_key_present": None,
                "key_type": None,
                "error": "version_not_first",
            }

    if "p" not in tags:
        return {
            **base_result,
            "status": "Invalid",
            "message": (
                "The DKIM record does not contain the "
                "required public-key tag."
            ),
            "confidence": "High",
            "public_key_present": False,
            "key_type": tags.get("k", "rsa"),
            "error": "public_key_missing",
        }

    if not tags["p"].strip():
        return {
            **base_result,
            "status": "Revoked",
            "message": (
                "The DKIM selector exists, but its public "
                "key has been revoked."
            ),
            "confidence": "High",
            "public_key_present": False,
            "key_type": tags.get("k", "rsa"),
            "error": "public_key_revoked",
        }

    key_type = tags.get("k", "rsa").lower()

    if key_type not in {"rsa", "ed25519"}:
        return {
            **base_result,
            "status": "Unsupported",
            "message": (
                "The DKIM record uses a key type that "
                "WebShield does not currently validate."
            ),
            "confidence": "Limited",
            "public_key_present": True,
            "key_type": key_type,
            "error": "unsupported_key_type",
        }

    if not valid_public_key(tags["p"]):
        return {
            **base_result,
            "status": "Invalid",
            "message": (
                "The DKIM public key is not valid "
                "base64-encoded data."
            ),
            "confidence": "High",
            "public_key_present": True,
            "key_type": key_type,
            "error": "invalid_public_key",
        }

    return {
        **base_result,
        "status": "Configured",
        "message": (
            "A DKIM record with a syntactically valid "
            "public key was found for this selector."
        ),
        "confidence": "Medium",
        "public_key_present": True,
        "key_type": key_type,
        "error": None,
    }


def check_dkim(domain, selector=None):
    clean_domain_name = clean_domain(domain)

    if selector is None or not str(selector).strip():
        return {
            "name": "DKIM Email Signing",
            "domain": clean_domain_name,
            "selector": None,
            "record_name": None,
            "status": "Selector Required",
            "message": (
                "Enter the DKIM selector used by your "
                "email provider to validate its signing key."
            ),
            "confidence": "Not Tested",
            "source": "DNS TXT record",
            "score_eligible": False,
            "public_key_present": None,
            "key_type": None,
            "error": None,
        }

    clean_selector_name = clean_selector(selector)

    record_name = build_dkim_record_name(
        clean_domain_name,
        clean_selector_name,
    )

    values, lookup_error = resolve_txt_records(
        record_name
    )

    return analyze_dkim_records(
        values,
        clean_domain_name,
        clean_selector_name,
        lookup_error,
    )