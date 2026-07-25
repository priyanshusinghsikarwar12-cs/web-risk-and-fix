import ipaddress
import socket

import requests

from app.utils.safe_http import safe_get


EDGE_PROVIDERS = (
    {
        "name": "Cloudflare",
        "category": "CDN / reverse proxy",
        "headers": ("cf-ray", "cf-cache-status"),
        "server_terms": ("cloudflare",),
    },
    {
        "name": "GitHub Pages",
        "category": "Managed static hosting",
        "headers": ("x-github-request-id",),
        "server_terms": ("github.com",),
    },
    {
        "name": "Vercel",
        "category": "Managed application hosting",
        "headers": ("x-vercel-id", "x-vercel-cache"),
        "server_terms": ("vercel",),
    },
    {
        "name": "Netlify",
        "category": "Managed static hosting",
        "headers": ("x-nf-request-id",),
        "server_terms": ("netlify",),
    },
    {
        "name": "Amazon CloudFront",
        "category": "CDN / reverse proxy",
        "headers": ("x-amz-cf-id", "x-amz-cf-pop"),
        "server_terms": ("cloudfront",),
    },
    {
        "name": "Fastly",
        "category": "CDN / reverse proxy",
        "headers": ("x-served-by", "x-fastly-request-id"),
        "server_terms": ("fastly",),
    },
    {
        "name": "Akamai",
        "category": "CDN / reverse proxy",
        "headers": ("akamai-grn", "x-akamai-transformed"),
        "server_terms": ("akamai",),
    },
)

REVERSE_DNS_PROVIDERS = (
    {
        "suffix": "webhostbox.net",
        "name": "WebHostBox",
        "category": "Shared web hosting",
    },
    {
        "suffix": "amazonaws.com",
        "name": "Amazon Web Services",
        "category": "Cloud hosting",
    },
    {
        "suffix": "googleusercontent.com",
        "name": "Google Cloud",
        "category": "Cloud hosting",
    },
    {
        "suffix": "digitalocean.com",
        "name": "DigitalOcean",
        "category": "Cloud hosting",
    },
)


def detect_managed_provider(headers):
    normalized = {
        str(name).lower(): str(value)
        for name, value in headers.items()
    }
    server = normalized.get("server", "").lower()

    for provider in EDGE_PROVIDERS:
        evidence = []

        for header in provider["headers"]:
            if header in normalized:
                evidence.append(
                    f"Response included the {header} header."
                )

        if any(
            term in server
            for term in provider["server_terms"]
        ):
            evidence.append(
                "The public Server header matched this provider."
            )

        if evidence:
            return {
                "name": provider["name"],
                "category": provider["category"],
                "confidence": (
                    "High" if len(evidence) >= 2 else "Medium"
                ),
                "evidence": evidence,
            }

    return {
        "name": None,
        "category": "Not identified",
        "confidence": "None",
        "evidence": [],
    }


def resolve_public_addresses(domain, resolver=socket.getaddrinfo):
    records = resolver(
        domain,
        443,
        type=socket.SOCK_STREAM,
    )
    addresses = []

    for record in records:
        address = record[4][0]
        parsed = ipaddress.ip_address(address)

        if not parsed.is_global:
            continue

        item = {
            "address": parsed.compressed,
            "version": f"IPv{parsed.version}",
            "reverse_dns": None,
        }

        if item not in addresses:
            addresses.append(item)

    return addresses


def add_reverse_dns(addresses, reverse_lookup=socket.gethostbyaddr):
    results = []

    for item in addresses:
        result = item.copy()

        try:
            result["reverse_dns"] = reverse_lookup(
                item["address"]
            )[0].rstrip(".").lower()
        except (socket.herror, socket.gaierror, OSError):
            result["reverse_dns"] = None

        results.append(result)

    return results


def infer_provider_from_reverse_dns(addresses):
    for item in addresses:
        hostname = str(
            item.get("reverse_dns") or ""
        ).lower()
        for provider in REVERSE_DNS_PROVIDERS:
            if (
                hostname == provider["suffix"]
                or hostname.endswith(
                    f".{provider['suffix']}"
                )
            ):
                evidence = [
                    (
                        "The public IP reverse-DNS hostname ends in "
                        f"{provider['suffix']}."
                    )
                ]
                if "plesk" in hostname:
                    evidence.append(
                        "The reverse-DNS hostname also references Plesk."
                    )
                return {
                    "name": provider["name"],
                    "category": provider["category"],
                    "confidence": "Medium",
                    "evidence": evidence,
                }

    return None


def classify_shared_infrastructure(provider):
    category = provider["category"]

    if category in {
        "Managed static hosting",
        "Managed application hosting",
        "Shared web hosting",
    }:
        return {
            "status": "Likely Shared",
            "message": (
                "The website appears to use a managed hosting platform "
                "where infrastructure is normally shared between customers."
            ),
            "confidence": provider["confidence"],
        }

    if category == "CDN / reverse proxy":
        return {
            "status": "Shared Edge Observed",
            "message": (
                "The public address appears to be a shared CDN or proxy "
                "edge. It may not be the website's origin server."
            ),
            "confidence": provider["confidence"],
        }

    return {
        "status": "Not Determined",
        "message": (
            "A single external request cannot reliably prove whether "
            "the origin server is shared or dedicated."
        ),
        "confidence": "None",
    }


def check_hosting_context(
    domain: str,
    response=None,
    resolver=socket.getaddrinfo,
    reverse_lookup=socket.gethostbyaddr,
    fetcher=safe_get,
):
    fetch_error = None

    if response is None:
        try:
            response = fetcher(
                f"https://{domain}",
                timeout=10,
            )
        except requests.RequestException as error:
            fetch_error = type(error).__name__

    headers = response.headers if response is not None else {}
    provider = detect_managed_provider(headers)
    addresses = add_reverse_dns(
        resolve_public_addresses(domain, resolver),
        reverse_lookup,
    )
    if not provider["name"]:
        reverse_provider = infer_provider_from_reverse_dns(
            addresses
        )
        if reverse_provider:
            provider = reverse_provider
    sharing = classify_shared_infrastructure(provider)

    if provider["name"]:
        status = "Hosting Provider Observed"
        message = (
            f"WebShield found evidence that the public website uses "
            f"{provider['name']}."
        )
    else:
        status = "Hosting Context Observed"
        message = (
            "WebShield recorded the public hosting addresses, but could "
            "not identify the provider from reliable response evidence."
        )

    return {
        "name": "Hosting and Infrastructure Context",
        "domain": domain,
        "status": status,
        "message": message,
        "provider": provider,
        "addresses": addresses,
        "address_count": len(addresses),
        "shared_infrastructure": sharing,
        "attribution_note": (
            "Ports and network services observed on a CDN, reverse proxy, "
            "or shared host may belong to the provider rather than the "
            "website owner. Confirm the origin before assigning findings."
        ),
        "scope": "Public DNS and initial homepage response only",
        "homepage_evidence_available": response is not None,
        "homepage_fetch_error": fetch_error,
        "score_eligible": False,
    }
