import time
from collections import deque
from html.parser import HTMLParser
from urllib.parse import (
    parse_qsl,
    urljoin,
    urlsplit,
    urlunsplit,
)

import requests
from app.utils.domain import clean_domain
from app.utils.safe_http import safe_get
from app.deep_scanners.form_hygiene import (
    analyze_form_hygiene,
)
from app.deep_scanners.page_security import (
    analyze_page_security,
    summarize_page_security,
)

SKIPPED_EXTENSIONS = {
    ".7z",
    ".avi",
    ".css",
    ".doc",
    ".docx",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".mov",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".rar",
    ".svg",
    ".tar",
    ".webp",
    ".woff",
    ".woff2",
    ".xls",
    ".xlsx",
    ".zip",
}

RISKY_PATH_TERMS = {
    "delete",
    "destroy",
    "logout",
    "remove",
    "signout",
    "unsubscribe",
}

LOGIN_TERMS = {
    "admin",
    "auth",
    "log-in",
    "login",
    "sign-in",
    "signin",
}


class CrawlPageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)

        self.links = []
        self.forms = []
        self.title_parts = []

        self.current_link = None
        self.current_form = None
        self.inside_title = False

    def handle_starttag(self, tag, attributes):
        tag = tag.lower()
        attribute_map = dict(attributes)

        if tag == "title":
            self.inside_title = True

        if tag == "a":
            self.current_link = {
                "href": str(
                    attribute_map.get("href", "")
                ).strip(),
                "text_parts": [],
            }

        if tag == "form":
            self.current_form = {
                "action": str(
                    attribute_map.get("action", "")
                ).strip(),
                "method": str(
                    attribute_map.get("method", "get")
                ).upper(),
                "fields": [],
                "has_password_field": False,
            }

        if (
            self.current_form is not None
            and tag in {
                "input",
                "button",
                "select",
                "textarea",
            }
        ):
            field_type = str(
                attribute_map.get(
                    "type",
                    tag,
                )
            ).lower()

            field = {
                "name": str(
                    attribute_map.get("name", "")
                ),
                "type": field_type,
                "autocomplete": str(
                    attribute_map.get(
                        "autocomplete",
                        "",
                    )
                ),
            }

            self.current_form["fields"].append(field)

            if field_type == "password":
                self.current_form[
                    "has_password_field"
                ] = True

    def handle_data(self, data):
        clean_text = " ".join(data.split())

        if not clean_text:
            return

        if self.inside_title:
            self.title_parts.append(clean_text)

        if self.current_link is not None:
            self.current_link[
                "text_parts"
            ].append(clean_text)

    def handle_endtag(self, tag):
        tag = tag.lower()

        if tag == "title":
            self.inside_title = False

        if tag == "a" and self.current_link:
            self.links.append({
                "href": self.current_link["href"],
                "text": " ".join(
                    self.current_link["text_parts"]
                ),
            })

            self.current_link = None

        if tag == "form" and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None


def inspect_candidate_url(
    base_url: str,
    href: str,
    domain: str,
):
    href = href.strip()

    if not href or href.startswith((
        "#",
        "javascript:",
        "mailto:",
        "tel:",
        "data:",
    )):
        return None

    absolute_url = urljoin(base_url, href)
    parsed = urlsplit(absolute_url)

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        return None

    hostname = (
        parsed.hostname.lower()
        if parsed.hostname
        else ""
    )

    path = parsed.path or "/"
    lower_path = path.lower()

    parameter_names = sorted({
        name
        for name, _ in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )
        if name
    })

    normalized_url = urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        path,
        "",
        "",
    ))

    extension_skipped = any(
        lower_path.endswith(extension)
        for extension in SKIPPED_EXTENSIONS
    )

    risky_path = any(
        term in {
            segment
            for segment in lower_path.split("/")
            if segment
        }
        for term in RISKY_PATH_TERMS
    )

    internal = hostname == domain
    secure = parsed.scheme.lower() == "https"

    return {
        "url": absolute_url,
        "crawl_url": normalized_url,
        "hostname": hostname,
        "internal": internal,
        "secure": secure,
        "parameter_names": parameter_names,
        "risky_path": risky_path,
        "extension_skipped": extension_skipped,
        "crawlable": (
            internal
            and secure
            and not risky_path
            and not extension_skipped
        ),
    }


def analyze_crawl_page(
    html_content: str,
    page_url: str,
    domain: str,
):
    parser = CrawlPageParser()
    parser.feed(html_content)

    internal_urls = set()
    external_hosts = set()
    parameter_names = set()
    skipped_urls = []
    login_surfaces = []

    for link in parser.links:
        candidate = inspect_candidate_url(
            page_url,
            link["href"],
            domain,
        )

        if candidate is None:
            continue

        parameter_names.update(
            candidate["parameter_names"]
        )

        if not candidate["internal"]:
            if candidate["hostname"]:
                external_hosts.add(
                    candidate["hostname"]
                )
            continue

        link_text = link["text"].lower()
        link_path = urlsplit(
            candidate["url"]
        ).path.lower()

        if any(
            term in link_text or term in link_path
            for term in LOGIN_TERMS
        ):
            login_surfaces.append({
                "type": "Login Link",
                "url": candidate["url"],
                "evidence": (
                    link["text"]
                    or "Login-related URL"
                ),
            })

        if candidate["crawlable"]:
            internal_urls.add(
                candidate["crawl_url"]
            )
        else:
            skipped_urls.append({
                "url": candidate["url"],
                "reason": (
                    "Potentially state-changing path"
                    if candidate["risky_path"]
                    else
                    "Insecure HTTP link"
                    if not candidate["secure"]
                    else
                    "Non-HTML resource type"
                ),
            })

    forms = []

    for form in parser.forms:
        action = form["action"] or page_url

        inspected_action = inspect_candidate_url(
            page_url,
            action,
            domain,
        )

        form_result = {
            **form,
            "page_url": page_url,
            "action_url": (
                inspected_action["url"]
                if inspected_action
                else page_url
            ),
            "internal_action": (
                inspected_action["internal"]
                if inspected_action
                else True
            ),
        }

        forms.append(form_result)

        for field in form["fields"]:
            if field["name"]:
                parameter_names.add(
                    field["name"]
                )

        if form["has_password_field"]:
            login_surfaces.append({
                "type": "Password Form",
                "url": page_url,
                "evidence": (
                    "A password input field was observed."
                ),
            })

    return {
        "title": " ".join(
            parser.title_parts
        ).strip(),
        "internal_urls": sorted(internal_urls),
        "external_hosts": sorted(external_hosts),
        "parameter_names": sorted(parameter_names),
        "forms": forms,
        "login_surfaces": login_surfaces,
        "skipped_urls": skipped_urls,
    }


def crawl_verified_site(
    domain: str,
    max_pages: int = 25,
    max_depth: int = 2,
    delay_seconds: float = 0.2,
    start_url: str | None = None,
    session=None,
    authenticated: bool = False,
    allow_invalid_tls: bool = False,
):
    safe_domain = clean_domain(domain)

    if not 1 <= max_pages <= 50:
        raise ValueError(
            "The crawler page limit must be "
            "between 1 and 50."
        )

    if not 0 <= max_depth <= 3:
        raise ValueError(
            "The crawler depth must be "
            "between 0 and 3."
        )

    if not 0 <= delay_seconds <= 2:
        raise ValueError(
            "The crawler delay must be "
            "between 0 and 2 seconds."
        )

    start_url = start_url or f"https://{safe_domain}/"
    start_location = urlsplit(start_url)
    if (
        start_location.scheme.lower() != "https"
        or (start_location.hostname or "").lower() != safe_domain
        or start_location.username
        or start_location.password
        or start_location.port not in (None, 443)
    ):
        raise ValueError(
            "The crawler start URL must use the verified HTTPS hostname."
        )
    queue = deque([(start_url, 0)])
    queued_urls = {start_url}
    visited_urls = set()

    pages = []
    page_security_results = []
    forms = []   
    parameters = set()
    login_surfaces = []
    external_hosts = set()
    skipped_urls = []
    errors = []

    while queue and len(pages) < max_pages:
        current_url, depth = queue.popleft()

        if current_url in visited_urls:
            continue

        visited_urls.add(current_url)

        try:
            request_options = {
                "timeout": 10,
                "max_bytes": 500000,
                "allowed_redirect_host": safe_domain,
                "redirect_delay_seconds": delay_seconds,
                "verify_tls": not allow_invalid_tls,
            }
            if session is not None:
                request_options["session"] = session
            response = safe_get(current_url, **request_options)

            final_url = response.url
            final_location = urlsplit(final_url)

            if (
                final_location.scheme.lower()
                != "https"
                or (
                    final_location.hostname or ""
                ).lower() != safe_domain
            ):
                errors.append({
                    "url": current_url,
                    "error": (
                        "The page redirected outside "
                        "the verified HTTPS hostname."
                    ),
                })
                continue

            content_type = response.headers.get(
                "Content-Type",
                "",
            ).lower()

            page_result = {
                "url": final_url,
                "depth": depth,
                "status_code": response.status_code,
                "content_type": content_type,
                "content_truncated": getattr(
                    response,
                    "webshield_content_truncated",
                    False,
                ),
                "tls_verified": getattr(
                    response,
                    "webshield_tls_verified",
                    True,
                ),
            }

            if "text/html" not in content_type:
                page_result["title"] = ""
                pages.append(page_result)
                continue

            analysis = analyze_crawl_page(
                response.text,
                final_url,
                safe_domain,
            )
            page_security_result = (
                analyze_page_security(response)
            )

            page_security_results.append(
                page_security_result
            )

            page_result["security_status"] = (
                page_security_result["status"]
            )
                    

            page_result["title"] = analysis["title"]
            pages.append(page_result)

            forms.extend(analysis["forms"])
            parameters.update(
                analysis["parameter_names"]
            )
            login_surfaces.extend(
                analysis["login_surfaces"]
            )
            external_hosts.update(
                analysis["external_hosts"]
            )
            skipped_urls.extend(
                analysis["skipped_urls"]
            )

            if depth < max_depth:
                for discovered_url in (
                    analysis["internal_urls"]
                ):
                    if (
                        discovered_url
                        not in visited_urls
                        and discovered_url
                        not in queued_urls
                    ):
                        queue.append((
                            discovered_url,
                            depth + 1,
                        ))
                        queued_urls.add(
                            discovered_url
                        )

        except requests.RequestException as error:
            errors.append({
                "url": current_url,
                "error_type": type(error).__name__,
                "error": (
                    "The page could not be downloaded."
                ),
            })

        if queue and delay_seconds:
            time.sleep(delay_seconds)

    if not pages:
        status = "Unavailable"
        message = (
            "The controlled crawler could not inspect "
            "any HTML pages."
        )
    elif errors:
        status = "Partial"
        message = (
            f"WebShield inspected {len(pages)} page(s), "
            "but some pages could not be processed."
        )
    else:
        status = "Completed"
        message = (
            f"WebShield safely inspected {len(pages)} "
            "page(s) without submitting forms."
        )
    form_hygiene = analyze_form_hygiene(forms)  
    page_security = summarize_page_security(
        page_security_results
    )          

    return {
        "name": "Verified Application Crawler",
        "domain": safe_domain,
        "authenticated": bool(authenticated),
        "start_url": start_url,
        "status": status,
        "message": message,
        "pages_scanned": len(pages),
        "page_limit": max_pages,
        "depth_limit": max_depth,
        "limit_reached": bool(queue),
        "pages": pages,
        "forms": forms,
        "form_count": len(forms),
        "form_hygiene": form_hygiene,
        "page_security": page_security,
        "parameter_names": sorted(parameters),
        "parameter_count": len(parameters),
        "login_surfaces": login_surfaces,
        "login_surface_count": len(
            login_surfaces
        ),
        "external_hosts": sorted(
            external_hosts
        ),
        "skipped_urls": skipped_urls[:50],
        "errors": errors[:50],
        "safety": {
            "http_methods": ["GET"],
            "forms_submitted": False,
            "same_verified_hostname_only": True,
            "rate_delay_seconds": delay_seconds,
        },
    }
