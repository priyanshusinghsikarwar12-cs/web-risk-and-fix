# 🛡️ Web Risk & Fix

> **Clear security evidence. Practical remediation.**  
> An automated web application security assessment platform.

---

## Overview

Web Risk & Fix is a full-stack automated security assessment platform that 
performs multi-layered security analysis across four scan modes and generates 
professional PDF reports with prioritized remediation plans.

Comparable to commercial platforms like **Detectify**, **ImmuniWeb**, 
and **Qualys WAS**.

---

## Architecture — Four Scanner Layers

### 1. Surface Scanners (`/scanners`) — 18 modules
Passive and lightweight checks run on every scan.

| Module | Purpose |
|---|---|
| `ssl.py` | SSL certificate validation, expiry, issuer chain |
| `tls_protocols.py` | TLS 1.0 / 1.1 / 1.2 / 1.3 support detection |
| `headers.py` | HSTS, CSP, X-Frame-Options, Referrer-Policy, Feature-Policy |
| `dns.py` | A, MX, SPF, DMARC, DNSSEC, IPv6 records |
| `dkim.py` | DKIM email authentication validation |
| `cookies.py` | Secure, HttpOnly, SameSite flag analysis |
| `technologies.py` | Framework, library, server fingerprinting |
| `reputation.py` | Google Web Risk API integration |
| `rdap.py` | WHOIS / RDAP domain registration data |
| `domain_trust.py` | CAA records, certificate issuance control |
| `privacy_signals.py` | Cookie consent, privacy policy detection |
| `public_files.py` | robots.txt, security.txt, sitemap.xml |
| `mixed_content.py` | HTTP resources loaded on HTTPS pages |
| `hosting_context.py` | Hosting provider and infrastructure detection |
| `script_inventory.py` | JavaScript file inventory |
| `error_leakage.py` | Stack trace and error information disclosure |
| `health.py` | Website availability and response analysis |
| `connectivity.py` | DNS resolution and network reachability |

---

### 2. Deep Scanners (`/deep_scanners`) — 11 modules
Active verification including OWASP ZAP integration.

| Module | Purpose |
|---|---|
| `crawler.py` | Autonomous application crawler (25+ pages, no form submission) |
| `ports.py` | Port scan: FTP(21), DNS(53), SMTP(587), IMAP(143), MySQL(3306) + more |
| `subdomains.py` | DNS-confirmed subdomain enumeration |
| `cors.py` | Cross-origin resource sharing policy verification |
| `http_methods.py` | TRACE, PUT, DELETE method exposure detection |
| `page_security.py` | Per-page security header verification |
| `form_hygiene.py` | CSRF token and form security validation |
| `query_security.py` | Query parameter injection surface analysis |
| `js_advisories.py` | Known CVEs in detected JavaScript libraries |
| `exposure_checks.py` | Sensitive file and directory exposure |
| `zap_baseline.py` | **OWASP ZAP baseline scan integration** |

---

### 3. Source Scanners (`/source_scanners`) — 4 modules
Static analysis on uploaded or repository source code.

| Module | Purpose |
|---|---|
| `static_analysis.py` | SAST — static application security testing |
| `dependency_inventory.py` | SCA — software composition analysis |
| `dependency_advisories.py` | CVE matching against dependency versions |
| `project_files.py` | Sensitive file detection in source (`.env`, keys) |

---

### 4. Services (`/services`) — 20 modules
Scan orchestration, authenticated testing, and report generation.

| Module | Purpose |
|---|---|
| `scan_engine.py` | Main scan orchestration and pipeline management |
| `deep_scan_engine.py` | Deep scan coordination |
| `source_scan_engine.py` | Source code scan pipeline |
| `authenticated_crawl.py` | **Authenticated session crawling** |
| `authenticated_security.py` | Security testing on login-protected pages |
| `credential_vault.py` | Secure credential management for auth scans |
| `login_session.py` | Login flow automation and session management |
| `logout_invalidation.py` | Session invalidation and token expiry testing |
| `object_access_control.py` | **BOLA / IDOR vulnerability testing** (OWASP API Top 10) |
| `domain_verification.py` | Domain ownership verification |
| `risk_engine.py` | Quantitative risk scoring engine |
| `recommendation_engine.py` | Automated remediation guidance generation |
| `fix_guidance.py` | Plain-English fix suggestions per finding |
| `vulnerability_report.py` | PDF report generation |
| `engagement_profile.py` | Scan scope and engagement configuration |
| `subdomain_scope.py` | Subdomain inclusion/exclusion scoping |
| `development_access.py` | Dev endpoint and staging exposure detection |
| `protected_page.py` | Access control verification on protected routes |
| `source_archive.py` | Source code archiving and version management |
| `homepage_fetcher.py` | Initial homepage analysis and parsing |

---

## Report Output

Each scan produces an **18-page professional PDF** containing:

- **Executive Summary** — Risk totals by severity (Critical/High/Medium/Low), 
  confidence levels, confirmed findings vs. items requiring validation
- **Remediation Action Plan** — Prioritized table with suggested owners and deadlines
- **Confirmed Security Findings** — Directly observed vulnerabilities with evidence
- **Technical Evidence Appendix** — Supporting observations and scanner data
- **Passed & Protected Checks** — Full audit trail of what passed

### Example Output — aitd.ac.in

> Scan type: Normal + Verified Deep Security Assessment  
> Pages crawled: 25  
> Scanners run: 80+

| Severity | Count |
|---|---|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 11 |
| 🔵 Low | 3 |

**Key findings:** Obsolete TLS 1.0/1.1 enabled, missing HSTS/CSP/X-Frame headers, 
CSRF review required, MySQL (3306) internet-accessible, TRACE method exposed, 
technology stack disclosure.

---

## Scan Modes

| Mode | Description |
|---|---|
| **Normal Scan** | Surface scanners — passive, lightweight |
| **Deep Scan** | Active verification + ZAP baseline + crawler + port scan |
| **Authenticated Scan** | Deep scan on login-protected pages with session management |
| **Source Scan** | SAST + SCA on uploaded source code or repository |

---

## Tech Stack

- **Backend:** Python, FastAPI
- **Frontend:** HTML, CSS, Vanilla JS
- **DAST Integration:** OWASP ZAP
- **Report Engine:** Custom PDF generation with professional layout
- **Scanner Engine:** 53 custom Python modules across 4 layers

---

## Run Locally

```bash
git clone https://github.com/priyanshusinghsikarwar12-cs/web-risk-and-fix.git
cd web-risk-and-fix

cd backend
pip install -r requirements.txt
uvicorn main:app --reload

# Frontend
cd ../frontend
python -m http.server 3000
