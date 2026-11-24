# 🛡️ Web Risk & Fix

> **Clear security evidence. Practical remediation.**

A comprehensive automated web security assessment platform that scans domains 
and generates professional PDF security reports with prioritized remediation plans.

---

## 📋 What It Does

Web Risk & Fix performs a **Normal and Verified Deep Security Assessment** on 
any domain, running 80+ scanners across 15+ security categories and producing 
a structured, professional-grade report — similar to commercial tools like 
Detectify or ImmuniWeb.

---

## 🔍 Scanner Categories

| Category | What It Checks |
|---|---|
| **Deep Security Scan** | Certificate validation, cross-origin access, sensitive exposure |
| **Application Crawler** | Crawls up to 25+ pages autonomously without submitting forms |
| **Open Ports & Services** | FTP (21), DNS (53), SMTP (587), IMAP (143), POP3 (110), MySQL (3306), and more |
| **Security Headers** | HSTS, CSP, X-Frame-Options, Feature-Policy, Referrer-Policy, X-Content-Type |
| **TLS Protocol Security** | TLS 1.0 / 1.1 / 1.2 / 1.3 support and configuration |
| **DNS Records** | SPF, DMARC, DNSSEC, MX, A/AAAA records |
| **Subdomain Discovery** | DNS-confirmed subdomains (lms, mail, webmail, www, etc.) |
| **Domain Trust** | CAA records, certificate issuance control, DNSSEC delegation |
| **Technology Detection** | Application framework, frontend library, server fingerprinting |
| **HTTP Method Exposure** | TRACE, PUT, DELETE method detection |
| **Cookie Security** | Secure, HttpOnly, SameSite flags |
| **CORS Configuration** | Cross-origin resource sharing policy analysis |
| **Privacy Signals** | Cookie consent, privacy policy detection |
| **Public Security Files** | robots.txt, security.txt, sitemap.xml |
| **Website Reputation** | Google Web Risk integration |
| **JavaScript Inventory** | Referenced JS files and known vulnerability advisories |

---

## 📄 Report Output

Generates an **18-page professional PDF** containing:

1. **Executive Summary** — Risk totals (Critical / High / Medium / Low), 
   confidence levels, and assessment scope
2. **Remediation Action Plan** — Prioritized findings with suggested owners 
   and target deadlines
3. **Confirmed Security Findings** — Directly observed vulnerabilities with 
   evidence records
4. **Items Requiring Confirmation** — Observations needing human validation
5. **Methodology and Limitations** — Testing boundaries and coverage notes
6. **Appendix A: Technical Evidence** — Supporting observations
7. **Appendix B: Passed & Protected Checks** — What passed clean

### Sample Report Output (aitd.ac.in)

| Severity | Count |
|---|---|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 11 |
| 🔵 Low | 3 |

**Findings included:** Clickjacking protection missing, CSP missing, 
Obsolete TLS 1.0/1.1 enabled, CSRF protection review required, 
Technology stack disclosure, TRACE method exposed, and more.

---

## 🚀 Tech Stack

- **Backend:** Python (FastAPI)
- **Frontend:** HTML, CSS, Vanilla JS
- **Report Generation:** PDF with branded layout
- **Scanners:** Custom-built Python scanner modules (80+ checks)

---

## ⚙️ Run Locally

```bash
git clone https://github.com/priyanshusinghsikarwar12-cs/web-risk-and-fix.git
cd web-risk-and-fix

# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload

# Frontend — open in browser
cd ../frontend
python -m http.server 3000
