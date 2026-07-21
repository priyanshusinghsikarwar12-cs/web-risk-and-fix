# WebShield Project Memory

Last updated: 18 July 2026

## Product Goal

Build WebShield into a trustworthy one-stop security assessment platform
that combines:

- safe public website and infrastructure checks;
- ownership-gated deep scanning;
- hosting and shared-infrastructure context;
- permission-based server-side source-code analysis;
- plain-English findings, evidence, priorities, and fixes.

WebShield automates repeatable assessment work. It does not claim that a
single automated scan replaces every manual penetration test.

## Project Locations

```text
Project:  D:\projects\webshield
Backend:  D:\projects\webshield\backend
Frontend: D:\projects\webshield\frontend
```

## Verified Baseline

- FastAPI public and authorized deep-scan workflows exist.
- React/Vite public and deep-scan reporting interfaces exist.
- Ownership verification and development-only authorized access exist.
- CORS and HTTP-method exposure are integrated into deep scanning.
- Last user-confirmed backend baseline: 286 tests passed.
- Last user-confirmed frontend production build: passed, 19 modules.

## Current Milestone

### Provider-Edge Port Attribution

Implementation prepared in the Codex working copy:

- authorized deep scans refresh hosting/CDN context before port checks;
- shared CDN or managed-provider ports are labelled as provider-edge
  observations with origin ownership unconfirmed;
- the TCP connection fact is preserved without claiming a vulnerability;
- potential service severity is retained only as context if the address is
  later confirmed to be the client's origin;
- unknown/non-shared hosting keeps the existing port-review behavior;
- the deep-scan interface explains provider, confidence, infrastructure
  sharing, and origin attribution;
- focused hosting, ports, and deep-engine tests: 24 passed;
- frontend production build: passed, 21 modules.

Pending: apply these files to the D-drive repository and run its native Python
3.14 regression and frontend build.

### Hosting and Shared-Infrastructure Context

Implementation prepared in the Codex working copy:

- identifies supported CDN or managed-hosting providers from response evidence;
- records public IPv4/IPv6 addresses and best-effort reverse DNS;
- distinguishes shared CDN edge from likely managed shared hosting;
- refuses to claim dedicated hosting when evidence is insufficient;
- warns that ports may belong to the provider rather than the website owner;
- remains informational and does not affect the security score;
- has eight focused unit tests;
- focused hosting and scan-engine tests: 14 passed;
- frontend production build: passed, 19 modules.

Pending: copy the prepared files into the real D-drive repository and run the
full Python 3.14 test suite there.

### Permission-Based Source-Code Review Foundation

Implementation prepared in the Codex working copy:

- reads supported source/configuration files but never executes client code;
- requires an explicit authorization attestation and client approval reference;
- accepts a ZIP archive through a bounded streaming API endpoint;
- rejects unsafe archive paths, symlinks, encryption, excessive files, and
  excessive extracted size;
- deletes the temporary extracted archive after the review;
- ignores dependency, build, Git, virtual-environment, and generated folders;
- inventories supported languages and dependency manifests;
- detects a small initial set of secret and risky-code patterns;
- redacts suspected credentials from every returned finding;
- explains impact and remediation in plain language;
- accurately states that a clean pattern scan is not proof of secure code;
- source engine and archive tests: 18 passed, 1 Windows symlink test skipped;
- backend syntax compilation passed;
- frontend source-review interface production build passed, 21 modules.

Pending: apply to the real repository and run its native Python 3.14 test suite.
Dependency vulnerability lookup and broader language-aware rules remain future
work; this foundation is not yet a complete SAST product.

## Next Milestones

### Vulnerability-First Product Direction

Implementation prepared in the Codex working copy:

- deep scanner results are normalized into one severity-sorted vulnerability
  report with Critical, High, Medium, and Low counts;
- confirmed configuration/exposure findings are separated from potential
  findings requiring confirmation;
- CSRF/form hygiene now includes severity, confidence, validation status,
  remediation, and POST-form coverage counts without submitting forms;
- sensitive exposures, CORS, HTTP methods, crawled page protections, exact
  JavaScript advisory matches, and passive ZAP findings feed the prioritized
  list;
- shared-provider ports, subdomains, hosting context, and crawler inventory do
  not inflate vulnerability totals;
- passed checks are collapsed and available on demand;
- all raw technical observations and scanner evidence remain available in a
  separate collapsed section;
- the normal report now leads with prioritized fixes and moves long TLS, DNS,
  email, hosting, script, privacy, and technology evidence into a collapsed
  technical section;
- focused backend tests passed and the frontend production build passed with
  22 modules.

Pending: apply this phase to the D-drive repository, run the native full test
suite and frontend build, then visually validate both zero-finding and
finding-present reports. Reusable engagements and authenticated/controlled
active scanners remain subsequent phases.

### DNSSEC and CAA Domain Trust

Implementation prepared in the Codex working copy:

- passively queries public DS, DNSKEY, and CAA records;
- distinguishes configured, missing, partial, and unavailable evidence;
- reports DNSSEC record-chain evidence without falsely claiming complete
  independent cryptographic validation;
- reports named CAA certificate authorities while preserving raw evidence;
- distinguishes named-authority restrictions, empty rules that block
  issuance, wildcard-only policies, and non-restrictive iodef records;
- treats missing CAA or DNSSEC as optional protection not observed, not as a
  confirmed vulnerability or compromise;
- remains score-ineligible while validation evidence is collected;
- adds a plain-language Domain Trust section to the normal scan interface;
- focused domain-trust and scan-engine tests passed;
- frontend production build passed with 21 modules.

Pending: apply the prepared files to the D-drive repository, run the full
native Python 3.14 suite, build the frontend, and inspect a real scan result.

1. Finish and verify hosting-context integration in the real repository.
2. Use hosting context when explaining deep port-scan findings.
3. Finish scoped authorization for explicitly selected subdomains.
4. Add evidence-centered export/reporting and scan history.
5. Expand private source-code security analysis:
   - authenticated user accounts and encrypted-at-rest job storage;
   - Git provider connection with repository-specific permission;
   - OSV-backed dependency and lockfile vulnerability analysis;
   - broader language-aware static rules or sandboxed mature SAST adapters;
   - framework and deployment-configuration review;
   - evidence review, suppression, and false-positive workflow.

## Safety Rules

- Public checks remain low impact.
- Deep scans require ownership or explicit written authorization.
- Bug-bounty scans must stay inside the program's published scope.
- Shared hosting or an open port is context, not automatically a vulnerability.
- Source code must remain private and cannot be sent to third parties without
  the client's informed permission.
# 2026-07-19 — Signed Engagement Profile foundation

- Added a signed, expiring Engagement Profile on top of verified domain ownership.
- The profile records the client reference, authorizer, environment, approved scanner groups, crawl limits, and ZAP choice.
- The deep-scan API enforces signed profile limits instead of trusting browser-edited request values.
- The frontend asks for engagement details once after verification and keeps the signed receipt only in browser `sessionStorage` until the tab/session ends or the receipt expires.
- No client passwords or authenticated test credentials are stored in this phase.
- Local development admin testing automatically creates an internal signed Engagement Profile and starts the scan without asking for client details. It remains restricted to development mode, localhost, and the configured domain allowlist.
- Validation: 7 engagement-profile tests passed; frontend production build passed (22 modules).
- Next phase: authenticated-session test-account vault and login workflow, using encrypted server-side credential storage rather than browser storage.

# 2026-07-19 — Encrypted test-account vault foundation

- Added a volatile server-side vault for dedicated authenticated-testing accounts.
- Username and password are encrypted immediately using Fernet authenticated encryption; API responses never return either value.
- Each credential is bound to one signed engagement and domain, accepts HTTPS login URLs only, expires in 5 minutes to 4 hours, and can be deleted immediately.
- Vault contents exist only in server memory and disappear on backend restart; no database persistence yet.
- Added `WEBSHIELD_CREDENTIAL_VAULT_SECRET`, separate from the verification signing secret.
- Added protected create/delete API endpoints. A basic ownership receipt is insufficient; a signed Engagement Profile is required.
- Validation: 17 focused vault + engagement tests passed. Full API suite must run in the project's Windows virtual environment after installing `cryptography==49.0.0`.
- Next: build a controlled login-session adapter that can consume a vault credential internally without exposing it through the API.

# 2026-07-19 — Controlled login-session adapter

- Added one-attempt HTML login support using only encrypted vault credentials.
- Requires one unambiguous POST login form, preserves hidden CSRF fields, blocks GET credential submission and cross-domain form actions, and stops when no session cookie is observed.
- Session cookies remain in volatile backend memory. Only cookie names are reported; cookie values and credentials are never returned.
- Added engagement-protected create/delete login-session API endpoints. Basic ownership receipts are rejected.
- Validation: 17 focused login-session and vault tests passed; Python syntax checks passed.
- Next: authenticated protected-page verification, then authenticated crawling with strict read-only navigation rules.

# 2026-07-19 — Protected-page authentication verification

- Added anonymous-versus-authenticated comparison for one explicitly approved HTTPS protected URL.
- High confidence requires a login/denial response anonymously and an allowed non-login response with the stored session. Mere page differences are labeled only Medium confidence.
- Identical responses or a remaining password form are reported as Not Verified.
- No page content, response fingerprints, credentials, or cookie values are returned.
- Added a signed-engagement API endpoint and 15 focused protected-page/login-session tests.
- Next: allow authenticated crawling only after protected-page verification returns Verified or explicitly accepted Medium confidence.

# 2026-07-19 — Read-only authenticated crawler

- Extended the existing crawler to accept an in-memory authenticated session and an approved same-host HTTPS start URL without changing public-crawl defaults.
- Added a gate requiring Verified authentication; Medium confidence requires explicit acceptance and Not Verified always stops.
- Authenticated crawl limits are stricter: maximum 25 pages, depth 2, 0.3-second delay, GET navigation only, no form submissions or state-changing requests.
- Added a signed-engagement API endpoint and focused compatibility/safety tests.
- Next: add frontend credential setup, protected-page verification, session deletion, and authenticated-crawl controls.

# 2026-07-19 — One-action authenticated-testing UI

- Added an optional collapsed frontend panel shown only after an Engagement Profile exists.
- A single form collects login URL, protected URL, dedicated test username, and temporary password. Form submission works by button or Enter.
- The UI automatically performs encrypted storage, one login attempt, protected-page verification, read-only authenticated crawling, and cleanup.
- Password state clears immediately after storage and again on completion/failure. Session and credential deletion run in `finally` even when a stage fails.
- Medium-confidence crawling is an upfront optional checkbox, avoiding another confirmation click while preserving explicit consent.
- Production frontend build passed with 23 transformed modules.

# 2026-07-19 — Authenticated vulnerability-first reporting

- Authenticated crawl output now includes the same prioritized vulnerability report component used by the main deep scan.
- Password autocomplete guidance is categorized as `Login Form Security`, not `Authentication Failures`.
- Advertised HTTP methods such as TRACE are labeled `Requires Confirmation` unless separately proven executable and harmful.
- Validation: 26 focused backend tests passed; production frontend build passed with 23 modules.

# 2026-07-19 - Vibrant homepage and compact source scanner

- Refreshed the homepage with a blue-violet-pink ambient background, subtle
  grid texture, translucent navigation, stronger brand mark, gradient headline,
  scan assurances, and a raised glass-style scan workspace.
- Kept the normal website scan as the primary action and preserved all existing
  scan behavior.
- Moved the source-code scanner from the bottom of the page to immediately below
  the normal website input.
- Source review is now a slim collapsed row by default. Its existing authorized
  ZIP workflow, privacy controls, findings, and results expand in place.
- Validation: production frontend build passed with 23 transformed modules.

# 2026-07-21 - Dependency vulnerability scanning

- Added exact-version inventory for Python requirements, Poetry locks, Pipfile
  locks, npm package manifests/locks, and Yarn locks without executing client
  code.
- Version ranges are never guessed; unresolved entries are reported separately.
- Added an explicit opt-in OSV.dev advisory lookup. Only package ecosystem,
  package name, and exact version leave WebShield; source code, credentials,
  project name, and client reference are not transmitted.
- Known advisory matches join the existing source findings with severity,
  confidence, advisory ID, fixed-version evidence, and plain-English remediation.
- OSV outages and incomplete advisory details produce Unavailable or Partial
  results instead of a false clean result.
- Source uploads now require `WEBSHIELD_WORK_DIRECTORY`; local configuration
  uses `D:\webshield-data\temp` so extracted archives do not use the C drive.
- Added focused parser, advisory-client, privacy, failure, API, archive, and
  source-engine tests.
- Added alias-aware advisory grouping so equivalent OSV records are not counted
  twice; all related record IDs remain available as evidence.
- A real controlled scan of `jinja2==2.4.1` matched 18 OSV records and safely
  consolidated them into 9 unique vulnerability groups without installing or
  executing the dependency.
- Final validation: 32 focused checks passed with 1 expected platform skip;
  the complete backend suite passed 416 tests with 1 expected platform skip;
  and the frontend production build passed with 23 transformed modules.
