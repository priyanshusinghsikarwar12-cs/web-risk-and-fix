# WebShield Project Memory

- Added a visible **Create New Profile** action to the saved engagement card. It removes the current browser-session receipt and returns to profile setup so scanner choices and signed policy exclusions can be changed without manually clearing browser storage.
- Added a signed, opt-in bug-bounty authenticated-testing mode for researcher-owned accounts. It permits one standard-form login attempt and a read-only same-host crawl only when explicitly enabled in the profile; bounty limits are five pages, depth one, at least 0.5-second pacing, no form submission, and High-confidence protected-page verification. Temporary credentials remain encrypted in memory and are deleted after the run.
- Added a short-lived Browser Session Handoff for JavaScript, OTP, and federated login flows. The user logs in normally, copies only their own Cookie request-header value into local WebShield, and confirms account ownership. The backend rejects malformed/oversized/control-character/duplicate cookie input, binds cookies to the signed hostname, never returns cookie names or values, keeps the active session only in volatile memory, verifies a protected page before crawling, and deletes the session after the run.
- Added a bug-bounty-specific manual boundary confirmation for JavaScript application shells that produce only Medium automated login confidence. The operator must verify the exact protected URL in a logged-out Incognito/private window and attest that it redirected or exposed no account data. WebShield preserves the Medium confidence label, records the human confirmation separately, and retains all signed crawl/rate limits.
- Added the first one-account Authenticated Vulnerability Suite. One additional same-host GET checks credentialed arbitrary-Origin reflection, protected-page shared-cache signals, and sensitive-looking query parameter names. Response bodies and values are never returned; cache findings remain Medium/Requires Confirmation unless stronger impact is proven. Findings feed the existing prioritized report, while the UI shows compact CORS, cache, and sensitive-URL statuses.
- Added a controlled two-stage Logout Session Invalidation test. WebShield creates a volatile salted-hash baseline, pauses for the operator to use the real website logout control, then replays the old session once against the same protected URL and deletes it. Exact private indicators persisting only in the old-session response produce a High-confidence review finding; an unchanged fingerprint without private evidence stays Medium/Requires Confirmation; matching anonymous/login-denial behavior is Protected. Page contents, emails, and cookie values are never returned.

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

# 2026-07-21 - Bug Bounty Safe Profile

- Added a separate public bug-bounty authorization path that does not require
  researchers to pretend they own a program-owned domain.
- The signed receipt records the program name and HackerOne URL, researcher
  handle, exact scope reference, saved policy date, safe-harbor confirmation,
  and researcher-owned-account restriction.
- Safe limits are fixed by the backend: five pages, depth one, one concurrent
  request, and at least 0.5 seconds between target requests.
- Only the crawler, bounded exposure fingerprints, CORS observation, and exact
  JavaScript advisory matching are allowed. Ports, subdomain discovery, HTTP
  method probing, infrastructure checks, and ZAP cannot be enabled by editing
  browser requests.
- The deep-scan engine now enforces the signed `approved_scanners` list instead
  of merely recording it.
- Same-host redirect locking stops requests before they contact a third-party
  hostname, including redirect chains.
- Authenticated bug-bounty testing remains locked until its login, protected
  page, and session crawler workflows receive the same pacing enforcement.
- The homepage can open bug-bounty setup before the normal public scan, so no
  ordinary scanner traffic is sent before the safe profile exists.
- Prepared-workspace validation: 30 focused tests passed, runtime smoke test
  passed, Python syntax passed, and the frontend production build passed with
  25 transformed modules. Native Python 3.14 full-suite validation remains part
  of the guarded D-drive apply step.

# 2026-07-21 - Per-program bug-bounty scanner selection

- Added four explicit safe-scanner checkboxes to the public bug-bounty profile:
  crawler, bounded exposure checks, CORS observation, and JavaScript advisories.
- At least one scanner must be selected. Ports, subdomains, HTTP methods,
  infrastructure checks, and ZAP remain impossible to select in safe mode.
- The backend validates the requested list as a subset of the bug-bounty safe
  allowlist, signs that exact subset, and the deep-scan engine enforces it.
- The ready-to-run profile now displays friendly names for the signed scanners
  so the researcher can verify the final permissions before sending requests.

# 2026-07-21 - Policy-aware bug-bounty reporting

- Added signed per-program exclusions for missing security headers, generic
  cookie-attribute observations, form best-practice observations, and mixed
  content. Only exclusions explicitly selected from the saved program policy
  are accepted.
- The deep-scan engine passes the signed exclusions into the vulnerability
  report. Excluded evidence remains visible but no longer inflates severity or
  reportable-candidate totals.
- Repeated cookie observations are deduplicated across crawled pages and retain
  occurrence counts plus affected-page evidence.
- Generic cookies are now `Cookie Security Observation` items with Medium
  confidence and `Requires Confirmation`, rather than falsely being labeled
  confirmed authentication failures.
- Unparsed cookie headers are scanner diagnostics, never target
  vulnerabilities.
- The frontend separates reportable candidates, policy-excluded observations,
  scanner diagnostics, and passed checks.

# 2026-07-21 - Endpoint-aware logout verification

- The logout invalidation workflow can now use one optional same-host,
  read-only account endpoint instead of relying only on a JavaScript page shell.
- The backend permits only HTTPS GET behavior through the existing safe HTTP
  client, locks redirects to the signed hostname, and rejects URL credentials,
  fragments, unsafe ports, out-of-scope hosts, and token-like query parameters.
- Preparation compares anonymous and authenticated endpoint responses. It
  continues only when the endpoint proves or confirms an account boundary.
- After manual logout, WebShield makes one anonymous request and one replay of
  the old session, then deletes the old session and temporary hashed baseline.
- Response bodies, cookies, personal indicators, and endpoint values are never
  returned in the result. Findings remain conservative: rejected old sessions
  are Protected, persistent private access is High, and ambiguous evidence is
  Inconclusive rather than a fabricated vulnerability.

# 2026-07-21 - Controlled read-only POST/RPC verification

- Added an optional read-only JSON POST mode for modern applications whose
  account-information APIs do not provide a usable GET endpoint.
- This is intentionally not a general request sender: the signed same-host
  HTTPS restriction remains mandatory, redirects are rejected, the final path
  action must begin with a recognized read verb, and the researcher must
  explicitly confirm the operation reads only their own test account.
- JSON bodies are limited to one object and 16 KB with bounded depth, field
  count, array size, and string length. Secret-like keys such as tokens,
  passwords, cookies, OTPs, CSRF values, credentials, and payment PIN/CVV data
  are rejected before any target request is sent.
- The POST response is capped at 1 MB. WebShield makes only the anonymous and
  authenticated comparisons required before and after manual logout, applies
  engagement pacing, never follows a POST redirect, never returns body values,
  and removes the temporary body with the expiring logout-test record.
- Prepared validation: 22 focused backend safety tests passed, Python syntax
  passed, and the frontend production build passed with 25 transformed modules.

# 2026-07-21 - Bounded application input security

- Added an explicitly approved `query_input_security` scanner for owner-verified
  and local-admin engagements. It is deliberately unavailable to the public
  bug-bounty safe profile.
- The scanner tests only existing query parameters discovered on already
  crawled, same-host HTTPS pages. Sensitive parameter names and paths that look
  state-changing are skipped.
- Open-redirect checks use the reserved `webshield.invalid` hostname, never
  follow the redirect, and never contact the marker destination.
- Reflection checks use a harmless non-script marker and report only when HTML-
  significant characters are returned unescaped. Findings remain `Requires
  Confirmation` instead of being mislabeled as confirmed XSS.
- Each run is capped at six paced GET requests. It submits no forms, sends no
  state-changing request, executes no script payload, and contacts no external
  destination.
- Added detailed frontend evidence showing parameters tested, requests made,
  candidates, confidence, validation state, and remediation.
- Prepared validation: 48 focused backend tests and 436 non-API backend tests
  passed with 1 expected platform skip; Python syntax passed; and the frontend
  production build passed with 25 transformed modules. Native Python 3.14 API
  and full-suite validation remain part of the guarded D-drive apply.

# 2026-07-23 - Two-account object access control

- Added an owner-verified, read-only IDOR/BOLA candidate check using exactly two
  client-owned low-privilege accounts and two client-owned test objects.
- The operator supplies one same-host HTTPS JSON endpoint template containing
  `{object_id}` exactly once. Secret-like query parameters, unsafe authority
  data, custom ports, fragments, and state-changing path names are rejected.
- WebShield first collects the distinct owner baselines. Only then does it make
  the two cross-account GET requests, for a strict maximum of four paced
  requests. It never guesses or enumerates identifiers.
- A High-confidence candidate requires an exact private JSON response match to
  the other account's owner baseline. HTTP 200 alone is Inconclusive, while two
  explicit 401/403/404 cross-account responses are Protected.
- Response bodies, cookie values, and object identifiers are never returned in
  results. Both volatile browser sessions are deleted after the check.
- The workflow is unavailable in public bug-bounty mode for now and requires a
  signed owner-verified engagement plus explicit read-only and test-data
  confirmations.
- Prepared validation: 32 focused backend tests and 447 non-API backend tests
  passed with 1 expected platform skip; Python syntax passed; and the frontend
  production build passed with 26 transformed modules. Native Python 3.14 API
  and complete-suite validation remain part of the guarded D-drive apply.

# 2026-07-24 - One-account API authentication boundary

- Added an owner-verified check that compares one authorized private JSON object
  response with one logged-out request to the exact same client-owned object.
- The check uses one temporary test-account session and a strict maximum of two
  paced GET requests. It never returns the object value or identifier.
- An exact anonymous match becomes a High-confidence candidate; an anonymous
  401/403/404 is Protected; any other successful or redirected response is
  Inconclusive rather than being mislabeled as vulnerable.
- The authenticated response must first be a non-empty successful JSON baseline.
  Otherwise WebShield stops before making the anonymous request.
- Added a separate always-visible UI card so one-account missing-authentication
  testing is not confused with the two-account IDOR/BOLA workflow.
- Prepared validation: 36 focused backend tests and 451 non-API backend tests
  passed with 1 expected platform skip; Python syntax passed; and the frontend
  production build passed with 27 transformed modules. Native Python 3.14 API
  and complete-suite validation remain part of the guarded D-drive apply.

# 2026-07-24 - Bounded database-error candidate detection

- Strengthened the owner-verified `query_input_security` scanner with a
  conservative database-error check on existing same-host, read-only GET query
  parameters discovered by the crawler.
- Each eligible parameter is compared using a harmless control marker and one
  quote mutation. A candidate is produced only when a recognizable database
  error family appears in the mutation response but was absent from the
  control response.
- Findings are High severity, Medium confidence, and `Requires Confirmation`.
  They indicate unsafe database-error behavior, not proven data extraction or
  confirmed SQL injection.
- The scanner never sends UNION, boolean, time-based, or extraction payloads.
  Sensitive parameter names and state-changing paths remain excluded, request
  pacing and the existing six-request cap remain enforced, and response values
  are not returned.
- The deep-scan UI now shows database-error test counts and clearly states the
  exact safety boundary.
- Prepared validation: 33 focused backend tests and 453 non-API backend tests
  passed with 1 expected platform skip; Python syntax passed; and the frontend
  production build passed with 27 transformed modules. Native Python 3.14 API
  and complete-suite validation remain part of the guarded D-drive apply.

# 2026-07-24 - Session-fixation protection

- Added session-identifier rotation analysis to the existing owner-authorized
  standard login workflow. No extra login attempt or form submission is made.
- WebShield compares only likely session-cookie identifiers observed before and
  after authentication. Cookie values are used only for an in-memory equality
  comparison and are never returned in API or UI results.
- A changed identifier is reported as Protected. An unchanged identifier is a
  High-severity, Medium-confidence candidate that Requires Confirmation. Mixed
  or insufficient evidence is Inconclusive or Not Observable instead of being
  mislabeled as a vulnerability.
- Browser-session handoff remains Not Observable because WebShield did not
  witness that browser's anonymous-to-authenticated transition.
- Session-fixation evidence is added to the authenticated vulnerability report
  and displayed beside authenticated CORS, private caching, and sensitive-URL
  transport results.
- Prepared validation: 39 focused backend tests and 458 non-API backend tests
  passed with 1 expected platform skip; Python syntax passed; and the frontend
  production build passed with 27 transformed modules. Native Python 3.14 API
  and complete-suite validation remain part of the guarded D-drive apply.

# 2026-07-24 - Trust-failure and zero-finding correction

- Corrected the normal scanner's handling of an expired or otherwise invalid
  HTTPS certificate. A TLS verification failure no longer causes every scanner
  to stop with the generic `Website not reachable` result.
- When trusted page content is blocked by TLS, WebShield continues independent
  certificate, DNS, TLS-protocol, registration, reputation, and infrastructure
  checks. The scan becomes Partial and the certificate problem is prioritized.
  WebShield still refuses to bypass certificate verification for page-content
  inspection.
- A deep scan that requested the crawler but inspected zero pages is now
  `Incomplete`, never a clean zero-vulnerability result. The vulnerability
  report carries explicit coverage metadata and tells the user to resolve the
  connection or certificate problem before interpreting the result.
- Page-level findings remain deduplicated and aggregated. A protection missing
  from 25 pages is one prioritized finding with affected-page evidence, rather
  than 25 repetitive cards.
- The normal report now keeps all owner verification, authenticated crawling,
  IDOR/BOLA, and specialist controls inside one collapsed `Advanced authorized
  security assessment` section. Common owner-profile labels were rewritten in
  simpler language.
- Prepared validation: 28 focused backend tests and 462 non-API backend tests
  passed with 1 expected platform skip; Python syntax passed; and the frontend
  production build passed with 27 transformed modules. Native Python 3.14 API
  and complete-suite validation remain part of the guarded D-drive apply.

# 2026-07-24 - Unified passive and verified assessment pipeline

- Corrected the deeper architectural problem behind misleading zero-result
  reports. Owner-verified deep assessments now include the independent passive
  baseline instead of discarding certificate, TLS-protocol, DNS, registration,
  reputation, mixed-content, and error-leakage evidence.
- Passive baseline evidence is converted into the same prioritized
  vulnerability report. An expired certificate is therefore retained as a
  High-severity confirmed configuration finding even if page crawling fails.
- Owner-controlled and local-development assessments may collect bounded page
  evidence through an invalid certificate. The certificate remains a finding,
  every affected page is marked as not TLS-verified, and the report records
  that trusted transport verification was bypassed.
- Published third-party bug-bounty profiles remain strict: they neither bypass
  TLS verification nor silently run baseline scanners outside the signed
  program policy.
- The verified invalid-TLS option now reaches the crawler, exposure checks,
  CORS, HTTP method observation, JavaScript inventory/advisories, and bounded
  query-input checks. SSRF protection, exact-host restrictions, response-size
  caps, request limits, and pacing remain enforced.
- Prepared validation: 89 focused non-API backend tests passed and all changed
  Python modules compiled successfully. Native Python 3.14 API, complete-suite,
  and frontend validation remain part of the guarded D-drive apply.
- The first guarded apply exposed one stale API test double that did not accept
  the new `baseline_scanner` and `allow_invalid_tls` arguments. The installer
  correctly rolled the D-drive project back. The mock now accepts and asserts
  both options; its Python syntax and the 89 focused non-API tests pass again.

# 2026-07-24 - Normal scan invalid-certificate recovery

- Corrected the normal scan's shared homepage pipeline. WebShield still tries
  trusted HTTPS first. When and only when certificate validation fails, it
  records that failure and performs one bounded, read-only retry without
  trusting the certificate.
- The recovered homepage response is reused by Website Health, headers,
  cookies, mixed-content, privacy, JavaScript inventory, technology detection,
  and hosting-context checks instead of disabling all of them.
- Public `robots.txt`, `sitemap.xml`, `security.txt`, and bounded missing-page
  error checks receive the same invalid-certificate handling.
- Website Health now says the website responded but its certificate was not
  trusted. The frontend displays `Not measured` instead of an empty `ms`, and
  displays `Certificate expired` when the certificate result says it expired.
- The bypass does not hide or downgrade the certificate issue. It marks the
  normal assessment Partial and keeps the certificate as the actual security
  finding.
- Hosting context now treats a provider-owned reverse-DNS suffix as Medium-
  confidence evidence rather than ignoring it. For example,
  `dd-plesk-web1.webhostbox.net` becomes `Possible WebHostBox`, with Plesk
  recorded as supporting hostname evidence; it is not presented as confirmed.
- Prepared validation: 87 relevant backend tests passed, all changed Python
  modules compiled, and the frontend
  production build completed with 27 transformed modules. The guarded installer
  will run native API and complete-suite validation before keeping the change.
- Live verification then exposed a separate Technology Detection bug: the
  scanner accepted the shared homepage response but ignored it and performed a
  second strict HTTPS request. It now reuses the recovered response exactly as
  JavaScript Inventory does. A regression test prevents duplicate fetching.
- Scan execution and website security status are now separate. A successfully
  recovered invalid-certificate assessment is `Complete` with a transport
  warning, while the website remains `Critical` and the expired certificate
  remains prioritized. Only actual scanner failures make the scan `Partial`.
- Prepared follow-up validation: 24 focused tests passed and both corrected
  Python modules compiled successfully.
- Live output confirmed Technology Detection was executing successfully but
  returned `Not Detected`: its original evidence rules covered only a narrow
  set of platforms/providers. It now reports public HTML references to jQuery
  and Bootstrap as Medium-confidence frontend technologies and recognizes
  ASP.NET Web Forms state fields. These observations do not claim a hidden
  backend platform or version.
- A regression test confirms the AITD-style jQuery/Bootstrap evidence is
  recognized. Nineteen focused pipeline tests pass and the module compiles.

# 2026-07-24 - Client-ready normal and deep PDF report

- Added one report format for normal scans and combined normal plus verified
  deep scans. The deep report automatically includes the normal baseline.
- The report separates executive priority findings from the complete evidence
  appendix. Items are labelled Critical, High, Medium, Low, Informational,
  Passed, or Unavailable so non-vulnerability observations are not discarded
  or falsely presented as vulnerabilities.
- Included priority recommendations, scanner findings, remediation, affected
  URLs, confidence, passed checks, policy exclusions, diagnostics, scanner
  failures, and coverage/transport limitations.
- Added a client-facing report summary and an A4 print layout with cover page,
  executive metrics, grouped evidence cards, page-break protection, and a
  local-data notice.
- `Save report as PDF` opens the operating system/browser print dialog, where
  the user selects `Save as PDF`. This uses no external PDF package, creates no
  temporary report on C:, and uploads no report data.
- Multiple normal/combined report controls can coexist; only the report whose
  button was pressed is included in the print job.
- Frontend production build passed with 28 transformed modules and oxlint
  completed without errors. A browser rendering attempt confirmed the built
  frontend loaded, but the local backend was not available for a populated
  report preview during that check.
- Upgraded the export into a professional client assessment. Repeated
  per-page observations are consolidated into unique finding groups while
  retaining occurrence counts and representative affected URLs.
- Added explicit options to include verified deep-scan findings, a technical
  evidence appendix, and passed checks. Normal-only and combined reports
  remain supported.
- Completed deep-scan results now flow back into the main report exporter, so
  the primary client-report controls expose the deep-scan inclusion checkbox
  immediately after a verified deep scan finishes. Standalone bug-bounty
  workflows retain their own report exporter.
- The report now separates confirmed findings from observations requiring
  human validation and includes a confidentiality cover, report ID, scope,
  executive metrics, methodology, limitations, remediation, and appendices.
- Added a full on-screen report preview before printing. The A4 print path
  still uses the browser's local Save as PDF workflow.
- Final frontend build passed with 28 transformed modules and oxlint completed
  without errors. A populated live normal-scan report was visually inspected
  against `aitd.ac.in`; the isolated preview server was stopped afterward and
  did not use or remain on WebShield's production development ports.

# 2026-07-24 - Client report maturity and pagination correction

- Reviewed the exported `aitd-report.pdf`. Confirmed that the blank second
  sheet was caused by forced page breaks around an oversized cover, and that a
  trailing forced break could create another empty sheet near the end.
- Removed conflicting forced section breaks. The cover now occupies one
  bounded A4 content area and the remaining sections flow naturally, while
  individual finding cards still avoid splitting where possible.
- Added a real table of contents, confidential page-margin footer, and
  `Page X of Y` counters. The export UI tells the user to disable the browser's
  own headers and footers so localhost, the development title, and timestamps
  do not appear in a client report.
- Replaced the developer-oriented local-generation footer with a professional
  end-of-report marker containing only the report ID and classification.
- Finding groups now deduplicate by canonical finding title across the
  prioritized report and technical evidence. Supporting evidence enriches the
  finding's occurrence and affected-location counts but is not printed again
  as a second finding.
- Validation classification is now deterministic and explained in the
  executive summary: direct observations, verified results, and exact
  vulnerability matches are confirmed; potential, contextual, inconclusive,
  or review signals require human validation.
- Added executive confidence cards for High, Medium, Low, and unstated
  confidence so confidence is visible before readers open individual findings.
- Replaced the generic recommendation boilerplate with finding-specific
  remediation for insecure links/mixed content, technology disclosure, TRACE,
  security headers, cookies, certificates, open services, CORS, and directory
  listing findings.
- Scanner collection, severity generation, authorization, and scan execution
  were not changed. Frontend oxlint and the Vite production build both pass
  with 28 transformed modules.
- Follow-up print testing showed that `visibility: hidden` left the complete
  WebShield application layout in the print document. That invisible layout
  could create many blank pages after the report. Printing now creates a
  temporary report-only clone directly under the document body, removes the
  application from print layout, and deletes the clone when printing ends.
- The Executive Summary now always starts on the page after the table of
  contents. The cover, contents, summary, findings, and appendices otherwise
  continue to flow without trailing forced page breaks.
- Follow-up frontend oxlint and the Vite production build pass with 28
  transformed modules.
