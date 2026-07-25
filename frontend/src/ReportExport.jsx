import { useRef, useState } from "react";


const LEVEL_ORDER = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Informational: 4,
  Passed: 5,
  Unavailable: 6,
};

const ACTIONABLE_LEVELS = new Set([
  "Critical",
  "High",
  "Medium",
  "Low",
]);

const CONFIRMED_MARKERS = [
  "confirmed",
  "known vulnerability match",
  "verified",
  "exact match",
];

const REVIEW_MARKERS = [
  "potential",
  "requires confirmation",
  "requires validation",
  "review",
  "inconclusive",
  "candidate",
];

const REMEDIATION_RULES = [
  {
    matches: ["insecure link", "mixed content", "http resource"],
    guidance:
      "Replace the insecure HTTP URL with HTTPS in the affected template, page, or content record. Confirm that the destination supports HTTPS, add an HTTP-to-HTTPS redirect where you control it, and rescan every affected page.",
  },
  {
    matches: ["technology disclosure", "version disclosure"],
    guidance:
      "Remove unnecessary product and version details from response headers, generated error pages, and public metadata. Keep only information required for normal operation, then verify that Server and X-Powered-By style disclosures no longer reveal avoidable implementation details.",
  },
  {
    matches: ["trace method"],
    guidance:
      "Disable the TRACE method at the public web server, reverse proxy, or load balancer unless the application has a documented operational need for it. Retest the affected endpoint and confirm that TRACE is rejected without changing the methods the application actually requires.",
  },
  {
    matches: ["script attack protection", "content-security-policy"],
    guidance:
      "Create and test a Content-Security-Policy that allows scripts, styles, frames, and other resources only from required sources. Begin in report-only mode where possible, fix blocked legitimate resources, then enforce the policy consistently on HTML responses.",
  },
  {
    matches: ["click protection", "x-frame-options", "frame-ancestors"],
    guidance:
      "Prevent unauthorized framing by setting Content-Security-Policy frame-ancestors to trusted origins, or X-Frame-Options where legacy support is required. Test any legitimate embedded pages before enforcing the change site-wide.",
  },
  {
    matches: ["https protection", "strict-transport-security", "hsts"],
    guidance:
      "After confirming that the whole site and required subdomains work over HTTPS, enable Strict-Transport-Security with an appropriate max-age. Increase the duration gradually and consider includeSubDomains or preload only after validating their operational impact.",
  },
  {
    matches: ["file type protection", "x-content-type-options"],
    guidance:
      "Set X-Content-Type-Options: nosniff on applicable responses and make sure every asset is served with the correct Content-Type. Retest downloads, scripts, stylesheets, and user-uploaded content.",
  },
  {
    matches: ["browser feature protection", "permissions-policy"],
    guidance:
      "Publish a Permissions-Policy that disables camera, microphone, location, and other browser capabilities the site does not use. Explicitly allow only the features and origins required by the application.",
  },
  {
    matches: ["privacy protection", "referrer-policy"],
    guidance:
      "Set a Referrer-Policy such as strict-origin-when-cross-origin, then test analytics, authentication redirects, and third-party integrations to confirm they receive only the referral data they require.",
  },
  {
    matches: ["cookie"],
    guidance:
      "Classify the cookie by purpose before changing it. Apply Secure to HTTPS-only cookies, HttpOnly to cookies that JavaScript does not need, and an appropriate SameSite value. Retest login, logout, embedded content, and cross-site flows.",
  },
  {
    matches: ["certificate", "tls certificate"],
    guidance:
      "Renew or replace the certificate, install the complete trusted chain, and confirm that the certificate covers every public hostname. Enable automatic renewal and an expiry alert, then verify the result with a trusted TLS client.",
  },
  {
    matches: ["open port", "service exposure"],
    guidance:
      "Confirm that the service belongs to the assessed origin and is required for business operation. Restrict unnecessary exposure with firewall or access-control rules, remove unused services, and retest from an external network.",
  },
  {
    matches: ["cors", "cross-origin"],
    guidance:
      "Allow only the trusted origins, methods, and headers required by the application. Do not combine credentialed access with broadly reflected origins, and verify the policy using both trusted and untrusted origin requests.",
  },
  {
    matches: ["directory listing"],
    guidance:
      "Disable automatic directory indexes at the web server or storage layer. Publish only intended files, remove sensitive backups or artifacts, and verify that directory paths return a controlled response.",
  },
];


function text(value, fallback = "Not provided") {
  const clean = String(value ?? "").trim();
  return clean || fallback;
}

function normalized(value) {
  return text(value, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function findingSpecificRemediation(item, defaults = {}) {
  const combined = normalized(
    [
      item.title,
      item.name,
      item.message,
      item.reason,
      defaults.title,
    ].join(" ")
  );

  const rule = REMEDIATION_RULES.find(({ matches }) =>
    matches.some((match) => combined.includes(match))
  );

  return rule?.guidance || "";
}

function isGenericRemediation(value) {
  const clean = normalized(value);
  return (
    clean ===
      "review the supporting evidence confirm the behavior and apply the narrowest appropriate security control" ||
    clean ===
      "review the finding and apply the appropriate security control" ||
    clean === "review and remediate as appropriate"
  );
}

function validationState(value) {
  const clean = normalized(value);

  if (CONFIRMED_MARKERS.some((marker) => clean.includes(marker))) {
    return "confirmed";
  }

  if (REVIEW_MARKERS.some((marker) => clean.includes(marker))) {
    return "review";
  }

  return "observed";
}

function confidenceLevel(value) {
  const clean = normalized(value);
  if (clean.includes("high")) return "High";
  if (clean.includes("medium") || clean.includes("moderate")) {
    return "Medium";
  }
  if (clean.includes("low")) return "Low";
  return "Not stated";
}

function canonicalFindingKey(entry) {
  return normalized(entry.title);
}


function levelFrom(item = {}) {
  const explicit = text(
    item.severity || item.priority,
    ""
  ).toLowerCase();

  if (explicit === "critical") return "Critical";
  if (explicit === "high") return "High";
  if (explicit === "medium") return "Medium";
  if (explicit === "low") return "Low";

  const status = text(item.status, "").toLowerCase();

  if (
    status.includes("critical") ||
    status.includes("threat detected") ||
    status === "expired"
  ) {
    return "High";
  }

  if (
    status.includes("needs attention") ||
    status.includes("review") ||
    status.includes("partial") ||
    status.includes("incomplete")
  ) {
    return "Medium";
  }

  if (
    status.includes("unavailable") ||
    status.includes("not requested") ||
    status.includes("inconclusive")
  ) {
    return "Unavailable";
  }

  if (
    status.includes("protected") ||
    status.includes("healthy") ||
    status.includes("configured") ||
    status.includes("completed") ||
    status.includes("no known threats") ||
    status.includes("not observed")
  ) {
    return "Passed";
  }

  return "Informational";
}


function makeEntry(
  section,
  source,
  item = {},
  defaults = {}
) {
  const validation = text(
    item.validation ||
      item.verification ||
      defaults.validation ||
      item.status ||
      defaults.status,
    "Observed"
  );
  const providedRemediation = text(
    item.remediation ||
      item.recommended_action ||
      item.guidance?.how_to_fix ||
      defaults.remediation,
    ""
  );
  const specificRemediation =
    findingSpecificRemediation(item, defaults);
  const remediation =
    isGenericRemediation(providedRemediation)
      ? specificRemediation
      : providedRemediation || specificRemediation;

  return {
    section,
    source,
    title: text(
      item.title || item.name || defaults.title,
      source
    ),
    level: defaults.level || levelFrom(item),
    status: text(
      item.status ||
        item.validation ||
        defaults.status,
      "Observed"
    ),
    message: text(
      item.message ||
        item.reason ||
        item.value ||
        defaults.message,
      "No additional explanation was returned."
    ),
    remediation,
    affectedUrl: text(
      item.affected_url ||
        item.url ||
        item.page_url ||
        defaults.affectedUrl,
      ""
    ),
    confidence: text(
      item.confidence || defaults.confidence,
      "Not stated"
    ),
    validation,
    validationState: validationState(validation),
    actionable: defaults.actionable === true,
  };
}


function addEvidence(entries, section, source, result) {
  if (!result) return;

  const checks = Array.isArray(result.checks)
    ? result.checks
    : [];

  if (checks.length) {
    checks.forEach((check) => {
      entries.push(
        makeEntry(section, source, check)
      );
    });
    return;
  }

  entries.push(
    makeEntry(section, source, result, {
      title: source,
    })
  );
}


function collectNormalEntries(report) {
  if (!report) return [];

  const entries = [];

  (report.recommendations || []).forEach((item) => {
    entries.push(
      makeEntry(
        "Normal scan findings",
        "Normal Security Scan",
        item,
        {
          status: "Needs Attention",
          actionable: true,
        }
      )
    );
  });

  [
    ["Website and transport", "Website Health", report.health],
    ["Website and transport", "Security Certificate", report.ssl_certificate],
    ["Website and transport", "TLS Protocol Security", report.tls_protocols],
    ["Browser protections", "Security Headers", report.security_headers],
    ["Browser protections", "Cookie Security", report.cookie_security],
    ["Domain and email", "DNS Records", report.dns_records],
    ["Domain and email", "Domain Trust", report.domain_trust],
    ["Domain and email", "DKIM Email Signing", report.dkim],
    ["Domain and email", "Domain Registration", report.domain_registration],
    ["Trust and reputation", "Website Reputation", report.reputation],
    ["Page observations", "Mixed Content", report.mixed_content],
    ["Page observations", "Privacy Signals", report.privacy_signals],
    ["Page observations", "JavaScript Inventory", report.script_inventory],
    ["Page observations", "Public Security Files", report.public_security_files],
    ["Page observations", "Error Information Leakage", report.error_leakage],
    ["Technology and hosting", "Technology Detection", report.technologies],
    ["Technology and hosting", "Hosting Context", report.hosting_context],
  ].forEach(([section, source, result]) => {
    addEvidence(entries, section, source, result);
  });

  (report.scan_failures || []).forEach((failure) => {
    entries.push(
      makeEntry(
        "Coverage limitations",
        failure.scanner || "Scanner",
        failure,
        {
          level: "Unavailable",
          status: "Could Not Finish",
        }
      )
    );
  });

  if (report.transport_warning) {
    entries.push(
      makeEntry(
        "Coverage limitations",
        "HTTPS Transport",
        report.transport_warning,
        {
          level: "Informational",
          status: "Coverage Note",
        }
      )
    );
  }

  return entries;
}


function collectDeepEntries(report) {
  if (!report) return [];

  const entries = [];
  const vulnerabilityReport =
    report.vulnerability_report || {};

  (vulnerabilityReport.findings || []).forEach((finding) => {
    entries.push(
      makeEntry(
        "Verified deep-scan findings",
        finding.scanner || "Deep Security Scan",
        finding,
        {
          actionable: true,
        }
      )
    );
  });

  (vulnerabilityReport.excluded_observations || []).forEach((finding) => {
    entries.push(
      makeEntry(
        "Policy-excluded observations",
        finding.scanner || "Deep Security Scan",
        finding,
        {
          level: "Informational",
          status: "Excluded by Policy",
        }
      )
    );
  });

  (vulnerabilityReport.diagnostics || []).forEach((diagnostic) => {
    entries.push(
      makeEntry(
        "Scanner diagnostics",
        diagnostic.scanner || "Deep Security Scan",
        diagnostic,
        {
          level: "Informational",
          status: "Diagnostic",
        }
      )
    );
  });

  (vulnerabilityReport.passed_checks || []).forEach((passed) => {
    entries.push(
      makeEntry(
        "Passed deep checks",
        "Deep Security Scan",
        passed,
        {
          level: "Passed",
          status: "Passed",
        }
      )
    );
  });

  [
    ["Deep scanner evidence", "Application Crawler", report.crawler],
    ["Deep scanner evidence", "Sensitive Exposure Checks", report.sensitive_exposures],
    ["Deep scanner evidence", "CORS Configuration", report.cors_configuration],
    ["Deep scanner evidence", "HTTP Method Exposure", report.http_method_exposure],
    ["Deep scanner evidence", "Subdomain Discovery", report.subdomains],
    ["Deep scanner evidence", "Hosting Context", report.hosting_context],
    ["Deep scanner evidence", "Open Ports and Services", report.open_ports],
    ["Deep scanner evidence", "JavaScript Advisories", report.javascript_advisories],
    ["Deep scanner evidence", "Application Input Security", report.query_input_security],
    ["Deep scanner evidence", "OWASP ZAP Baseline", report.zap_baseline],
  ].forEach(([section, source, result]) => {
    addEvidence(entries, section, source, result);
  });

  (report.scan_failures || []).forEach((failure) => {
    entries.push(
      makeEntry(
        "Coverage limitations",
        failure.scanner || "Deep Scanner",
        failure,
        {
          level: "Unavailable",
          status: "Could Not Finish",
        }
      )
    );
  });

  return entries;
}


function consolidateEntries(entries) {
  const grouped = new Map();

  entries.forEach((entry) => {
    const key = canonicalFindingKey(entry);

    if (!grouped.has(key)) {
      grouped.set(key, {
        ...entry,
        occurrences: 0,
        locations: [],
        confidences: [],
        validationStates: [],
        validationLabels: [],
      });
    }

    const group = grouped.get(key);
    group.occurrences += 1;

    if (LEVEL_ORDER[entry.level] < LEVEL_ORDER[group.level]) {
      group.level = entry.level;
    }

    if (
      entry.affectedUrl &&
      !group.locations.includes(entry.affectedUrl)
    ) {
      group.locations.push(entry.affectedUrl);
    }

    if (
      entry.confidence &&
      !group.confidences.includes(entry.confidence)
    ) {
      group.confidences.push(entry.confidence);
    }

    if (!group.validationStates.includes(entry.validationState)) {
      group.validationStates.push(entry.validationState);
    }

    if (!group.validationLabels.includes(entry.validation)) {
      group.validationLabels.push(entry.validation);
    }

    if (!group.remediation && entry.remediation) {
      group.remediation = entry.remediation;
    }
  });

  return Array.from(grouped.values()).map((group) => {
    const hasConfirmed = group.validationStates.includes("confirmed");
    const hasObserved = group.validationStates.includes("observed");

    return {
      ...group,
      validationState: hasConfirmed || hasObserved
        ? "confirmed"
        : "review",
      validation: hasConfirmed
        ? "Confirmed by direct scanner evidence"
        : hasObserved
          ? "Directly observed configuration"
          : "Requires human validation",
    };
  }).sort(
    (left, right) =>
      LEVEL_ORDER[left.level] - LEVEL_ORDER[right.level] ||
      left.title.localeCompare(right.title)
  );
}


function reportId(domain, generatedDate) {
  const date = generatedDate
    .toISOString()
    .slice(0, 10)
    .replaceAll("-", "");
  const target = domain
    .replace(/[^a-z0-9]/gi, "")
    .slice(0, 16)
    .toUpperCase();

  return `WS-${date}-${target || "ASSESSMENT"}`;
}


function ReportFinding({ entry, index }) {
  const visibleLocations = entry.locations.slice(0, 5);
  const hiddenLocationCount =
    entry.locations.length - visibleLocations.length;
  const confirmationRequired =
    entry.validationState === "review";
  const confidence = entry.confidences.length
    ? entry.confidences.join(", ")
    : entry.confidence;

  return (
    <article className="export-finding">
      <div className="export-finding-heading">
        <span
          className={`export-level level-${entry.level.toLowerCase()}`}
        >
          {entry.level}
        </span>

        <div>
          <strong>{index + 1}. {entry.title}</strong>
          <small>
            {entry.source} - {entry.validation}
          </small>
        </div>
      </div>

      <div className="export-finding-flags">
        <span
          className={
            confirmationRequired
              ? "flag-review"
              : "flag-confirmed"
          }
        >
          {confirmationRequired
            ? "Requires validation"
            : "Confirmed evidence"}
        </span>

        {entry.occurrences > 1 && (
          <span>
            Observed {entry.occurrences} times
          </span>
        )}
      </div>

      <p>{entry.message}</p>

      {entry.remediation && (
        <div className="export-remediation">
          <strong>Recommended action</strong>
          <p>{entry.remediation}</p>
        </div>
      )}

      {(visibleLocations.length > 0 || confidence) && (
        <div className="export-evidence">
          {confidence && (
            <span>
              Confidence: {confidence}
            </span>
          )}

          {visibleLocations.length > 0 && (
            <>
              <strong>
                Affected locations ({entry.locations.length})
              </strong>
              {visibleLocations.map((location) => (
                <span key={location}>{location}</span>
              ))}
              {hiddenLocationCount > 0 && (
                <span>
                  Plus {hiddenLocationCount} additional location(s)
                  retained in scanner evidence.
                </span>
              )}
            </>
          )}
        </div>
      )}
    </article>
  );
}


function EvidenceEntry({ entry }) {
  return (
    <tr>
      <td>{entry.source}</td>
      <td>{entry.title}</td>
      <td>{entry.status}</td>
      <td>{entry.message}</td>
    </tr>
  );
}


function ReportExport({
  normalReport = null,
  deepReport = null,
}) {
  const printableReportRef = useRef(null);
  const generatedDateRef = useRef(new Date());
  const [includeDeepScan, setIncludeDeepScan] = useState(
    Boolean(deepReport)
  );
  const [includeTechnicalAppendix, setIncludeTechnicalAppendix] =
    useState(false);
  const [includePassedChecks, setIncludePassedChecks] =
    useState(false);
  const [showReportPreview, setShowReportPreview] =
    useState(false);

  if (!normalReport && !deepReport) return null;

  const deepIsRequired = Boolean(deepReport && !normalReport);
  const deepIncluded =
    Boolean(deepReport) &&
    (deepIsRequired || includeDeepScan);
  const allEntries = [
    ...collectNormalEntries(normalReport),
    ...(deepIncluded
      ? collectDeepEntries(deepReport)
      : []),
  ];

  const initialFindings = consolidateEntries(
    allEntries.filter(
      (entry) =>
        entry.actionable &&
        ACTIONABLE_LEVELS.has(entry.level)
    )
  );
  const initialFindingKeys = new Set(
    initialFindings.map(canonicalFindingKey)
  );
  const corroboratingEvidence = consolidateEntries(
    allEntries.filter(
      (entry) =>
        initialFindingKeys.has(canonicalFindingKey(entry)) &&
        ACTIONABLE_LEVELS.has(entry.level)
    )
  );
  const corroboratingByKey = new Map(
    corroboratingEvidence.map((entry) => [
      canonicalFindingKey(entry),
      entry,
    ])
  );
  const findings = initialFindings.map((entry) => {
    const supporting = corroboratingByKey.get(
      canonicalFindingKey(entry)
    );

    if (!supporting) return entry;

    return {
      ...entry,
      occurrences: Math.max(
        entry.occurrences,
        supporting.occurrences
      ),
      locations: Array.from(
        new Set([
          ...entry.locations,
          ...supporting.locations,
        ])
      ),
      confidences: Array.from(
        new Set([
          ...entry.confidences,
          ...supporting.confidences,
        ])
      ),
    };
  });
  const confirmedFindings = findings.filter(
    (entry) => entry.validationState === "confirmed"
  );
  const reviewFindings = findings.filter(
    (entry) => entry.validationState === "review"
  );
  const findingKeys = new Set(
    findings.map(canonicalFindingKey)
  );
  const limitations = consolidateEntries(
    allEntries.filter(
      (entry) =>
        entry.level === "Unavailable" ||
        entry.section === "Coverage limitations"
    )
  );
  const passedChecks = consolidateEntries(
    allEntries.filter(
      (entry) => entry.level === "Passed"
    )
  );
  const technicalEvidence = consolidateEntries(
    allEntries.filter(
      (entry) =>
        !entry.actionable &&
        entry.level !== "Unavailable" &&
        entry.level !== "Passed" &&
        !findingKeys.has(canonicalFindingKey(entry))
    )
  );

  const counts = ["Critical", "High", "Medium", "Low"].reduce(
    (result, level) => ({
      ...result,
      [level]: findings.filter(
        (entry) => entry.level === level
      ).length,
    }),
    {}
  );
  const confidenceCounts = findings.reduce(
    (result, entry) => {
      const levels = entry.confidences.length
        ? entry.confidences
        : [entry.confidence];
      const confidence = levels
        .map(confidenceLevel)
        .sort(
          (left, right) =>
            ["High", "Medium", "Low", "Not stated"].indexOf(left) -
            ["High", "Medium", "Low", "Not stated"].indexOf(right)
        )[0];
      result[confidence] += 1;

      return result;
    },
    {
      High: 0,
      Medium: 0,
      Low: 0,
      "Not stated": 0,
    }
  );
  const domain =
    deepReport?.domain ||
    normalReport?.domain ||
    "Unknown website";
  const generatedDate = generatedDateRef.current;
  const generatedAt = generatedDate.toLocaleString();
  const identifier = reportId(domain, generatedDate);
  const assessmentType = deepIncluded
    ? "Normal and Verified Deep Security Assessment"
    : "Website Security Health Assessment";
  const reportSections = [
    {
      number: "01",
      title: "Executive Summary",
      description: "Risk totals, confidence, scope, and assessment context",
    },
    {
      number: "02",
      title: "Confirmed Security Findings",
      description: `${confirmedFindings.length} directly observed finding group(s)`,
    },
    ...(reviewFindings.length
      ? [{
          number: "03",
          title: "Items Requiring Confirmation",
          description: `${reviewFindings.length} observation(s) needing human validation`,
        }]
      : []),
    {
      number: reviewFindings.length ? "04" : "03",
      title: "Methodology and Limitations",
      description: "Testing boundaries and incomplete coverage",
    },
    ...(includeTechnicalAppendix && technicalEvidence.length
      ? [{
          number: "A",
          title: "Technical Evidence",
          description: "Supporting observations not repeated as findings",
        }]
      : []),
    ...(includePassedChecks && passedChecks.length
      ? [{
          number: "B",
          title: "Passed and Protected Checks",
          description: "Checks that produced no security finding",
        }]
      : []),
  ];

  const printReport = () => {
    if (!printableReportRef.current) return;

    document
      .querySelectorAll(".report-print-clone")
      .forEach((staleClone) => staleClone.remove());

    const printableClone =
      printableReportRef.current.cloneNode(true);
    printableClone.classList.remove(
      "screen-preview-active"
    );
    printableClone.classList.add(
      "print-active",
      "report-print-clone"
    );
    document.body.appendChild(printableClone);
    document.body.classList.add("report-print-mode");

    const previousTitle = document.title;
    document.title = `WebShield Security Assessment - ${domain}`;

    const finishPrint = () => {
      printableClone.remove();
      document.body.classList.remove(
        "report-print-mode"
      );
      document.title = previousTitle;
      window.removeEventListener("afterprint", finishPrint);
    };

    window.addEventListener("afterprint", finishPrint);
    requestAnimationFrame(() => window.print());
  };

  return (
    <div className="report-export">
      <div className="report-export-controls">
        <div className="report-export-intro">
          <strong>Professional client report</strong>
          <span>
            Repeated page findings are consolidated into clear issue groups.
          </span>
        </div>

        <div className="report-export-options">
          {deepReport && normalReport && (
            <label>
              <input
                type="checkbox"
                checked={includeDeepScan}
                onChange={(event) =>
                  setIncludeDeepScan(event.target.checked)
                }
              />
              Include verified deep-scan findings
            </label>
          )}

          <label>
            <input
              type="checkbox"
              checked={includeTechnicalAppendix}
              onChange={(event) =>
                setIncludeTechnicalAppendix(
                  event.target.checked
                )
              }
            />
            Include technical evidence appendix
          </label>

          <label>
            <input
              type="checkbox"
              checked={includePassedChecks}
              onChange={(event) =>
                setIncludePassedChecks(
                  event.target.checked
                )
              }
            />
            Include passed checks
          </label>
        </div>

        <div className="report-export-actions">
          <button
            className="report-preview-button"
            type="button"
            onClick={() =>
              setShowReportPreview(
                (currentValue) => !currentValue
              )
            }
          >
            {showReportPreview
              ? "Hide full preview"
              : "Preview full report"}
          </button>

          <button type="button" onClick={printReport}>
            Save professional PDF
          </button>
        </div>

        <p className="report-print-tip">
          In the print dialog, turn off the browser option named
          "Headers and footers." WebShield supplies its own confidential
          page footer and page count.
        </p>
      </div>

      <div className="report-preview">
        <strong>{findings.length} unique finding group(s)</strong>
        <span>
          {confirmedFindings.length} confirmed -{" "}
          {reviewFindings.length} require validation
          {deepIncluded ? " - deep scan included" : ""}
        </span>
      </div>

      <section
        className={
          "security-report-print"
          + (showReportPreview
            ? " screen-preview-active"
            : "")
        }
        ref={printableReportRef}
      >
        <header className="export-cover">
          <div className="export-classification">
            CONFIDENTIAL SECURITY ASSESSMENT
          </div>
          <div className="export-brand">WebShield</div>
          <span>Clear security evidence. Practical remediation.</span>
          <h1>{assessmentType}</h1>
          <h2>{domain}</h2>

          <div className="export-meta">
            <span>Report ID: {identifier}</span>
            <span>Generated: {generatedAt}</span>
            <span>
              Normal scan: {normalReport?.scan_status || "Not included"}
            </span>
            <span>
              Deep scan:{" "}
              {deepIncluded
                ? deepReport?.scan_status || "Included"
                : "Not included"}
            </span>
          </div>

          <p className="export-confidentiality-note">
            Prepared for the authorized recipient. Distribution should be
            limited to personnel responsible for the assessed system.
          </p>
        </header>

        <nav className="export-contents" aria-label="Report contents">
          <p className="export-kicker">Document navigation</p>
          <h2>Table of Contents</h2>
          <ol>
            {reportSections.map((section) => (
              <li key={`${section.number}-${section.title}`}>
                <span>{section.number}</span>
                <div>
                  <strong>{section.title}</strong>
                  <small>{section.description}</small>
                </div>
              </li>
            ))}
          </ol>
          <p className="export-page-note">
            Page numbers and total page count are printed in the PDF
            footer. Section letters identify appendices.
          </p>
        </nav>

        <section className="export-summary" id="executive-summary">
          <p className="export-kicker">Executive overview</p>
          <h2>Executive Summary</h2>
          <p>
            {deepIncluded
              ? deepReport?.message
              : normalReport?.summary}
          </p>

          <div className="export-metrics">
            {["Critical", "High", "Medium", "Low"].map((level) => (
              <div
                key={level}
                className={`metric-${level.toLowerCase()}`}
              >
                <strong>{counts[level]}</strong>
                <span>{level}</span>
              </div>
            ))}
          </div>

          <div className="export-verdict-grid">
            <div>
              <strong>{confirmedFindings.length}</strong>
              <span>Confirmed finding groups</span>
            </div>
            <div>
              <strong>{reviewFindings.length}</strong>
              <span>Require human validation</span>
            </div>
            <div>
              <strong>{limitations.length}</strong>
              <span>Coverage limitations</span>
            </div>
          </div>

          <div className="export-confidence-summary">
            <div>
              <strong>{confidenceCounts.High}</strong>
              <span>High confidence</span>
            </div>
            <div>
              <strong>{confidenceCounts.Medium}</strong>
              <span>Medium confidence</span>
            </div>
            <div>
              <strong>{confidenceCounts.Low}</strong>
              <span>Low confidence</span>
            </div>
            <div>
              <strong>{confidenceCounts["Not stated"]}</strong>
              <span>Confidence not stated</span>
            </div>
          </div>

          <div className="export-scope-card">
            <h3>Assessment scope</h3>
            <dl>
              <div>
                <dt>Target</dt>
                <dd>{domain}</dd>
              </div>
              <div>
                <dt>Assessment</dt>
                <dd>{assessmentType}</dd>
              </div>
              <div>
                <dt>Normal scan</dt>
                <dd>{normalReport ? "Included" : "Not included"}</dd>
              </div>
              <div>
                <dt>Verified deep scan</dt>
                <dd>{deepIncluded ? "Included" : "Not included"}</dd>
              </div>
            </dl>
          </div>

          <p className="export-scope-warning">
            Results cover only the pages, responses, and bounded checks
            completed during this assessment. Automated testing reduces
            manual effort but does not prove that an application cannot be
            attacked.
          </p>

          <div className="export-validation-key">
            <h3>How validation labels are assigned</h3>
            <p>
              <strong>Confirmed evidence</strong> means the scanner
              directly observed the configuration or exposure, or matched
              an exact known-vulnerability record.
            </p>
            <p>
              <strong>Requires validation</strong> means the signal is
              indirect, context-dependent, or needs manual reproduction
              before it should be reported as a vulnerability.
            </p>
          </div>
        </section>

        <section
          className="export-section export-findings-section"
          id="confirmed-findings"
        >
          <p className="export-kicker">Prioritized remediation</p>
          <h2>Confirmed Security Findings</h2>
          {confirmedFindings.length ? (
            confirmedFindings.map((entry, index) => (
              <ReportFinding
                key={`confirmed-${entry.source}-${entry.title}`}
                entry={entry}
                index={index}
              />
            ))
          ) : (
            <p className="export-empty-state">
              No confirmed actionable finding group was produced by the
              included checks.
            </p>
          )}
        </section>

        {reviewFindings.length > 0 && (
          <section className="export-section" id="validation-queue">
            <p className="export-kicker">Validation queue</p>
            <h2>Items Requiring Confirmation</h2>
            <p className="export-section-intro">
              These observations are not confirmed vulnerabilities. Review
              the supporting application behavior before reporting them to
              the system owner.
            </p>
            {reviewFindings.map((entry, index) => (
              <ReportFinding
                key={`review-${entry.source}-${entry.title}`}
                entry={entry}
                index={index}
              />
            ))}
          </section>
        )}

        <section className="export-section" id="methodology">
          <p className="export-kicker">Coverage statement</p>
          <h2>Methodology and Limitations</h2>
          <p className="export-section-intro">
            WebShield used bounded, read-only or explicitly authorized
            checks. Findings are based on observable responses and do not
            include destructive exploitation.
          </p>

          {limitations.length ? (
            limitations.map((entry, index) => (
              <ReportFinding
                key={`limit-${entry.source}-${entry.title}`}
                entry={entry}
                index={index}
              />
            ))
          ) : (
            <p className="export-empty-state">
              All requested scanners completed without a recorded tool
              failure. Scope limitations still apply.
            </p>
          )}
        </section>

        {includeTechnicalAppendix &&
          technicalEvidence.length > 0 && (
            <section
              className="export-section export-appendix"
              id="technical-evidence"
            >
              <p className="export-kicker">Appendix A</p>
              <h2>Technical Evidence</h2>
              <table className="export-evidence-table">
                <thead>
                  <tr>
                    <th>Scanner</th>
                    <th>Check</th>
                    <th>Status</th>
                    <th>Evidence summary</th>
                  </tr>
                </thead>
                <tbody>
                  {technicalEvidence.map((entry) => (
                    <EvidenceEntry
                      key={`evidence-${entry.source}-${entry.title}`}
                      entry={entry}
                    />
                  ))}
                </tbody>
              </table>
            </section>
          )}

        {includePassedChecks && passedChecks.length > 0 && (
          <section
            className="export-section export-appendix"
            id="passed-checks"
          >
            <p className="export-kicker">Appendix B</p>
            <h2>Passed and Protected Checks</h2>
            <table className="export-evidence-table">
              <thead>
                <tr>
                  <th>Scanner</th>
                  <th>Check</th>
                  <th>Status</th>
                  <th>Evidence summary</th>
                </tr>
              </thead>
              <tbody>
                {passedChecks.map((entry) => (
                  <EvidenceEntry
                    key={`passed-${entry.source}-${entry.title}`}
                    entry={entry}
                  />
                ))}
              </tbody>
            </table>
          </section>
        )}

        <footer className="export-document-close">
          <strong>End of assessment report</strong>
          <span>{identifier} - Confidential</span>
        </footer>
      </section>
    </div>
  );
}


export default ReportExport;
