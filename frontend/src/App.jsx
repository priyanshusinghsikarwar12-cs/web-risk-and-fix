import { useEffect, useState } from "react";
import "./App.css";
import DeepScanPanel from "./DeepScanPanel";

function App() {
  const [domain, setDomain] = useState("");
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [recentDomains, setRecentDomains] = useState([]);
  const [error, setError] = useState("");
  const [expandedRecommendation, setExpandedRecommendation] = useState(null);
  const [showRecentSearches, setShowRecentSearches] = useState(false);
  const [dkimSelector, setDkimSelector] = useState("");

  useEffect(() => {
    const savedDomains = JSON.parse(
      localStorage.getItem("webshieldRecentDomains") || "[]"
    );

    setRecentDomains(savedDomains);
  }, []);

  const saveRecentDomain = (website) => {
    const updatedDomains = [
      website,
      ...recentDomains.filter((item) => item !== website),
    ].slice(0, 5);

    setRecentDomains(updatedDomains);

    localStorage.setItem(
      "webshieldRecentDomains",
      JSON.stringify(updatedDomains)
    );
  };

  const clearRecentDomains = () => {
    setRecentDomains([]);
    setShowRecentSearches(false);
    localStorage.removeItem("webshieldRecentDomains");
  };

  const normalizeDomain = (website) => {
  return website
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/+$/, "")
    .toLowerCase();
  };

  const handleScan = async (website = domain) => {
    const cleanDomain = normalizeDomain(website);

    setShowRecentSearches(false);

    if (!cleanDomain) {
      setError("Enter a website before starting a scan.");
      return;
    }

    setError("");
    setExpandedRecommendation(null);

    try {
      setLoading(true);
      setReport(null);
      setDomain(cleanDomain);

    const query = new URLSearchParams({
        domain: cleanDomain,
      });

    const cleanSelector = dkimSelector.trim();

      if (cleanSelector) {
        query.set(
          "dkim_selector",
          cleanSelector
        );
      }

    const response = await fetch(
        `http://127.0.0.1:8000/scan?${query.toString()}`
      );

    const data = await response.json();

      if (!response.ok) {
        setError(
          data.detail ||
            "The scan request could not be completed."
        );

        return;
      }

      if (
        data.overall_status ===
        "Website not reachable"
      ) {
        setError(
          "We couldn't reach this website. Check the domain and try again."
        );

        return;
      }

      setReport(data);
      saveRecentDomain(cleanDomain);
    } catch (scanError) {
      setError("Something went wrong while scanning. Please try again.");
      console.error("Scan failed:", scanError);
    } finally {
      setLoading(false);
    }
  };

  const filteredRecentDomains = recentDomains.filter((item) =>
    item.toLowerCase().includes(domain.toLowerCase())
  );

  const getScoreClass = (score) => {
    if (score >= 90) return "score-excellent";
    if (score >= 70) return "score-good";
    if (score >= 50) return "score-warning";

    return "score-critical";
  };

  const formatRegistrationDate = (value) => {
    if (!value) {
      return "Not published";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return "Not published";
    }

    return date.toLocaleDateString(undefined, {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  };

  return (
    <main className="app">
      <nav className="top-nav">
        <div className="webshield-logo">WebShield</div>
      </nav>

      <section className="hero">
        <div className="hero-intro">
          <h1>Know your website. Fix the risk.</h1>

          <p>
            Understand your website security without the technical
            confusion.
          </p>
        </div>

        <div className="search-area">
          <div className="scan-box">
            <input
              type="text"
              placeholder="Enter your website, e.g. example.com"
              value={domain}
              onFocus={() => setShowRecentSearches(true)}
              onBlur={() => setShowRecentSearches(false)}
              onChange={(event) => {
                setDomain(event.target.value);
                setShowRecentSearches(true);
              }}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  handleScan();
                }
              }}
            />
            <button onClick={() => handleScan()} disabled={loading}>
              {loading ? "Scanning..." : "Scan Website"}
            </button>
          </div>
          
          <details className="email-scan-options">
            <summary>
              Optional: check email signing
            </summary>

            <div className="email-selector-field">
              <label htmlFor="dkim-selector">
                Email signing selector
              </label>

              <p>
                Your email provider may call this a DKIM
                selector. Examples include google,
                selector1, or default.
              </p>

              <input
                id="dkim-selector"
                type="text"
                placeholder="Example: google"
                value={dkimSelector}
                onChange={(event) =>
                  setDkimSelector(event.target.value)
                }
              />
            </div>
          </details>          


          {showRecentSearches &&
            domain &&
            filteredRecentDomains.length > 0 && (
              <div
                className="recent-searches"
                onMouseDown={(event) => event.preventDefault()}
              >
                <p>Recent websites</p>

                {filteredRecentDomains.map((website) => (
                  <button
                    key={website}
                    onClick={() => handleScan(website)}
                  >
                    {website}
                  </button>
                ))}

                <button
                  className="clear-history"
                  onClick={clearRecentDomains}
                >
                  Clear recent searches
                </button>
              </div>
            )}
        </div>

        {error && <div className="error-message">{error}</div>}

        {report && (
          <section className="report">
            <div className="score-header">
              <div className={`score-circle ${getScoreClass(report.score)}`}>
                <strong>{report.score}</strong>
                <span>/100</span>
              </div>

              <div>
  <span
    className={
      report.scan_status === "Partial"
        ? "scan-status scan-partial"
        : "scan-status scan-complete"
    }
  >
    {report.scan_status} scan
  </span>

  <h3>{report.overall_status}</h3>
  <p>{report.summary}</p>
</div>
            </div>
<DeepScanPanel
  key={report.domain}
  domain={report.domain || domain}
/>                       
            <div className="recommendations">
              <h3>What should you fix first?</h3>

              {report.recommendations?.map((item, index) => (
                <div className="recommendation-card" key={index}>
                  <button
                    className="recommendation-header"
                    onClick={() =>
                      setExpandedRecommendation(
                        expandedRecommendation === index ? null : index
                      )
                    }
                  >
                    <div>
                      <h4>
                        {index + 1}. {item.title}
                      </h4>

                      <div className="recommendation-tags">
                        <span>{item.priority} priority</span>
                        <span>{item.estimated_time}</span>
                        <span>{item.difficulty}</span>
                      </div>
                    </div>

                    <span className="expand-icon">
                      {expandedRecommendation === index ? "−" : "+"}
                    </span>
                  </button>

                  {expandedRecommendation === index && (
                    <div className="recommendation-content">
                      <p>{item.reason}</p>

                      {item.guidance && (
                        <div className="fix-guidance">
                          <div>
                            <h5>Why this matters</h5>
                            <p>{item.guidance.why_it_matters}</p>
                          </div>

                          <div>
                            <h5>How to fix</h5>
                            <p>{item.guidance.how_to_fix}</p>
                          </div>

                          {item.guidance.platform_guidance && (
                            <div className="platform-guidance">
                              <h5>
                                Fix guidance for {item.guidance.platform}
                              </h5>

                              <p>{item.guidance.platform_guidance}</p>
                            </div>
                          )}

                          <div className="technical-guidance">
                            <h5>Technical setting</h5>

                            <code>{item.guidance.technical_name}</code>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>

            <div className="status-grid">
              <div className="status-card">
                <h3>Website Health</h3>
                <p>{report.health?.message}</p>

                <strong>{report.health?.response_time_ms} ms</strong>
              </div>

              <div className="status-card">
                <h3>Security Certificate</h3>

                <p>{report.ssl_certificate?.message}</p>

                <strong>
                  {Number.isInteger(report.ssl_certificate?.days_left)
    ? `${report.ssl_certificate.days_left} days left`
    : report.ssl_certificate?.status === "Unavailable"
      ? "Check unavailable"
      : "Certificate needs review"}
                </strong>
              </div>

      <div className="report-section">
  <h3>TLS Protocol Security</h3>

  <p className="section-summary">
    {report.tls_protocols?.message}
  </p>

  <div className="protection-list">
    {report.tls_protocols?.checks?.map((check) => {
      const passed =
        check.security === "Obsolete"
          ? check.supported === false
          : check.supported === true;

      return (
        <div className="protection-item" key={check.name}>
          <div>
            <strong>{check.name}</strong>
            <p>{check.message}</p>

            {check.cipher && (
              <code className="tls-cipher">
                {check.cipher}
              </code>
            )}
          </div>

          <span
            className={
              passed
                ? "status-protected"
                : "status-attention"
            }
          >
            {check.status}
          </span>
        </div>
      );
    })}
  </div>
</div>   

<div className="report-section">
  <h3>Mixed Content</h3>

  <p className="section-summary">
    {report.mixed_content?.message}
  </p>

  {report.mixed_content?.checks?.length > 0 ? (
    <div className="protection-list">
      {report.mixed_content.checks.map(
        (check, index) => (
          <div className="protection-item" key={index}>
            <div>
              <strong>{check.name}</strong>
              <p>{check.message}</p>

              <code className="mixed-resource-url">
                {check.url}
              </code>
            </div>

            <span className="status-attention">
              {check.status}
            </span>
          </div>
        )
      )}
    </div>
  ) : (
    <div className="protection-item">
      <div>
        <strong>Homepage Resources</strong>
        <p>{report.mixed_content?.scope}</p>
      </div>

      <span
        className={
          report.mixed_content?.status === "Protected"
            ? "status-protected"
            : "status-attention"
        }
      >
        {report.mixed_content?.status}
      </span>
    </div>
  )}
</div>

<div className="report-section">
  <h3>JavaScript Inventory</h3>

  <p className="section-summary">
    {report.script_inventory?.message}
  </p>

  <div className="script-summary-grid">
    <div>
      <strong>
        {report.script_inventory?.total_script_files || 0}
      </strong>
      <span>Script files</span>
    </div>

    <div>
      <strong>
        {report.script_inventory?.external_script_count || 0}
      </strong>
      <span>External hosts</span>
    </div>

    <div>
  <strong>
    {report.script_inventory
      ?.detected_library_count || 0}
  </strong>
  <span>Recognized libraries</span>
</div>

    <div>
      <strong>
        {report.script_inventory?.inline_script_count || 0}
      </strong>
      <span>Inline scripts</span>
    </div>

    <div>
      <strong>
        {report.script_inventory?.insecure_script_count || 0}
      </strong>
      <span>Insecure scripts</span>
    </div>
  </div>

  {report.script_inventory?.checks?.length > 0 && (
    <div className="protection-list script-list">
      {report.script_inventory.checks.map(
        (script, index) => (
          <div className="protection-item" key={index}>
            <div>
              <strong>{script.host}</strong>

              <p>{script.message}</p>
              
              <code className="script-resource-url">
  {script.url}
</code>

{script.library && (
  <div className="detected-library">
    <strong>{script.library.name}</strong>

    <span>
      {script.library.version
        ? `Version ${script.library.version}`
        : "Version not exposed"}
    </span>

    <span>
      {script.library.confidence} confidence
    </span>
  </div>
)}

<div className="script-details">
                <span>
                  {script.secure_transport
                    ? "HTTPS"
                    : "HTTP"}
                </span>

                <span>{script.relationship}</span>

                {script.integrity_attribute && (
                  <span>Integrity declared</span>
                )}
              </div>
            </div>

            <span
              className={
                script.status === "Needs Attention"
                  ? "status-attention"
                  : "status-observed"
              }
            >
              {script.status}
            </span>
          </div>
        )
      )}
    </div>
  )}
</div>

<div className="report-section">
  <h3>Public Security Files</h3>

  <p className="section-summary">
    {report.public_security_files?.message}
  </p>

  <div className="protection-list">
    {report.public_security_files?.checks?.map(
      (check) => (
        <div
          className="protection-item"
          key={check.name}
        >
          <div>
            <strong>{check.name}</strong>
            <p>{check.message}</p>

            <code className="public-file-url">
              {check.url}
            </code>

            {check.name === "robots.txt" && (
              <div className="public-file-details">
                <span>
                  {check.disallowed_path_count || 0} blocked paths
                </span>

                <span>
                  {check.sitemap_reference_count || 0} sitemap references
                </span>
              </div>
            )}

            {check.name === "sitemap.xml" && (
              <div className="public-file-details">
                <span>
                  {check.url_count || 0} listed URLs
                </span>

                <span>
                  {check.insecure_url_count || 0} insecure URLs
                </span>
              </div>
            )}

            {check.name === "security.txt" && (
              <div className="public-file-details">
                <span>
                  {check.contact_count || 0} contacts
                </span>

                {check.location && (
                  <span>{check.location} location</span>
                )}

                {check.expires && (
                  <span>
                    Expires:{" "}
                    {new Date(
                      check.expires
                    ).toLocaleDateString()}
                  </span>
                )}
              </div>
            )}
          </div>

          <span
            className={
              ["Found", "Configured"].includes(
                check.status
              )
                ? "status-protected"
                : check.status === "Not Found"
                  ? "status-observed"
                  : "status-attention"
            }
          >
            {check.status}
          </span>
        </div>
      )
    )}
  </div>
</div>

{report.error_leakage && (
  <div className="report-section">
    <h3>Error Information Exposure</h3>

    <p className="section-summary">
      {report.error_leakage.message}
    </p>

    <div className="protection-list">
      <div className="protection-item">
        <div>
          <strong>Missing-page safety check</strong>

          <p>
            WebShield safely requested one nonexistent page to see
            whether the website exposed debugging or technical details.
          </p>

          <div className="public-file-details">
            <span>
              HTTP status:{" "}
              {report.error_leakage.status_code ?? "Unavailable"}
            </span>

            <span>
              {report.error_leakage.redirected
                ? "Request was redirected"
                : "No redirect observed"}
            </span>

            <span>{report.error_leakage.scope}</span>
          </div>
        </div>

        <span
          className={
            report.error_leakage.status === "Not Observed"
              ? "status-protected"
              : report.error_leakage.status === "Inconclusive"
                ? "status-observed"
                : "status-attention"
          }
        >
          {report.error_leakage.status}
        </span>
      </div>

      {report.error_leakage.checks?.map((check, index) => (
        <div
          className="protection-item"
          key={`${check.name || "finding"}-${index}`}
        >
          <div>
            <strong>
              {check.name || check.category || "Possible exposure"}
            </strong>

            <p>
              {check.message ||
                "The tested error response exposed technical information."}
            </p>
          </div>

          <span className="status-attention">
            {check.status || "Review"}
          </span>
        </div>
      ))}
    </div>
  </div>
)}

{report.privacy_signals && (
  <div className="report-section">
    <h3>Privacy and Cookie Consent</h3>

    <p className="section-summary">
      {report.privacy_signals.message}
    </p>

    <div className="protection-list">
      {report.privacy_signals.checks?.map((check) => (
        <div
          className="protection-item"
          key={check.name}
        >
          <div>
            <strong>{check.name}</strong>
            <p>{check.message}</p>

            {check.links?.length > 0 && (
              <div className="privacy-signal-details">
                {check.links.map((link) => (
                  <a
                    key={link.url}
                    href={link.url}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {link.text || "View privacy page"}
                  </a>
                ))}
              </div>
            )}

            {check.evidence?.length > 0 && (
              <div className="privacy-signal-details">
                {check.evidence.map((evidence) => (
                  <span key={evidence}>
                    {evidence}
                  </span>
                ))}
              </div>
            )}
          </div>

          <span
            className={
              check.status === "Observed"
                ? "status-protected"
                : check.status === "Not Observed"
                  ? "status-observed"
                  : "status-attention"
            }
          >
            {check.status}
          </span>
        </div>
      ))}
    </div>

    <p className="scope-note">
      Scope: {report.privacy_signals.scope}. This is an
      informational signal check, not a legal compliance audit.
    </p>
  </div>
)}
              <div className="status-card">
                <h3>Domain Setup</h3>

                <p>
                  {report.dns_records?.checks?.filter(
    (item) => item.passed === true
  ).length || 0}{" "}
  configured checks
                </p>
              </div>
            </div>
        <div className="report-section">
  <h3>Website Reputation</h3>

  <p className="section-summary">
    {report.reputation?.message}
  </p>

  <div className="protection-list">
    <div className="protection-item">
      <div>
        <strong>
          {report.reputation?.provider ||
            "Reputation provider unavailable"}
        </strong>

        <p>
          Checked:{" "}
          {report.reputation?.checked_url ||
            "Not checked"}
        </p>

        <div className="dkim-details">
          <span>
            Scope:{" "}
            {report.reputation?.scope ||
              "Unavailable"}
          </span>

          <span>
            Confidence:{" "}
            {report.reputation?.confidence ||
              "Unavailable"}
          </span>

          <span>
            Threats observed:{" "}
            {report.reputation?.threat_types
              ?.length || 0}
          </span>
        </div>

        {report.reputation?.checks?.map(
          (check, index) => (
            <p key={index}>
              <strong>{check.name}:</strong>{" "}
              {check.message}
            </p>
          )
        )}
      </div>

      <span
        className={
          report.reputation?.status ===
          "No Known Threats"
            ? "status-protected"
            : report.reputation?.status ===
              "Threat Detected"
              ? "status-attention"
              : "status-neutral"
        }
      >
        {report.reputation?.status ||
          "Unavailable"}
      </span>
    </div>
  </div>
</div>
            <div className="report-section">
  <h3>Domain Registration</h3>
<div className="report-section">
  <h3>Email Signing (DKIM)</h3>

  <p className="section-summary">
    {report.dkim?.message}
  </p>

  <div className="protection-list">
    <div className="protection-item">
      <div>
        <strong>
          {report.dkim?.selector
            ? `Selector: ${report.dkim.selector}`
            : "Selector not provided"}
        </strong>

        <p>
          {report.dkim?.record_name
            ? `Checked: ${report.dkim.record_name}`
            : (
                "Provide the selector used by your email "
                + "provider to perform this check."
              )}
        </p>

        <div className="dkim-details">
          <span>
            Key type:{" "}
            {report.dkim?.key_type || "Not tested"}
          </span>

          <span>
            Confidence:{" "}
            {report.dkim?.confidence || "Unavailable"}
          </span>

          <span>
            Public key:{" "}
            {report.dkim?.public_key_present === true
              ? "Observed"
              : report.dkim?.public_key_present === false
                ? "Not usable"
                : "Not tested"}
          </span>
        </div>
      </div>

      <span
        className={
          report.dkim?.status === "Configured"
            ? "status-protected"
            : [
                "Invalid",
                "Revoked",
              ].includes(report.dkim?.status)
              ? "status-attention"
              : "status-neutral"
        }
      >
        {report.dkim?.status || "Unavailable"}
      </span>
    </div>
  </div>
</div>  

  <p className="section-summary">
    {report.domain_registration?.message}
  </p>

  <div className="protection-list">
    <div className="protection-item">
      <div>
        <strong>
          {report.domain_registration?.domain ||
            report.domain}
        </strong>

        <p>
          Expires:{" "}
          {formatRegistrationDate(
            report.domain_registration
              ?.expiration_date
          )}
        </p>

        <div className="registration-details">
          <span>
            Registered:{" "}
            {formatRegistrationDate(
              report.domain_registration
                ?.registration_date
            )}
          </span>

          <span>
            Last updated:{" "}
            {formatRegistrationDate(
              report.domain_registration
                ?.last_changed_date
            )}
          </span>

          <span>
            Days remaining:{" "}
            {report.domain_registration?.days_left ??
              "Unknown"}
          </span>

          <span>
            Source:{" "}
            {report.domain_registration?.source ||
              "Unavailable"}
          </span>
        </div>
      </div>

      <span
        className={
          report.domain_registration?.status ===
          "Healthy"
            ? "status-protected"
            : "status-attention"
        }
      >
        {report.domain_registration?.status ||
          "Unavailable"}
      </span>
    </div>
  </div>
</div>

            <div className="report-section">
              <h3>Security Protection</h3>

              <div className="protection-list">
                {report.security_headers?.checks?.map((check, index) => (
                  <div className="protection-item" key={index}>
                    <div>
                      <strong>{check.name}</strong>
                      <p>{check.message}</p>
                    </div>

                    <span
                      className={
                        check.status === "Protected"
                          ? "status-protected"
                          : "status-attention"
                      }
                    >
                      {check.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
            <div className="report-section">
  <h3>Cookie Security</h3>

  <p className="section-summary">
    {report.cookie_security?.message}
  </p>

  {report.cookie_security?.checks?.length > 0 ? (
    <div className="protection-list">
      {report.cookie_security.checks.map(
        (check, index) => (
          <div className="protection-item" key={index}>
            <div>
              <strong>{check.name}</strong>
              <p>{check.message}</p>

              <div className="cookie-flags">
                <span
                  className={
                    check.flags?.secure
                      ? "flag-good"
                      : "flag-warning"
                  }
                >
                  {check.flags?.secure
                    ? "Secure"
                    : "Secure missing"}
                </span>

                <span
                  className={
                    check.flags?.http_only
                      ? "flag-good"
                      : "flag-review"
                  }
                >
                  {check.flags?.http_only
                    ? "HttpOnly"
                    : "HttpOnly missing"}
                </span>

                <span
                  className={
                    check.flags?.same_site
                      ? "flag-good"
                      : "flag-review"
                  }
                >
                  {check.flags?.same_site
                    ? `SameSite=${check.flags.same_site}`
                    : "SameSite missing"}
                </span>
              </div>

              {check.warnings?.length > 0 && (
                <ul className="cookie-warnings">
                  {check.warnings.map(
                    (warning, warningIndex) => (
                      <li key={warningIndex}>
                        {warning}
                      </li>
                    )
                  )}
                </ul>
              )}
            </div>

            <span
              className={
                check.status === "Protected"
                  ? "status-protected"
                  : check.status === "Needs Attention"
                    ? "status-attention"
                    : "status-neutral"
              }
            >
              {check.status}
            </span>
          </div>
        )
      )}
    </div>
  ) : (
    <div className="cookie-empty">
      <strong>
        {report.cookie_security?.status}
      </strong>

      <p>
        No cookies were observed in the initial
        homepage response.
      </p>
    </div>
  )}
</div>

            <div className="report-section">
              <h3>Domain Setup</h3>

              <div className="protection-list">
                {report.dns_records?.checks?.map((check, index) => (
                  <div className="protection-item" key={index}>
                    <div>
                      <strong>{check.name}</strong>
                      <p>{check.message}</p>
                    </div>

                    <span
                      className={
  check.passed === true
    ? "status-protected"
    : check.passed === false
      ? "status-attention"
      : "status-neutral"
}
                    >
                      {check.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="report-section">
              <h3>Website Technology</h3>

              {report.technologies?.checks?.map((technology, index) => (
                <div className="technology-card" key={index}>
                  <strong>{technology.name}</strong>
                  <p>{technology.value}</p>
                </div>
              ))}
            </div>
          </section>
        )}
      </section>
    </main>
  );
}

export default App;