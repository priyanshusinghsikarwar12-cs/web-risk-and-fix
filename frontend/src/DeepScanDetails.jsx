function getStatusClass(status) {
  if (
    [
      "Completed",
      "Protected",
      "Not Observed",
      "No Known Threats",
    ].includes(status)
  ) {
    return "status-protected";
  }

  if (
    [
      "Needs Attention",
      "Threat Detected",
      "Observed",
    ].includes(status)
  ) {
    return "status-attention";
  }

  return "status-neutral";
}


function EmptyResult({ message }) {
  return (
    <div className="deep-empty-result">
      {message}
    </div>
  );
}


function ResultItem({
  title,
  message,
  status,
  children,
}) {
  return (
    <div className="deep-result-item">
      <div>
        <strong>{title}</strong>

        {message && <p>{message}</p>}

        {children}
      </div>

      {status && (
        <span className={getStatusClass(status)}>
          {status}
        </span>
      )}
    </div>
  );
}


function ResultSection({
  title,
  result,
  children,
}) {
  return (
    <details className="deep-result-section">
      <summary>
        <div>
          <strong>{title}</strong>
          <p>{result?.message}</p>
        </div>

        <span
          className={getStatusClass(
            result?.status
          )}
        >
          {result?.status || "Unavailable"}
        </span>
      </summary>

      <div className="deep-result-section-content">
        {children}
      </div>
    </details>
  );
}


function DeepScanDetails({ report }) {
  if (!report) {
    return null;
  }

  const crawler = report.crawler;
  const exposures = report.sensitive_exposures;
  const subdomains = report.subdomains;
  const ports = report.open_ports;
  const advisories = report.javascript_advisories;
  const zap = report.zap_baseline;

  return (
    <div className="deep-details">
      <h4>Detailed Deep Scan Results</h4>

      <ResultSection
        title="Application Crawler"
        result={crawler}
      >
        <div className="deep-metadata-grid">
          <span>
            <strong>
              {crawler?.pages_scanned || 0}
            </strong>
            Pages
          </span>

          <span>
            <strong>
              {crawler?.form_count || 0}
            </strong>
            Forms
          </span>

          <span>
            <strong>
              {crawler?.parameter_count || 0}
            </strong>
            Parameters
          </span>

          <span>
            <strong>
              {crawler?.login_surface_count || 0}
            </strong>
            Login surfaces
          </span>
        </div>

        {crawler?.pages?.length > 0 ? (
          <div className="deep-result-list">
            {crawler.pages.map((page, index) => (
              <ResultItem
                key={`${page.url}-${index}`}
                title={
                  page.title ||
                  `Page ${index + 1}`
                }
                message={`HTTP ${
                  page.status_code ??
                  "Unavailable"
                } · Depth ${page.depth ?? 0}`}
                status={
                  page.security_status ||
                  "Crawled"
                }
              >
                <code className="deep-result-url">
                  {page.url}
                </code>
              </ResultItem>
            ))}
          </div>
        ) : (
          <EmptyResult message="No pages were returned by the crawler." />
        )}
      </ResultSection>


      <ResultSection
        title="Sensitive Exposure Checks"
        result={exposures}
      >
        {exposures?.checks?.length > 0 ? (
          <div className="deep-result-list">
            {exposures.checks.map(
              (finding, index) => (
                <ResultItem
                  key={`${finding.path}-${index}`}
                  title={finding.name}
                  message={finding.message}
                  status={
                    finding.severity ||
                    finding.status
                  }
                >
                  <code className="deep-result-url">
                    {finding.url}
                  </code>
                </ResultItem>
              )
            )}
          </div>
        ) : (
          <EmptyResult
            message={
              exposures?.status ===
              "Not Observed"
                ? "No sensitive exposure was confirmed by the fixed safe checks."
                : "No exposure results were available."
            }
          />
        )}
      </ResultSection>


      <ResultSection
        title="Subdomain Discovery"
        result={subdomains}
      >
        <div className="deep-metadata-grid">
          <span>
            <strong>
              {subdomains?.discovered_count || 0}
            </strong>
            Discovered
          </span>

          <span>
            <strong>
              {subdomains?.dns_confirmed_count || 0}
            </strong>
            DNS confirmed
          </span>

          <span>
            <strong>
              {subdomains?.wildcard_dns
                ? "Yes"
                : "No"}
            </strong>
            Wildcard DNS
          </span>
        </div>

        {subdomains?.checks?.length > 0 ? (
          <div className="deep-result-list">
            {subdomains.checks.map(
              (subdomain) => (
                <ResultItem
                  key={subdomain.hostname}
                  title={subdomain.hostname}
                  message={subdomain.message}
                  status={subdomain.status}
                >
                  <div className="deep-inline-details">
                    <span>
                      Confidence:{" "}
                      {subdomain.confidence}
                    </span>

                    <span>
                      DNS records:{" "}
                      {
                        Object.keys(
                          subdomain.dns_records || {}
                        ).length
                      }
                    </span>
                  </div>
                </ResultItem>
              )
            )}
          </div>
        ) : (
          <EmptyResult message="No subdomains were returned." />
        )}
      </ResultSection>


      <ResultSection
        title="Open Ports and Services"
        result={ports}
      >
        <p className="deep-scope-note">
          {ports?.important_note}
        </p>

        {ports?.checks?.length > 0 ? (
          <div className="deep-result-list">
            {ports.checks.map((port) => (
              <ResultItem
                key={port.port}
                title={`${port.service} — port ${port.port}`}
                message={port.message}
                status={port.status}
              >
                <div className="deep-inline-details">
                  <span>
                    Severity: {port.severity}
                  </span>

                  <span>
                    Connection confirmed
                  </span>

                  <span>
                    No banner or commands sent
                  </span>
                </div>
              </ResultItem>
            ))}
          </div>
        ) : (
          <EmptyResult message="No open port was observed in WebShield’s controlled list." />
        )}
      </ResultSection>


      <ResultSection
        title="JavaScript Known Vulnerabilities"
        result={advisories}
      >
        <p className="deep-scope-note">
          {advisories?.important_note}
        </p>

        {advisories?.checks?.length > 0 ? (
          <div className="deep-result-list">
            {advisories.checks.map(
              (advisory, index) => (
                <ResultItem
                  key={`${advisory.name}-${index}`}
                  title={advisory.name}
                  message={
                    advisory.vulnerability
                      ?.summary ||
                    advisory.message
                  }
                  status={advisory.status}
                >
                  <div className="deep-inline-details">
                    <span>
                      Package: {advisory.package}
                    </span>

                    <span>
                      Version: {advisory.version}
                    </span>

                    <span>
                      Detection confidence:{" "}
                      {
                        advisory.detection_confidence
                      }
                    </span>
                  </div>

                  {advisory.vulnerability
                    ?.osv_url && (
                    <a
                      className="deep-result-link"
                      href={
                        advisory.vulnerability
                          .osv_url
                      }
                      target="_blank"
                      rel="noreferrer"
                    >
                      View official OSV advisory
                    </a>
                  )}
                </ResultItem>
              )
            )}
          </div>
        ) : (
          <EmptyResult message="No exact JavaScript package advisory match was returned." />
        )}
      </ResultSection>


      <ResultSection
        title="OWASP ZAP Baseline"
        result={zap}
      >
        {zap?.status === "Not Requested" && (
          <EmptyResult message="ZAP was not requested because the local Docker engine is currently disabled." />
        )}

        {zap?.checks?.length > 0 && (
          <div className="deep-result-list">
            {zap.checks.map(
              (finding, index) => (
                <ResultItem
                  key={`${finding.rule_id}-${index}`}
                  title={finding.name}
                  message={finding.description}
                  status={finding.risk}
                >
                  {finding.solution && (
                    <p>
                      <strong>Suggested fix:</strong>{" "}
                      {finding.solution}
                    </p>
                  )}

                  {finding.rule_id && (
                    <div className="deep-inline-details">
                      <span>
                        ZAP rule: {finding.rule_id}
                      </span>

                      <span>
                        Confidence:{" "}
                        {finding.confidence ||
                          "Unavailable"}
                      </span>
                    </div>
                  )}
                </ResultItem>
              )
            )}
          </div>
        )}
      </ResultSection>
    </div>
  );
}


export default DeepScanDetails;