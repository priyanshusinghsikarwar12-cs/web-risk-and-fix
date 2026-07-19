import { useState } from "react";
import "./SourceScanPanel.css";


const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";


function SourceScanPanel() {
  const [archive, setArchive] = useState(null);
  const [projectName, setProjectName] = useState("");
  const [clientReference, setClientReference] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState(null);

  const scanSource = async (event) => {
    event.preventDefault();
    setError("");
    setReport(null);

    if (!archive) {
      setError("Choose the authorized project's ZIP file.");
      return;
    }

    if (archive.size > 20_000_000) {
      setError("The ZIP file must be smaller than 20 MB.");
      return;
    }

    if (!authorized) {
      setError("Confirm that the client or owner authorized this review.");
      return;
    }

    if (!clientReference.trim()) {
      setError("Add the approval email, contract, or ticket reference.");
      return;
    }

    try {
      setLoading(true);

      const response = await fetch(
        `${API_BASE_URL}/source-scan/archive`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/zip",
            "X-WebShield-Project-Name":
              projectName.trim() || archive.name.replace(/\.zip$/i, ""),
            "X-WebShield-Source-Authorization": "authorized",
            "X-WebShield-Client-Reference": clientReference.trim(),
          },
          body: archive,
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "The source review could not run.");
      }

      setReport(data);
    } catch (scanError) {
      setError(scanError.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <details className="source-scan-shell">
      <summary className="source-scan-summary">
        <span className="source-scan-icon" aria-hidden="true">{"</>"}</span>

        <span className="source-scan-summary-copy">
          <strong>Source code scanner</strong>
          <small>Review an authorized project ZIP safely</small>
        </span>

        <span className="source-scan-open-label">
          Open scanner
          <span className="source-scan-chevron" aria-hidden="true">⌄</span>
        </span>
      </summary>

      <div className="source-scan-body">
        <div className="source-scan-heading">
          <span className="source-scan-label">Authorized code review</span>
          <h2>Check the application behind the website</h2>
          <p>
            Upload a ZIP supplied by the owner or client. WebShield reads
            supported source files without running the application and deletes
            the temporary copy after the review.
          </p>
        </div>

        <form className="source-scan-form" onSubmit={scanSource}>
        <label>
          Project name
          <input
            value={projectName}
            onChange={(event) => setProjectName(event.target.value)}
            placeholder="Example: Client customer portal"
            maxLength={120}
          />
        </label>

        <label>
          Approval reference
          <input
            value={clientReference}
            onChange={(event) => setClientReference(event.target.value)}
            placeholder="Contract, ticket, or approval email reference"
            maxLength={200}
          />
        </label>

        <label className="source-file-field">
          Authorized project ZIP
          <input
            type="file"
            accept=".zip,application/zip"
            onChange={(event) => setArchive(event.target.files?.[0] || null)}
          />
        </label>

        <label className="authorization-confirmation">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(event) => setAuthorized(event.target.checked)}
          />
          <span>
            I confirm that the owner or client explicitly authorized me to
            upload and review this source code.
          </span>
        </label>

        <button type="submit" disabled={loading}>
          {loading ? "Reviewing source safely..." : "Review source code"}
        </button>

        {error && <div className="source-scan-error">{error}</div>}
        </form>

        {report && (
          <div className="source-scan-report">
          <div className="source-report-header">
            <div>
              <span>{report.name}</span>
              <h3>{report.project_name}</h3>
              <p>{report.message}</p>
            </div>
            <strong>{report.status}</strong>
          </div>

          <div className="source-summary-grid">
            <div><strong>{report.files_scanned}</strong><span>Files read</span></div>
            <div><strong>{report.finding_counts?.Critical || 0}</strong><span>Critical</span></div>
            <div><strong>{report.finding_counts?.High || 0}</strong><span>High</span></div>
            <div><strong>{report.finding_counts?.Medium || 0}</strong><span>Medium</span></div>
          </div>

          <div className="source-safety-note">
            <strong>Privacy protections</strong>
            <p>
              {report.execution_policy} Suspected credentials are redacted.
              Temporary upload deleted:{" "}
              {report.intake?.temporary_files_deleted ? "Yes" : "Unconfirmed"}.
            </p>
          </div>

          {report.findings?.map((finding, index) => (
            <details
              className="source-finding"
              key={`${finding.rule_id}-${finding.path}-${finding.line}-${index}`}
            >
              <summary>
                <span>{finding.severity}</span>
                <strong>{finding.title}</strong>
                <small>{finding.path}:{finding.line}</small>
              </summary>

              <div>
                <h4>Why this matters</h4>
                <p>{finding.explanation}</p>
                <h4>What to do</h4>
                <p>{finding.fix}</p>
                <p className="source-confidence">
                  Confidence: {finding.confidence}
                </p>
              </div>
            </details>
          ))}

          {report.findings?.length === 0 && (
            <p className="source-empty">
              No listed patterns were observed. This limited automated result
              does not prove that the application is vulnerability-free.
            </p>
          )}
          </div>
        )}
      </div>
    </details>
  );
}

export default SourceScanPanel;
