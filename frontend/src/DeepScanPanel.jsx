import { useEffect, useState } from "react";
import DeepScanDetails from "./DeepScanDetails";


const API_URL = "http://127.0.0.1:8000";


async function readResponse(response) {
  let data;

  try {
    data = await response.json();
  } catch {
    throw new Error(
      "WebShield received an unreadable server response."
    );
  }

  if (!response.ok) {
    throw new Error(
      data.detail ||
        "The request could not be completed."
    );
  }

  return data;
}


function DeepScanPanel({ domain }) {
  const [challenge, setChallenge] = useState(null);
  const [method, setMethod] = useState("dns");
  const [authorizationReceipt, setAuthorizationReceipt] =
    useState("");
  const [authorizationExpiresAt, setAuthorizationExpiresAt] =
    useState(null);
  const [deepReport, setDeepReport] = useState(null);

  const [creatingChallenge, setCreatingChallenge] =
    useState(false);
  const [checkingProof, setCheckingProof] =
    useState(false);
  const [deepScanning, setDeepScanning] =
    useState(false);
  const [error, setError] = useState("");
  const [devAdminToken, setDevAdminToken] =
  useState("");


  useEffect(() => {
    setChallenge(null);
    setMethod("dns");
    setAuthorizationReceipt("");
    setAuthorizationExpiresAt(null);
    setDeepReport(null);
    setError("");
  }, [domain]);


  const createChallenge = async () => {
    if (!domain) {
      setError(
        "Scan a website before requesting ownership verification."
      );
      return;
    }

    setError("");
    setCreatingChallenge(true);
    setAuthorizationReceipt("");
    setDeepReport(null);

    try {
      const response = await fetch(
        `${API_URL}/verification/challenge`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            domain,
          }),
        }
      );

      const data = await readResponse(response);

      setChallenge(data);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setCreatingChallenge(false);
    }
  };


  const verifyOwnership = async () => {
    if (!challenge) {
      setError(
        "Create a verification challenge first."
      );
      return;
    }

    setError("");
    setCheckingProof(true);

    try {
      const response = await fetch(
        `${API_URL}/verification/check`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            domain: challenge.domain,
            token: challenge.token,
            method,
          }),
        }
      );

      const data = await readResponse(response);

      if (!data.verified) {
        setError(
          data.message ||
            "WebShield could not confirm the verification proof yet."
        );
        return;
      }

      setAuthorizationReceipt(
        data.authorization_receipt
      );

      setAuthorizationExpiresAt(
        data.authorization_expires_at
      );
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setCheckingProof(false);
    }
  };


  const startDeepScan = async () => {
  const cleanAdminToken =
    devAdminToken.trim();

  if (
    !authorizationReceipt
    && !cleanAdminToken
  ) {
    setError(
      "Verify ownership or enter the local development admin token."
    );
    return;
  }

    setError("");
    setDeepScanning(true);
    setDeepReport(null);

    try {
      const requestHeaders = {
  "Content-Type": "application/json",
};

if (authorizationReceipt) {
  requestHeaders.Authorization = (
    `Bearer ${authorizationReceipt}`
  );
} else {
  requestHeaders[
    "X-WebShield-Admin-Token"
  ] = cleanAdminToken;
}  
      const response = await fetch(
        `${API_URL}/deep-scan/run`,
        {
          method: "POST",
          headers: requestHeaders,
          body: JSON.stringify({
            domain,
            max_pages: 25,
            max_depth: 2,

            // Docker is currently disabled.
            include_zap: false,

            zap_spider_minutes: 1,
            zap_maximum_minutes: 5,
          }),
        }
      );

      const data = await readResponse(response);

      setDeepReport(data);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setDeepScanning(false);
    }
  };


  const formatExpiry = (timestamp) => {
    if (!timestamp) {
      return "Unavailable";
    }

    return new Date(
      timestamp * 1000
    ).toLocaleString();
  };


  return (
    <div className="deep-scan-panel">
      <div className="deep-scan-heading">
        <div>
          <span className="deep-scan-label">
            Verified assessment
          </span>

          <h3>Deep Security Scan</h3>

          <p>
            Prove that you control this domain before
            WebShield performs deeper security checks.
          </p>
        </div>

        {!challenge && (
          <button
            className="deep-primary-button"
            onClick={createChallenge}
            disabled={creatingChallenge}
          >
            {creatingChallenge
              ? "Creating challenge..."
              : "Verify ownership"}
          </button>
        )}
      </div>
{import.meta.env.DEV &&
  !authorizationReceipt && (
    <details className="dev-admin-panel">
      <summary>
        Local development admin testing
      </summary>

      <p>
        This option works only from this computer,
        in development mode, and for domains listed
        in the backend allowlist.
      </p>

      <input
        type="password"
        placeholder="Development admin token"
        value={devAdminToken}
        onChange={(event) =>
          setDevAdminToken(event.target.value)
        }
        autoComplete="off"
      />

      <button
        className="deep-primary-button"
        onClick={startDeepScan}
        disabled={
          deepScanning ||
          !devAdminToken.trim()
        }
      >
        {deepScanning
          ? "Running test scan..."
          : "Run Admin Test Scan"}
      </button>
    </details>
  )}      


      {challenge && !authorizationReceipt && (
        <div className="verification-workspace">
          <div className="verification-methods">
            <button
              className={
                method === "dns"
                  ? "verification-method active"
                  : "verification-method"
              }
              onClick={() => setMethod("dns")}
            >
              DNS TXT record
            </button>

            <button
              className={
                method === "file"
                  ? "verification-method active"
                  : "verification-method"
              }
              onClick={() => setMethod("file")}
            >
              Verification file
            </button>
          </div>


          {method === "dns" && (
            <div className="verification-instructions">
              <h4>Add this DNS TXT record</h4>

              <p>
                Open the DNS settings at your domain
                provider and create the following record.
              </p>

              <div className="verification-value">
                <span>Record type</span>
                <code>
                  {challenge.dns_record_type}
                </code>
              </div>

              <div className="verification-value">
                <span>Record name</span>
                <code>
                  {challenge.dns_record_name}
                </code>
              </div>

              <div className="verification-value">
                <span>Record value</span>
                <code>
                  {challenge.dns_record_value}
                </code>
              </div>
            </div>
          )}


          {method === "file" && (
            <div className="verification-instructions">
              <h4>Publish this verification file</h4>

              <p>
                Create a plain-text file at the exact URL
                below and paste the provided content into it.
              </p>

              <div className="verification-value">
                <span>File URL</span>
                <code>{challenge.file_url}</code>
              </div>

              <div className="verification-value">
                <span>File content</span>
                <code>{challenge.file_content}</code>
              </div>
            </div>
          )}


          <div className="verification-actions">
            <button
              className="deep-secondary-button"
              onClick={createChallenge}
              disabled={creatingChallenge}
            >
              Create new challenge
            </button>

            <button
              className="deep-primary-button"
              onClick={verifyOwnership}
              disabled={checkingProof}
            >
              {checkingProof
                ? "Checking proof..."
                : "I added it — verify now"}
            </button>
          </div>

          <p className="verification-expiry">
            This challenge expires in approximately{" "}
            {Math.ceil(
              challenge.expires_in_seconds / 60
            )}{" "}
            minutes.
          </p>
        </div>
      )}


      {authorizationReceipt && (
        <div className="verified-domain">
          <div>
            <span className="verified-badge">
              Ownership verified
            </span>

            <h4>{domain}</h4>

            <p>
              Deep-scan permission expires:{" "}
              {formatExpiry(
                authorizationExpiresAt
              )}
            </p>
          </div>

          <button
            className="deep-primary-button"
            onClick={startDeepScan}
            disabled={deepScanning}
          >
            {deepScanning
              ? "Running deep scan..."
              : "Start Deep Scan"}
          </button>
        </div>
      )}


      {deepScanning && (
        <div className="deep-scan-progress">
          <strong>
            WebShield is examining the verified website.
          </strong>

          <p>
          Crawling, exposure checks, CORS and HTTP method testing,
subdomains, controlled ports, and JavaScript
advisories may take a few minutes.  
          </p>
        </div>
      )}


      {error && (
        <div className="deep-scan-error">
          {error}
        </div>
      )}


      {deepReport && (
        <div className="deep-scan-results">
          <div className="deep-result-header">
            <div>
              <span
                className={
                  deepReport.scan_status === "Complete"
                    ? "deep-status complete"
                    : "deep-status partial"
                }
              >
                {deepReport.scan_status}
              </span>

              <h4>{deepReport.name}</h4>
              <p>{deepReport.message}</p>
            </div>

            <strong>
              {deepReport.duration_seconds} seconds
            </strong>
          </div>


          <div className="deep-summary-grid">
            <div>
              <strong>
                {deepReport.finding_summary
                  ?.pages_crawled || 0}
              </strong>
              <span>Pages crawled</span>
            </div>

            <div>
              <strong>
                {deepReport.finding_summary
                  ?.sensitive_exposures || 0}
              </strong>
              <span>Exposures</span>
            </div>

<div>
  <strong>
    {deepReport.finding_summary
      ?.cors_findings || 0}
  </strong>

  <span>CORS findings</span>
</div>

<div>
  <strong>
    {deepReport.finding_summary
      ?.http_method_findings || 0}
  </strong>

  <span>HTTP method findings</span>
</div>

            <div>
              <strong>
                {deepReport.finding_summary
                  ?.subdomains_discovered || 0}
              </strong>
              <span>Subdomains</span>
            </div>

            <div>
              <strong>
                {deepReport.finding_summary
                  ?.open_ports || 0}
              </strong>
              <span>Open ports</span>
            </div>

            <div>
              <strong>
                {deepReport.finding_summary
                  ?.javascript_advisories || 0}
              </strong>
              <span>JS advisories</span>
            </div>

            <div>
              <strong>
                {deepReport.finding_summary
                  ?.zap_findings || 0}
              </strong>
              <span>ZAP findings</span>
            </div>
          </div>
          <DeepScanDetails report={deepReport} />


          {deepReport.scan_failures?.length > 0 && (
            <div className="deep-scan-failures">
              <h5>Checks that could not finish</h5>

              {deepReport.scan_failures.map(
                (failure) => (
                  <p key={failure.scanner}>
                    <strong>{failure.scanner}:</strong>{" "}
                    {failure.message}
                  </p>
                )
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}


export default DeepScanPanel;