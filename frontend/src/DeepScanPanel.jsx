import { useEffect, useState } from "react";
import DeepScanDetails from "./DeepScanDetails";
import VulnerabilityOverview from "./VulnerabilityOverview";
import AuthenticatedTestingPanel from "./AuthenticatedTestingPanel";


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
  const [engagementReceipt, setEngagementReceipt] =
    useState("");
  const [engagementProfile, setEngagementProfile] =
    useState(null);
  const [clientReference, setClientReference] =
    useState("");
  const [authorizedBy, setAuthorizedBy] = useState("");
  const [environment, setEnvironment] =
    useState("production");
  const [authorizationConfirmed, setAuthorizationConfirmed] =
    useState(false);
  const [deepReport, setDeepReport] = useState(null);

  const [creatingChallenge, setCreatingChallenge] =
    useState(false);
  const [checkingProof, setCheckingProof] =
    useState(false);
  const [deepScanning, setDeepScanning] =
    useState(false);
  const [creatingEngagement, setCreatingEngagement] =
    useState(false);
  const [error, setError] = useState("");
  const [devAdminToken, setDevAdminToken] =
  useState("");


  useEffect(() => {
    setChallenge(null);
    setMethod("dns");
    setAuthorizationReceipt("");
    setAuthorizationExpiresAt(null);
    const storageKey = `webshield-engagement:${domain.toLowerCase()}`;
    const storedProfile = sessionStorage.getItem(storageKey);
    if (storedProfile) {
      try {
        const parsed = JSON.parse(storedProfile);
        if (parsed.expires_at * 1000 > Date.now()) {
          setEngagementReceipt(parsed.receipt);
          setEngagementProfile(parsed);
        } else {
          sessionStorage.removeItem(storageKey);
          setEngagementReceipt("");
          setEngagementProfile(null);
        }
      } catch {
        sessionStorage.removeItem(storageKey);
        setEngagementReceipt("");
        setEngagementProfile(null);
      }
    } else {
      setEngagementReceipt("");
      setEngagementProfile(null);
    }
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


  const createEngagement = async () => {
    if (!authorizationReceipt) {
      setError("Verify domain ownership before creating the engagement.");
      return;
    }
    if (!authorizationConfirmed) {
      setError("Confirm that the named client authorized this assessment.");
      return;
    }

    setError("");
    setCreatingEngagement(true);

    try {
      const requestHeaders = {
        "Content-Type": "application/json",
      };
      requestHeaders.Authorization = `Bearer ${authorizationReceipt}`;

      const response = await fetch(
        `${API_URL}/engagement/profile`,
        {
          method: "POST",
          headers: requestHeaders,
          body: JSON.stringify({
            domain,
            client_reference: clientReference,
            authorized_by: authorizedBy,
            environment,
            max_pages: 25,
            max_depth: 2,
            include_zap: false,
            zap_spider_minutes: 1,
            zap_maximum_minutes: 5,
            approved_scanners: [
              "crawler",
              "exposure_checks",
              "cors",
              "http_methods",
              "subdomains",
              "ports",
              "javascript_advisories",
            ],
            authorization_confirmed: true,
          }),
        }
      );
      const data = await readResponse(response);
      setEngagementReceipt(data.receipt);
      setEngagementProfile(data);
      sessionStorage.setItem(
        `webshield-engagement:${domain.toLowerCase()}`,
        JSON.stringify(data)
      );
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setCreatingEngagement(false);
    }
  };


  const runAdminTestScan = async () => {
    const cleanAdminToken = devAdminToken.trim();
    if (!cleanAdminToken) {
      setError("Enter the local development admin token first.");
      return;
    }

    setError("");
    setCreatingEngagement(true);
    setDeepScanning(true);
    setDeepReport(null);

    try {
      const profileResponse = await fetch(
        `${API_URL}/engagement/profile`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-WebShield-Admin-Token": cleanAdminToken,
          },
          body: JSON.stringify({
            domain,
            client_reference: "Local development test",
            authorized_by: "WebShield local administrator",
            environment: "development",
            max_pages: 25,
            max_depth: 2,
            include_zap: false,
            zap_spider_minutes: 1,
            zap_maximum_minutes: 5,
            approved_scanners: [
              "crawler",
              "exposure_checks",
              "cors",
              "http_methods",
              "subdomains",
              "ports",
              "javascript_advisories",
            ],
            authorization_confirmed: true,
          }),
        }
      );
      const profile = await readResponse(profileResponse);
      setEngagementReceipt(profile.receipt);
      setEngagementProfile(profile);
      sessionStorage.setItem(
        `webshield-engagement:${domain.toLowerCase()}`,
        JSON.stringify(profile)
      );

      const scanResponse = await fetch(
        `${API_URL}/deep-scan/run`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${profile.receipt}`,
          },
          body: JSON.stringify({
            domain,
            max_pages: 25,
            max_depth: 2,
            include_zap: false,
            zap_spider_minutes: 1,
            zap_maximum_minutes: 5,
          }),
        }
      );
      setDeepReport(await readResponse(scanResponse));
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setCreatingEngagement(false);
      setDeepScanning(false);
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
    !engagementReceipt
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

if (engagementReceipt) {
  requestHeaders.Authorization = (
    `Bearer ${engagementReceipt}`
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

        {!challenge && !engagementReceipt && (
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
  !authorizationReceipt &&
  !engagementReceipt && (
    <details className="dev-admin-panel">
      <summary>
        Local development admin testing
      </summary>

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
        onClick={runAdminTestScan}
        disabled={
          deepScanning || creatingEngagement ||
          !devAdminToken.trim()
        }
      >
        {deepScanning
          ? "Running admin test scan..."
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


      {authorizationReceipt && !engagementReceipt && (
        <div className="engagement-setup">
          <div className="engagement-setup-heading">
            <span className="verified-badge">Ownership verified</span>
            <h4>Set the assessment rules once</h4>
            <p>
              These signed rules control this engagement. WebShield will
              reuse them for scans in this browser session.
            </p>
          </div>

          <div className="engagement-fields">
            <label>
              Client or approval reference
              <input
                value={clientReference}
                onChange={(event) => setClientReference(event.target.value)}
                placeholder="Example: Client website assessment #001"
              />
            </label>

            <label>
              Authorized by
              <input
                value={authorizedBy}
                onChange={(event) => setAuthorizedBy(event.target.value)}
                placeholder="Name or role of approving person"
              />
            </label>

            <label>
              Environment
              <select
                value={environment}
                onChange={(event) => setEnvironment(event.target.value)}
              >
                <option value="production">Production website</option>
                <option value="staging">Staging website</option>
                <option value="development">Development website</option>
              </select>
            </label>
          </div>

          <div className="engagement-scope-summary">
            <strong>Approved safe deep checks</strong>
            <p>
              Up to 25 pages and depth 2: crawling, exposure checks,
              CORS, HTTP methods, subdomains, ports, and JavaScript advisories.
              ZAP remains off until Docker is available.
            </p>
          </div>

          <label className="engagement-confirmation">
            <input
              type="checkbox"
              checked={authorizationConfirmed}
              onChange={(event) =>
                setAuthorizationConfirmed(event.target.checked)
              }
            />
            I confirm that the named client authorized WebShield to perform
            these checks on this domain.
          </label>

          <button
            className="deep-primary-button"
            onClick={createEngagement}
            disabled={
              creatingEngagement ||
              !clientReference.trim() ||
              !authorizedBy.trim() ||
              !authorizationConfirmed
            }
          >
            {creatingEngagement
              ? "Signing engagement..."
              : "Create Engagement Profile"}
          </button>

          <p className="verification-expiry">
            Ownership proof expires: {formatExpiry(authorizationExpiresAt)}
          </p>
        </div>
      )}

      {engagementReceipt && engagementProfile && (
        <div className="verified-domain engagement-ready">
          <div>
            <span className="verified-badge">Engagement ready</span>
            <h4>{engagementProfile.client_reference}</h4>
            <p>
              {domain} · {engagementProfile.environment} · authorized by{" "}
              {engagementProfile.authorized_by}
            </p>
            <p>
              Signed limits expire: {formatExpiry(engagementProfile.expires_at)}
            </p>
          </div>

          <button
            className="deep-primary-button"
            onClick={startDeepScan}
            disabled={deepScanning}
          >
            {deepScanning ? "Running deep scan..." : "Start Deep Scan"}
          </button>
        </div>
      )}

      {engagementReceipt && (
        <AuthenticatedTestingPanel
          domain={domain}
          engagementReceipt={engagementReceipt}
        />
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


          <VulnerabilityOverview report={deepReport} />

          <details className="technical-evidence-disclosure">
            <summary>
              <span>
                Technical observations and complete scanner evidence
                <small>
                  Pages, subdomains, hosting, ports, and raw scanner results
                </small>
              </span>

              <strong>View details</strong>
            </summary>

            <DeepScanDetails report={deepReport} />
          </details>


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
