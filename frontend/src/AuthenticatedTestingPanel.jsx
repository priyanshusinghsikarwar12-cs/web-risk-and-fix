import { useState } from "react";
import VulnerabilityOverview from "./VulnerabilityOverview";


const API_URL = "http://127.0.0.1:8000";


async function readResponse(response) {
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("WebShield received an unreadable server response.");
  }
  if (!response.ok) {
    throw new Error(data.detail || "The authenticated assessment could not continue.");
  }
  return data;
}


function AuthenticatedTestingPanel({ domain, engagementReceipt }) {
  const [loginUrl, setLoginUrl] = useState("");
  const [protectedUrl, setProtectedUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [acceptMedium, setAcceptMedium] = useState(false);
  const [running, setRunning] = useState(false);
  const [stage, setStage] = useState("");
  const [error, setError] = useState("");
  const [cleanupWarning, setCleanupWarning] = useState("");
  const [result, setResult] = useState(null);

  const authorizationHeaders = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${engagementReceipt}`,
  };

  const removeTemporaryAccess = async (sessionId, credentialId) => {
    const failures = [];
    if (sessionId) {
      try {
        const response = await fetch(
          `${API_URL}/engagement/login-session/${encodeURIComponent(sessionId)}`
            + `?domain=${encodeURIComponent(domain)}`,
          { method: "DELETE", headers: authorizationHeaders }
        );
        if (!response.ok) failures.push("login session");
      } catch {
        failures.push("login session");
      }
    }
    if (credentialId) {
      try {
        const response = await fetch(
          `${API_URL}/engagement/test-account/${encodeURIComponent(credentialId)}`
            + `?domain=${encodeURIComponent(domain)}`,
          { method: "DELETE", headers: authorizationHeaders }
        );
        if (!response.ok) failures.push("test credential");
      } catch {
        failures.push("test credential");
      }
    }
    if (failures.length) {
      setCleanupWarning(
        `WebShield could not confirm deletion of: ${failures.join(", ")}. `
          + "Restarting the backend clears all volatile test access."
      );
    }
  };

  const runAssessment = async (event) => {
    event.preventDefault();
    if (running) return;

    let credentialId = "";
    let sessionId = "";
    setRunning(true);
    setError("");
    setCleanupWarning("");
    setResult(null);

    try {
      setStage("Encrypting the dedicated test account...");
      const stored = await readResponse(
        await fetch(`${API_URL}/engagement/test-account`, {
          method: "POST",
          headers: authorizationHeaders,
          body: JSON.stringify({
            domain,
            login_url: loginUrl,
            username,
            password,
            ttl_minutes: 60,
          }),
        })
      );
      credentialId = stored.credential_id;
      setPassword("");

      setStage("Making one authorized login attempt...");
      const loginSession = await readResponse(
        await fetch(`${API_URL}/engagement/login-session`, {
          method: "POST",
          headers: authorizationHeaders,
          body: JSON.stringify({ domain, credential_id: credentialId }),
        })
      );
      sessionId = loginSession.session_id;

      setStage("Confirming access to the protected page...");
      const verification = await readResponse(
        await fetch(`${API_URL}/engagement/protected-page/verify`, {
          method: "POST",
          headers: authorizationHeaders,
          body: JSON.stringify({
            domain,
            session_id: sessionId,
            protected_url: protectedUrl,
          }),
        })
      );

      if (verification.status === "Not Verified") {
        throw new Error(
          "Login could not be verified, so WebShield stopped before crawling private pages."
        );
      }
      if (verification.status === "Likely Authenticated" && !acceptMedium) {
        throw new Error(
          "Authentication evidence was only medium confidence. Enable the option below only if this result is acceptable for the engagement."
        );
      }

      setStage("Inspecting protected pages with safe GET requests...");
      const crawl = await readResponse(
        await fetch(`${API_URL}/engagement/authenticated-crawl`, {
          method: "POST",
          headers: authorizationHeaders,
          body: JSON.stringify({
            domain,
            session_id: sessionId,
            protected_url: protectedUrl,
            max_pages: 15,
            max_depth: 2,
            accept_medium_confidence: acceptMedium,
          }),
        })
      );
      setResult({ verification, crawl });
      setStage("Authenticated assessment complete.");
    } catch (requestError) {
      setError(requestError.message);
      setStage("Authenticated assessment stopped safely.");
    } finally {
      setPassword("");
      await removeTemporaryAccess(sessionId, credentialId);
      setRunning(false);
    }
  };

  return (
    <details className="authenticated-testing-panel">
      <summary>Optional authenticated testing</summary>

      <div className="authenticated-testing-body">
        <div>
          <span className="deep-scan-label">Protected pages</span>
          <h4>Run one complete authenticated assessment</h4>
          <p>
            Use a dedicated low-privilege test account. Press Enter in any field
            or click once; WebShield handles every protected step automatically.
          </p>
        </div>

        <form onSubmit={runAssessment} className="authenticated-testing-form">
          <label>
            Login page URL
            <input
              type="url"
              required
              value={loginUrl}
              onChange={(event) => setLoginUrl(event.target.value)}
              placeholder="https://example.com/login"
            />
          </label>
          <label>
            Protected page URL
            <input
              type="url"
              required
              value={protectedUrl}
              onChange={(event) => setProtectedUrl(event.target.value)}
              placeholder="https://example.com/dashboard"
            />
          </label>
          <label>
            Dedicated test username
            <input
              required
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="off"
            />
          </label>
          <label>
            Temporary test password
            <input
              type="password"
              required
              minLength="8"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="new-password"
            />
          </label>

          <label className="authenticated-medium-option">
            <input
              type="checkbox"
              checked={acceptMedium}
              onChange={(event) => setAcceptMedium(event.target.checked)}
            />
            Allow read-only crawling when login evidence is Medium confidence.
          </label>

          <button className="deep-primary-button" type="submit" disabled={running}>
            {running ? "Assessment running..." : "Run Authenticated Assessment"}
          </button>
        </form>

        {stage && <p className="authenticated-stage">{stage}</p>}
        {error && <div className="deep-scan-error">{error}</div>}
        {cleanupWarning && (
          <div className="authenticated-cleanup-warning">{cleanupWarning}</div>
        )}

        {result && (
          <>
          <div className="authenticated-result">
            <div>
              <span>Authentication</span>
              <strong>{result.verification.status}</strong>
              <small>{result.verification.confidence} confidence</small>
            </div>
            <div>
              <span>Protected pages inspected</span>
              <strong>{result.crawl.pages_scanned || 0}</strong>
              <small>Read-only GET requests</small>
            </div>
            <div>
              <span>Forms submitted</span>
              <strong>{result.crawl.forms_submitted || 0}</strong>
              <small>Temporary access deleted</small>
            </div>
          </div>
          {result.crawl.vulnerability_report && (
            <VulnerabilityOverview
              report={result.crawl.vulnerability_report}
            />
          )}
          </>
        )}
      </div>
    </details>
  );
}


export default AuthenticatedTestingPanel;
