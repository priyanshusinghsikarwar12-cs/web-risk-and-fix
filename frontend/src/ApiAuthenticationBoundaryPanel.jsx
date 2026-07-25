import { useState } from "react";


const API_URL = "http://127.0.0.1:8000";


async function readResponse(response) {
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("WebShield received an unreadable server response.");
  }
  if (!response.ok) {
    throw new Error(data.detail || "The API authentication check could not continue.");
  }
  return data;
}


function ApiAuthenticationBoundaryPanel({
  domain,
  engagementReceipt,
  enabled = true,
  unavailableReason = "An owner-verified engagement is required.",
}) {
  const [cookieHeader, setCookieHeader] = useState("");
  const [endpointTemplate, setEndpointTemplate] = useState("");
  const [objectId, setObjectId] = useState("");
  const [privateObjectConfirmed, setPrivateObjectConfirmed] = useState(false);
  const [readOnlyConfirmed, setReadOnlyConfirmed] = useState(false);
  const [running, setRunning] = useState(false);
  const [stage, setStage] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${engagementReceipt}`,
  };

  const deleteSession = async (sessionId) => {
    if (!sessionId) return;
    try {
      await fetch(
        `${API_URL}/engagement/login-session/${encodeURIComponent(sessionId)}`
          + `?domain=${encodeURIComponent(domain)}`,
        { method: "DELETE", headers }
      );
    } catch {
      // Restarting the backend clears volatile sessions if cleanup fails.
    }
  };

  const runCheck = async (event) => {
    event.preventDefault();
    if (running) return;

    let sessionId = "";
    setRunning(true);
    setError("");
    setResult(null);

    try {
      if (!privateObjectConfirmed || !readOnlyConfirmed) {
        throw new Error(
          "Confirm the private test object and read-only GET operation."
        );
      }

      setStage("Holding the test-account session in volatile memory...");
      const stored = await readResponse(
        await fetch(`${API_URL}/engagement/browser-session`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            domain,
            cookie_header: cookieHeader,
            ttl_minutes: 15,
            researcher_owned_account_confirmed: true,
          }),
        })
      );
      sessionId = stored.session_id;
      setCookieHeader("");

      setStage("Comparing the logged-in and logged-out object responses...");
      const checked = await readResponse(
        await fetch(`${API_URL}/engagement/api-auth-boundary/check`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            domain,
            session_id: sessionId,
            endpoint_template: endpointTemplate,
            object_id: objectId,
            read_only_get_confirmed: readOnlyConfirmed,
            private_test_object_confirmed: privateObjectConfirmed,
          }),
        })
      );
      setResult(checked);
      setStage("API authentication check complete. Temporary access was deleted.");
    } catch (requestError) {
      setError(requestError.message);
      setStage("API authentication check stopped safely.");
    } finally {
      setCookieHeader("");
      await deleteSession(sessionId);
      setRunning(false);
    }
  };

  if (!enabled) {
    return (
      <details className="object-access-panel object-access-locked" open>
        <summary>
          Common vulnerability test: API authentication boundary
        </summary>
        <div className="object-access-body">
          <span className="deep-scan-label">Available after authorization</span>
          <h4>Can a logged-out visitor read a private API object?</h4>
          <p>{unavailableReason}</p>
          <p>
            This test needs one client-owned test account, one private test
            object, and one confirmed read-only JSON endpoint.
          </p>
        </div>
      </details>
    );
  }

  return (
    <details className="object-access-panel" open>
      <summary>Common vulnerability test: API authentication boundary</summary>
      <div className="object-access-body">
        <div>
          <span className="deep-scan-label">Broken access control</span>
          <h4>Can a logged-out visitor read a private API object?</h4>
          <p>
            WebShield compares one authorized private JSON response with one
            logged-out response. It returns fingerprints and status only, never
            the object&apos;s private values.
          </p>
        </div>

        <form onSubmit={runCheck} className="object-access-form">
          <label>
            Read-only endpoint template
            <input
              type="url"
              required
              value={endpointTemplate}
              onChange={(event) => setEndpointTemplate(event.target.value)}
              placeholder="https://example.com/api/orders/{object_id}"
            />
          </label>
          <label>
            Test-account object ID
            <input
              required
              maxLength="128"
              value={objectId}
              onChange={(event) => setObjectId(event.target.value)}
              autoComplete="off"
            />
          </label>
          <label>
            Test-account Cookie request-header value
            <textarea
              required
              rows="4"
              maxLength="16384"
              value={cookieHeader}
              onChange={(event) => setCookieHeader(event.target.value)}
              autoComplete="off"
              spellCheck="false"
            />
          </label>

          <label className="authenticated-medium-option">
            <input
              type="checkbox"
              checked={privateObjectConfirmed}
              onChange={(event) => setPrivateObjectConfirmed(event.target.checked)}
            />
            This private object belongs to the client-owned test account and is
            not intended to be publicly accessible.
          </label>
          <label className="authenticated-medium-option">
            <input
              type="checkbox"
              checked={readOnlyConfirmed}
              onChange={(event) => setReadOnlyConfirmed(event.target.checked)}
            />
            I inspected this endpoint and confirm that GET only reads the test
            object; it does not create, update, send, purchase, or delete.
          </label>

          <button className="deep-primary-button" type="submit" disabled={running}>
            {running ? "Comparing two responses..." : "Run One-Account API Check"}
          </button>
        </form>

        {stage && <p className="authenticated-stage">{stage}</p>}
        {error && <div className="deep-scan-error">{error}</div>}
        {result && (
          <div className={`object-access-result status-${result.status
            .toLowerCase().replaceAll(" ", "-")}`}>
            <span>API authentication boundary</span>
            <strong>{result.status}</strong>
            <p>{result.message}</p>
            <small>{result.requests_made} bounded GET requests · values hidden</small>
            {result.checks?.map((finding) => (
              <div key={finding.name} className="object-access-finding">
                <b>{finding.severity}: {finding.name}</b>
                <p>{finding.message}</p>
                <small>{finding.confidence} confidence · {finding.validation}</small>
                <p><strong>Recommended action:</strong> {finding.remediation}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </details>
  );
}


export default ApiAuthenticationBoundaryPanel;
