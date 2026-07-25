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
    throw new Error(data.detail || "The object access check could not continue.");
  }
  return data;
}


function ObjectAccessControlPanel({
  domain,
  engagementReceipt,
  enabled = true,
  unavailableReason = "An owner-verified engagement is required.",
}) {
  const [cookieA, setCookieA] = useState("");
  const [cookieB, setCookieB] = useState("");
  const [endpointTemplate, setEndpointTemplate] = useState("");
  const [objectA, setObjectA] = useState("");
  const [objectB, setObjectB] = useState("");
  const [authorizedObjects, setAuthorizedObjects] = useState(false);
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
      // Restarting the backend clears every volatile session if cleanup fails.
    }
  };

  const runCheck = async (event) => {
    event.preventDefault();
    if (running) return;

    let sessionA = "";
    let sessionB = "";
    setRunning(true);
    setError("");
    setResult(null);

    try {
      if (!authorizedObjects || !readOnlyConfirmed) {
        throw new Error(
          "Confirm ownership of both test objects and the read-only GET operation."
        );
      }

      setStage("Holding Account A session in volatile memory...");
      const storedA = await readResponse(
        await fetch(`${API_URL}/engagement/browser-session`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            domain,
            cookie_header: cookieA,
            ttl_minutes: 15,
            researcher_owned_account_confirmed: true,
          }),
        })
      );
      sessionA = storedA.session_id;
      setCookieA("");

      setStage("Holding Account B session in volatile memory...");
      const storedB = await readResponse(
        await fetch(`${API_URL}/engagement/browser-session`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            domain,
            cookie_header: cookieB,
            ttl_minutes: 15,
            researcher_owned_account_confirmed: true,
          }),
        })
      );
      sessionB = storedB.session_id;
      setCookieB("");

      setStage("Comparing four bounded read-only object responses...");
      const checked = await readResponse(
        await fetch(`${API_URL}/engagement/object-access/check`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            domain,
            session_a_id: sessionA,
            session_b_id: sessionB,
            endpoint_template: endpointTemplate,
            object_a_id: objectA,
            object_b_id: objectB,
            read_only_get_confirmed: readOnlyConfirmed,
            test_accounts_own_objects_confirmed: authorizedObjects,
          }),
        })
      );
      setResult(checked);
      setStage("Object access-control check complete. Both sessions were deleted.");
    } catch (requestError) {
      setError(requestError.message);
      setStage("Object access-control check stopped safely.");
    } finally {
      setCookieA("");
      setCookieB("");
      await Promise.all([deleteSession(sessionA), deleteSession(sessionB)]);
      setRunning(false);
    }
  };

  if (!enabled) {
    return (
      <details className="object-access-panel object-access-locked" open>
        <summary>
          Advanced vulnerability test: Object access control (IDOR/BOLA)
        </summary>
        <div className="object-access-body">
          <span className="deep-scan-label">Available after authorization</span>
          <h4>Two-account access-control testing</h4>
          <p>{unavailableReason}</p>
          <p>
            This test needs two client-owned accounts, two client-owned test
            objects, and one confirmed read-only JSON endpoint. WebShield keeps
            it locked until that engagement context exists.
          </p>
        </div>
      </details>
    );
  }

  return (
    <details className="object-access-panel" open>
      <summary>
        Advanced vulnerability test: Object access control (IDOR/BOLA)
      </summary>
      <div className="object-access-body">
        <div>
          <span className="deep-scan-label">Broken access control</span>
          <h4>Can one test account read the other test account&apos;s object?</h4>
          <p>
            Use exactly two client-owned low-privilege test accounts and one
            read-only JSON endpoint. WebShield never guesses identifiers and
            never reads an unrelated customer&apos;s object.
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

          <div className="object-access-grid">
            <label>
              Account A object ID
              <input
                required
                maxLength="128"
                value={objectA}
                onChange={(event) => setObjectA(event.target.value)}
                autoComplete="off"
              />
            </label>
            <label>
              Account B object ID
              <input
                required
                maxLength="128"
                value={objectB}
                onChange={(event) => setObjectB(event.target.value)}
                autoComplete="off"
              />
            </label>
            <label>
              Account A Cookie request-header value
              <textarea
                required
                rows="4"
                maxLength="16384"
                value={cookieA}
                onChange={(event) => setCookieA(event.target.value)}
                autoComplete="off"
                spellCheck="false"
              />
            </label>
            <label>
              Account B Cookie request-header value
              <textarea
                required
                rows="4"
                maxLength="16384"
                value={cookieB}
                onChange={(event) => setCookieB(event.target.value)}
                autoComplete="off"
                spellCheck="false"
              />
            </label>
          </div>

          <label className="authenticated-medium-option">
            <input
              type="checkbox"
              checked={authorizedObjects}
              onChange={(event) => setAuthorizedObjects(event.target.checked)}
            />
            Both accounts and both object IDs were created for this authorized
            assessment and belong to the client&apos;s dedicated test data.
          </label>

          <label className="authenticated-medium-option">
            <input
              type="checkbox"
              checked={readOnlyConfirmed}
              onChange={(event) => setReadOnlyConfirmed(event.target.checked)}
            />
            I inspected this endpoint and confirm that GET only reads an object;
            it does not create, update, purchase, send, delete, or trigger work.
          </label>

          <button className="deep-primary-button" type="submit" disabled={running}>
            {running ? "Checking four responses..." : "Run Object Access Check"}
          </button>
        </form>

        {stage && <p className="authenticated-stage">{stage}</p>}
        {error && <div className="deep-scan-error">{error}</div>}

        {result && (
          <div className={`object-access-result status-${result.status
            .toLowerCase().replaceAll(" ", "-")}`}>
            <span>Object access control</span>
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


export default ObjectAccessControlPanel;
