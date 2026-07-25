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


function AuthenticatedTestingPanel({
  domain,
  engagementReceipt,
  bugBountyMode = false,
}) {
  const [accessMethod, setAccessMethod] = useState("standard");
  const [loginUrl, setLoginUrl] = useState("");
  const [protectedUrl, setProtectedUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [cookieHeader, setCookieHeader] = useState("");
  const [ownSessionConfirmed, setOwnSessionConfirmed] = useState(false);
  const [anonymousDenialConfirmed, setAnonymousDenialConfirmed] =
    useState(false);
  const [acceptMedium, setAcceptMedium] = useState(false);
  const [running, setRunning] = useState(false);
  const [stage, setStage] = useState("");
  const [error, setError] = useState("");
  const [cleanupWarning, setCleanupWarning] = useState("");
  const [result, setResult] = useState(null);
  const [prepareLogoutTest, setPrepareLogoutTest] = useState(false);
  const [verificationEndpointUrl, setVerificationEndpointUrl] = useState("");
  const [verificationMethod, setVerificationMethod] = useState("GET");
  const [verificationJsonBody, setVerificationJsonBody] = useState("{}");
  const [readOnlyPostConfirmed, setReadOnlyPostConfirmed] = useState(false);
  const [logoutTest, setLogoutTest] = useState(null);
  const [logoutResult, setLogoutResult] = useState(null);
  const [checkingLogout, setCheckingLogout] = useState(false);

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
    setLogoutResult(null);

    try {
      if (accessMethod === "browser") {
        if (!ownSessionConfirmed) {
          throw new Error(
            "Confirm that this browser session belongs to your own dedicated test account."
          );
        }
        setStage("Creating a short-lived local browser-session handoff...");
        const browserSession = await readResponse(
          await fetch(`${API_URL}/engagement/browser-session`, {
            method: "POST",
            headers: authorizationHeaders,
            body: JSON.stringify({
              domain,
              cookie_header: cookieHeader,
              ttl_minutes: 15,
              researcher_owned_account_confirmed: ownSessionConfirmed,
            }),
          })
        );
        sessionId = browserSession.session_id;
        setCookieHeader("");
      } else {
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
      }

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
      if (
        verification.status === "Likely Authenticated"
        && bugBountyMode
        && !anonymousDenialConfirmed
      ) {
        throw new Error(
          "WebShield found Medium-confidence login evidence. First confirm below that this protected URL denied account access in a logged-out Incognito window."
        );
      }
      if (
        verification.status === "Likely Authenticated"
        && !bugBountyMode
        && !acceptMedium
      ) {
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
            max_pages: bugBountyMode ? 5 : 15,
            max_depth: bugBountyMode ? 1 : 2,
            accept_medium_confidence: bugBountyMode
              ? anonymousDenialConfirmed
              : acceptMedium,
            anonymous_access_denial_confirmed: bugBountyMode
              ? anonymousDenialConfirmed
              : false,
          }),
        })
      );
      if (prepareLogoutTest) {
        let parsedVerificationBody = null;
        if (verificationMethod === "POST") {
          try {
            parsedVerificationBody = JSON.parse(verificationJsonBody);
          } catch {
            throw new Error(
              "The read-only POST body must be valid JSON."
            );
          }
          if (
            !parsedVerificationBody
            || Array.isArray(parsedVerificationBody)
            || typeof parsedVerificationBody !== "object"
          ) {
            throw new Error(
              "The read-only POST body must be one JSON object."
            );
          }
        }
        setStage("Preparing a short-lived logout invalidation baseline...");
        const preparedLogout = await readResponse(
          await fetch(`${API_URL}/engagement/logout-test/prepare`, {
            method: "POST",
            headers: authorizationHeaders,
            body: JSON.stringify({
              domain,
              session_id: sessionId,
              protected_url: protectedUrl,
              anonymous_access_denial_confirmed: bugBountyMode
                ? anonymousDenialConfirmed
                : false,
              verification_endpoint_url:
                verificationEndpointUrl.trim() || null,
              verification_method: verificationMethod,
              verification_json_body: parsedVerificationBody,
              read_only_post_confirmed: readOnlyPostConfirmed,
            }),
          })
        );
        setLogoutTest(preparedLogout);
        sessionId = "";
      }
      setResult({ verification, crawl });
      setStage(
        prepareLogoutTest
          ? "Assessment complete. Log out manually, then run the one-time old-session check below."
          : "Authenticated assessment complete."
      );
    } catch (requestError) {
      setError(requestError.message);
      setStage("Authenticated assessment stopped safely.");
    } finally {
      setPassword("");
      setCookieHeader("");
      await removeTemporaryAccess(sessionId, credentialId);
      setRunning(false);
    }
  };

  const checkLogoutInvalidation = async () => {
    if (!logoutTest || checkingLogout) return;
    setCheckingLogout(true);
    setError("");
    setStage("Replaying the old session once after your confirmed logout...");
    try {
      const checked = await readResponse(
        await fetch(`${API_URL}/engagement/logout-test/check`, {
          method: "POST",
          headers: authorizationHeaders,
          body: JSON.stringify({
            domain,
            test_id: logoutTest.test_id,
            logout_completed_confirmed: true,
          }),
        })
      );
      setLogoutResult(checked);
      setLogoutTest(null);
      setStage("Logout invalidation check complete. The old session was deleted.");
    } catch (requestError) {
      setError(requestError.message);
      setLogoutTest(null);
      setStage("Logout check stopped; WebShield discarded the temporary test.");
    } finally {
      setCheckingLogout(false);
    }
  };

  const cancelLogoutTest = async () => {
    if (!logoutTest || checkingLogout) return;
    setCheckingLogout(true);
    try {
      await readResponse(
        await fetch(
          `${API_URL}/engagement/logout-test/${encodeURIComponent(logoutTest.test_id)}`
            + `?domain=${encodeURIComponent(domain)}`,
          { method: "DELETE", headers: authorizationHeaders }
        )
      );
      setLogoutTest(null);
      setStage("Logout test cancelled and the old session deleted.");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setCheckingLogout(false);
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
            Use only your dedicated low-privilege test account. WebShield makes
            either one standard login attempt or accepts a short-lived session
            from your already logged-in browser. It verifies one protected page,
            sends read-only GET requests, and deletes temporary access afterward.
          </p>
          {bugBountyMode && (
            <p>
              Bug bounty limits: five same-host pages, depth one, half-second
              pacing, no form submission, and High-confidence login evidence.
            </p>
          )}

          <label className="authenticated-medium-option logout-test-option">
            <input
              type="checkbox"
              checked={prepareLogoutTest}
              onChange={(event) => setPrepareLogoutTest(event.target.checked)}
              disabled={running || Boolean(logoutTest)}
            />
            After this assessment, preserve one short-lived session baseline so
            I can log out manually and test whether the old session was revoked.
          </label>

          {prepareLogoutTest && (
            <div className="logout-endpoint-option">
              <div className="logout-method-selector">
                <button
                  type="button"
                  className={verificationMethod === "GET" ? "selected" : ""}
                  onClick={() => setVerificationMethod("GET")}
                  disabled={running || Boolean(logoutTest)}
                >
                  Safe GET
                </button>
                <button
                  type="button"
                  className={verificationMethod === "POST" ? "selected" : ""}
                  onClick={() => setVerificationMethod("POST")}
                  disabled={running || Boolean(logoutTest)}
                >
                  Controlled read-only POST
                </button>
              </div>
              <label>
                Read-only account endpoint URL (recommended)
                <input
                  type="url"
                  value={verificationEndpointUrl}
                  onChange={(event) =>
                    setVerificationEndpointUrl(event.target.value)
                  }
                  disabled={running || Boolean(logoutTest)}
                  placeholder="https://example.com/api/account/profile"
                />
              </label>
              {verificationMethod === "POST" && (
                <>
                  <label>
                    JSON request body
                    <textarea
                      rows="7"
                      maxLength="16384"
                      value={verificationJsonBody}
                      onChange={(event) =>
                        setVerificationJsonBody(event.target.value)
                      }
                      disabled={running || Boolean(logoutTest)}
                      spellCheck="false"
                      autoComplete="off"
                    />
                  </label>
                  <label className="authenticated-medium-option">
                    <input
                      type="checkbox"
                      checked={readOnlyPostConfirmed}
                      onChange={(event) =>
                        setReadOnlyPostConfirmed(event.target.checked)
                      }
                      disabled={running || Boolean(logoutTest)}
                    />
                    I inspected this operation and confirm it only reads my own
                    researcher-owned test account. It does not book, pay, edit,
                    bind, send, upload, cancel, delete, or trigger an OTP.
                  </label>
                </>
              )}
              <p>
                Use one same-host endpoint that returns account information while
                logged in and denies it while logged out. Leave this empty in GET
                mode to use the protected page instead. Never include a token,
                password, booking action, payment action, or another person&apos;s
                identifier.
              </p>
            </div>
          )}
        </div>

        <form onSubmit={runAssessment} className="authenticated-testing-form">
          <div className="authenticated-access-methods">
            <button
              type="button"
              className={accessMethod === "standard" ? "selected" : ""}
              onClick={() => setAccessMethod("standard")}
              disabled={running}
            >
              Standard login form
            </button>
            <button
              type="button"
              className={accessMethod === "browser" ? "selected" : ""}
              onClick={() => setAccessMethod("browser")}
              disabled={running}
            >
              Existing browser session
            </button>
          </div>

          {accessMethod === "standard" && (
          <>
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
          </>
          )}

          {accessMethod === "browser" && (
            <div className="browser-session-handoff">
              <div className="browser-session-instructions">
                <strong>Copy your session locally</strong>
                <ol>
                  <li>Log in normally and open the protected account page.</li>
                  <li>Press F12, open Network, then reload that page.</li>
                  <li>Select the same-host document request.</li>
                  <li>Under Request Headers, copy only the Cookie value.</li>
                  <li>Paste it below. Never send it in chat or commit it to Git.</li>
                </ol>
              </div>
              <label>
                Cookie request-header value
                <textarea
                  required
                  rows="4"
                  maxLength="16384"
                  value={cookieHeader}
                  onChange={(event) => setCookieHeader(event.target.value)}
                  placeholder="cookie_name=value; another_cookie=value"
                  autoComplete="off"
                  spellCheck="false"
                />
              </label>
              <label className="authenticated-medium-option">
                <input
                  type="checkbox"
                  checked={ownSessionConfirmed}
                  onChange={(event) =>
                    setOwnSessionConfirmed(event.target.checked)
                  }
                />
                This session belongs only to my dedicated researcher-owned test
                account, and I understand it is as sensitive as a password.
              </label>
            </div>
          )}

          <label>
            Protected page URL
            <input
              type="url"
              required
              value={protectedUrl}
              onChange={(event) => setProtectedUrl(event.target.value)}
              placeholder="https://example.com/account"
            />
          </label>

          {bugBountyMode && (
            <label className="authenticated-medium-option">
              <input
                type="checkbox"
                checked={anonymousDenialConfirmed}
                onChange={(event) =>
                  setAnonymousDenialConfirmed(event.target.checked)
                }
              />
              I opened this exact protected URL in a logged-out Incognito/private
              window and confirmed that it redirected to login or showed no
              account information.
            </label>
          )}

          {!bugBountyMode && (
          <label className="authenticated-medium-option">
            <input
              type="checkbox"
              checked={acceptMedium}
              onChange={(event) => setAcceptMedium(event.target.checked)}
            />
            Allow read-only crawling when login evidence is Medium confidence.
          </label>
          )}

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
          {result.crawl.authenticated_security && (
            <div className="authenticated-security-summary">
              <div>
                <span>Authenticated CORS</span>
                <strong>
                  {result.crawl.authenticated_security.cors?.status || "Unavailable"}
                </strong>
                <small>Credentialed cross-origin reading</small>
              </div>
              <div>
                <span>Private-page caching</span>
                <strong>
                  {result.crawl.authenticated_security.data_transport?.cache?.status
                    || "Unavailable"}
                </strong>
                <small>Shared-cache exposure signals</small>
              </div>
              <div>
                <span>Sensitive URL transport</span>
                <strong>
                  {result.crawl.authenticated_security.data_transport?.checks?.some(
                    (item) => item.name.includes("Page URL")
                  ) ? "Needs Attention" : "Not Observed"}
                </strong>
                <small>Values are never displayed</small>
              </div>
              <div>
                <span>Session fixation protection</span>
                <strong>
                  {result.crawl.session_fixation?.status || "Not Observable"}
                </strong>
                <small>
                  {result.crawl.session_fixation?.confidence || "Low"} confidence
                  {" · "}cookie values never displayed
                </small>
              </div>
            </div>
          )}
          {result.crawl.vulnerability_report && (
            <VulnerabilityOverview
              report={result.crawl.vulnerability_report}
            />
          )}
          </>
        )}

        {logoutTest && (
          <div className="logout-test-workflow">
            <span className="deep-scan-label">Manual step required</span>
            <h4>Log out normally in Trip.com</h4>
            <ol>
              <li>Return to the same browser account.</li>
              <li>Use Trip.com&apos;s normal Log out button.</li>
              <li>Confirm the account page no longer displays your information.</li>
              <li>Return here and run the one-time old-session check.</li>
            </ol>
            <p>
              Do not close the backend. This temporary baseline expires in about
              fifteen minutes and contains hashes only, never returned values.
            </p>
            <div className="logout-test-actions">
              <button
                className="deep-primary-button"
                type="button"
                onClick={checkLogoutInvalidation}
                disabled={checkingLogout}
              >
                {checkingLogout ? "Checking once..." : "I Logged Out — Check Old Session"}
              </button>
              <button
                className="deep-secondary-button"
                type="button"
                onClick={cancelLogoutTest}
                disabled={checkingLogout}
              >
                Cancel and Delete Session
              </button>
            </div>
          </div>
        )}

        {logoutResult && (
          <div className={`logout-test-result status-${logoutResult.status
            .toLowerCase().replaceAll(" ", "-")}`}>
            <span>Logout session invalidation</span>
            <strong>{logoutResult.status}</strong>
            <p>{logoutResult.message}</p>
            <small>Verification: {logoutResult.verification_mode}</small>
            {logoutResult.finding && (
              <div>
                <b>{logoutResult.finding.severity}: {logoutResult.finding.title}</b>
                <p>{logoutResult.finding.message}</p>
              </div>
            )}
            <small>Old session deleted: {logoutResult.old_session_deleted ? "Yes" : "No"}</small>
          </div>
        )}

      </div>
    </details>
  );
}


export default AuthenticatedTestingPanel;
