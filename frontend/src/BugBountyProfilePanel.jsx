import { useState } from "react";
import "./BugBountyProfilePanel.css";


const API_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

const SAFE_SCANNERS = [
  {
    id: "crawler",
    name: "Application crawler",
    description: "Read a maximum of five same-host pages without submitting forms.",
  },
  {
    id: "exposure_checks",
    name: "Sensitive exposure checks",
    description: "Check a small fixed list of commonly exposed public resources.",
  },
  {
    id: "cors",
    name: "Cross-origin access (CORS)",
    description: "Observe whether unrelated websites receive permission to read responses.",
  },
  {
    id: "javascript_advisories",
    name: "JavaScript advisories",
    description: "Match exact visible library versions to known advisories; disable when version-only reports are excluded.",
  },
];

const POLICY_EXCLUSIONS = [
  {
    id: "missing_security_headers",
    name: "Missing security headers",
    description: "Exclude header-only observations when the program requires direct exploit impact.",
  },
  {
    id: "cookie_attribute_observations",
    name: "Cookie attribute observations",
    description: "Exclude generic cookie-flag observations without proven session or account impact.",
  },
  {
    id: "form_hygiene_observations",
    name: "Form best-practice observations",
    description: "Exclude HTML-form signals such as missing visible CSRF fields or autocomplete guidance.",
  },
  {
    id: "mixed_content_observations",
    name: "Mixed-content observations",
    description: "Exclude HTTP-resource configuration observations when the program does not reward them.",
  },
];


async function readResponse(response) {
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.detail || "The safe profile could not be created.");
  }
  return data;
}


function BugBountyProfilePanel({ domain, onProfileCreated }) {
  const [programName, setProgramName] = useState("");
  const [programUrl, setProgramUrl] = useState("");
  const [researcherHandle, setResearcherHandle] = useState("");
  const [scopeReference, setScopeReference] = useState("");
  const [policySavedDate, setPolicySavedDate] = useState(
    new Date().toISOString().slice(0, 10)
  );
  const [confirmations, setConfirmations] = useState({
    asset: false,
    rules: false,
    safeHarbor: false,
    ownAccounts: false,
  });
  const [approvedScanners, setApprovedScanners] = useState(
    SAFE_SCANNERS.map((scanner) => scanner.id)
  );
  const [excludedFindingTypes, setExcludedFindingTypes] = useState([]);
  const [authenticatedTestingApproved, setAuthenticatedTestingApproved] =
    useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const allConfirmed = Object.values(confirmations).every(Boolean);

  const updateConfirmation = (name, checked) => {
    setConfirmations((current) => ({ ...current, [name]: checked }));
  };

  const updateScanner = (scannerId, checked) => {
    setApprovedScanners((current) => {
      if (checked) {
        return current.includes(scannerId)
          ? current
          : [...current, scannerId];
      }
      return current.filter((item) => item !== scannerId);
    });
  };

  const updatePolicyExclusion = (findingType, checked) => {
    setExcludedFindingTypes((current) => {
      if (checked) {
        return current.includes(findingType)
          ? current
          : [...current, findingType];
      }
      return current.filter((item) => item !== findingType);
    });
  };

  const createProfile = async (event) => {
    event.preventDefault();
    setError("");

    if (!domain) {
      setError("Run the normal website check before creating a profile.");
      return;
    }
    if (!allConfirmed) {
      setError("Confirm every bug bounty safety rule first.");
      return;
    }
    if (approvedScanners.length === 0) {
      setError("Select at least one safe scanner for this program.");
      return;
    }

    try {
      setLoading(true);
      const response = await fetch(
        `${API_URL}/engagement/bug-bounty-profile`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            domain,
            program_name: programName.trim(),
            program_url: programUrl.trim(),
            researcher_handle: researcherHandle.trim(),
            scope_reference: scopeReference.trim(),
            policy_saved_date: policySavedDate,
            approved_scanners: approvedScanners,
            excluded_finding_types: excludedFindingTypes,
            asset_in_scope_confirmed: confirmations.asset,
            program_rules_confirmed: confirmations.rules,
            safe_harbor_confirmed: confirmations.safeHarbor,
            researcher_owned_accounts_only: confirmations.ownAccounts,
            authenticated_testing_approved: authenticatedTestingApproved,
          }),
        }
      );
      onProfileCreated(await readResponse(response));
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <details className="bug-bounty-profile-panel">
      <summary>
        <span>
          <strong>Authorized public bug bounty</strong>
          <small>Create a rate-limited, scope-bound safe profile</small>
        </span>
        <span>Use program authorization</span>
      </summary>

      <form onSubmit={createProfile}>
        <div className="bug-bounty-intro">
          <strong>Safe profile for {domain || "the selected hostname"}</strong>
          <p>
            Five pages, depth one, one request at a time, and a minimum
            half-second delay. Ports, subdomains, infrastructure checks,
            HTTP-method probing, third-party navigation, and ZAP stay disabled.
          </p>
        </div>

        <div className="bug-bounty-fields">
          <label>
            Program name
            <input
              value={programName}
              onChange={(event) => setProgramName(event.target.value)}
              placeholder="Example: Company public bug bounty"
              required
            />
          </label>
          <label>
            HackerOne program URL
            <input
              type="url"
              value={programUrl}
              onChange={(event) => setProgramUrl(event.target.value)}
              placeholder="https://hackerone.com/program_handle"
              required
            />
          </label>
          <label>
            HackerOne researcher handle
            <input
              value={researcherHandle}
              onChange={(event) => setResearcherHandle(event.target.value)}
              placeholder="Your public HackerOne username"
              required
            />
          </label>
          <label>
            Saved policy date
            <input
              type="date"
              value={policySavedDate}
              onChange={(event) => setPolicySavedDate(event.target.value)}
              required
            />
          </label>
          <label className="bug-bounty-scope-field">
            Exact scope reference
            <input
              value={scopeReference}
              onChange={(event) => setScopeReference(event.target.value)}
              placeholder="Example: example.com — registration and login"
              required
            />
          </label>
        </div>

        <fieldset className="bug-bounty-scanners">
          <legend>Scanners approved for this program</legend>
          <p>
            Select only checks permitted by the saved policy. This exact list
            is signed into the profile and enforced by the backend.
          </p>

          <div className="bug-bounty-scanner-grid">
            {SAFE_SCANNERS.map((scanner) => (
              <label key={scanner.id}>
                <input
                  type="checkbox"
                  checked={approvedScanners.includes(scanner.id)}
                  onChange={(event) =>
                    updateScanner(scanner.id, event.target.checked)
                  }
                />
                <span>
                  <strong>{scanner.name}</strong>
                  <small>{scanner.description}</small>
                </span>
              </label>
            ))}
          </div>

          <strong className="bug-bounty-scanner-count">
            {approvedScanners.length} safe scanner
            {approvedScanners.length === 1 ? "" : "s"} selected
          </strong>
        </fieldset>

        <fieldset className="bug-bounty-scanners policy-exclusions">
          <legend>Findings excluded by the saved program policy</legend>
          <p>
            Select an item only when the written policy explicitly excludes it.
            WebShield will retain the evidence under excluded observations but
            remove it from the vulnerability total.
          </p>

          <div className="bug-bounty-scanner-grid">
            {POLICY_EXCLUSIONS.map((item) => (
              <label key={item.id}>
                <input
                  type="checkbox"
                  checked={excludedFindingTypes.includes(item.id)}
                  onChange={(event) =>
                    updatePolicyExclusion(item.id, event.target.checked)
                  }
                />
                <span>
                  <strong>{item.name}</strong>
                  <small>{item.description}</small>
                </span>
              </label>
            ))}
          </div>

          <strong className="bug-bounty-scanner-count">
            {excludedFindingTypes.length} policy exclusion
            {excludedFindingTypes.length === 1 ? "" : "s"} selected
          </strong>
        </fieldset>

        <div className="bug-bounty-confirmations">
          <label>
            <input
              type="checkbox"
              checked={confirmations.asset}
              onChange={(event) =>
                updateConfirmation("asset", event.target.checked)
              }
            />
            The exact hostname is currently listed as an in-scope asset.
          </label>
          <label>
            <input
              type="checkbox"
              checked={confirmations.rules}
              onChange={(event) =>
                updateConfirmation("rules", event.target.checked)
              }
            />
            I saved and reviewed the current program rules and rate limits.
          </label>
          <label>
            <input
              type="checkbox"
              checked={confirmations.safeHarbor}
              onChange={(event) =>
                updateConfirmation("safeHarbor", event.target.checked)
              }
            />
            The program explicitly provides safe harbor for this asset.
          </label>
          <label>
            <input
              type="checkbox"
              checked={confirmations.ownAccounts}
              onChange={(event) =>
                updateConfirmation("ownAccounts", event.target.checked)
              }
            />
            Authenticated testing will use only researcher-owned accounts.
          </label>
          <label>
            <input
              type="checkbox"
              checked={authenticatedTestingApproved}
              onChange={(event) =>
                setAuthenticatedTestingApproved(event.target.checked)
              }
            />
            Enable read-only authenticated testing for my own dedicated test
            account. WebShield may make one login attempt and inspect at most
            five same-host protected pages without submitting forms.
          </label>
        </div>

        <button
          type="submit"
          disabled={
            loading || !allConfirmed || approvedScanners.length === 0
          }
        >
          {loading ? "Signing safe profile..." : "Create Bug Bounty Safe Profile"}
        </button>
        {error && <p className="bug-bounty-error">{error}</p>}
      </form>
    </details>
  );
}


export default BugBountyProfilePanel;
