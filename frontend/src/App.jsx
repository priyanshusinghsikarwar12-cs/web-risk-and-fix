import { useEffect, useState } from "react";
import "./App.css";

function App() {
  const [domain, setDomain] = useState("");
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [recentDomains, setRecentDomains] = useState([]);
  const [error, setError] = useState("");
  const [expandedRecommendation, setExpandedRecommendation] = useState(null);
  const [showRecentSearches, setShowRecentSearches] = useState(false);

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

      const response = await fetch(
        `http://127.0.0.1:8000/scan?domain=${encodeURIComponent(cleanDomain)}`
      );

      const data = await response.json();

      if (!response.ok || data.overall_status === "Website not reachable") {
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
                <h3>{report.overall_status}</h3>
                <p>{report.summary}</p>
              </div>
            </div>

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
                  {report.ssl_certificate?.days_left !== undefined
                    ? `${report.ssl_certificate.days_left} days left`
                    : "Certificate needs review"}
                </strong>
              </div>

              <div className="status-card">
                <h3>Domain Setup</h3>

                <p>
                  {report.dns_records?.checks?.filter(
                    (item) => item.status === "Found"
                  ).length || 0}{" "}
                  checks found
                </p>
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
                        check.status === "Found"
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