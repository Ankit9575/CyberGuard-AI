
import {
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  ShieldCheck,
  Info,
  ExternalLink,
  Clock3,
  Mail,
  MessageSquare,
  Globe,
  Sparkles,
  ArrowUpRight,
} from "lucide-react";
import "./AnalysisResult.css";

function AnalysisResult({ result, onReset }) {
  if (!result) return null;

  const isEmail = result.type === "email";
  const isMessage = result.type === "message";

  const findings = Array.isArray(result.findings)
    ? result.findings
    : [];

  const recommendations = Array.isArray(result.recommendations)
    ? result.recommendations
    : [];

  const findingCount =
    typeof result.findingCount === "number"
      ? result.findingCount
      : findings.length;

  const score = Math.max(
    0,
    Math.min(100, Number(result.score) || 0)
  );

  const level = String(result.level || "").toLowerCase();

  // A serious finding must never be hidden by a low score.
  const hasHighFinding = findings.some(
    (finding) => finding.severity === "high"
  );

  const hasMediumFinding = findings.some(
    (finding) => finding.severity === "medium"
  );

  const isHigh = level === "high" || hasHighFinding;
  const isMedium =
    !isHigh && (level === "medium" || hasMediumFinding);

  const isClear = !isHigh && !isMedium && findingCount === 0;

  const verdict = isHigh
    ? "HIGH RISK"
    : isMedium
      ? "SUSPICIOUS"
      : isClear
        ? "NO RED FLAGS FOUND"
        : "LOW RISK";

  const verdictTone = isHigh
    ? "danger"
    : isMedium
      ? "warning"
      : "safe";

  const StatusIcon = isHigh
    ? ShieldAlert
    : isMedium
      ? AlertTriangle
      : ShieldCheck;

  const TypeIcon = isEmail
    ? Mail
    : isMessage
      ? MessageSquare
      : Globe;

  const reportTitle = isEmail
    ? "Email security report"
    : isMessage
      ? "Message security report"
      : "URL security report";

  const reportSubject = isEmail
    ? "Email content analysis"
    : isMessage
      ? "Message content analysis"
      : result.hostname || result.normalizedURL || "Website analysis";

  const verdictTitle = isHigh
    ? "Danger signs detected"
    : isMedium
      ? "Pause. Verify before you trust."
      : isClear
        ? "No obvious red flags found!"
        : "A few things deserve attention";

  const verdictDescription = isHigh
    ? "Our checks found important warning signs. Do not share information, send money, or follow instructions until you verify the source independently."
    : isMedium
      ? "Something deserves a closer look. Review the warnings below before clicking links, sharing information, or sending money."
      : isClear
        ? "Great! Our checks didn't find common warning signs. You can continue with normal caution, but remember that no automated check can guarantee safety."
        : "Our checks found limited warning signs. Review the details and use your judgment before proceeding.";

  const nextStepMessage = isHigh
    ? "STOP — verify the source before taking action."
    : isMedium
      ? "TAKE A MOMENT — check the warnings below."
      : isClear
        ? "LOOKS CLEAR — stay alert and use common sense."
        : "CHECK THE DETAILS — then decide what to do.";

  const scoreColor = isHigh
    ? "#ff526b"
    : isMedium
      ? "#ffb454"
      : "#4ce3b1";

  const analyzedAt = result.analyzedAt
    ? new Date(result.analyzedAt)
    : null;

  const formattedDate =
    analyzedAt && !Number.isNaN(analyzedAt.getTime())
      ? analyzedAt.toLocaleString()
      : "Time unavailable";

  const protocolLabel = result.protocol
    ? String(result.protocol).toUpperCase()
    : isEmail
      ? "EMAIL CONTENT"
      : isMessage
        ? "MESSAGE CONTENT"
        : "URL ANALYSIS";

  const links = Array.isArray(result.links) ? result.links : [];

  const suspiciousLinks = Array.isArray(result.suspiciousLinks)
    ? result.suspiciousLinks
    : [];

  return (
    <section
      className={`analysis-result threat-report tone-${verdictTone}`}
      aria-labelledby="analysis-result-title"
      aria-live="polite"
    >
      <div className="threat-report-grid" aria-hidden="true" />

      <header className="result-header threat-report-header">
        <div>
          <span className="result-eyebrow">
            <span className="status-dot" />
            <Sparkles size={14} />
            THREAT SCAN COMPLETE
          </span>

          <h3 id="analysis-result-title">{reportTitle}</h3>

          <p className="result-hostname">
            <TypeIcon
              size={16}
              style={{
                display: "inline-block",
                verticalAlign: "middle",
                marginRight: "8px",
              }}
            />
            <span>{reportSubject}</span>
          </p>
        </div>

        <button
          type="button"
          className="result-reset-button"
          onClick={onReset}
        >
          New analysis <ArrowUpRight size={16} />
        </button>
      </header>

      <div
        className="threat-verdict"
        key={String(
          result.id || result.analyzedAt || `${result.type}-${score}`
        )}
      >
        <div className="threat-verdict-topline">
          <span className="threat-live-indicator">
            <span className="threat-live-dot" />
            SECURITY VERDICT
          </span>

          <span className="threat-verdict-tag">
            <StatusIcon size={15} />
            {verdict}
          </span>
        </div>

        <div className="threat-verdict-content">
          <div
            className="threat-score-visual"
            style={{
              "--score-color": scoreColor,
              "--score-angle": `${score * 3.6}deg`,
            }}
            role="img"
            aria-label={`Heuristic risk indicator score: ${score} out of 100`}
          >
            <div className="threat-ring-orbit" />

            <div className="threat-score-ring">
              <div className="threat-score-inner">
                <StatusIcon
                  className="threat-main-shield"
                  size={32}
                />

                <strong key={score} className="verdict-score-number">
                  {score}
                </strong>

                <span>
                  {isClear ? "WARNING POINTS" : "RISK SCORE / 100"}
                </span>
              </div>
            </div>

            <span className="threat-ring-spark threat-ring-spark-one" />
            <span className="threat-ring-spark threat-ring-spark-two" />
          </div>

          <div className="threat-verdict-copy">
            <span className="threat-kicker">
              <span className="threat-kicker-line" />
              CYBERGUARD INTELLIGENCE
            </span>

            <h4>{verdictTitle}</h4>
            <p>{verdictDescription}</p>

            <div className={`friendly-verdict-action friendly-${verdictTone}`}>
              <span className="friendly-verdict-icon">
                {isHigh ? (
                  <ShieldAlert size={20} />
                ) : isMedium ? (
                  <AlertTriangle size={20} />
                ) : (
                  <CheckCircle2 size={20} />
                )}
              </span>

              <span>{nextStepMessage}</span>
            </div>

            <div className="threat-verdict-pills">
              <span>
                <Info size={14} />
                {findingCount}{" "}
                {findingCount === 1 ? "warning sign" : "warning signs"}
              </span>

              <span>
                <ShieldCheck size={14} />
                {result.engine || "Local heuristic analysis"}
              </span>
            </div>
          </div>
        </div>

        <div className="threat-score-scale" aria-hidden="true">
          <span>LOW</span>

          <div className="threat-score-track">
            <span style={{ width: `${score}%` }} />
          </div>

          <span>HIGH</span>
        </div>

        <p className="threat-score-note">
          This score represents detected warning indicators, not the
          probability that content is malicious.
        </p>
      </div>

      <div className="result-details threat-details">
        <div className="result-section-heading">
          <h4>What did we find?</h4>
          <span>
            {findingCount}{" "}
            {findingCount === 1 ? "finding" : "findings"}
          </span>
        </div>

        {findings.length === 0 ? (
          <div className="result-empty friendly-clear-result">
            <CheckCircle2 size={23} />

            <div>
              <strong>
                {isClear
                  ? "You're all set — no common warning signs found"
                  : "No additional warning details"}
              </strong>

              <p>
                {isClear
                  ? "Our configured checks didn't match known warning patterns in this input. Stay cautious with unexpected requests and unfamiliar websites."
                  : "Review the overall verdict and follow the recommended next steps."}
              </p>
            </div>
          </div>
        ) : (
          <div className="finding-list">
            {findings.map((finding, index) => (
              <article
                className="finding-item"
                key={finding.id || `${finding.title}-${index}`}
              >
                <span
                  className={`finding-severity severity-${finding.severity || "low"}`}
                >
                  {finding.severity === "high" ? (
                    <ShieldAlert size={18} />
                  ) : finding.severity === "medium" ? (
                    <AlertTriangle size={18} />
                  ) : (
                    <Info size={18} />
                  )}
                </span>

                <div className="finding-copy">
                  <h5>{finding.title || "Warning indicator"}</h5>
                  <p>
                    {finding.description ||
                      "A configured warning pattern was detected."}
                  </p>
                </div>

                <span className="finding-points">
                  +{Number(finding.points) || 0}
                </span>
              </article>
            ))}
          </div>
        )}
      </div>

      {(isEmail || isMessage) && (
        <div className="result-details threat-details">
          <div className="result-section-heading">
            <h4>Links found in content</h4>
            <span>
              {links.length} {links.length === 1 ? "link" : "links"}
            </span>
          </div>

          {links.length > 0 ? (
            <ul className="recommendation-list">
              {links.map((link, index) => {
                const isFlagged = suspiciousLinks.includes(link);

                return (
                  <li key={`${link}-${index}`}>
                    {isFlagged ? (
                      <AlertTriangle
                        size={17}
                        style={{ color: "#ffb454", flexShrink: 0 }}
                      />
                    ) : (
                      <ExternalLink size={17} />
                    )}

                    <span style={{ overflowWrap: "anywhere" }}>
                      {link}
                      {isFlagged ? " — needs review" : ""}
                    </span>
                  </li>
                );
              })}
            </ul>
          ) : (
            <div className="result-empty">
              <Info size={20} />

              <div>
                <strong>No links found</strong>
                <p>
                  No recognizable web links were found in the submitted
                  content. Other risks may still exist.
                </p>
              </div>
            </div>
          )}
        </div>
      )}

      <div className="result-details threat-details">
        <div className="result-section-heading">
          <h4>What should you do next?</h4>
          <span>{recommendations.length} steps</span>
        </div>

        {recommendations.length > 0 ? (
          <ul className="recommendation-list">
            {recommendations.map((recommendation, index) => (
              <li key={`${index}-${recommendation}`}>
                <CheckCircle2 size={17} />
                <span>{recommendation}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p>Verify the source independently before trusting the content.</p>
        )}
      </div>

      <footer className="result-metadata threat-metadata">
        <span>
          <Clock3 size={14} />
          {formattedDate}
        </span>

        <span>
          <ExternalLink size={14} />
          {protocolLabel}
        </span>
      </footer>

      <div className="result-disclaimer threat-disclaimer">
        <AlertTriangle size={17} />

        <p>
          {result.disclaimer ||
            "This is a heuristic analysis, not proof that content is safe or malicious."}
        </p>
      </div>
    </section>
  );
}

export default AnalysisResult;
