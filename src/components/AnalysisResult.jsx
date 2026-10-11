
import {
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  ShieldCheck,
  Info,
  ExternalLink,
  Clock3,
} from "lucide-react";

function AnalysisResult({ result, onReset }) {
  if (!result) return null;

  const isHigh = result.level === "high";
  const isMedium = result.level === "medium";

  const StatusIcon = isHigh
    ? ShieldAlert
    : isMedium
      ? AlertTriangle
      : ShieldCheck;

  const statusLabel = isHigh
    ? "High-risk indicators detected"
    : isMedium
      ? "Caution: warning indicators found"
      : result.findingCount === 0
        ? "No configured warning indicators found"
        : "Low-level warning indicators found";

  const statusDescription = isHigh
    ? "Several concerning indicators were detected. Avoid interacting with this URL until you verify the destination independently."
    : isMedium
      ? "Warning indicators were detected. Review the findings below before deciding what to do."
      : result.findingCount === 0
        ? "The local checks found no configured warning indicators. This does not prove the website is safe."
        : "The scanner found limited warning indicators. Review the details and verify the destination independently.";

  const scoreColor = isHigh
    ? "#ff647c"
    : isMedium
      ? "#ffb454"
      : "#53e4e7";

  return (
    <section
      className="analysis-result"
      aria-labelledby="analysis-result-title"
      aria-live="polite"
    >
      <div className="result-header">
        <div>
          <span className="result-eyebrow">
            <span className="status-dot" />
            ANALYSIS COMPLETE
          </span>
          <h3 id="analysis-result-title">Security report</h3>
          <p className="result-hostname">{result.hostname}</p>
        </div>

        <button
          type="button"
          className="result-reset-button"
          onClick={onReset}
        >
          New analysis
        </button>
      </div>

      <div className="result-score-panel">
        <div
          className="score-ring"
          style={{
            "--score-color": scoreColor,
            "--score-angle": `${result.score * 3.6}deg`,
          }}
          role="img"
          aria-label={`Heuristic risk indicator score: ${result.score} out of 100`}
        >
          <div className="score-ring-inner">
            <strong>{result.score}</strong>
            <span>/ 100</span>
          </div>
        </div>

        <div className="score-explanation">
          <span className="result-status-icon" style={{ color: scoreColor }}>
            <StatusIcon size={25} />
          </span>

          <h4>{statusLabel}</h4>
          <p>{statusDescription}</p>

          <span className="result-engine">
            <Info size={14} />
            {result.engine}
          </span>
        </div>
      </div>

      <div className="result-details">
        <div className="result-section-heading">
          <h4>Detected indicators</h4>
          <span>{result.findingCount} findings</span>
        </div>

        {result.findings.length === 0 ? (
          <div className="result-empty">
            <CheckCircle2 size={21} />
            <div>
              <strong>No configured warning indicators found</strong>
              <p>
                This is not a safety certification. The scanner performs
                limited local checks and cannot detect every threat.
              </p>
            </div>
          </div>
        ) : (
          <div className="finding-list">
            {result.findings.map((finding) => (
              <article className="finding-item" key={finding.id}>
                <span className={`finding-severity severity-${finding.severity}`}>
                  {finding.severity === "high" ? (
                    <ShieldAlert size={18} />
                  ) : finding.severity === "medium" ? (
                    <AlertTriangle size={18} />
                  ) : (
                    <Info size={18} />
                  )}
                </span>

                <div className="finding-copy">
                  <h5>{finding.title}</h5>
                  <p>{finding.description}</p>
                </div>

                <span className="finding-points">+{finding.points}</span>
              </article>
            ))}
          </div>
        )}
      </div>

      <div className="result-details">
        <div className="result-section-heading">
          <h4>Recommended actions</h4>
        </div>

        <ul className="recommendation-list">
          {result.recommendations.map((recommendation, index) => (
            <li key={`${index}-${recommendation}`}>
              <CheckCircle2 size={17} />
              <span>{recommendation}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="result-metadata">
        <span>
          <Clock3 size={14} />
          {new Date(result.analyzedAt).toLocaleString()}
        </span>
        <span>
          <ExternalLink size={14} />
          {result.protocol.toUpperCase()}
        </span>
      </div>

      <div className="result-disclaimer">
        <AlertTriangle size={17} />
        <p>{result.disclaimer}</p>
      </div>
    </section>
  );
}

export default AnalysisResult;
