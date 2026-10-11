import WebsiteIntelligence from "./components/WebsiteIntelligence.jsx";
import { useState } from "react";
import {
  ShieldCheck, ArrowUpRight, Search, Link2, Mail,
  MessageSquare, Activity, LockKeyhole, ScanSearch,
  GraduationCap, Menu, X, ArrowRight, ChevronDown,
  Zap, Eye, CheckCircle2, AlertCircle, History,
  Trash2, Download, ExternalLink, Filter, Clock3,
  RefreshCw
} from "lucide-react";

import AnalysisResult from "./components/AnalysisResult.jsx";
import { analyzeURL } from "./services/urlAnalyzer.js";
import {
  getScanHistory,
  saveScanToHistory,
  deleteScanFromHistory,
  clearScanHistory,
  exportScanHistory,
} from "./services/scanHistory.js";

import "./App.css";

const navigation = [
  { label: "Overview", id: "home" },
  { label: "Analyzer", id: "analyzer" },
  { label: "History", id: "history" },
  { label: "Learn", id: "learn" },
  { label: "Intelligence", id: "intelligence" },
  { label: "About", id: "about" },
];

const features = [
  {
    icon: Link2,
    number: "01",
    title: "URL intelligence",
    description: "Inspect URLs for common phishing indicators and suspicious structures.",
    tag: "LINK ANALYSIS",
  },
  {
    icon: Mail,
    number: "02",
    title: "Email inspection",
    description: "Learn to recognize suspicious requests and phishing signals.",
    tag: "EMAIL SECURITY",
  },
  {
    icon: MessageSquare,
    number: "03",
    title: "Message screening",
    description: "Understand common scam patterns and social-engineering techniques.",
    tag: "SCAM AWARENESS",
  },
];

function App() {
  const [activePage, setActivePage] = useState("home");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [analysisType, setAnalysisType] = useState("url");
  const [inputValue, setInputValue] = useState("");
  const [result, setResult] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState("");
  const [history, setHistory] = useState(() => getScanHistory());
  const [historySearch, setHistorySearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");
  const [historyMessage, setHistoryMessage] = useState("");

  function navigateTo(id) {
    setActivePage(id);
    setMobileMenuOpen(false);
    document.getElementById(id)?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  }

  function selectAnalysisType(type) {
    setAnalysisType(type);
    setInputValue("");
    setResult(null);
    setError("");
  }

  function handleAnalyze(event) {
    event.preventDefault();
    setError("");
    setResult(null);

    if (!inputValue.trim()) {
      setError("Please enter a website URL before starting the analysis.");
      return;
    }

    if (analysisType !== "url") {
      setError("Please select URL. Email and message analysis are not available yet.");
      return;
    }

    setIsAnalyzing(true);

    window.setTimeout(() => {
      try {
        const analysis = analyzeURL(inputValue);

        setResult(analysis);

        try {
          const updatedHistory = saveScanToHistory(analysis);
          setHistory(updatedHistory);
          setHistoryMessage("");
        } catch (storageError) {
          setHistoryMessage(
            storageError instanceof Error
              ? storageError.message
              : "The analysis completed, but its history could not be saved."
          );
        }
      } catch (analysisError) {
        setError(
          analysisError instanceof Error
            ? analysisError.message
            : "Unable to analyze this URL. Please check your input."
        );
      } finally {
        setIsAnalyzing(false);
      }
    }, 650);
  }

  function resetAnalysis() {
    setResult(null);
    setError("");
    setInputValue("");
  }

  function openHistoryItem(item) {
    setResult(item);
    setInputValue(item.url || item.hostname || "");
    setAnalysisType("url");
    setError("");
    navigateTo("analyzer");
  }

  function handleDeleteHistory(id) {
    try {
      const updated = deleteScanFromHistory(id);
      setHistory(updated);
      setHistoryMessage("Scan removed from history.");
    } catch (deleteError) {
      setHistoryMessage(
        deleteError instanceof Error
          ? deleteError.message
          : "Could not delete this scan."
      );
    }
  }

  function handleClearHistory() {
    if (history.length === 0) return;

    const confirmed = window.confirm(
      "Delete all saved scan history? This action cannot be undone."
    );

    if (!confirmed) return;

    try {
      setHistory(clearScanHistory());
      setHistoryMessage("All scan history has been cleared.");
    } catch (clearError) {
      setHistoryMessage(
        clearError instanceof Error
          ? clearError.message
          : "Could not clear history."
      );
    }
  }

  function handleExportHistory() {
    try {
      const data = exportScanHistory();
      const blob = new Blob(
        [JSON.stringify(data, null, 2)],
        { type: "application/json" }
      );

      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");

      link.href = url;
      link.download = "cyberguard-scan-history.json";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);

      setHistoryMessage("Scan history export downloaded.");
    } catch {
      setHistoryMessage("Unable to export scan history.");
    }
  }

  const filteredHistory = history.filter((item) => {
    const searchText = historySearch.trim().toLowerCase();

    const matchesSearch =
      !searchText ||
      item.hostname?.toLowerCase().includes(searchText) ||
      item.url?.toLowerCase().includes(searchText) ||
      item.findings?.some(
        (finding) =>
          finding.title?.toLowerCase().includes(searchText) ||
          finding.description?.toLowerCase().includes(searchText)
      );

    const level = item.level || "low";

    const matchesRisk =
      riskFilter === "all" ||
      (riskFilter === "high" && level === "high") ||
      (riskFilter === "medium" && level === "medium") ||
      (riskFilter === "low" && level !== "high" && level !== "medium");

    return matchesSearch && matchesRisk;
  });

  const highRiskCount = history.filter(
    (item) => item.level === "high"
  ).length;

  const cautionCount = history.filter(
    (item) => item.level === "medium"
  ).length;

  const lowIndicatorCount = history.filter(
    (item) => item.level !== "high" && item.level !== "medium"
  ).length;

  return (
    <div className="app-shell" id="home">
      <div className="ambient ambient-one" aria-hidden="true" />
      <div className="ambient ambient-two" aria-hidden="true" />

      <header className="site-header">
        <a
          href="#home"
          className="brand"
          onClick={(event) => {
            event.preventDefault();
            navigateTo("home");
          }}
          aria-label="CyberGuard AI home"
        >
          <span className="brand-icon">
            <ShieldCheck size={25} />
          </span>
          <span className="brand-copy">
            <strong>CYBERGUARD<span>AI</span></strong>
            <small>THINK BEFORE YOU CLICK</small>
          </span>
        </a>

        <nav
          className={`desktop-nav ${mobileMenuOpen ? "nav-open" : ""}`}
          aria-label="Main navigation"
        >
          {navigation.map((item) => (
            <button
              key={item.id}
              type="button"
              className={`nav-link ${
                activePage === item.id ? "nav-link-active" : ""
              }`}
              onClick={() => navigateTo(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <button
          type="button"
          className="header-cta"
          onClick={() => navigateTo("analyzer")}
        >
          Scan a threat <ArrowUpRight size={16} />
        </button>

        <button
          type="button"
          className="mobile-menu-toggle"
          onClick={() => setMobileMenuOpen((previous) => !previous)}
          aria-label={mobileMenuOpen ? "Close menu" : "Open menu"}
          aria-expanded={mobileMenuOpen}
        >
          {mobileMenuOpen ? <X size={22} /> : <Menu size={22} />}
        </button>
      </header>

      <main>
        <section className="hero-section">
          <div className="hero-copy">
            <div className="eyebrow">
              <span className="status-dot" />
              YOUR DIGITAL SAFETY COMPANION
            </div>

            <h1>
              The internet is vast.
              <br />
              <span>Stay one step</span>
              <br />
              ahead of threats.
            </h1>

            <p className="hero-description">
              Examine suspicious URLs, understand potential warning signs,
              and develop smarter digital safety habits with CyberGuard AI.
            </p>

            <div className="hero-actions">
              <button
                type="button"
                className="button-primary"
                onClick={() => navigateTo("analyzer")}
              >
                Analyze a URL <ArrowRight size={18} />
              </button>
              <button
                type="button"
                className="button-secondary"
                onClick={() => navigateTo("learn")}
              >
                Explore cyber safety <GraduationCap size={18} />
              </button>
            </div>

            <div className="hero-trust">
              <LockKeyhole size={15} />
              <span>Local URL analysis</span>
              <span className="trust-separator">·</span>
              <span>Education first</span>
            </div>
          </div>

          <div className="hero-visual">
            <div className="orbit orbit-outer" />
            <div className="orbit orbit-inner" />
            <div className="orbit-node node-top"><ScanSearch size={19} /></div>
            <div className="orbit-node node-right"><Activity size={19} /></div>
            <div className="orbit-node node-left"><LockKeyhole size={19} /></div>

            <div className="shield-core">
              <div className="shield-glow" />
              <ShieldCheck size={94} strokeWidth={1.15} />
              <span className="core-spark spark-one" />
              <span className="core-spark spark-two" />
            </div>

            <div className="floating-card scan-card">
              <span className="floating-icon orange-icon"><Activity size={17} /></span>
              <span>
                <strong>URL analysis</strong>
                <small>Heuristic indicators</small>
              </span>
              <span className="mini-live-dot" />
            </div>

            <div className="floating-card privacy-card">
              <span className="floating-icon cyan-icon"><Eye size={17} /></span>
              <span>
                <strong>Privacy awareness</strong>
                <small>Think before you click</small>
              </span>
            </div>

            <div className="visual-caption">
              <span className="caption-line" />
              INTELLIGENCE · AWARENESS · PROTECTION
            </div>
          </div>
        </section>

        <section className="metrics-strip" aria-label="Platform capabilities">
          {[
            { icon: ScanSearch, title: "URL", description: "Risk indicators" },
            { icon: Mail, title: "Email", description: "Coming soon" },
            { icon: MessageSquare, title: "Messages", description: "Coming soon" },
            { icon: GraduationCap, title: "Learn", description: "Cyber awareness" },
          ].map((item) => {
            const Icon = item.icon;
            return (
              <div className="metric-item" key={item.title}>
                <span className="metric-icon"><Icon size={19} /></span>
                <span>
                  <strong>{item.title}</strong>
                  <small>{item.description}</small>
                </span>
              </div>
            );
          })}
        </section>

        <section className="analyzer-section section-container" id="analyzer">
          <div className="section-heading">
            <div>
              <div className="eyebrow">
                <span className="status-dot" /> THREAT ANALYSIS LAB
              </div>
              <h2>Curiosity is good. <span>Clicking blindly isn't.</span></h2>
              <p>
                Inspect URLs for common warning indicators. This local scanner
                does not visit websites or check live reputation databases.
              </p>
            </div>
            <span className="section-index">01 / ANALYZE</span>
          </div>

          <div className="analyzer-panel">
            <div className="analyzer-panel-top">
              <div>
                <span className="panel-overline">CYBERGUARD SCANNER</span>
                <h3>What would you like to check?</h3>
              </div>
              <span className="scanner-badge">
                <span className="status-dot" /> LOCAL ANALYSIS
              </span>
            </div>

            <div className="analysis-tabs" role="group" aria-label="Analysis type">
              {[
                { id: "url", label: "URL", icon: Link2 },
                { id: "email", label: "Email", icon: Mail },
                { id: "message", label: "Message", icon: MessageSquare },
              ].map((tab) => {
                const Icon = tab.icon;
                return (
                  <button
                    type="button"
                    key={tab.id}
                    className={`analysis-tab ${
                      analysisType === tab.id ? "selected" : ""
                    }`}
                    onClick={() => selectAnalysisType(tab.id)}
                    aria-pressed={analysisType === tab.id}
                  >
                    <Icon size={17} /> {tab.label}
                  </button>
                );
              })}
            </div>

            <form className="analyzer-form" onSubmit={handleAnalyze}>
              <label htmlFor="analysis-input">
                {analysisType === "url" ? "Website URL" : "Module coming soon"}
              </label>

              <textarea
                id="analysis-input"
                value={inputValue}
                onChange={(event) => {
                  setInputValue(event.target.value);
                  setError("");
                }}
                placeholder={
                  analysisType === "url"
                    ? "Enter a URL, for example: https://example.com"
                    : "Please select URL. This module is not available yet."
                }
                rows={4}
                maxLength={2048}
              />

              <div className="analyzer-form-bottom">
                <span className="input-hint">
                  <LockKeyhole size={14} />
                  Local checks only. Avoid entering private information.
                </span>

                <button
                  type="submit"
                  className="button-primary analyze-button"
                  disabled={isAnalyzing}
                >
                  <Search size={17} />
                  {isAnalyzing ? "Analyzing..." : "Analyze URL"}
                </button>
              </div>
            </form>

            {isAnalyzing && (
              <div className="scan-progress-panel" role="status" aria-live="polite">
                <div className="scan-progress-icon">
                  <ScanSearch size={28} />
                </div>
                <div className="scan-progress-content">
                  <div className="scan-progress-heading">
                    <strong>Analyzing URL structure</strong>
                    <span className="scanning-indicator"><span /> WORKING</span>
                  </div>
                  <p>
                    Checking protocol, hostname, URL structure and configured
                    phishing indicators locally.
                  </p>
                  <div className="scan-progress-track"><span /></div>
                  <div className="scan-progress-footer">
                    <span>LOCAL HEURISTIC ENGINE</span>
                    <span>Please wait…</span>
                  </div>
                </div>
              </div>
            )}

            {error && (
              <div className="inline-notice" role="alert">
                <AlertCircle size={17} />
                <span>{error}</span>
              </div>
            )}

            <div className="panel-footer">
              <span><CheckCircle2 size={15} /> Educational security tool</span>
              <span><Zap size={15} /> No live reputation lookup</span>
            </div>
          </div>

          {result && (
            <AnalysisResult result={result} onReset={resetAnalysis} />
          )}
        </section>

        <section className="history-section section-container" id="history">
          <div className="section-heading">
            <div>
              <div className="eyebrow">
                <span className="status-dot" /> YOUR SECURITY ACTIVITY
              </div>
              <h2>Scan history. <span>Stay informed.</span></h2>
              <p>
                Review saved local scans, search findings and reopen previous
                reports. These results reflect local heuristics, not verified
                website reputations.
              </p>
            </div>
            <span className="section-index">02 / HISTORY</span>
          </div>

          <div className="history-stats">
            <article className="history-stat">
              <span className="history-stat-icon"><History size={20} /></span>
              <span className="history-stat-label">Total scans</span>
              <strong>{history.length}</strong>
            </article>
            <article className="history-stat">
              <span className="history-stat-icon history-red"><ShieldAlertIcon /></span>
              <span className="history-stat-label">High-risk labels</span>
              <strong>{highRiskCount}</strong>
            </article>
            <article className="history-stat">
              <span className="history-stat-icon history-amber"><AlertCircle size={20} /></span>
              <span className="history-stat-label">Caution labels</span>
              <strong>{cautionCount}</strong>
            </article>
            <article className="history-stat">
              <span className="history-stat-icon history-cyan"><ShieldCheck size={20} /></span>
              <span className="history-stat-label">Other results</span>
              <strong>{lowIndicatorCount}</strong>
            </article>
          </div>

          <div className="history-panel">
            <div className="history-toolbar">
              <div>
                <span className="panel-overline">LOCAL SCAN ARCHIVE</span>
                <h3>Previous analyses</h3>
              </div>

              <div className="history-actions">
                <button
                  type="button"
                  className="history-action-button"
                  onClick={handleExportHistory}
                  disabled={history.length === 0}
                >
                  <Download size={16} /> Export
                </button>
                <button
                  type="button"
                  className="history-action-button history-delete-all"
                  onClick={handleClearHistory}
                  disabled={history.length === 0}
                >
                  <Trash2 size={16} /> Clear all
                </button>
              </div>
            </div>

            <div className="history-filters">
              <label className="history-search">
                <Search size={17} />
                <input
                  type="search"
                  value={historySearch}
                  onChange={(event) => setHistorySearch(event.target.value)}
                  placeholder="Search hostnames or findings..."
                  aria-label="Search scan history"
                />
              </label>

              <label className="history-risk-filter">
                <Filter size={16} />
                <select
                  value={riskFilter}
                  onChange={(event) => setRiskFilter(event.target.value)}
                  aria-label="Filter by risk category"
                >
                  <option value="all">All results</option>
                  <option value="high">High risk</option>
                  <option value="medium">Caution</option>
                  <option value="low">Other results</option>
                </select>
              </label>
            </div>

            {historyMessage && (
              <div className="history-message" role="status">
                {historyMessage}
                <button
                  type="button"
                  onClick={() => setHistoryMessage("")}
                  aria-label="Dismiss message"
                >
                  <X size={15} />
                </button>
              </div>
            )}

            {filteredHistory.length === 0 ? (
              <div className="history-empty">
                <div className="history-empty-icon">
                  <History size={30} />
                </div>
                <h4>
                  {history.length === 0
                    ? "Your scan history starts here"
                    : "No matching scans found"}
                </h4>
                <p>
                  {history.length === 0
                    ? "Run your first URL analysis. Completed scans will appear here automatically."
                    : "Try a different search term or change the risk filter."}
                </p>
                {history.length === 0 && (
                  <button
                    type="button"
                    className="button-primary"
                    onClick={() => navigateTo("analyzer")}
                  >
                    Start your first scan <ArrowRight size={17} />
                  </button>
                )}
              </div>
            ) : (
              <div className="history-list">
                {filteredHistory.map((item) => {
                  const itemHigh = item.level === "high";
                  const itemMedium = item.level === "medium";

                  const label = itemHigh
                    ? "High risk"
                    : itemMedium
                      ? "Caution"
                      : "No configured warnings";

                  return (
                    <article className="history-item" key={item.id}>
                      <div className={`history-result-icon ${
                        itemHigh
                          ? "history-red"
                          : itemMedium
                            ? "history-amber"
                            : "history-cyan"
                      }`}>
                        {itemHigh ? (
                          <AlertCircle size={20} />
                        ) : itemMedium ? (
                          <AlertCircle size={20} />
                        ) : (
                          <ShieldCheck size={20} />
                        )}
                      </div>

                      <div className="history-item-main">
                        <strong className="history-hostname">
                          {item.hostname}
                        </strong>
                        <span className="history-item-date">
                          <Clock3 size={13} />
                          {new Date(item.analyzedAt).toLocaleString()}
                        </span>
                        <span className={`history-status ${
                          itemHigh
                            ? "history-status-high"
                            : itemMedium
                              ? "history-status-medium"
                              : "history-status-low"
                        }`}>
                          {label}
                        </span>
                        <span className="history-findings-count">
                          {item.findingCount ?? item.findings.length} findings
                        </span>
                      </div>

                      <div className="history-item-score">
                        <strong>{item.score}</strong>
                        <span>/ 100</span>
                      </div>

                      <div className="history-item-actions">
                        <button
                          type="button"
                          className="history-icon-button"
                          onClick={() => openHistoryItem(item)}
                          aria-label={`Open report for ${item.hostname}`}
                          title="Open report"
                        >
                          <ExternalLink size={16} />
                        </button>
                        <button
                          type="button"
                          className="history-icon-button history-remove-button"
                          onClick={() => handleDeleteHistory(item.id)}
                          aria-label={`Delete scan for ${item.hostname}`}
                          title="Delete scan"
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </article>
                  );
                })}
              </div>
            )}

            <div className="history-footer">
              <span><LockKeyhole size={14} /> Stored in this browser</span>
              <span>{filteredHistory.length} of {history.length} scans shown</span>
            </div>
          </div>
        </section>

        <section className="features-section section-container" id="learn">
          <div className="section-heading">
            <div>
              <div className="eyebrow">
                <span className="status-dot" /> KNOW YOUR DIGITAL WORLD
              </div>
              <h2>Three ways to <span>think safer.</span></h2>
              <p>Explore URL safety, phishing awareness and social engineering.</p>
            </div>
            <span className="section-index">03 / EXPLORE</span>
          </div>

          <div className="feature-grid">
            {features.map((feature) => {
              const Icon = feature.icon;
              return (
                <article className="feature-card" key={feature.number}>
                  <div className="feature-card-top">
                    <span className="feature-icon"><Icon size={22} /></span>
                    <span className="feature-number">{feature.number}</span>
                  </div>
                  <span className="feature-tag">{feature.tag}</span>
                  <h3>{feature.title}</h3>
                  <p>{feature.description}</p>
                  <button
                    type="button"
                    className="text-link"
                    onClick={() => navigateTo(
                      feature.number === "01" ? "analyzer" : "about"
                    )}
                  >
                    {feature.number === "01" ? "Try URL analysis" : "Explore our approach"}
                    <ArrowUpRight size={16} />
                  </button>
                </article>
              );
            })}
          </div>
        </section>

        <section className="about-section section-container" id="about">
          <div className="about-card">
            <div className="about-symbol"><ShieldCheck size={36} /></div>
            <div className="about-copy">
              <div className="eyebrow">OUR PRINCIPLE</div>
              <h2>Security starts with <span>understanding.</span></h2>
              <p>
                CyberGuard AI is an educational cybersecurity project. Its URL
                analyzer checks selected structural indicators locally. It
                cannot establish whether a website is safe.
              </p>
            </div>
            <button
              type="button"
              className="button-secondary about-button"
              onClick={() => navigateTo("analyzer")}
            >
              Try the scanner <ArrowRight size={17} />
            </button>
          </div>
        </section>
              {activePage === "intelligence" && <WebsiteIntelligence />}
      </main>

     
      <section className="developer-section section-container" id="developer">
        <div className="developer-card">
          <div className="developer-grid-glow" aria-hidden="true" />

          <div className="developer-topline">
            <span className="developer-live-dot" />
            <span>BEHIND THE FIREWALL</span>
            <span className="developer-edition">INDEPENDENT PROJECT · 2026</span>
          </div>

          <div className="developer-content">
            <div className="developer-avatar" aria-label="Ankit Kushwah initials">
              AK
              <span className="avatar-status" />
            </div>

            <div className="developer-intro">
              <span className="developer-kicker">THE HUMAN BEHIND THE CODE</span>

              <h2>
                Not just a user.
                <br />
                <span>A builder of safer digital worlds.</span>
              </h2>

              <p className="developer-name">
                ANKIT <span>KUSHWAH</span>
              </p>

              <p className="developer-description">
                First-year B.Tech Cybersecurity student, technology explorer,
                and the developer behind CyberGuard AI. I'm learning by
                building, experimenting, and turning cybersecurity curiosity
                into practical projects that help people think before they click.
              </p>

              <div className="developer-tags">
                <span>Cybersecurity</span>
                <span>Web Development</span>
                <span>AI Explorer</span>
              </div>

              <div className="developer-actions">
                <a
                  className="developer-github-button"
                  href="https://github.com/Ankit9575"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <svg
                    width="20"
                    height="20"
                    viewBox="0 0 24 24"
                    fill="currentColor"
                    aria-hidden="true"
                  >
                    <path d="M12 .9a11.1 11.1 0 0 0-3.51 21.63c.56.1.76-.24.76-.54v-2.1c-3.1.67-3.75-1.32-3.75-1.32-.5-1.29-1.24-1.63-1.24-1.63-1.02-.7.08-.69.08-.69 1.12.08 1.71 1.15 1.71 1.15 1 .1.76 2.1 3.63 1.58.1-.73.4-1.23.7-1.52-2.48-.28-5.08-1.24-5.08-5.52 0-1.22.44-2.22 1.15-3-.12-.28-.5-1.42.11-2.96 0 0 .94-.3 3.05 1.14a10.6 10.6 0 0 1 5.55 0c2.1-1.44 3.04-1.14 3.04-1.14.61 1.54.23 2.68.11 2.96.72.78 1.15 1.78 1.15 3 0 4.29-2.61 5.23-5.1 5.51.4.34.75 1 .75 2.02v3c0 .3.2.65.77.54A11.1 11.1 0 0 0 12 .9Z" />
                  </svg>
                  Explore my GitHub
                  <span aria-hidden="true">↗</span>
                </a>

                <button
                  type="button"
                  className="developer-contact-button"
                  onClick={() => navigateTo("about")}
                >
                  About CyberGuard AI <ArrowRight size={16} />
                </button>
              </div>
            </div>
          </div>

          <div className="developer-bottomline">
            <span>BUILT WITH CURIOSITY. DRIVEN BY SECURITY.</span>
            <span className="developer-terminal">
              <span>&gt;</span> keep_learning();
            </span>
          </div>
        </div>
      </section>

      <footer className="site-footer">
        <div className="footer-main">
          <a
            href="#home"
            className="footer-brand"
            onClick={(event) => {
              event.preventDefault();
              navigateTo("home");
            }}
          >
            <ShieldCheck size={22} />
            <span>CYBERGUARD<span className="footer-brand-accent">AI</span></span>
          </a>

          <p className="footer-tagline">
            Think before you click. Build before you quit.
          </p>

          <a
            className="footer-github-link"
            href="https://github.com/Ankit9575"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub <ArrowUpRight size={15} />
          </a>
        </div>

        <div className="footer-divider" />

        <div className="footer-bottom">
          <p>
            © {new Date().getFullYear()} <strong>Ankit Kushwah</strong>.
            All rights reserved.
          </p>

          <p className="footer-project-credit">
            Designed and developed for cybersecurity awareness.
          </p>

          <button
            type="button"
            className="footer-top-button"
            onClick={() => navigateTo("home")}
          >
            Back to top ↑
          </button>
        </div>

        <p className="footer-disclaimer">
          CyberGuard AI is an educational project. Local heuristic results
          cannot establish whether a website is safe.
        </p>
      </footer>


      <button
        type="button"
        className="back-to-top"
        onClick={() => navigateTo("home")}
        aria-label="Back to top"
      >
        <ChevronDown size={19} />
      </button>
    </div>
  );
}

function ShieldAlertIcon() {
  return <AlertCircle size={20} />;
}

export default App;
