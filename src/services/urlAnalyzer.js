
/**
 * CyberGuard AI
 * URL Security Analysis Engine — Version 1.0
 *
 * Educational, heuristic-based URL analysis.
 * Does not visit the URL or perform live threat intelligence.
 */

const SUSPICIOUS_WORDS = [
  "verify",
  "urgent",
  "password",
  "suspended",
  "account-update",
  "confirm-account",
  "security-alert",
  "free-gift",
  "claim-prize",
  "wallet-connect",
  "reset-password",
  "login-verify",
];

const SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "is.gd",
  "cutt.ly",
  "rb.gy",
  "shorturl.at",
]);

const RISK_LEVELS = {
  low: {
    label: "Low indicators",
    color: "#53e4e7",
  },
  medium: {
    label: "Elevated indicators",
    color: "#ffb454",
  },
  high: {
    label: "High indicators",
    color: "#ff647c",
  },
};

function createFinding(id, title, description, severity, points) {
  return {
    id,
    title,
    description,
    severity,
    points,
  };
}

function isIPv4(hostname) {
  const parts = hostname.split(".");

  return (
    parts.length === 4 &&
    parts.every((part) => {
      if (!/^\d{1,3}$/.test(part)) return false;

      const number = Number(part);
      return number >= 0 && number <= 255;
    })
  );
}

function isIPv6(hostname) {
  return hostname.startsWith("[") && hostname.endsWith("]");
}

function normalizeInput(value) {
  const trimmed = value.trim();

  if (!trimmed) {
    throw new Error("Please enter a website URL.");
  }

  if (trimmed.length > 2048) {
    throw new Error("URL exceeds the maximum supported length.");
  }

  if (/[\u0000-\u001F\u007F]/.test(trimmed)) {
    throw new Error("URL contains unsupported control characters.");
  }

  if (/\s/.test(trimmed)) {
    throw new Error("A URL cannot contain unescaped spaces.");
  }

  if (
    /^[a-z][a-z0-9+.-]*:/i.test(trimmed) &&
    !/^https?:\/\//i.test(trimmed)
  ) {
    throw new Error("Only HTTP and HTTPS URLs are supported.");
  }

  return /^https?:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;
}

export function analyzeURL(input) {
  const startedAt = new Date().toISOString();
  const normalized = normalizeInput(input);

  let url;

  try {
    url = new URL(normalized);
  } catch {
    throw new Error("Invalid URL. Please check the address and try again.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs can be analyzed.");
  }

  if (!url.hostname || !url.hostname.includes(".") && url.hostname !== "localhost") {
    throw new Error("Please enter a valid website hostname.");
  }

  const hostname = url.hostname.toLowerCase();
  const findings = [];
  let score = 0;

  function addFinding(id, title, description, severity, points) {
    findings.push(createFinding(id, title, description, severity, points));
    score += points;
  }

  // 1. HTTPS inspection
  if (url.protocol === "http:") {
    addFinding(
      "insecure-protocol",
      "Unencrypted HTTP connection",
      "This address uses HTTP rather than HTTPS. Information sent to the website may not be encrypted.",
      "high",
      25
    );
  }

  // 2. IP-based URL
  if (isIPv4(hostname) || isIPv6(hostname)) {
    addFinding(
      "ip-address",
      "IP address used instead of a domain",
      "This URL uses an IP address. This is not automatically malicious, but it can make website identity harder to recognize.",
      "medium",
      18
    );
  }

  // 3. Punycode detection
  if (hostname.split(".").some((label) => label.startsWith("xn--"))) {
    addFinding(
      "punycode",
      "Internationalized domain encoding",
      "The hostname contains punycode. Verify the intended domain carefully because visually similar characters can be misleading.",
      "medium",
      22
    );
  }

  // 4. Excessive subdomains
  const labels = hostname.replace(/\.$/, "").split(".");

  if (labels.length >= 5) {
    addFinding(
      "many-subdomains",
      "Unusually deep subdomain structure",
      "This address has several hostname levels. Check the actual registered domain rather than trusting words appearing at the beginning.",
      "medium",
      12
    );
  }

  // 5. URL shortener
  if (SHORTENERS.has(hostname)) {
    addFinding(
      "shortened-url",
      "Shortened link",
      "This URL uses a known shortening service, which can conceal the final destination until the redirect is inspected.",
      "medium",
      18
    );
  }

  // 6. Suspicious keywords
  const searchableText = (
    hostname +
    url.pathname +
    url.search
  ).toLowerCase();

  const matchedWords = SUSPICIOUS_WORDS.filter((word) =>
    searchableText.includes(word)
  );

  if (matchedWords.length > 0) {
    addFinding(
      "suspicious-keywords",
      "Potential social-engineering keywords",
      `The URL contains terms sometimes associated with phishing: ${matchedWords.slice(0, 5).join(", ")}. These terms may also appear on legitimate websites.`,
      "medium",
      Math.min(24, matchedWords.length * 8)
    );
  }

  // 7. Long URL
  if (normalized.length > 150) {
    addFinding(
      "long-url",
      "Long URL structure",
      "The address is unusually long. Long links are not inherently unsafe, but may be harder to inspect manually.",
      "low",
      8
    );
  }

  // 8. Username/password in URL
  if (url.username || url.password) {
    addFinding(
      "url-credentials",
      "Credentials embedded in URL",
      "The URL contains username or password information before the hostname. This can be misleading and may expose sensitive data.",
      "high",
      30
    );
  }

  // 9. Excessive hyphens
  if ((hostname.match(/-/g) || []).length >= 4) {
    addFinding(
      "many-hyphens",
      "Multiple hostname hyphens",
      "The hostname contains several hyphens. Review the spelling and identity of the domain.",
      "low",
      8
    );
  }

  // 10. Unusual port
  if (url.port && !["80", "443"].includes(url.port)) {
    addFinding(
      "unusual-port",
      "Non-standard website port",
      `This URL specifies port ${url.port}. Custom ports are common in development and some legitimate services, but deserve verification.`,
      "low",
      7
    );
  }

  // 11. Encoded characters
  if (/%[0-9a-f]{2}/i.test(url.pathname)) {
    addFinding(
      "encoded-path",
      "Encoded URL path",
      "The path contains percent-encoded characters. This is common in legitimate URLs but can make links harder to read.",
      "low",
      5
    );
  }

  // 12. Local development host
  if (hostname === "localhost" || hostname === "127.0.0.1") {
    addFinding(
      "local-host",
      "Local development address",
      "This address points to the local computer rather than a normal public website.",
      "info",
      0
    );
  }

  score = Math.min(100, score);

  let level = "low";

  if (score >= 60) {
    level = "high";
  } else if (score >= 25) {
    level = "medium";
  }

  const recommendations = [];

  if (url.protocol === "http:") {
    recommendations.push(
      "Avoid entering passwords or sensitive information on an unencrypted HTTP page."
    );
  }

  if (matchedWords.length > 0) {
    recommendations.push(
      "Verify unexpected account warnings through the organization's official website or app."
    );
  }

  if (SHORTENERS.has(hostname)) {
    recommendations.push(
      "Verify the final destination of shortened links before opening them."
    );
  }

  if (findings.some((finding) => finding.id === "punycode")) {
    recommendations.push(
      "Double-check the domain spelling for lookalike characters."
    );
  }

  recommendations.push(
    "Do not enter passwords, OTPs, or payment information unless you have independently verified the website."
  );

  recommendations.push(
    "A low score only means that these specific URL indicators were not detected. It does not prove the destination is safe."
  );

  return {
    id: `url-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
    type: "url",
    originalInput: input,
    normalizedURL: url.href,
    hostname,
    protocol: url.protocol.replace(":", ""),
    score,
    level,
    risk: RISK_LEVELS[level],
    findings,
    findingCount: findings.length,
    recommendations,
    analyzedAt: startedAt,
    engine: "CyberGuard URL Heuristics v1.0",
    isLiveScan: false,
    disclaimer:
      "This is a local heuristic analysis, not a live malware or reputation scan. Results cannot establish whether a website is safe.",
  };
}

export default analyzeURL;
