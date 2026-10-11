
/**
 * CyberGuard AI
 * Email and Message Security Analysis Engine v1.2
 *
 * Educational, local, heuristic-based analysis.
 * Submitted content is not sent to an external service.
 */

const RISK_LEVELS = {
  low: { label: "Low indicators", color: "#53e4e7" },
  medium: { label: "Elevated indicators", color: "#ffb454" },
  high: { label: "High indicators", color: "#ff647c" },
};

const URGENCY_PATTERNS = [
  /\bact\s+(?:now|immediately|fast|quickly)\b/i,
  /\bwithin\s+\d+\s*(?:minutes?|hours?|days?)\b/i,
  /\b(?:account|card|service|access).{0,45}\b(?:suspend(?:ed)?|block(?:ed)?|lock(?:ed)?|disable[ds]?)\b/i,
  /\b(?:immediate|urgent)\s+(?:action|response|attention|verification)\s+(?:is\s+)?required\b/i,
  /\blast\s+warning\b/i,
  /\bexpires?\s+(?:today|soon|tonight|in\s+\d+\s+hours?)\b/i,
  /\b(?:final|last)\s+notice\b/i,
  /\b(?:act|respond|verify|pay)\s+before\s+(?:midnight|the deadline|your account)\b/i,
];

const CREDENTIAL_PATTERNS = [
  /\b(?:share|send|provide|reveal|tell us)\b.{0,40}\b(?:otp|one[- ]time password|password|pin|recovery code)\b/i,
  /\b(?:enter|confirm|verify|submit)\b.{0,45}\b(?:otp|one[- ]time password|password|pin|login credentials|recovery code)\b/i,
  /\b(?:otp|one[- ]time password|password|pin|recovery code)\b.{0,35}\b(?:required|needed|send|share|confirm|verify)\b/i,
  /\b(?:send|share|tell us)\s+(?:your\s+)?(?:login|banking)\s+credentials\b/i,
  /\b(?:never|do not|don't)\s+share\b.{0,35}\b(?:otp|password|pin)\b/i,
];

const MONEY_PATTERNS = [
  /\b(?:pay immediately|urgent payment|payment required|pay now to avoid)\b/i,
  /\b(?:gift cards?|cryptocurrency|bitcoin|crypto)\b.{0,50}\b(?:send|pay|transfer|deposit|purchase|buy)\b/i,
  /\b(?:send|transfer|deposit|pay)\b.{0,45}\b(?:money|funds|bitcoin|gift cards?|cryptocurrency)\b/i,
  /\b(?:prize|lottery winnings?|reward)\b.{0,45}\b(?:claim|fee|payment|tax|deposit)\b/i,
  /\b(?:processing|release|delivery|withdrawal)\s+fee\b/i,
  /\bpay\s+(?:a\s+)?(?:small\s+)?fee\s+to\s+(?:claim|receive|unlock|release)\b/i,
];

const REWARD_PATTERNS = [
  /\b(?:claim|collect|unlock|receive)\b.{0,45}\b(?:your\s+)?(?:prize|reward|lottery winnings?|free gift|giveaway)\b/i,
  /\b(?:you(?:'ve| have)?\s+won|you are the winner|selected as a winner)\b/i,
  /\bcongratulations\b.{0,70}\b(?:winner|prize|reward|giveaway)\b/i,
];

const IMPERSONATION_PATTERNS = [
  /\b(?:ceo|director|manager|boss)\b.{0,60}\b(?:gift cards?|wire transfer|payment|bank details|confidential transfer)\b/i,
  /\b(?:technical support|bank security|government officer|police officer)\b.{0,60}\b(?:otp|password|payment|remote access|bank details)\b/i,
  /\b(?:your account|your bank account)\b.{0,45}\b(?:verify|suspend|block|freeze|restrict)\b/i,
  /\b(?:pretend|impersonat(?:e|ing))\b.{0,35}\b(?:bank|support|employee|official)\b/i,
];

const SENSITIVE_DATA_PATTERN =
  /\b(?:bank details|card number|cvv|social security number|identity documents|bank account number)\b/i;

const DATA_ACTION_PATTERN =
  /\b(?:send|share|provide|submit|reply|enter|upload)\b/i;

const SHORTENER_DOMAINS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "cutt.ly",
  "rb.gy",
  "is.gd",
  "rebrand.ly",
  "shorturl.at",
]);

function makeFinding(id, title, description, severity, points) {
  return { id, title, description, severity, points };
}

function classifyRisk(score, findings) {
  // A serious credential or sensitive-data request must not
  // be hidden by a low combined score.
  if (findings.some((finding) => finding.severity === "high")) {
    return "high";
  }

  // Any detected medium-severity indicator requires caution.
  if (findings.some((finding) => finding.severity === "medium")) {
    return "medium";
  }

  if (score >= 60) return "high";
  if (score >= 25) return "medium";

  return "low";
}

function findLinks(text) {
  return text.match(/\b(?:https?:\/\/|www\.)[^\s<>"']+/gi) || [];
}

function normalizeContent(input) {
  if (typeof input !== "string" || !input.trim()) {
    throw new Error("Please enter the content to analyze.");
  }

  if (input.length > 20000) {
    throw new Error("Content is too long. Maximum 20,000 characters.");
  }

  return input.trim();
}

function inspectLink(link) {
  const cleaned = link.replace(/[),.!?;:]+$/, "");

  try {
    const candidate = /^www\./i.test(cleaned)
      ? `https://${cleaned}`
      : cleaned;

    const parsed = new URL(candidate);
    const hostname = parsed.hostname.toLowerCase();
    const parts = hostname.split(".");
    const reasons = [];

    if (parsed.protocol !== "https:") {
      reasons.push("The link does not use HTTPS.");
    }

    if (hostname.includes("xn--")) {
      reasons.push("The hostname contains a punycode label.");
    }

    if (parts.length >= 5) {
      reasons.push("The hostname has an unusually deep subdomain structure.");
    }

    if (parsed.username || parsed.password) {
      reasons.push("The URL embeds user information before the hostname.");
    }

    if (SHORTENER_DOMAINS.has(hostname)) {
      reasons.push("The link uses a URL-shortening service.");
    }

    return {
      link,
      hostname,
      suspicious: reasons.length > 0,
      reasons,
    };
  } catch {
    return {
      link,
      hostname: "",
      suspicious: true,
      reasons: ["The link could not be parsed as a valid URL."],
    };
  }
}

function analyzeContent(input, type) {
  const content = normalizeContent(input);
  const findings = [];
  const recommendations = [];
  let score = 0;

  function addFinding(id, title, description, severity, points) {
    if (findings.some((finding) => finding.id === id)) return;

    findings.push(
      makeFinding(id, title, description, severity, points)
    );

    score += points;
  }

  // Urgency and pressure tactics
  if (URGENCY_PATTERNS.some((pattern) => pattern.test(content))) {
    addFinding(
      "urgent-language",
      "Urgency or pressure tactics",
      "The content uses time pressure or threatening language that may encourage rushed decisions.",
      "medium",
      18
    );
  }

  // Requests for authentication information
  // Avoid flagging general safety advice such as "never share your OTP".
  const isCredentialWarningOnly =
    /\b(?:never|do not|don't)\s+share\b/i.test(content) &&
    !/\b(?:please|kindly|must|need to|needs you to|send us|provide us)\b/i.test(content);

  if (
    !isCredentialWarningOnly &&
    CREDENTIAL_PATTERNS.some((pattern) => pattern.test(content))
  ) {
    addFinding(
      "credential-request",
      "Possible credential or OTP request",
      "The content appears to request authentication information such as a password, PIN, OTP, or recovery code. Verify the sender independently and do not disclose these secrets.",
      "high",
      35
    );
  }

  // Financial transfers, payments, and fees
  if (MONEY_PATTERNS.some((pattern) => pattern.test(content))) {
    addFinding(
      "financial-request",
      "Suspicious financial request",
      "The wording matches patterns involving payments, money transfers, cryptocurrency, gift cards, or fees.",
      "high",
      30
    );
  }

  // Prize and reward bait
  if (REWARD_PATTERNS.some((pattern) => pattern.test(content))) {
    addFinding(
      "reward-bait",
      "Unexpected prize or reward claim",
      "The content uses prize, winner, or reward language often seen in scams. Verify the claim independently.",
      "medium",
      20
    );
  }

  // Possible impersonation
  if (IMPERSONATION_PATTERNS.some((pattern) => pattern.test(content))) {
    addFinding(
      "possible-impersonation",
      "Possible impersonation",
      "The wording may imitate an authority figure, organization, bank, or support team.",
      "medium",
      22
    );
  }

  // Links in emails and messages
  const links = findLinks(content);
  const linkDetails = links.map(inspectLink);
  const suspiciousLinks = linkDetails
    .filter((item) => item.suspicious)
    .map((item) => item.link);

  if (suspiciousLinks.length > 0) {
    const reasons = [
      ...new Set(linkDetails.flatMap((item) => item.reasons)),
    ];

    addFinding(
      "suspicious-link",
      "Link needs additional verification",
      `${reasons.join(" ")} These characteristics alone do not prove that a link is malicious.`,
      "medium",
      20
    );
  }

  // Sensitive personal and banking data
  if (
    SENSITIVE_DATA_PATTERN.test(content) &&
    DATA_ACTION_PATTERN.test(content)
  ) {
    addFinding(
      "sensitive-data-request",
      "Possible sensitive-data request",
      "The content may request banking, payment-card, identity, or other sensitive personal information.",
      "high",
      30
    );
  }

  const finalScore = Math.min(score, 100);

  // IMPORTANT: pass the findings so severity affects the verdict.
  const level = classifyRisk(finalScore, findings);

  if (findings.length === 0) {
    recommendations.push(
      "No configured warning patterns were detected. This does not establish that the content is safe."
    );
    recommendations.push(
      "Check the sender and verify unexpected requests through an independent, trusted channel."
    );
  } else {
    recommendations.push(
      "Verify the sender using a separate, trusted contact method before acting."
    );
    recommendations.push(
      "Never share passwords, OTPs, PINs, or recovery codes in response to an unexpected request."
    );
    recommendations.push(
      "Visit an organization's official website or app directly instead of following an unexpected link."
    );
    recommendations.push(
      "Verify payment requests and prize claims independently before sending money."
    );
  }

  return {
    id: `${type}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
    type,
    originalInput: input,
    score: finalScore,
    level,
    risk: RISK_LEVELS[level],
    findings,
    findingCount: findings.length,
    links,
    suspiciousLinks,
    recommendations,
    analyzedAt: new Date().toISOString(),
    engine: `CyberGuard ${type === "email" ? "Email" : "Message"} Heuristics v1.2`,
    isLiveScan: false,
    disclaimer:
      "This is a local heuristic analysis. It does not verify sender identity, inspect attachments, query live threat intelligence, or prove that content is safe or malicious.",
  };
}

/**
 * Analyze pasted email content, including headers if provided.
 * Does not connect to an email account or verify delivery.
 */
export function analyzeEmail(input) {
  return analyzeContent(input, "email");
}

/**
 * Analyze SMS, chat messages, and other pasted message content.
 */
export function analyzeMessage(input) {
  return analyzeContent(input, "message");
}
