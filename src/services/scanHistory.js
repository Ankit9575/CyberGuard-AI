
const STORAGE_KEY = "cyberguard-ai-scan-history";
const MAX_HISTORY_ITEMS = 100;

/**
 * Read saved scan history from this browser.
 */
export function getScanHistory() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);

    if (!saved) {
      return [];
    }

    const parsed = JSON.parse(saved);

    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed.filter(
      (item) =>
        item &&
        typeof item.id === "string" &&
        typeof item.hostname === "string" &&
        typeof item.analyzedAt === "string" &&
        typeof item.score === "number" &&
        Array.isArray(item.findings)
    );
  } catch {
    return [];
  }
}

/**
 * Save a completed analysis.
 * Keeps only the latest 100 entries.
 */
export function saveScanToHistory(result) {
  if (
    !result ||
    typeof result.hostname !== "string" ||
    typeof result.score !== "number" ||
    !Array.isArray(result.findings)
  ) {
    throw new Error("Invalid scan result. History was not saved.");
  }

  const existing = getScanHistory();

  const entry = {
    ...result,
    id:
      typeof crypto !== "undefined" &&
      typeof crypto.randomUUID === "function"
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
    analyzedAt:
      typeof result.analyzedAt === "string"
        ? result.analyzedAt
        : new Date().toISOString(),
  };

  const updated = [entry, ...existing].slice(0, MAX_HISTORY_ITEMS);

  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch {
    throw new Error(
      "Unable to save scan history. Browser storage may be unavailable or full."
    );
  }
}

/**
 * Delete one history entry by its ID.
 */
export function deleteScanFromHistory(id) {
  const updated = getScanHistory().filter((item) => item.id !== id);

  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch {
    throw new Error("Unable to update scan history.");
  }
}

/**
 * Clear all saved history.
 */
export function clearScanHistory() {
  try {
    localStorage.removeItem(STORAGE_KEY);
    return [];
  } catch {
    throw new Error("Unable to clear scan history.");
  }
}

/**
 * Export history as a downloadable JSON file.
 */
export function exportScanHistory() {
  const history = getScanHistory();

  return {
    exportedAt: new Date().toISOString(),
    application: "CyberGuard AI",
    count: history.length,
    scans: history,
  };
}
