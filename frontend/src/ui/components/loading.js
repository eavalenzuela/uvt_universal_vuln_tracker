/**
 * Wrap an async click handler so the target button shows a loading indicator
 * while the operation is in-flight.
 *
 * Works with the el() helper — pass the returned function as `onClick`.
 *
 * @param {(e: Event) => Promise<void>} handler - Async click handler
 * @param {object} [opts]
 * @param {string} [opts.loadingText] - Text to show while loading (default: "Loading…")
 * @returns {(e: Event) => Promise<void>}
 */
export function withLoading(handler, { loadingText = "Loading\u2026" } = {}) {
  return async (e) => {
    const btn = e.currentTarget;
    if (btn.disabled) return;
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = loadingText;
    try {
      await handler(e);
    } finally {
      btn.disabled = false;
      btn.textContent = originalText;
    }
  };
}
