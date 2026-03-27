import { el } from "../dom/el.js";

/**
 * Render a loading spinner with optional message.
 * @param {string} [message] - Text beside the spinner
 * @returns {HTMLElement}
 */
export function loadingBlock(message = "Loading\u2026") {
  return el("div", { class: "loading-block" },
    el("div", { class: "loading-spinner" }),
    message ? el("span", { text: message }) : null,
  );
}

/**
 * Render a skeleton placeholder row.
 * @param {number} [count=3] - Number of skeleton rows
 * @returns {HTMLElement}
 */
export function skeletonRows(count = 3) {
  const container = el("div", { class: "flex-col-8" });
  for (let i = 0; i < count; i++) {
    container.appendChild(el("div", { class: "skeleton skeleton-row" }));
  }
  return container;
}

/**
 * Render an empty-state message.
 * @param {string} message - Message to display
 * @returns {HTMLElement}
 */
export function emptyState(message) {
  return el("div", { class: "empty-state" },
    el("div", { class: "empty-state-icon", text: "\u2205" }),
    el("div", { text: message }),
  );
}

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
