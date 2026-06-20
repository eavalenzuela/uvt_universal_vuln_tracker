import { el } from "../dom/el.js";

/**
 * Show a modal dialog that replaces window.prompt / window.confirm patterns.
 *
 * @param {object} opts
 * @param {string} opts.title          - Dialog heading
 * @param {string} [opts.message]      - Optional descriptive text
 * @param {string} [opts.defaultValue] - Pre-filled input value (omit for confirm-only dialogs)
 * @param {string} [opts.inputLabel]   - Label for the input field
 * @param {string} [opts.placeholder]  - Placeholder text for the input
 * @param {string} [opts.confirmText]  - Text for the confirm button (default "OK")
 * @param {string} [opts.cancelText]   - Text for the cancel button (default "Cancel")
 * @param {boolean} [opts.required]    - Whether a non-empty value is required
 * @returns {Promise<string|null>}     - Resolves with the input value, or null if cancelled
 */
export function promptModal({
  title = "Prompt",
  message = "",
  defaultValue = "",
  inputLabel = "",
  placeholder = "",
  confirmText = "OK",
  cancelText = "Cancel",
  required = false,
} = {}) {
  return new Promise((resolve) => {
    const backdrop = el("div", {
      class: "modal-backdrop",
      role: "dialog",
      "aria-modal": "true",
      "aria-label": title,
    });

    const input = el("input", {
      class: "input w-full",
      value: defaultValue,
      placeholder,
      "aria-label": inputLabel || title,
    });

    const errorEl = el("div", {
      class: "text-error modal-error",
    });

    const confirmBtn = el("button", { class: "btn primary", type: "submit" }, confirmText);
    const cancelBtn = el("button", { class: "btn", type: "button" }, cancelText);

    // Remember the trigger so focus can be restored when the dialog closes.
    const previouslyFocused = document.activeElement;

    function close(value) {
      backdrop.remove();
      document.removeEventListener("keydown", onKey);
      if (previouslyFocused && typeof previouslyFocused.focus === "function") {
        previouslyFocused.focus();
      }
      resolve(value);
    }

    function focusableNodes() {
      return Array.from(
        backdrop.querySelectorAll(
          'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((node) => node.offsetParent !== null);
    }

    function onKey(e) {
      if (e.key === "Escape") {
        close(null);
        return;
      }
      if (e.key === "Tab") {
        // Trap focus inside the dialog so Tab can't escape to the page behind it.
        const nodes = focusableNodes();
        if (!nodes.length) return;
        const first = nodes[0];
        const last = nodes[nodes.length - 1];
        const active = document.activeElement;
        if (e.shiftKey && (active === first || !backdrop.contains(active))) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && (active === last || !backdrop.contains(active))) {
          e.preventDefault();
          first.focus();
        }
      }
    }

    cancelBtn.addEventListener("click", () => close(null));
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) close(null);
    });

    const form = el(
      "form",
      {
        class: "modal-panel modal-sm",
        style: "min-width:340px;max-width:480px;",
        onsubmit: (e) => {
          e.preventDefault();
          const val = input.value;
          if (required && !val.trim()) {
            errorEl.textContent = "This field is required.";
            input.focus();
            return;
          }
          close(val);
        },
      },
      el("h3", { class: "m-0" }, title),
      message ? el("p", { class: "muted m-0" }, message) : null,

      inputLabel
        ? el(
            "label",
            { class: "flex-col" },
            el("span", {}, inputLabel),
            input,
          )
        : input,
      errorEl,
      el(
        "div",
        { class: "row flex-end gap-8" },
        cancelBtn,
        confirmBtn,
      ),
    );

    backdrop.appendChild(form);
    document.body.appendChild(backdrop);
    document.addEventListener("keydown", onKey);
    input.focus();
    input.select();
  });
}
