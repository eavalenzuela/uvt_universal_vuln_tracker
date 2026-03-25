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
      style:
        "position:fixed;inset:0;z-index:100;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;",
      role: "dialog",
      "aria-modal": "true",
      "aria-label": title,
    });

    const input = el("input", {
      class: "input",
      style: "width:100%;box-sizing:border-box;",
      value: defaultValue,
      placeholder,
      "aria-label": inputLabel || title,
    });

    const errorEl = el("div", {
      style: "color:#dc2626;font-size:13px;min-height:18px;margin-top:2px;",
    });

    const confirmBtn = el("button", { class: "btn primary", type: "submit" }, confirmText);
    const cancelBtn = el("button", { class: "btn", type: "button" }, cancelText);

    function close(value) {
      backdrop.remove();
      document.removeEventListener("keydown", onKey);
      resolve(value);
    }

    function onKey(e) {
      if (e.key === "Escape") close(null);
    }

    cancelBtn.addEventListener("click", () => close(null));
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) close(null);
    });

    const form = el(
      "form",
      {
        class: "card",
        style:
          "min-width:340px;max-width:480px;width:90%;padding:20px;display:flex;flex-direction:column;gap:10px;",
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
      el("h3", { style: "margin:0;" }, title),
      message ? el("p", { class: "muted", style: "margin:0;" }, message) : null,
      inputLabel
        ? el(
            "label",
            { style: "display:flex;flex-direction:column;gap:4px;" },
            el("span", {}, inputLabel),
            input,
          )
        : input,
      errorEl,
      el(
        "div",
        { class: "row", style: "justify-content:flex-end;gap:8px;" },
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
