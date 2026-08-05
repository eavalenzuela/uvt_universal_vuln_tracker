import { el } from "../dom/el.js";

export function createFilterRow({ controls = [], actions = [] }) {
  return el("div", { class: "row", style: "gap: 8px; align-items: center; flex-wrap: wrap;" },
    ...controls,
    el("div", { class: "spacer" }),
    ...actions,
  );
}

let fieldSeq = 0;

/**
 * Wrap a control in a real <label>.
 *
 * Placeholder text is not an accessible name — screen readers announce an
 * unnamed combobox — and it vanishes the moment a value is selected, so
 * sighted users lose the field's meaning too. 45 controls across the app were
 * labelled this way, 30 of them on the vulnerabilities page alone.
 */
export function filterField(labelText, control) {
  if (!control.id) {
    fieldSeq += 1;
    control.id = `filter-field-${fieldSeq}`;
  }
  return el(
    "div",
    { class: "filter-field" },
    el("label", { class: "filter-label", for: control.id, text: labelText }),
    control,
  );
}

/**
 * Compact filter bar with the rarely-used filters behind a disclosure.
 *
 * The vulnerabilities page previously stacked ten full-width controls, so the
 * first result sat below 800px of chrome and the page ran to 4,371px. Status
 * and severity do not need 1,140px each, and "Max transitive depth" does not
 * deserve the same prominence as "Search".
 *
 * @param {object}   opts
 * @param {Array}    opts.primary   [{label, control}] — always visible.
 * @param {Array}    opts.advanced  [{label, control}] — inside <details>.
 * @param {Array}    opts.actions   Buttons, right-aligned.
 * @param {string}   opts.advancedLabel
 */
export function createFilterBar({ primary = [], advanced = [], actions = [], advancedLabel = "More filters" }) {
  const primaryRow = el(
    "div",
    { class: "filter-bar-primary" },
    ...primary.map(({ label, control }) => filterField(label, control)),
  );

  const children = [primaryRow];

  if (advanced.length) {
    // Count in the summary so it is obvious that more filters exist without
    // having to open it.
    const details = el(
      "details",
      { class: "filter-advanced" },
      el("summary", { class: "filter-advanced-summary", text: `${advancedLabel} (${advanced.length})` }),
      el(
        "div",
        { class: "filter-bar-advanced" },
        ...advanced.map(({ label, control }) => filterField(label, control)),
      ),
    );
    children.push(details);
  }

  if (actions.length) {
    children.push(el("div", { class: "filter-bar-actions" }, ...actions));
  }

  return el("div", { class: "filter-bar" }, ...children);
}
