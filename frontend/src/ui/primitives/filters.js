import { el } from "../dom/el.js";

export function createFilterRow({ controls = [], actions = [] }) {
  return el("div", { class: "row", style: "gap: 8px; align-items: center; flex-wrap: wrap;" },
    ...controls,
    el("div", { class: "spacer" }),
    ...actions,
  );
}
