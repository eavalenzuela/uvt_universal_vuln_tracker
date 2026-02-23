import { el } from "../dom/el.js";

export function createTableHeader(columns = []) {
  return el("div", { style: "display:grid; gap:8px; align-items:center;" },
    ...columns.map((column) => el("div", { text: column })),
  );
}

export function createEmptyState(message) {
  return el("div", { class: "muted", text: message });
}
