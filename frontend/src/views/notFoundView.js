import { el } from "../ui/dom/el.js";

export function NotFoundView({ message = "Page not found." } = {}) {
  return el("div", { class: "card" },
    el("h1", { class: "page-title", text: "Not found" }),
    el("p", { class: "muted", text: message })
  );
}
