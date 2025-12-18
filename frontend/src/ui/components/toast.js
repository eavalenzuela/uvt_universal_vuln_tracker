import { el } from "../dom/el.js";

export function toast({ title = "Notice", message = "", ms = 2600 } = {}) {
  const root = document.getElementById("toast-root");
  if (!root) return;

  const node = el("div", { class: "toast" },
    el("div", { class: "title", text: title }),
    el("div", { class: "msg", text: message })
  );

  root.appendChild(node);

  window.setTimeout(() => {
    node.remove();
  }, ms);
}
