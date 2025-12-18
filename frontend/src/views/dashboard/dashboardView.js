import { el } from "../../ui/dom/el.js";
import { getState } from "../../state/store.js";

export async function DashboardView() {
  const user = getState()?.session?.user;
  return el("div", { class: "card" },
    el("h1", { class: "page-title", text: "Dashboard" }),
    el("p", { class: "muted", text: `Signed in as ${user?.username || "?"} (${user?.role || "?"}).` }),
    el("p", { class: "muted", text: "Next: vuln list UI sketch goes here." }),
  );
}
