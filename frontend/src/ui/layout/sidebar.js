import { el } from "../dom/el.js";
import { getState } from "../../state/store.js";
import { isAuthed, isAdmin } from "../../state/permissions.js";
import { currentPath, navigate } from "../../router/router.js";

function isActiveLink(current, target) {
  // exact match OR nested path (e.g. "/vulnerabilities/123" should activate "/vulnerabilities")
  if (current === target) return true;
  if (target !== "/" && current.startsWith(target + "/")) return true;
  return false;
}

function navLink(label, path) {
  const active = isActiveLink(currentPath(), path);
  return el("a", {
    href: "#",
    class: active ? "active" : "",
    onclick: (e) => {
      e.preventDefault();
      navigate(path);
    }
  }, label);
}

export function renderSidebar() {
  const root = document.getElementById("app-sidebar");
  if (!root) return;
  root.innerHTML = "";

  const state = getState();
  if (!isAuthed(state)) {
    root.appendChild(el("div", { class: "muted" }, "Please log in."));
    return;
  }

  const nav = el("div", { class: "nav" },
    navLink("Dashboard", "/"),
    navLink("Vulnerabilities", "/vulnerabilities"),
    navLink("Products", "/products"),
  );

  if (isAdmin(state)) {
    nav.appendChild(el("div", { style: "height:10px" }));
    nav.appendChild(navLink("Admin: Users", "/admin/users"));
  }

  root.appendChild(nav);
}
