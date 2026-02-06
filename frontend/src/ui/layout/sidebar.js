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
  const authed = isAuthed(state);
  const admin = isAdmin(state);

  if (!authed) {
    root.appendChild(el("div", { class: "muted" }, "Please log in."));
    return;
  }

  const nav = el("div", { class: "nav" },
    navLink("Dashboard", "/"),
    navLink("Vulnerabilities", "/vulnerabilities"),
    navLink("Controls", "/controls"),
    navLink("Products", "/products"),
  );

  if (admin) {
    nav.appendChild(el("div", { style: "height:10px" }));
    nav.appendChild(navLink("Admin: Users", "/admin/users"));
    nav.appendChild(navLink("Admin: Logs", "/admin/logs"));
    nav.appendChild(navLink("Admin: Plugins", "/admin/plugins"));
    nav.appendChild(navLink("Admin: Notification Rules", "/admin/notification-rules"));
  }

  root.appendChild(nav);
}
