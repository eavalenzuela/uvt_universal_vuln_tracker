import { el } from "../dom/el.js";
import { getState, clearLiveNotifications } from "../../state/store.js";
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
    },
  }, label);
}

function eventSummary(entry) {
  const type = entry?.type;
  const payload = entry?.payload || {};
  if (type === "mention_notification_created") {
    return payload?.notification?.message || "You were mentioned.";
  }
  if (type === "rule_triggered") {
    return `Rule event on vulnerability #${payload?.vulnerability_id || "?"}`;
  }
  if (type === "scheduled_scan_escalation_logged") {
    return `Escalation step ${payload?.escalation_step || 0} on #${payload?.vulnerability_id || "?"}`;
  }
  return "Live notification";
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

  const nav = el(
    "div",
    { class: "nav" },
    navLink("Dashboard", "/"),
    navLink("Vulnerabilities", "/vulnerabilities"),
    navLink("Controls", "/controls"),
    navLink("Products", "/products"),
    navLink("Component Diff", "/products/component-diff"),
    navLink("API Tokens", "/admin/api-tokens"),
  );

  if (admin) {
    nav.appendChild(el("div", { style: "height:10px" }));
    nav.appendChild(navLink("Admin: Users", "/admin/users"));
    nav.appendChild(navLink("Admin: Logs", "/admin/logs"));
    nav.appendChild(navLink("Admin: Plugins", "/admin/plugins"));
    nav.appendChild(navLink("Admin: Notification Rules", "/admin/notification-rules"));
    nav.appendChild(navLink("Admin: Notification Delivery", "/admin/notification-delivery"));
  }

  root.appendChild(nav);

  const liveItems = state.liveNotifications || [];
  const inbox = el("div", { class: "inbox card" },
    el("div", { class: "row" },
      el("strong", {}, `Inbox (${liveItems.length})`),
      el("div", { class: "spacer" }),
      el("button", { class: "btn", onclick: () => clearLiveNotifications() }, "Clear"),
    ),
  );

  const list = el("div", { class: "inbox-list" });
  if (!liveItems.length) {
    list.appendChild(el("div", { class: "muted" }, "No live notifications yet."));
  } else {
    liveItems.slice(0, 5).forEach((item) => {
      list.appendChild(el("div", { class: "inbox-item" }, eventSummary(item)));
    });
  }

  inbox.appendChild(list);
  root.appendChild(el("div", { style: "height:10px" }));
  root.appendChild(inbox);
}
