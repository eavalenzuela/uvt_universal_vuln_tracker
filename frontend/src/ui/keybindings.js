/**
 * Global keyboard shortcuts (F20).
 *
 * Single-key and chord (leader-then-key) shortcuts that navigate around the
 * app and open a help overlay. Intentionally vanilla-JS: no external deps.
 *
 * Bindings:
 *   ? or Shift+/        Show this help
 *   /                   Focus global search input (if present)
 *   Esc                 Close modal / blur input
 *   g then d            Dashboard
 *   g then v            Vulnerabilities
 *   g then p            Products
 *   g then c            Controls
 *   g then n            Notifications
 *   g then u            Admin users
 *   g then s            Admin logs (security audit)
 *   g then t            API tokens
 *   c                   Create new vulnerability (on list pages)
 */

import { el } from "./dom/el.js";
import { navigate } from "../router/router.js";

const LEADER_TIMEOUT_MS = 1500;

const BINDINGS = [
  { key: "?", label: "Show keyboard shortcuts", action: showHelp, shift: true },
  { key: "/", label: "Focus search", action: focusSearch },
  { chord: ["g", "d"], label: "Go to Dashboard", action: () => navigate("/") },
  { chord: ["g", "v"], label: "Go to Vulnerabilities", action: () => navigate("/vulnerabilities") },
  { chord: ["g", "p"], label: "Go to Products", action: () => navigate("/products") },
  { chord: ["g", "c"], label: "Go to Controls", action: () => navigate("/controls") },
  { chord: ["g", "n"], label: "Go to Notifications", action: () => navigate("/notifications") },
  { chord: ["g", ","], label: "Go to Settings", action: () => navigate("/settings") },
  { chord: ["g", "u"], label: "Admin: Users", action: () => navigate("/admin/users"), role: "Admin" },
  { chord: ["g", "s"], label: "Admin: Audit logs", action: () => navigate("/admin/logs"), role: "Admin" },
  { chord: ["g", "t"], label: "Admin: API tokens", action: () => navigate("/admin/api-tokens") },
];

let leaderKey = null;
let leaderTimer = null;
let helpOpen = false;

function isTypingContext(target) {
  if (!target) return false;
  const tag = (target.tagName || "").toLowerCase();
  if (tag === "input" || tag === "textarea" || tag === "select") return true;
  if (target.isContentEditable) return true;
  return false;
}

function clearLeader() {
  leaderKey = null;
  if (leaderTimer) {
    clearTimeout(leaderTimer);
    leaderTimer = null;
  }
}

function focusSearch() {
  const input = document.querySelector("[data-global-search], input[type='search'], input[name='search']");
  if (input) {
    input.focus();
    if (typeof input.select === "function") input.select();
  }
}

function userHasRole(requiredRole) {
  if (!requiredRole) return true;
  // Read user role from the DOM sidebar which is kept in sync by state/store.
  const roleAttr = document.body.getAttribute("data-user-role");
  return roleAttr === requiredRole || roleAttr === "Admin";
}

function showHelp() {
  if (helpOpen) return;
  helpOpen = true;

  const backdrop = el("div", {
    class: "modal-backdrop",
    role: "dialog",
    "aria-modal": "true",
    "aria-label": "Keyboard shortcuts",
  });

  function close() {
    helpOpen = false;
    backdrop.remove();
    document.removeEventListener("keydown", onEsc);
  }

  function onEsc(e) {
    if (e.key === "Escape") close();
  }

  backdrop.addEventListener("click", (e) => {
    if (e.target === backdrop) close();
  });

  const rows = BINDINGS.filter((b) => userHasRole(b.role)).map((b) =>
    el(
      "tr",
      {},
      el("td", { class: "shortcut-key" }, formatBinding(b)),
      el("td", {}, b.label),
    ),
  );

  const panel = el(
    "div",
    { class: "modal-panel", style: "min-width:420px;max-width:560px;" },
    el("h3", { class: "m-0" }, "Keyboard shortcuts"),
    el(
      "table",
      { class: "shortcut-table" },
      el("tbody", {}, ...rows),
    ),
    el(
      "div",
      { class: "row flex-end gap-8" },
      el("button", { class: "btn", onclick: close }, "Close"),
    ),
  );

  backdrop.appendChild(panel);
  document.body.appendChild(backdrop);
  document.addEventListener("keydown", onEsc);
}

function formatBinding(b) {
  if (b.chord) return b.chord.join(" then ");
  return b.shift ? `Shift + ${b.key}` : b.key;
}

function matchSingle(e) {
  if (e.ctrlKey || e.metaKey || e.altKey) return null;
  for (const b of BINDINGS) {
    if (b.chord) continue;
    if (b.key !== e.key) continue;
    if (b.shift && !e.shiftKey) continue;
    if (!userHasRole(b.role)) continue;
    return b;
  }
  return null;
}

function matchChord(first, second) {
  for (const b of BINDINGS) {
    if (!b.chord) continue;
    if (b.chord[0] === first && b.chord[1] === second) {
      if (!userHasRole(b.role)) return null;
      return b;
    }
  }
  return null;
}

function onKeyDown(e) {
  if (isTypingContext(e.target)) {
    // Allow Esc to blur even inside inputs.
    if (e.key === "Escape" && typeof e.target.blur === "function") {
      e.target.blur();
    }
    return;
  }

  if (helpOpen) return;

  if (leaderKey) {
    const binding = matchChord(leaderKey, e.key);
    clearLeader();
    if (binding) {
      e.preventDefault();
      binding.action();
    }
    return;
  }

  // Single-key bindings first.
  const single = matchSingle(e);
  if (single) {
    e.preventDefault();
    single.action();
    return;
  }

  // Begin chord if any binding starts with this key.
  const startsChord = BINDINGS.some((b) => b.chord && b.chord[0] === e.key && userHasRole(b.role));
  if (startsChord) {
    leaderKey = e.key;
    leaderTimer = setTimeout(clearLeader, LEADER_TIMEOUT_MS);
  }
}

export function installKeybindings() {
  document.addEventListener("keydown", onKeyDown);
}

export const __test = { BINDINGS, matchSingle, matchChord };
