import { el } from "../../ui/dom/el.js";

function pill(label, color, subtle = false) {
  const baseColor = color || "#1f2937";
  const bg = subtle ? `${baseColor}15` : `${baseColor}22`;
  return el("span", {
    class: "pill",
    style: `display:inline-flex; align-items:center; gap:6px; padding:4px 8px; border-radius:12px; font-size:12px; background:${bg}; color:${baseColor}; border:1px solid ${baseColor}33; font-weight:600;`,
    text: label,
  });
}

function statCard(title, value, hint) {
  return el("div", { class: "card", style: "flex:1; min-width: 180px; padding: 12px;" },
    el("div", { class: "muted", text: title }),
    el("div", { style: "font-size: 24px; font-weight: 700;" , text: value }),
    hint ? el("div", { class: "muted", style: "font-size: 12px;", text: hint }) : null,
  );
}

function improvementCard(index, improvement) {
  return el("div", { class: "card", style: "flex:1; min-width: 220px; padding: 12px; display:flex; flex-direction:column; gap:6px;" },
    el("div", { class: "row", style: "align-items: center; gap: 8px;" },
      pill(`#${index + 1}`, "#2563eb", true),
      el("div", { style: "font-weight: 700;", text: improvement.title }),
    ),
    el("div", { class: "muted", text: improvement.detail }),
  );
}

function userCard(user) {
  const statusColor = {
    Active: "#16a34a",
    Pending: "#f59e0b",
    Disabled: "#dc2626",
  }[user.status] || "#4b5563";

  return el("div", { class: "card", style: "padding: 12px;" },
    el("div", { class: "row", style: "justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap;" },
      el("div", { style: "flex:1; min-width: 220px;" },
        el("div", { class: "row", style: "align-items: center; gap: 8px; flex-wrap: wrap;" },
          el("div", { class: "muted", text: user.username }),
          pill(user.role, "#2563eb"),
          pill(user.status, statusColor, true),
          user.mfa ? pill("MFA", "#0d9488", true) : null,
        ),
        el("div", { style: "font-weight: 700; margin-top: 4px;", text: user.name }),
        el("div", { class: "muted", style: "margin-top: 2px;", text: `${user.email} \u2022 Last seen ${user.lastSeen}` }),
        user.notes ? el("div", { style: "margin-top: 8px;" , text: user.notes }) : null,
      ),
      el("div", { class: "row", style: "gap: 6px; flex-wrap: wrap;" },
        el("button", { class: "btn" }, "Impersonate"),
        el("button", { class: "btn" }, user.status === "Disabled" ? "Enable" : "Disable"),
        el("button", { class: "btn" }, "Reset MFA"),
      ),
    ),
  );
}

export async function AdminUsersView() {
  const users = [
    { username: "asato", name: "Alicia Sato", email: "asato@example.com", role: "Admin", status: "Active", lastSeen: "5m ago", mfa: true, notes: "Owns production RBAC and incident response." },
    { username: "jsingh", name: "Jaspreet Singh", email: "jaspreet@example.com", role: "Analyst", status: "Pending", lastSeen: "Awaiting invite", mfa: false, notes: "Awaiting approval to join the AppSec rotation." },
    { username: "lramirez", name: "Luis Ramirez", email: "lramirez@example.com", role: "Viewer", status: "Active", lastSeen: "2h ago", mfa: true, notes: "Read-only access for reporting. Auto-disables after 30 days idle." },
    { username: "tnguyen", name: "Thao Nguyen", email: "thao@example.com", role: "Analyst", status: "Disabled", lastSeen: "Revoked", mfa: false, notes: "Temporarily disabled after offboarding ticket." },
  ];

  const improvements = [
    {
      title: "Faster triage",
      detail: "At-a-glance stats plus search and filtering make it quick to spot risk and onboarding gaps.",
    },
    {
      title: "Actionable controls",
      detail: "Inline admin actions (impersonate, toggle access, reset MFA) are now one click away from each user row.",
    },
    {
      title: "Role clarity",
      detail: "Clear badges for role, status, and MFA reduce ambiguity and make auditing conversations easier.",
    },
  ];

  const stats = {
    total: users.length,
    active: users.filter((u) => u.status === "Active").length,
    pending: users.filter((u) => u.status === "Pending").length,
    disabled: users.filter((u) => u.status === "Disabled").length,
  };

  const controls = el("div", { class: "row", style: "gap: 8px; align-items: center; flex-wrap: wrap; margin: 12px 0;" },
    el("input", { class: "input", type: "search", placeholder: "Search by name, email, or username" }),
    el("select", { class: "input" },
      el("option", { value: "", text: "Filter by status" }),
      el("option", { value: "Active", text: "Active" }),
      el("option", { value: "Pending", text: "Pending" }),
      el("option", { value: "Disabled", text: "Disabled" }),
    ),
    el("select", { class: "input" },
      el("option", { value: "", text: "Filter by role" }),
      el("option", { value: "Admin", text: "Admin" }),
      el("option", { value: "Analyst", text: "Analyst" }),
      el("option", { value: "Viewer", text: "Viewer" }),
    ),
    el("div", { class: "spacer" }),
    el("button", { class: "btn primary" }, "Invite user"),
    el("button", { class: "btn" }, "Export CSV"),
  );

  const statsRow = el("div", { class: "row", style: "gap: 12px; flex-wrap: wrap;" },
    statCard("Total users", stats.total, "Includes all active, pending, and disabled"),
    statCard("Active", stats.active, "Allowed to sign in"),
    statCard("Pending", stats.pending, "Awaiting invite or approval"),
    statCard("Disabled", stats.disabled, "Access revoked"),
  );

  const improvementsRow = el("div", { class: "row", style: "gap: 12px; flex-wrap: wrap;" },
    improvements.map((imp, idx) => improvementCard(idx, imp)),
  );

  const userList = el("div", { style: "display: flex; flex-direction: column; gap: 10px; margin-top: 4px;" },
    users.map((u) => userCard(u)),
  );

  return el("div", { style: "display: flex; flex-direction: column; gap: 12px;" },
    el("div", { class: "card" },
      el("h1", { class: "page-title", text: "Admin: Users" }),
      el("p", { class: "muted", text: "Manage account access, MFA posture, and onboarding from a single control plane." }),
      el("div", { class: "muted", style: "font-weight: 600; margin-top: 8px;" }, "Top 3 improvements to the admin interface"),
      improvementsRow,
    ),
    el("div", { class: "card" },
      el("div", { class: "row", style: "align-items: center; gap: 8px;" },
        el("div", { style: "font-weight: 700;", text: "User overview" }),
        pill("Real-time", "#059669", true),
      ),
      statsRow,
      controls,
      userList,
    ),
  );
}
