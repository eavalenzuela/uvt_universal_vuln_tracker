import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { getState, setSession } from "../../state/store.js";
import { impersonateUser, inviteUser, listUsers, exportUsers, toggleUserActive } from "../../api/users.js";
import { createFilterRow } from "../../ui/primitives/filters.js";
import { createEmptyState } from "../../ui/primitives/table.js";

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
  const valueNode = (typeof value === "string" || typeof value === "number")
    ? el("div", { style: "font-size: 24px; font-weight: 700;", text: value })
    : value;

  return el("div", { class: "card", style: "flex:1; min-width: 180px; padding: 12px;" },
    el("div", { class: "muted", text: title }),
    valueNode,
    hint ? el("div", { class: "muted", style: "font-size: 12px;", text: hint }) : null,
  );
}

function userCard(user, { onImpersonate, onToggle }) {
  const statusLabel = user.is_active ? "Active" : "Disabled";
  const statusColor = user.is_active ? "#16a34a" : "#dc2626";
  const name = user.full_name || user.username;
  const lastSeen = (user.updated_at || user.created_at || "").slice(0, 10) || "Unknown";

  const impersonateBtn = el("button", { class: "btn" }, "Impersonate");
  impersonateBtn.addEventListener("click", () => onImpersonate(user));

  const toggleBtn = el("button", { class: "btn" }, user.is_active ? "Disable" : "Enable");
  toggleBtn.addEventListener("click", () => onToggle(user));

  return el("div", { class: "card", style: "padding: 12px;" },
    el("div", { class: "row", style: "justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap;" },
      el("div", { style: "flex:1; min-width: 220px;" },
        el("div", { class: "row", style: "align-items: center; gap: 8px; flex-wrap: wrap;" },
          el("div", { class: "muted", text: user.username }),
          pill(user.role, "#2563eb"),
          pill(statusLabel, statusColor, true),
        ),
        el("div", { style: "font-weight: 700; margin-top: 4px;", text: name }),
        el("div", { class: "muted", style: "margin-top: 2px;", text: `${user.email} \u2022 Updated ${lastSeen}` }),
      ),
      el("div", { class: "row", style: "gap: 6px; flex-wrap: wrap;" },
        impersonateBtn,
        toggleBtn,
      ),
    ),
  );
}

export async function AdminUsersView() {
  const totalEl = el("div", { style: "font-size: 24px; font-weight: 700;", text: "0" });
  const activeEl = el("div", { style: "font-size: 24px; font-weight: 700;", text: "0" });
  const pendingEl = el("div", { style: "font-size: 24px; font-weight: 700;", text: "0" });
  const disabledEl = el("div", { style: "font-size: 24px; font-weight: 700;", text: "0" });

  const searchInput = el("input", { class: "input", type: "search", placeholder: "Search by name, email, or username" });
  const statusSelect = el("select", { class: "input" },
    el("option", { value: "", text: "Filter by status" }),
    el("option", { value: "active", text: "Active" }),
    el("option", { value: "disabled", text: "Disabled" }),
  );
  const roleSelect = el("select", { class: "input" },
    el("option", { value: "", text: "Filter by role" }),
    el("option", { value: "Admin", text: "Admin" }),
    el("option", { value: "Analyst", text: "Analyst" }),
    el("option", { value: "Viewer", text: "Viewer" }),
  );
  const pageSizeSelect = el("select", { class: "input" },
    el("option", { value: "10", text: "10 / page" }),
    el("option", { value: "25", text: "25 / page", selected: "true" }),
    el("option", { value: "50", text: "50 / page" }),
    el("option", { value: "100", text: "100 / page" }),
  );

  const inviteBtn = el("button", { class: "btn primary" }, "Invite user");
  const exportBtn = el("button", { class: "btn" }, "Export CSV");
  const applyBtn = el("button", { class: "btn" }, "Apply filters");

  const controls = createFilterRow({
    controls: [searchInput, statusSelect, roleSelect, pageSizeSelect, applyBtn],
    actions: [inviteBtn, exportBtn],
  });
  controls.style.margin = "12px 0";

  const statsRow = el("div", { class: "row", style: "gap: 12px; flex-wrap: wrap;" },
    statCard("Total users", totalEl, "Across current filters"),
    statCard("Active (page)", activeEl, "Shown on this page"),
    statCard("Pending", pendingEl, "Awaiting activation"),
    statCard("Disabled (page)", disabledEl, "Shown on this page"),
  );

  const inviteUsername = el("input", { class: "input", placeholder: "Username", required: "true" });
  const inviteEmail = el("input", { class: "input", placeholder: "Email", required: "true" });
  const inviteRole = el("select", { class: "input" },
    el("option", { value: "Admin", text: "Admin" }),
    el("option", { value: "Analyst", text: "Analyst", selected: "true" }),
    el("option", { value: "Viewer", text: "Viewer" }),
  );
  const inviteFirstName = el("input", { class: "input", placeholder: "First name (optional)" });
  const inviteLastName = el("input", { class: "input", placeholder: "Last name (optional)" });
  const inviteSubmit = el("button", { class: "btn primary", type: "submit" }, "Send invite");
  const inviteCancel = el("button", { class: "btn", type: "button" }, "Cancel");

  const inviteForm = el(
    "form",
    { style: "display: flex; flex-direction: column; gap: 8px;" },
    el("div", {}, el("div", { class: "muted", text: "Username" }), inviteUsername),
    el("div", {}, el("div", { class: "muted", text: "Email" }), inviteEmail),
    el("div", {}, el("div", { class: "muted", text: "Role" }), inviteRole),
    el("div", {}, el("div", { class: "muted", text: "First name" }), inviteFirstName),
    el("div", {}, el("div", { class: "muted", text: "Last name" }), inviteLastName),
    el("div", { class: "row", style: "justify-content: flex-end; gap: 8px;" }, inviteCancel, inviteSubmit),
  );

  const inviteCard = el(
    "div",
    { class: "card", style: "margin-top: 12px; display: none;" },
    el("h3", { style: "margin-top: 0;", text: "Invite user" }),
    el("p", { class: "muted", text: "Create a new user and assign their role." }),
    inviteForm,
  );

  const userList = el("div", { style: "display: flex; flex-direction: column; gap: 10px; margin-top: 4px;" });
  const pageInfo = el("div", { class: "muted", text: "Page 1" });
  const prevBtn = el("button", { class: "btn" }, "Previous");
  const nextBtn = el("button", { class: "btn" }, "Next");

  const pagination = el("div", { class: "row", style: "gap:8px; align-items:center; margin-top:12px;" },
    pageInfo,
    el("div", { class: "spacer" }),
    prevBtn,
    nextBtn,
  );

  let currentPage = 1;
  let lastTotal = 0;

  function applyStats(items, total) {
    const active = items.filter((u) => u.is_active).length;
    const disabled = items.length - active;
    totalEl.textContent = String(total || 0);
    activeEl.textContent = active.toString();
    disabledEl.textContent = disabled.toString();
    pendingEl.textContent = "0";
  }

  async function loadUsersList() {
    userList.innerHTML = "";
    userList.appendChild(el("div", { class: "muted", text: "Loading users..." }));
    try {
      const pageSize = parseInt(pageSizeSelect.value || "25", 10) || 25;
      const res = await listUsers({
        search: searchInput.value.trim() || undefined,
        role: roleSelect.value || undefined,
        status: statusSelect.value || undefined,
        page: currentPage,
        page_size: pageSize,
      });
      const items = res?.items || [];
      const total = res?.total || 0;
      const page = res?.page || currentPage;
      const effectiveSize = res?.page_size || pageSize;

      userList.innerHTML = "";
      if (!items.length) {
        userList.appendChild(createEmptyState("No users found."));
      }

      applyStats(items, total);
      items.forEach((u) => userList.appendChild(userCard(u, {
        onImpersonate: async (user) => {
          try {
            const reason = window.prompt(`Why are you impersonating ${user.username}?`);
            if (!reason) {
              toast({ title: "Impersonation cancelled", message: "A reason is required" });
              return;
            }
            const resp = await impersonateUser(user.id, { reason });
            setSession({ token: resp.token, refreshToken: resp.refresh_token || getState()?.session?.refreshToken || null, user: resp.user });
            toast({ title: "Impersonation started", message: `Acting as ${user.username}` });
          } catch (e) {
            toast({ title: "Impersonation failed", message: e?.message || "Unable to impersonate user" });
          }
        },
        onToggle: async (user) => {
          try {
            const updated = await toggleUserActive(user.id);
            toast({ title: updated.is_active ? "User enabled" : "User disabled", message: `${user.username} is now ${updated.is_active ? "active" : "disabled"}.` });
            loadUsersList();
          } catch (e) {
            toast({ title: "Action failed", message: e?.message || "Unable to update user" });
          }
        },
      })));

      lastTotal = total;
      currentPage = page;
      const totalPages = Math.max(1, Math.ceil(total / effectiveSize));
      pageInfo.textContent = `Page ${page} of ${totalPages} • ${total} total`;
      prevBtn.disabled = page <= 1;
      nextBtn.disabled = page >= totalPages;
    } catch (e) {
      userList.innerHTML = "";
      toast({ title: "Failed to load users", message: e?.message || "Unable to fetch users" });
      userList.appendChild(el("div", { class: "muted", text: "Unable to load users." }));
    }
  }

  applyBtn.addEventListener("click", () => {
    currentPage = 1;
    loadUsersList();
  });
  pageSizeSelect.addEventListener("change", () => {
    currentPage = 1;
    loadUsersList();
  });
  prevBtn.addEventListener("click", () => {
    if (currentPage > 1) {
      currentPage -= 1;
      loadUsersList();
    }
  });
  nextBtn.addEventListener("click", () => {
    const pageSize = parseInt(pageSizeSelect.value || "25", 10) || 25;
    const totalPages = Math.max(1, Math.ceil(lastTotal / pageSize));
    if (currentPage < totalPages) {
      currentPage += 1;
      loadUsersList();
    }
  });

  inviteBtn.addEventListener("click", () => {
    const next = inviteCard.style.display === "none";
    inviteCard.style.display = next ? "block" : "none";
    if (next) inviteUsername.focus();
  });

  inviteCancel.addEventListener("click", () => {
    inviteCard.style.display = "none";
  });

  inviteForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = inviteUsername.value.trim();
    const email = inviteEmail.value.trim();
    if (!username || !email) {
      toast({ title: "Missing fields", message: "Username and email are required." });
      return;
    }

    inviteSubmit.disabled = true;
    try {
      const res = await inviteUser({
        username,
        email,
        role: inviteRole.value,
        first_name: inviteFirstName.value.trim() || undefined,
        last_name: inviteLastName.value.trim() || undefined,
      });
      toast({ title: "User invited", message: `Temp password: ${res.temp_password}` });
      inviteUsername.value = "";
      inviteEmail.value = "";
      inviteRole.value = "Analyst";
      inviteFirstName.value = "";
      inviteLastName.value = "";
      inviteCard.style.display = "none";
      loadUsersList();
    } catch (e) {
      toast({ title: "Invite failed", message: e?.message || "Unable to invite user" });
    } finally {
      inviteSubmit.disabled = false;
    }
  });

  exportBtn.addEventListener("click", async () => {
    try {
      const csv = await exportUsers({
        search: searchInput.value.trim() || undefined,
        role: roleSelect.value || undefined,
        status: statusSelect.value || undefined,
      });

      const blob = new Blob([csv], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "users.csv";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast({ title: "Exported", message: "User CSV downloaded" });
    } catch (e) {
      toast({ title: "Export failed", message: e?.message || "Unable to export users" });
    }
  });

  loadUsersList();

  return el("div", { style: "display: flex; flex-direction: column; gap: 12px;" },
    el("div", { class: "card" },
      el("h1", { class: "page-title", text: "Admin: Users" }),
      el("p", { class: "muted", text: "Manage account access, MFA posture, and onboarding from a single control plane." }),
    ),
    el("div", { class: "card" },
      el("div", { class: "row", style: "align-items: center; gap: 8px;" },
        el("div", { style: "font-weight: 700;", text: "User overview" }),
        pill("Real-time", "#059669", true),
      ),
      statsRow,
      controls,
      inviteCard,
      userList,
      pagination,
    ),
  );
}
