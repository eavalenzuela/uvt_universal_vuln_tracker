import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { promptModal } from "../../ui/components/modal.js";
import { getState, setSession } from "../../state/store.js";
import { impersonateUser, inviteUser, listUsers, exportUsers, toggleUserActive } from "../../api/users.js";
import { createFilterRow } from "../../ui/primitives/filters.js";
import { createDataTable, createDensityToggle, createTablePagination } from "../../ui/components/dataTable.js";

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
    ? el("div", { class: "kpi-value-lg", text: value })
    : value;

  return el("div", { class: "card flex-1 p-12", style: "min-width: 180px;" },
    el("div", { class: "muted", text: title }),
    valueNode,
    hint ? el("div", { class: "muted", style: "font-size: 12px;", text: hint }) : null,
  );
}

export async function AdminUsersView() {
  const totalEl = el("div", { class: "kpi-value-lg", text: "0" });
  const activeEl = el("div", { class: "kpi-value-lg", text: "0" });
  const pendingEl = el("div", { class: "kpi-value-lg", text: "0" });
  const disabledEl = el("div", { class: "kpi-value-lg", text: "0" });

  const searchInput = el("input", { class: "input", type: "search", placeholder: "Search by name, email, or username", "aria-label": "Search users" });
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

  const statsRow = el("div", { class: "row gap-12 flex-wrap" },
    statCard("Total users", totalEl, "Across current filters"),
    statCard("Active (page)", activeEl, "Shown on this page"),
    statCard("Pending", pendingEl, "Awaiting activation"),
    statCard("Disabled (page)", disabledEl, "Shown on this page"),
  );

  const inviteUsername = el("input", { class: "input", placeholder: "Username", required: "true", "aria-label": "Username" });
  const inviteEmail = el("input", { class: "input", placeholder: "Email", required: "true", "aria-label": "Email" });
  const inviteRole = el("select", { class: "input" },
    el("option", { value: "Admin", text: "Admin" }),
    el("option", { value: "Analyst", text: "Analyst", selected: "true" }),
    el("option", { value: "Viewer", text: "Viewer" }),
  );
  const inviteFirstName = el("input", { class: "input", placeholder: "First name (optional)", "aria-label": "First name" });
  const inviteLastName = el("input", { class: "input", placeholder: "Last name (optional)", "aria-label": "Last name" });
  const inviteSubmit = el("button", { class: "btn primary", type: "submit" }, "Send invite");
  const inviteCancel = el("button", { class: "btn", type: "button" }, "Cancel");

  const inviteForm = el(
    "form",
    { class: "flex-col-8" },
    el("div", {}, el("div", { class: "muted", text: "Username" }), inviteUsername),
    el("div", {}, el("div", { class: "muted", text: "Email" }), inviteEmail),
    el("div", {}, el("div", { class: "muted", text: "Role" }), inviteRole),
    el("div", {}, el("div", { class: "muted", text: "First name" }), inviteFirstName),
    el("div", {}, el("div", { class: "muted", text: "Last name" }), inviteLastName),
    el("div", { class: "row flex-end gap-8" }, inviteCancel, inviteSubmit),
  );

  const inviteCard = el(
    "div",
    { class: "card mt-12", style: "display: none;" },
    el("h3", { style: "margin-top: 0;", text: "Invite user" }),
    el("p", { class: "muted", text: "Create a new user and assign their role." }),
    inviteForm,
  );

  const tableContainer = el("div", { class: "mt-4" });
  const paginationContainer = el("div");

  let currentPage = 1;
  let lastTotal = 0;
  let density = "comfortable";

  const tableColumns = [
    { key: "username", label: "Username" },
    { key: "full_name", label: "Full Name", render: (user) => user.full_name || user.username },
    { key: "email", label: "Email" },
    { key: "role", label: "Role", render: (user) => pill(user.role, "#2563eb") },
    {
      key: "status",
      label: "Status",
      render: (user) => {
        const statusLabel = user.is_active ? "Active" : "Disabled";
        const statusColor = user.is_active ? "#16a34a" : "#dc2626";
        return pill(statusLabel, statusColor, true);
      },
    },
    {
      key: "updated_at",
      label: "Updated",
      render: (user) => (user.updated_at || user.created_at || "").slice(0, 10) || "\u2014",
    },
  ];

  function onImpersonate(user) {
    (async () => {
      try {
        const reason = await promptModal({ title: "Impersonation reason", message: `Why are you impersonating ${user.username}?`, inputLabel: "Reason", required: true });
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
    })();
  }

  function onToggle(user) {
    (async () => {
      try {
        const updated = await toggleUserActive(user.id);
        toast({ title: updated.is_active ? "User enabled" : "User disabled", message: `${user.username} is now ${updated.is_active ? "active" : "disabled"}.` });
        loadUsersList();
      } catch (e) {
        toast({ title: "Action failed", message: e?.message || "Unable to update user" });
      }
    })();
  }

  function applyStats(items, total) {
    const active = items.filter((u) => u.is_active).length;
    const disabled = items.length - active;
    totalEl.textContent = String(total || 0);
    activeEl.textContent = active.toString();
    disabledEl.textContent = disabled.toString();
    pendingEl.textContent = "0";
  }

  function renderTable(items, loading) {
    tableContainer.innerHTML = "";
    tableContainer.appendChild(createDataTable({
      columns: tableColumns,
      rows: items,
      loading,
      density,
      emptyText: "No users found.",
      rowActions: (user) => {
        const impersonateBtn = el("button", { class: "btn" }, "Impersonate");
        impersonateBtn.addEventListener("click", () => onImpersonate(user));

        const toggleBtn = el("button", { class: "btn" }, user.is_active ? "Disable" : "Enable");
        toggleBtn.addEventListener("click", () => onToggle(user));

        return el("div", { class: "row gap-6" }, impersonateBtn, toggleBtn);
      },
    }));
  }

  function renderPagination(page, totalPages, total) {
    paginationContainer.innerHTML = "";
    paginationContainer.appendChild(createTablePagination({
      page,
      totalPages,
      total,
      onPage: (newPage) => {
        currentPage = newPage;
        loadUsersList();
      },
    }));
  }

  async function loadUsersList() {
    renderTable([], true);
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

      applyStats(items, total);
      renderTable(items, false);

      lastTotal = total;
      currentPage = page;
      const totalPages = Math.max(1, Math.ceil(total / effectiveSize));
      renderPagination(page, totalPages, total);
    } catch (e) {
      tableContainer.innerHTML = "";
      toast({ title: "Failed to load users", message: e?.message || "Unable to fetch users" });
      tableContainer.appendChild(el("div", { class: "muted", text: "Unable to load users." }));
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
      toast({ title: "User invited", message: "A password reset link has been sent to their email." });
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

  const densityToggleContainer = el("div");

  function renderDensityToggle() {
    densityToggleContainer.innerHTML = "";
    densityToggleContainer.appendChild(createDensityToggle(density, (newDensity) => {
      density = newDensity;
      renderDensityToggle();
      loadUsersList();
    }));
  }

  renderDensityToggle();

  loadUsersList();

  return el("div", { class: "flex-col-12" },
    el("div", { class: "card" },
      el("h1", { class: "page-title", text: "Admin: Users" }),
      el("p", { class: "muted", text: "Manage account access, MFA posture, and onboarding from a single control plane." }),
    ),
    el("div", { class: "card" },
      el("div", { class: "row gap-8 flex-between" },
        el("div", { class: "row gap-8" },
          el("div", { class: "font-bold", text: "User overview" }),
          pill("Real-time", "#059669", true),
        ),
        densityToggleContainer,
      ),
      statsRow,
      controls,
      inviteCard,
      tableContainer,
      paginationContainer,
    ),
  );
}
