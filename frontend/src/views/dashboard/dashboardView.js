import { el } from "../../ui/dom/el.js";
import { listActiveUsers } from "../../api/users.js";
import {
  getVulnerability,
  listOpenHighCriticalVulnerabilities,
  updateVulnerability,
} from "../../api/vulnerabilities.js";
import { navigate } from "../../router/router.js";
import { canWrite } from "../../state/permissions.js";
import { getState } from "../../state/store.js";

const STORAGE_KEY = "uvt.dashboard.widgets.v1";
const DEFAULT_WIDGETS = [
  {
    id: "triage",
    title: "Triage Queue",
    description: "Incoming vulnerabilities awaiting assignment.",
    settings: { filter: "Unassigned", range: "Last 7 days" },
  },
  {
    id: "high-risk-open",
    title: "High risk open vulnerabilities",
    description: "Open High/Critical findings needing attention.",
    settings: { filter: "High/Critical", range: "Last 30 days" },
  },
  {
    id: "sla",
    title: "SLA Risk",
    description: "Items nearing SLA breach.",
    settings: { filter: "Critical", range: "Last 30 days" },
  },
  {
    id: "coverage",
    title: "Coverage",
    description: "Monitored assets by coverage tier.",
    settings: { filter: "Tier 1-3", range: "Quarter to date" },
  },
  {
    id: "remediation",
    title: "Remediation Progress",
    description: "Fix progress by team and severity.",
    settings: { filter: "All teams", range: "Month to date" },
  },
  {
    id: "intel",
    title: "Threat Intel",
    description: "Active campaigns mapped to CVEs.",
    settings: { filter: "External", range: "Last 14 days" },
  },
  {
    id: "exceptions",
    title: "Exception Requests",
    description: "Pending exception workflow status.",
    settings: { filter: "Pending review", range: "Last 60 days" },
  },
];

const STATUS_OPTIONS = ["Open", "In Progress", "Resolved", "Closed"];

function formatAge(value) {
  if (!value) return "-";
  const deltaMs = Date.now() - new Date(value).getTime();
  if (Number.isNaN(deltaMs)) return "-";
  const days = Math.floor(deltaMs / (1000 * 60 * 60 * 24));
  if (days <= 0) return "Today";
  return `${days}d`;
}

function severityBadge(severity) {
  const colors = {
    Critical: "#7f1d1d",
    High: "#b45309",
    Medium: "#92400e",
    Low: "#365314",
    None: "#334155",
  };
  const bg = {
    Critical: "#fef2f2",
    High: "#fffbeb",
    Medium: "#fffbeb",
    Low: "#f0fdf4",
    None: "#f8fafc",
  };
  const color = colors[severity] || "#0f172a";
  return el(
    "span",
    {
      class: "badge",
      style: `background: ${bg[severity] || "#f8fafc"}; color: ${color}; border: 1px solid #e2e8f0;`,
    },
    severity || "Unknown",
  );
}

let cachedUsers = null;
async function ensureActiveUsers() {
  if (cachedUsers) return cachedUsers;
  try {
    cachedUsers = await listActiveUsers();
    return cachedUsers;
  } catch (error) {
    console.warn("Unable to load active users.", error);
    cachedUsers = [];
    return cachedUsers;
  }
}

function loadDashboardState() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return null;
    return JSON.parse(stored);
  } catch (error) {
    console.warn("Unable to load dashboard layout.", error);
    return null;
  }
}

function saveDashboardState(state) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch (error) {
    console.warn("Unable to save dashboard layout.", error);
  }
}

export async function DashboardView() {
  const user = getState()?.session?.user;
  const writable = canWrite(getState());
  const savedState = loadDashboardState();
  const widgetById = new Map(DEFAULT_WIDGETS.map((widget) => [widget.id, widget]));
  const order = savedState?.order?.length ? savedState.order : DEFAULT_WIDGETS.map((widget) => widget.id);
  const visibility = savedState?.visibility || {};
  const settings = savedState?.settings || {};
  let activeModal = null;
  let draggingId = null;

  const layoutState = {
    order: order.filter((id) => widgetById.has(id)),
    visibility: { ...visibility },
    settings: { ...settings },
  };

  const container = el("div", { class: "card", style: "display:flex; flex-direction:column; gap:16px;" });

  const header = el(
    "div",
    { style: "display:flex; flex-direction:column; gap:6px;" },
    el("h1", { class: "page-title", text: "Dashboard" }),
    el("p", { class: "muted", text: `Signed in as ${user?.username || "?"} (${user?.role || "?"}).` }),
    el("p", { class: "muted", text: "Drag widgets to reorder or use the move controls for keyboard access." }),
  );

  const gridWrapper = el("div", { style: "display:flex; flex-direction:column; gap:12px;" });
  const grid = el("div", {
    style:
      "display:grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap:12px; align-items:stretch;",
  });
  const hiddenList = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });

  function persistState() {
    saveDashboardState(layoutState);
  }

  function moveWidget(id, direction) {
    const index = layoutState.order.indexOf(id);
    if (index < 0) return;
    const nextIndex = Math.max(0, Math.min(layoutState.order.length - 1, index + direction));
    if (nextIndex === index) return;
    const nextOrder = [...layoutState.order];
    nextOrder.splice(index, 1);
    nextOrder.splice(nextIndex, 0, id);
    layoutState.order = nextOrder;
    persistState();
    renderGrid();
  }

  function openModal(widgetId) {
    const widget = widgetById.get(widgetId);
    if (!widget) return;
    const currentSettings = { ...widget.settings, ...layoutState.settings[widgetId] };
    const currentVisibility = layoutState.visibility[widgetId] ?? true;

    const overlay = el("div", {
      style:
        "position:fixed; inset:0; background:rgba(15, 23, 42, 0.55); display:flex; align-items:center; justify-content:center; z-index:40;",
      onClick: (event) => {
        if (event.target === overlay) closeModal();
      },
    });

    const modal = el(
      "div",
      {
        style:
          "background:#fff; color:#0f172a; border-radius:12px; width:min(520px, 92vw); padding:20px; display:flex; flex-direction:column; gap:16px;",
        role: "dialog",
        "aria-modal": "true",
        "aria-label": `Configure ${widget.title}`,
      },
      el("h2", { text: `Configure ${widget.title}` }),
    );

    const filterInput = el("input", {
      type: "text",
      value: currentSettings.filter,
      placeholder: "Filter",
      style: "width:100%; padding:8px; border-radius:6px; border:1px solid #cbd5f5;",
    });
    const rangeSelect = el(
      "select",
      { style: "width:100%; padding:8px; border-radius:6px; border:1px solid #cbd5f5;" },
      ["Last 7 days", "Last 14 days", "Last 30 days", "Quarter to date", "Month to date"].map((range) =>
        el("option", { value: range, text: range, selected: range === currentSettings.range }),
      ),
    );
    const visibleToggle = el("input", {
      type: "checkbox",
      checked: currentVisibility,
    });

    modal.append(
      el("div", { style: "display:flex; flex-direction:column; gap:6px;" },
        el("label", { text: "Filter" }),
        filterInput,
      ),
      el("div", { style: "display:flex; flex-direction:column; gap:6px;" },
        el("label", { text: "Date range" }),
        rangeSelect,
      ),
      el("label", { style: "display:flex; align-items:center; gap:8px;" },
        visibleToggle,
        el("span", { text: "Widget visible" }),
      ),
      el("div", { style: "display:flex; justify-content:flex-end; gap:8px;" },
        el("button", { class: "btn", text: "Cancel", onClick: closeModal }),
        el("button", {
          class: "btn primary",
          text: "Save",
          onClick: () => {
            layoutState.settings[widgetId] = {
              filter: filterInput.value || "All",
              range: rangeSelect.value,
            };
            layoutState.visibility[widgetId] = visibleToggle.checked;
            persistState();
            closeModal();
            renderGrid();
          },
        }),
      ),
    );

    function closeModal() {
      overlay.remove();
      activeModal = null;
    }

    overlay.append(modal);
    activeModal = overlay;
    document.body.append(overlay);
  }

  function renderHighRiskWidget() {
    const container = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });
    const list = el("div", { class: "muted", text: "Loading high-risk vulnerabilities..." });
    container.append(list);

    const load = async () => {
      list.innerHTML = "";
      list.appendChild(el("div", { class: "muted", text: "Loading high-risk vulnerabilities..." }));
      try {
        const data = await listOpenHighCriticalVulnerabilities({ page_size: 6, sort: "updated_at", order: "desc" });
        const users = await ensureActiveUsers();
        const userMap = new Map((users || []).map((u) => [u.id, u]));
        const details = await Promise.all(
          (data.items || []).map(async (item) => {
            try {
              const detail = await getVulnerability(item.id);
              return { ...item, detail };
            } catch (error) {
              console.warn("Unable to load vulnerability detail.", error);
              return { ...item, detail: null };
            }
          }),
        );

        list.innerHTML = "";
        if (!details.length) {
          list.appendChild(el("div", { class: "muted", text: "No open High/Critical vulnerabilities." }));
          return;
        }

        const headerRow = el(
          "div",
          {
            style:
              "display:grid; grid-template-columns: 72px 1.6fr 1.1fr 70px 110px 70px 140px auto; gap:8px; font-size:12px; text-transform:uppercase; letter-spacing:0.04em; color:#64748b;",
          },
          el("div", { text: "ID" }),
          el("div", { text: "Title" }),
          el("div", { text: "Asset/App" }),
          el("div", { text: "CVSS" }),
          el("div", { text: "Severity" }),
          el("div", { text: "Age" }),
          el("div", { text: "Owner" }),
          el("div", { text: "Actions" }),
        );

        const rows = details.map((item) => {
          const detail = item.detail;
          const vulnId = item.cve_id || `VULN-${item.id}`;
          const productNames = Array.from(
            new Set((detail?.affected_versions || []).map((version) => version.product_name).filter(Boolean)),
          );
          const assetLabel = productNames.length
            ? productNames.length > 1
              ? `${productNames[0]} +${productNames.length - 1}`
              : productNames[0]
            : "-";
          const owner = detail?.assigned_to ? userMap.get(detail.assigned_to) : null;
          const ownerLabel = owner ? (owner.full_name || owner.username || owner.email || `User ${owner.id}`) : "Unassigned";

          const actionRow = el(
            "div",
            { style: "display:flex; gap:6px; flex-wrap:wrap; align-items:center;" },
            el("button", {
              class: "btn",
              text: "Open",
              onClick: () => navigate(`/vulnerabilities/${item.id}`),
            }),
          );

          if (writable) {
            const statusSelect = el(
              "select",
              { class: "input", style: "padding:4px 6px; font-size:12px;" },
              ...STATUS_OPTIONS.map((status) =>
                el("option", { value: status, text: status, selected: status === item.status }),
              ),
            );
            const assigneeSelect = el("select", { class: "input", style: "padding:4px 6px; font-size:12px; min-width:120px;" },
              el("option", { value: "", text: "Unassigned" }),
              ...(users || []).map((u) => {
                const label = u.full_name || u.username || u.email || `User ${u.id}`;
                return el("option", { value: u.id, text: label, selected: u.id === detail?.assigned_to });
              }),
            );
            const saveBtn = el("button", { class: "btn", text: "Update" });
            saveBtn.addEventListener("click", async () => {
              saveBtn.disabled = true;
              statusSelect.disabled = true;
              assigneeSelect.disabled = true;
              saveBtn.textContent = "Saving...";
              try {
                await updateVulnerability(item.id, {
                  status: statusSelect.value,
                  assigned_to: assigneeSelect.value ? Number(assigneeSelect.value) : null,
                });
                await load();
              } catch (error) {
                console.warn("Unable to update vulnerability.", error);
              } finally {
                saveBtn.disabled = false;
                statusSelect.disabled = false;
                assigneeSelect.disabled = false;
                saveBtn.textContent = "Update";
              }
            });
            actionRow.append(statusSelect, assigneeSelect, saveBtn);
          }

          return el(
            "div",
            {
              style:
                "display:grid; grid-template-columns: 72px 1.6fr 1.1fr 70px 110px 70px 140px auto; gap:8px; align-items:center; padding:6px 0; border-top:1px solid #e2e8f0;",
            },
            el("div", { style: "font-weight:600; color:#0f172a;", text: vulnId }),
            el("div", { style: "font-weight:600;", text: item.title }),
            el("div", { class: "muted", text: assetLabel }),
            el("div", { text: item.cvss_score ?? "-" }),
            severityBadge(item.severity || "Unknown"),
            el("div", { text: formatAge(item.created_at) }),
            el("div", { class: "muted", text: ownerLabel }),
            actionRow,
          );
        });

        list.append(headerRow, ...rows);
      } catch (error) {
        list.innerHTML = "";
        console.warn("Unable to load high risk vulnerabilities.", error);
        list.appendChild(el("div", { class: "muted", text: "Unable to load high risk vulnerabilities." }));
      }
    };

    load();

    return container;
  }

  function renderGrid() {
    grid.innerHTML = "";
    hiddenList.innerHTML = "";

    layoutState.order.forEach((widgetId) => {
      const widget = widgetById.get(widgetId);
      if (!widget) return;
      const isVisible = layoutState.visibility[widgetId] ?? true;
      if (!isVisible) return;

      const widgetSettings = { ...widget.settings, ...layoutState.settings[widgetId] };

      const card = el("div", {
        style:
          "border:1px solid #e2e8f0; border-radius:12px; padding:12px; background:#f8fafc; display:flex; flex-direction:column; gap:10px;",
        onDragOver: (event) => {
          event.preventDefault();
          card.style.borderColor = "#3b82f6";
        },
        onDragLeave: () => {
          card.style.borderColor = "#e2e8f0";
        },
        onDrop: (event) => {
          event.preventDefault();
          card.style.borderColor = "#e2e8f0";
          const draggedId = draggingId || event.dataTransfer?.getData("text/plain");
          if (!draggedId || draggedId === widgetId) return;
          const fromIndex = layoutState.order.indexOf(draggedId);
          const toIndex = layoutState.order.indexOf(widgetId);
          if (fromIndex < 0 || toIndex < 0) return;
          const nextOrder = [...layoutState.order];
          nextOrder.splice(fromIndex, 1);
          nextOrder.splice(toIndex, 0, draggedId);
          layoutState.order = nextOrder;
          persistState();
          renderGrid();
        },
      });

      const dragHandle = el("button", {
        class: "btn",
        text: "⠿",
        title: "Drag to reorder",
        "aria-label": `Drag ${widget.title} to reorder`,
        draggable: "true",
        onDragStart: (event) => {
          draggingId = widgetId;
          event.dataTransfer?.setData("text/plain", widgetId);
          event.dataTransfer?.setDragImage(card, 20, 20);
          event.dataTransfer.effectAllowed = "move";
        },
        onDragEnd: () => {
          draggingId = null;
        },
      });

      const actions = el(
        "div",
        { style: "display:flex; gap:6px; align-items:center;" },
        el("button", {
          class: "btn",
          text: "⚙️",
          title: "Configure widget",
          "aria-label": `Configure ${widget.title}`,
          onClick: () => openModal(widgetId),
        }),
        el("button", {
          class: "btn",
          text: "Hide",
          title: "Hide widget",
          onClick: () => {
            layoutState.visibility[widgetId] = false;
            persistState();
            renderGrid();
          },
        }),
        el("button", {
          class: "btn",
          text: "↑",
          title: "Move up",
          "aria-label": `Move ${widget.title} up`,
          onClick: () => moveWidget(widgetId, -1),
        }),
        el("button", {
          class: "btn",
          text: "↓",
          title: "Move down",
          "aria-label": `Move ${widget.title} down`,
          onClick: () => moveWidget(widgetId, 1),
        }),
      );

      const headerRow = el(
        "div",
        { style: "display:flex; justify-content:space-between; align-items:center; gap:8px;" },
        el("div", { style: "display:flex; align-items:center; gap:8px;" },
          dragHandle,
          el("div", { style: "display:flex; flex-direction:column;" },
            el("strong", { text: widget.title }),
            el("span", { class: "muted", text: widget.description }),
          ),
        ),
        actions,
      );

      const details = widgetId === "high-risk-open"
        ? renderHighRiskWidget()
        : el(
          "div",
          { style: "display:flex; flex-direction:column; gap:4px;" },
          el("div", { class: "muted", text: `Filter: ${widgetSettings.filter}` }),
          el("div", { class: "muted", text: `Date range: ${widgetSettings.range}` }),
        );

      card.append(headerRow, details);
      grid.append(card);
    });

    const hiddenWidgets = layoutState.order.filter((id) => !(layoutState.visibility[id] ?? true));
    if (hiddenWidgets.length) {
      hiddenList.append(
        el("div", { class: "muted", text: "Hidden widgets" }),
        el("div", { style: "display:flex; flex-wrap:wrap; gap:8px;" },
          hiddenWidgets.map((id) => {
            const widget = widgetById.get(id);
            if (!widget) return null;
            return el("button", {
              class: "btn",
              text: `Show ${widget.title}`,
              onClick: () => {
                layoutState.visibility[id] = true;
                persistState();
                renderGrid();
              },
            });
          }),
        ),
      );
    }
  }

  renderGrid();

  gridWrapper.append(
    el("div", { style: "display:flex; justify-content:space-between; align-items:center;" },
      el("h2", { text: "Widget layout" }),
      el("button", {
        class: "btn",
        text: "Reset layout",
        onClick: () => {
          layoutState.order = DEFAULT_WIDGETS.map((widget) => widget.id);
          layoutState.visibility = {};
          layoutState.settings = {};
          persistState();
          renderGrid();
        },
      }),
    ),
    grid,
    hiddenList,
  );

  container.append(header, gridWrapper);

  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && activeModal) {
      activeModal.remove();
      activeModal = null;
    }
  });

  return container;
}
