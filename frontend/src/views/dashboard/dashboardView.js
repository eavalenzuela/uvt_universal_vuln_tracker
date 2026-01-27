import { el } from "../../ui/dom/el.js";
import { listActiveUsers } from "../../api/users.js";
import {
  getVulnerability,
  listVulnerabilities,
  listOpenHighCriticalVulnerabilities,
  updateVulnerability,
} from "../../api/vulnerabilities.js";
import { navigate } from "../../router/router.js";
import { canWrite } from "../../state/permissions.js";
import { getState } from "../../state/store.js";

const STORAGE_KEY = "uvt.dashboard.widgets.v1";
const DEFAULT_WIDGETS = [
  {
    id: "risk-overview",
    title: "Risk Overview Summary",
    description: "KPI snapshot with trend insights.",
    settings: { filter: "Open", range: "Last 14 days", grouping: "Severity" },
    groupings: ["Severity", "Status"],
  },
  {
    id: "recent-updates",
    title: "Recently Updated Vulns",
    description: "Latest changes across the program.",
    settings: { filter: "All", range: "Last 7 days", grouping: "Severity" },
    groupings: ["Severity", "Status"],
  },
  {
    id: "sla-due",
    title: "SLA / Due Soon",
    description: "Deadlines based on severity SLA windows.",
    settings: { filter: "Open,In Progress", range: "Last 14 days", grouping: "Severity" },
    groupings: ["Severity", "Status", "Assignee"],
  },
  {
    id: "top-assets",
    title: "Top Affected Assets/Apps",
    description: "Most impacted products and versions.",
    settings: { filter: "All", range: "Last 30 days", grouping: "Product" },
    groupings: ["Product", "Product Version"],
  },
  {
    id: "my-work",
    title: "My Assigned Work",
    description: "Items assigned to you right now.",
    settings: { filter: "Open,In Progress", range: "Last 30 days", grouping: "Status" },
    groupings: ["Status", "Severity"],
  },
];

const STATUS_OPTIONS = ["Open", "In Progress", "Resolved", "Closed"];
const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low", "None"];
const RANGE_OPTIONS = ["Last 7 days", "Last 14 days", "Last 30 days", "Quarter to date", "Month to date"];
const SLA_DAYS = {
  Critical: 7,
  High: 14,
  Medium: 30,
  Low: 60,
  None: 90,
};
const WIDGET_BORDER = "rgba(148, 163, 184, 0.25)";
const WIDGET_BG = "rgba(15, 23, 42, 0.7)";
const WIDGET_SURFACE = "rgba(30, 41, 59, 0.7)";
const WIDGET_SUBTLE = "rgba(148, 163, 184, 0.18)";
const WIDGET_BORDER_HIGHLIGHT = "rgba(106, 169, 255, 0.9)";

function formatAge(value) {
  if (!value) return "-";
  const deltaMs = Date.now() - new Date(value).getTime();
  if (Number.isNaN(deltaMs)) return "-";
  const days = Math.floor(deltaMs / (1000 * 60 * 60 * 24));
  if (days <= 0) return "Today";
  return `${days}d`;
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleDateString();
}

function parseRange(range) {
  const now = new Date();
  if (range === "Month to date") {
    return new Date(now.getFullYear(), now.getMonth(), 1);
  }
  if (range === "Quarter to date") {
    const quarterStartMonth = Math.floor(now.getMonth() / 3) * 3;
    return new Date(now.getFullYear(), quarterStartMonth, 1);
  }
  const match = range?.match(/Last\s+(\d+)\s+days/i);
  if (match) {
    const days = Number(match[1]);
    const start = new Date(now);
    start.setDate(start.getDate() - days);
    return start;
  }
  return null;
}

function parseDueHorizon(range) {
  const now = new Date();
  if (range === "Month to date") {
    return new Date(now.getFullYear(), now.getMonth() + 1, 0);
  }
  if (range === "Quarter to date") {
    const quarterStartMonth = Math.floor(now.getMonth() / 3) * 3;
    return new Date(now.getFullYear(), quarterStartMonth + 3, 0);
  }
  const match = range?.match(/Last\s+(\d+)\s+days/i);
  if (match) {
    const days = Number(match[1]);
    const end = new Date(now);
    end.setDate(end.getDate() + days);
    return end;
  }
  return null;
}

function filterByRange(items, range, field) {
  const start = parseRange(range);
  if (!start) return items;
  return (items || []).filter((item) => {
    const value = item?.[field];
    if (!value) return false;
    const date = new Date(value);
    return !Number.isNaN(date.getTime()) && date >= start;
  });
}

function parseFilterList(filter, options) {
  if (!filter || filter === "All") return [];
  return filter
    .split(/[,/]/)
    .map((entry) => entry.trim())
    .filter((entry) => options.includes(entry));
}

async function listVulnerabilitiesWithFilters({ statusFilters, severityFilters, ...params }) {
  const statusList = statusFilters?.length ? statusFilters : [null];
  const severityList = severityFilters?.length ? severityFilters : [null];
  const requests = [];

  statusList.forEach((status) => {
    severityList.forEach((severity) => {
      requests.push(
        listVulnerabilities({
          ...params,
          status: status || undefined,
          severity: severity || undefined,
        }),
      );
    });
  });

  const results = await Promise.all(requests);
  const items = results.flatMap((result) => result?.items || []);
  const total = results.reduce((sum, result) => sum + (result?.total || 0), 0);
  const sortKey = params.sort || "updated_at";
  const order = (params.order || "desc").toLowerCase();
  items.sort((a, b) => {
    const left = a?.[sortKey] ? new Date(a[sortKey]).getTime() : 0;
    const right = b?.[sortKey] ? new Date(b[sortKey]).getTime() : 0;
    return order === "asc" ? left - right : right - left;
  });
  return {
    items: items.slice(0, params.page_size || 25),
    total,
  };
}

function renderSparkline(values) {
  const width = 140;
  const height = 38;
  if (!values.length) {
    return el("div", { class: "muted", text: "No trend data." });
  }
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const scale = max - min || 1;
  const points = values.map((value, index) => {
    const x = (index / (values.length - 1 || 1)) * (width - 8) + 4;
    const y = height - ((value - min) / scale) * (height - 8) - 4;
    return `${x},${y}`;
  });
  const svg = el("svg", { width, height, viewBox: `0 0 ${width} ${height}`, style: "display:block;" });
  svg.append(
    el("polyline", {
      points: points.join(" "),
      fill: "none",
      stroke: "#2563eb",
      "stroke-width": "2",
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
    }),
  );
  return svg;
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
      style: `background: ${bg[severity] || "#f8fafc"}; color: ${color}; border: 1px solid ${WIDGET_BORDER};`,
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
          "background:#0f172a; color:#e6e8ee; border-radius:12px; width:min(520px, 92vw); padding:20px; display:flex; flex-direction:column; gap:16px; border:1px solid rgba(148, 163, 184, 0.25); box-shadow:0 20px 40px rgba(2,6,23,0.6);",
        role: "dialog",
        "aria-modal": "true",
        "aria-label": `Configure ${widget.title}`,
      },
      el("h2", { text: `Configure ${widget.title}` }),
    );

    const filterInput = el("input", {
      class: "input",
      type: "text",
      value: currentSettings.filter,
      placeholder: "Filter",
    });
    const rangeSelect = el(
      "select",
      { class: "input" },
      RANGE_OPTIONS.map((range) =>
        el("option", { value: range, text: range, selected: range === currentSettings.range }),
      ),
    );
    const groupingSelect = el(
      "select",
      { class: "input" },
      (widget.groupings || []).map((grouping) =>
        el("option", { value: grouping, text: grouping, selected: grouping === currentSettings.grouping }),
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
      el("div", { style: "display:flex; flex-direction:column; gap:6px;" },
        el("label", { text: "Grouping" }),
        groupingSelect,
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
              grouping: groupingSelect.value || currentSettings.grouping,
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
                `display:grid; grid-template-columns: 72px 1.6fr 1.1fr 70px 110px 70px 140px auto; gap:8px; align-items:center; padding:6px 0; border-top:1px solid ${WIDGET_BORDER};`,
            },
            el("div", { style: "font-weight:600; color:#e2e8f0;", text: vulnId }),
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

  function renderRiskOverviewWidget(widgetSettings) {
    const container = el("div", { style: "display:flex; flex-direction:column; gap:10px;" });
    const content = el("div", { class: "muted", text: "Loading risk overview..." });
    container.append(content);

    const load = async () => {
      content.innerHTML = "";
      content.appendChild(el("div", { class: "muted", text: "Loading risk overview..." }));
      try {
        const statusFilters = parseFilterList(widgetSettings.filter, STATUS_OPTIONS);
        const totalResponse = await listVulnerabilitiesWithFilters({
          statusFilters,
          sort: "updated_at",
          order: "desc",
          page_size: 1,
        });
        const [critical, high] = await Promise.all([
          listVulnerabilitiesWithFilters({
            statusFilters,
            severityFilters: ["Critical"],
            sort: "updated_at",
            order: "desc",
            page_size: 1,
          }),
          listVulnerabilitiesWithFilters({
            statusFilters,
            severityFilters: ["High"],
            sort: "updated_at",
            order: "desc",
            page_size: 1,
          }),
        ]);

        const trendResponse = await listVulnerabilitiesWithFilters({
          statusFilters,
          sort: "updated_at",
          order: "desc",
          page_size: 80,
        });
        const filteredTrendItems = filterByRange(trendResponse.items || [], widgetSettings.range, "updated_at");
        const start = parseRange(widgetSettings.range) || new Date(Date.now() - 14 * 24 * 60 * 60 * 1000);
        const end = new Date();
        const days = Math.max(1, Math.ceil((end - start) / (1000 * 60 * 60 * 24)) + 1);
        const counts = Array.from({ length: days }, () => 0);
        filteredTrendItems.forEach((item) => {
          const date = new Date(item.updated_at);
          if (Number.isNaN(date.getTime()) || date < start || date > end) return;
          const index = Math.min(days - 1, Math.floor((date - start) / (1000 * 60 * 60 * 24)));
          counts[index] += 1;
        });

        content.innerHTML = "";
        const kpiRow = el(
          "div",
          { style: "display:grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap:8px;" },
          el("div", { style: `padding:8px; border-radius:8px; background:${WIDGET_SURFACE}; border:1px solid ${WIDGET_BORDER};` },
            el("div", { class: "muted", text: "Total" }),
            el("div", { style: "font-size:20px; font-weight:600;", text: totalResponse.total ?? 0 }),
          ),
          el("div", { style: `padding:8px; border-radius:8px; background:${WIDGET_SURFACE}; border:1px solid ${WIDGET_BORDER};` },
            el("div", { class: "muted", text: "Critical" }),
            el("div", { style: "font-size:20px; font-weight:600; color:#b91c1c;", text: critical.total ?? 0 }),
          ),
          el("div", { style: `padding:8px; border-radius:8px; background:${WIDGET_SURFACE}; border:1px solid ${WIDGET_BORDER};` },
            el("div", { class: "muted", text: "High" }),
            el("div", { style: "font-size:20px; font-weight:600; color:#b45309;", text: high.total ?? 0 }),
          ),
        );

        const trendBlock = el(
          "div",
          { style: `display:flex; align-items:center; gap:12px; padding:8px; border-radius:8px; background:${WIDGET_SURFACE}; border:1px solid ${WIDGET_BORDER};` },
          el("div", { style: "display:flex; flex-direction:column; gap:4px;" },
            el("div", { class: "muted", text: `Updates (${widgetSettings.range})` }),
            el("div", { style: "font-size:16px; font-weight:600;", text: `${filteredTrendItems.length} updates` }),
          ),
          renderSparkline(counts),
        );

        content.append(kpiRow, trendBlock);
      } catch (error) {
        content.innerHTML = "";
        console.warn("Unable to load risk overview.", error);
        content.appendChild(el("div", { class: "muted", text: "Unable to load risk overview." }));
      }
    };

    load();
    return container;
  }

  function renderRecentlyUpdatedWidget(widgetSettings) {
    const container = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });
    const list = el("div", { class: "muted", text: "Loading updates..." });
    container.append(list);

    const load = async () => {
      list.innerHTML = "";
      list.appendChild(el("div", { class: "muted", text: "Loading updates..." }));
      try {
        const statusFilters = parseFilterList(widgetSettings.filter, STATUS_OPTIONS);
        const severityFilters = parseFilterList(widgetSettings.filter, SEVERITY_OPTIONS);
        const data = await listVulnerabilitiesWithFilters({
          statusFilters,
          severityFilters,
          sort: "updated_at",
          order: "desc",
          page_size: 8,
        });
        const filtered = filterByRange(data.items || [], widgetSettings.range, "updated_at");
        list.innerHTML = "";
        if (!filtered.length) {
          list.appendChild(el("div", { class: "muted", text: "No updates in this range." }));
          return;
        }

        filtered.forEach((item) => {
          list.append(
            el(
              "div",
              {
                style:
                  `display:flex; justify-content:space-between; align-items:center; gap:8px; padding:6px 0; border-top:1px solid ${WIDGET_BORDER};`,
              },
              el("div", { style: "display:flex; flex-direction:column; gap:2px;" },
                el("span", { style: "font-weight:600;", text: item.title }),
                el("span", { class: "muted", text: `Updated ${formatAge(item.updated_at)} ago` }),
              ),
              el("div", { style: "display:flex; align-items:center; gap:6px;" },
                severityBadge(item.severity),
                el("button", { class: "btn", text: "Open", onClick: () => navigate(`/vulnerabilities/${item.id}`) }),
              ),
            ),
          );
        });
      } catch (error) {
        list.innerHTML = "";
        console.warn("Unable to load updates.", error);
        list.appendChild(el("div", { class: "muted", text: "Unable to load recent updates." }));
      }
    };

    load();
    return container;
  }

  function renderSlaWidget(widgetSettings) {
    const container = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });
    const list = el("div", { class: "muted", text: "Loading SLA items..." });
    container.append(list);

    const load = async () => {
      list.innerHTML = "";
      list.appendChild(el("div", { class: "muted", text: "Loading SLA items..." }));
      try {
        const statusFilters = parseFilterList(widgetSettings.filter, STATUS_OPTIONS);
        const data = await listVulnerabilitiesWithFilters({
          statusFilters,
          sort: "created_at",
          order: "asc",
          page_size: 80,
        });
        const horizon = parseDueHorizon(widgetSettings.range);
        const now = new Date();
        const dueSoon = (data.items || [])
          .map((item) => {
            const created = new Date(item.created_at);
            if (Number.isNaN(created.getTime())) return null;
            const days = SLA_DAYS[item.severity] ?? 30;
            const dueDate = new Date(created);
            dueDate.setDate(dueDate.getDate() + days);
            return { ...item, dueDate };
          })
          .filter(Boolean)
          .filter((item) => (horizon ? item.dueDate <= horizon : true))
          .sort((a, b) => a.dueDate - b.dueDate)
          .slice(0, 8);

        list.innerHTML = "";
        if (!dueSoon.length) {
          list.appendChild(el("div", { class: "muted", text: "No upcoming SLA deadlines." }));
          return;
        }

        dueSoon.forEach((item) => {
          const remainingDays = Math.ceil((item.dueDate - now) / (1000 * 60 * 60 * 24));
          const statusLabel = remainingDays < 0 ? `Overdue by ${Math.abs(remainingDays)}d` : `${remainingDays}d left`;
          list.append(
            el(
              "div",
              {
                style:
                  `display:grid; grid-template-columns: 1.6fr 0.8fr 0.8fr auto; gap:8px; align-items:center; padding:6px 0; border-top:1px solid ${WIDGET_BORDER};`,
              },
              el("div", { style: "display:flex; flex-direction:column; gap:2px;" },
                el("span", { style: "font-weight:600;", text: item.title }),
                el("span", { class: "muted", text: `Due ${formatDate(item.dueDate)}` }),
              ),
              severityBadge(item.severity),
              el("div", { class: "muted", text: statusLabel }),
              el("button", { class: "btn", text: "Open", onClick: () => navigate(`/vulnerabilities/${item.id}`) }),
            ),
          );
        });
      } catch (error) {
        list.innerHTML = "";
        console.warn("Unable to load SLA widget.", error);
        list.appendChild(el("div", { class: "muted", text: "Unable to load SLA items." }));
      }
    };

    load();
    return container;
  }

  function renderTopAssetsWidget(widgetSettings) {
    const container = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });
    const list = el("div", { class: "muted", text: "Loading affected assets..." });
    container.append(list);

    const load = async () => {
      list.innerHTML = "";
      list.appendChild(el("div", { class: "muted", text: "Loading affected assets..." }));
      try {
        const statusFilters = parseFilterList(widgetSettings.filter, STATUS_OPTIONS);
        const severityFilters = parseFilterList(widgetSettings.filter, SEVERITY_OPTIONS);
        const data = await listVulnerabilitiesWithFilters({
          statusFilters,
          severityFilters,
          sort: "updated_at",
          order: "desc",
          page_size: 30,
        });
        const scoped = filterByRange(data.items || [], widgetSettings.range, "updated_at");
        const details = await Promise.all(
          scoped.map(async (item) => {
            try {
              const detail = await getVulnerability(item.id);
              return { ...item, detail };
            } catch (error) {
              console.warn("Unable to load vulnerability detail.", error);
              return { ...item, detail: null };
            }
          }),
        );

        const grouping = widgetSettings.grouping || "Product";
        const counts = new Map();
        details.forEach((item) => {
          const versions = item.detail?.affected_versions || [];
          versions.forEach((version) => {
            const label =
              grouping === "Product Version"
                ? `${version.product_name || "Unknown"} ${version.version || ""}`.trim()
                : version.product_name || "Unknown";
            if (!label) return;
            counts.set(label, (counts.get(label) || 0) + 1);
          });
        });

        const sorted = [...counts.entries()]
          .map(([label, count]) => ({ label, count }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 6);

        list.innerHTML = "";
        if (!sorted.length) {
          list.appendChild(el("div", { class: "muted", text: "No affected assets in this range." }));
          return;
        }

        const max = Math.max(...sorted.map((entry) => entry.count), 1);
        sorted.forEach((entry) => {
          list.append(
            el(
              "div",
              { style: `display:flex; flex-direction:column; gap:4px; padding:6px 0; border-top:1px solid ${WIDGET_BORDER};` },
              el("div", { style: "display:flex; justify-content:space-between; align-items:center; gap:8px;" },
                el("span", { style: "font-weight:600;", text: entry.label }),
                el("span", { class: "muted", text: `${entry.count} vulns` }),
              ),
              el("div", { style: `height:6px; border-radius:999px; background:${WIDGET_SUBTLE}; overflow:hidden;` },
                el("div", {
                  style: `height:100%; width:${(entry.count / max) * 100}%; background:#2563eb;`,
                }),
              ),
            ),
          );
        });
      } catch (error) {
        list.innerHTML = "";
        console.warn("Unable to load top affected assets.", error);
        list.appendChild(el("div", { class: "muted", text: "Unable to load top affected assets." }));
      }
    };

    load();
    return container;
  }

  function renderMyWorkWidget(widgetSettings) {
    const container = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });
    const list = el("div", { class: "muted", text: "Loading assigned work..." });
    container.append(list);

    const load = async () => {
      list.innerHTML = "";
      list.appendChild(el("div", { class: "muted", text: "Loading assigned work..." }));
      try {
        if (!user?.id) {
          list.innerHTML = "";
          list.appendChild(el("div", { class: "muted", text: "Sign in to view assigned work." }));
          return;
        }
        const statusFilters = parseFilterList(widgetSettings.filter, STATUS_OPTIONS);
        const data = await listVulnerabilitiesWithFilters({
          statusFilters,
          assigned_to: user?.id,
          sort: "updated_at",
          order: "desc",
          page_size: 12,
        });
        const filtered = filterByRange(data.items || [], widgetSettings.range, "updated_at");
        list.innerHTML = "";
        if (!filtered.length) {
          list.appendChild(el("div", { class: "muted", text: "No assigned work in this range." }));
          return;
        }

        filtered.slice(0, 8).forEach((item) => {
          list.append(
            el(
              "div",
              {
                style:
                  `display:grid; grid-template-columns: 1.6fr 0.8fr 0.8fr auto; gap:8px; align-items:center; padding:6px 0; border-top:1px solid ${WIDGET_BORDER};`,
              },
              el("div", { style: "display:flex; flex-direction:column; gap:2px;" },
                el("span", { style: "font-weight:600;", text: item.title }),
                el("span", { class: "muted", text: `Updated ${formatAge(item.updated_at)} ago` }),
              ),
              severityBadge(item.severity),
              el("div", { class: "muted", text: item.status || "-" }),
              el("button", { class: "btn", text: "Open", onClick: () => navigate(`/vulnerabilities/${item.id}`) }),
            ),
          );
        });
      } catch (error) {
        list.innerHTML = "";
        console.warn("Unable to load assigned work.", error);
        list.appendChild(el("div", { class: "muted", text: "Unable to load assigned work." }));
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
          `border:1px solid ${WIDGET_BORDER}; border-radius:12px; padding:12px; background:${WIDGET_BG}; display:flex; flex-direction:column; gap:10px;`,
        onDragOver: (event) => {
          event.preventDefault();
          card.style.borderColor = WIDGET_BORDER_HIGHLIGHT;
        },
        onDragLeave: () => {
          card.style.borderColor = WIDGET_BORDER;
        },
        onDrop: (event) => {
          event.preventDefault();
          card.style.borderColor = WIDGET_BORDER;
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

      let details = null;
      if (widgetId === "high-risk-open") {
        details = renderHighRiskWidget();
      } else if (widgetId === "risk-overview") {
        details = renderRiskOverviewWidget(widgetSettings);
      } else if (widgetId === "recent-updates") {
        details = renderRecentlyUpdatedWidget(widgetSettings);
      } else if (widgetId === "sla-due") {
        details = renderSlaWidget(widgetSettings);
      } else if (widgetId === "top-assets") {
        details = renderTopAssetsWidget(widgetSettings);
      } else if (widgetId === "my-work") {
        details = renderMyWorkWidget(widgetSettings);
      } else {
        details = el(
          "div",
          { style: "display:flex; flex-direction:column; gap:4px;" },
          el("div", { class: "muted", text: `Filter: ${widgetSettings.filter}` }),
          el("div", { class: "muted", text: `Date range: ${widgetSettings.range}` }),
          el("div", { class: "muted", text: `Grouping: ${widgetSettings.grouping || "None"}` }),
        );
      }

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
