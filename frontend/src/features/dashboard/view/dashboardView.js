import { el } from "../../../ui/dom/el.js";
import { listActiveUsers } from "../../../api/users.js";
import {
  updateVulnerability,
} from "../../../api/vulnerabilities.js";
import { navigate } from "../../../router/router.js";
import { canWrite } from "../../../state/permissions.js";
import { getState, subscribe } from "../../../state/store.js";
import { downloadReportArtifact, exportDashboardSummary, getDashboardSummary } from "../../../api/reports.js";
import {
  createDashboardLayoutPreset,
  getDefaultDashboardLayoutPreset,
  listDashboardLayoutPresets,
  updateDashboardLayoutPreset,
} from "../../../api/dashboardLayoutPresets.js";
import { toast } from "../../../ui/components/toast.js";
import { applyDashboardMetricDelta, filterByRange, formatAge, formatDate, parseDueHorizon, parseFilterList } from "../selectors/dashboardLogic.js";
import { getDefaultLayoutState, loadDashboardState, loadLocalPresets, normalizeLayoutState, saveDashboardState, saveLocalPresets } from "../state/layoutState.js";
import { createWidgetRegistry } from "../widgets/widgetRegistry.js";
import { listVulnerabilitiesWithFilters, loadHighRiskVulnerabilityDetails, loadRiskTrendData } from "../effects/dashboardEffects.js";

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
    id: "risk-trends",
    title: "Risk Trends by Product",
    description: "Trend chart by product and version risk metrics.",
    settings: { filter: "All", range: "Last 30 days", grouping: "week", productFilter: "" },
    groupings: ["day", "week", "month"],
  },
  {
    id: "top-risk-products",
    title: "Top Risk Products",
    description: "Product versions with highest weighted risk posture.",
    settings: { filter: "All", range: "Last 30 days", grouping: "week", productFilter: "" },
    groupings: ["day", "week", "month"],
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
const WIDGET_BORDER = "rgba(148, 163, 184, 0.25)";
const WIDGET_BG = "rgba(15, 23, 42, 0.7)";
const WIDGET_SURFACE = "rgba(30, 41, 59, 0.7)";
const WIDGET_SUBTLE = "rgba(148, 163, 184, 0.18)";
const WIDGET_BORDER_HIGHLIGHT = "rgba(106, 169, 255, 0.9)";
const DASHBOARD_SUMMARY_POLL_MS = 30000;

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

function serializePresetLayout(layoutState) {
  return normalizeLayoutState(layoutState, DEFAULT_WIDGETS);
}

export async function DashboardView() {
  const user = getState()?.session?.user;
  const writable = canWrite(getState());
  const savedState = loadDashboardState(DEFAULT_WIDGETS) || getDefaultLayoutState(DEFAULT_WIDGETS);
  const widgetById = new Map(DEFAULT_WIDGETS.map((widget) => [widget.id, widget]));
  let activeModal = null;
  let draggingId = null;
  let presetsOnline = true;
  let presets = [];
  let selectedPresetId = "local-current";

  const layoutState = {
    order: savedState.order.filter((id) => widgetById.has(id)),
    visibility: { ...savedState.visibility },
    settings: { ...savedState.settings },
  };

  const container = el("div", { class: "card", style: "display:flex; flex-direction:column; gap:16px;" });

  const exportStatusSelect = el("select", { class: "input", style: "max-width: 180px;" },
    el("option", { value: "", text: "All statuses" }),
    ...STATUS_OPTIONS.map((status) => el("option", { value: status, text: status })),
  );
  const exportSeveritySelect = el("select", { class: "input", style: "max-width: 180px;" },
    el("option", { value: "", text: "All severities" }),
    ...SEVERITY_OPTIONS.map((severity) => el("option", { value: severity, text: severity })),
  );
  const exportFormatSelect = el("select", { class: "input", style: "max-width: 140px;" },
    el("option", { value: "csv", text: "CSV" }),
    el("option", { value: "json", text: "JSON" }),
    el("option", { value: "pdf", text: "PDF" }),
  );
  const exportBtn = el("button", { class: "btn", type: "button" }, "Export current view");
  exportBtn.addEventListener("click", async () => {
    exportBtn.disabled = true;
    try {
      const response = await exportDashboardSummary({
        status: exportStatusSelect.value || undefined,
        severity: exportSeveritySelect.value || undefined,
      }, exportFormatSelect.value);
      const artifact = response?.artifact;
      if (!artifact?.download_url) throw new Error("Export artifact missing download URL");
      const blob = await downloadReportArtifact(artifact.download_url);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `dashboard_summary.${artifact.format || exportFormatSelect.value}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast({ title: "Export ready", message: `Downloaded dashboard summary ${String((artifact.format || exportFormatSelect.value)).toUpperCase()}.` });
    } catch (error) {
      toast({ title: "Export failed", message: error?.message || "Unable to export dashboard summary" });
    } finally {
      exportBtn.disabled = false;
    }
  });

  const header = el(
    "div",
    { style: "display:flex; flex-direction:column; gap:6px;" },
    el("h1", { class: "page-title", text: "Dashboard" }),
    el("p", { class: "muted", text: `Signed in as ${user?.username || "?"} (${user?.role || "?"}).` }),
    el("p", { class: "muted", text: "Drag widgets to reorder or use the move controls for keyboard access." }),
    el("div", { class: "row", style: "gap: 8px; flex-wrap: wrap; align-items: center;" }, exportStatusSelect, exportSeveritySelect, exportFormatSelect, exportBtn),
  );

  const gridWrapper = el("div", { style: "display:flex; flex-direction:column; gap:12px;" });
  const grid = el("div", {
    style:
      "display:grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap:12px; align-items:stretch;",
  });
  const hiddenList = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });

  const presetSelect = el("select", { class: "input", style: "max-width: 260px;" });
  const presetNameInput = el("input", { class: "input", type: "text", placeholder: "Preset name", style: "max-width: 220px;" });
  const presetVisibilitySelect = el(
    "select",
    { class: "input", style: "max-width: 140px;" },
    el("option", { value: "private", text: "Private" }),
    el("option", { value: "team", text: "Team" }),
  );

  async function loadPresetsFromApi() {
    const [items, defaultResponse] = await Promise.all([
      listDashboardLayoutPresets(),
      getDefaultDashboardLayoutPreset(),
    ]);
    presets = Array.isArray(items) ? items : [];
    const defaultPreset = defaultResponse?.default;
    if (defaultPreset?.id) {
      selectedPresetId = String(defaultPreset.id);
      const config = normalizeLayoutState(defaultPreset.widget_config_json, DEFAULT_WIDGETS);
      layoutState.order = config.order;
      layoutState.visibility = config.visibility;
      layoutState.settings = config.settings;
      saveDashboardState(layoutState, DEFAULT_WIDGETS);
    }
  }

  function persistState() {
    saveDashboardState(layoutState, DEFAULT_WIDGETS);
    const localPresets = loadLocalPresets();
    const current = {
      id: "local-current",
      name: "Current (local)",
      visibility: "private",
      is_default: false,
      owner: { id: user?.id, username: user?.username },
      widget_config_json: serializePresetLayout(layoutState),
    };
    const remaining = localPresets.filter((item) => item?.id !== "local-current");
    saveLocalPresets([current, ...remaining]);
  }

  function renderPresetOptions() {
    presetSelect.innerHTML = "";
    const localItems = loadLocalPresets();
    const all = presetsOnline ? presets : localItems;
    presetSelect.append(
      el("option", { value: "local-current", text: presetsOnline ? "Current (local)" : "Current (offline local)" }),
      ...all.map((preset) =>
        el("option", {
          value: String(preset.id),
          text: `${preset.name}${preset.is_default ? " • default" : ""}${preset.visibility === "team" ? " • team" : ""}`,
          selected: String(preset.id) === String(selectedPresetId),
        }),
      ),
    );
  }

  async function savePreset({ markDefault = false } = {}) {
    const name = (presetNameInput.value || "").trim();
    if (!name) {
      toast({ title: "Preset name required", message: "Enter a name before saving your dashboard layout." });
      return;
    }

    const payload = {
      name,
      visibility: presetVisibilitySelect.value,
      is_default: markDefault,
      widget_config_json: serializePresetLayout(layoutState),
    };

    try {
      if (presetsOnline) {
        const created = await createDashboardLayoutPreset(payload);
        presets.push(created);
        if (markDefault) {
          selectedPresetId = String(created.id);
        }
      } else {
        const local = loadLocalPresets();
        const created = {
          ...payload,
          id: `local-${Date.now()}`,
          owner: { id: user?.id, username: user?.username },
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        };
        if (markDefault) {
          local.forEach((item) => {
            item.is_default = false;
          });
        }
        saveLocalPresets([...local.filter((item) => item.id !== created.id), created]);
        selectedPresetId = String(created.id);
      }
      renderPresetOptions();
      toast({ title: "Layout saved", message: "Dashboard layout preset saved." });
    } catch (error) {
      presetsOnline = false;
      const local = loadLocalPresets();
      const created = {
        ...payload,
        id: `local-${Date.now()}`,
        owner: { id: user?.id, username: user?.username },
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      if (markDefault) {
        local.forEach((item) => {
          item.is_default = false;
        });
      }
      saveLocalPresets([...local.filter((item) => item.id !== created.id), created]);
      selectedPresetId = String(created.id);
      renderPresetOptions();
      toast({ title: "Saved locally", message: "API unavailable; saved preset in local fallback storage." });
      console.warn("Unable to save preset via API.", error);
    }
  }

  async function applySelectedPreset() {
    const value = presetSelect.value;
    selectedPresetId = value;
    if (value === "local-current") {
      const current = loadDashboardState(DEFAULT_WIDGETS) || getDefaultLayoutState(DEFAULT_WIDGETS);
      layoutState.order = current.order;
      layoutState.visibility = current.visibility;
      layoutState.settings = current.settings;
      renderGrid();
      return;
    }

    const source = presetsOnline ? presets : loadLocalPresets();
    const preset = source.find((item) => String(item.id) === String(value));
    if (!preset) return;
    const config = normalizeLayoutState(preset.widget_config_json, DEFAULT_WIDGETS);
    layoutState.order = config.order;
    layoutState.visibility = config.visibility;
    layoutState.settings = config.settings;
    persistState();
    renderGrid();
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
    const productFilterInput = el("input", {
      class: "input",
      type: "text",
      value: currentSettings.productFilter || "",
      placeholder: "Product IDs (comma-separated)",
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
        el("label", { text: "Product filter" }),
        productFilterInput,
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
              productFilter: productFilterInput.value || "",
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
        const details = await loadHighRiskVulnerabilityDetails({ page_size: 6, sort: "updated_at", order: "desc" });
        const users = await ensureActiveUsers();
        const userMap = new Map((users || []).map((u) => [u.id, u]));

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

    let summaryState = null;
    let syncing = false;
    let seenEvents = new Set();

    const renderSummary = () => {
      if (!summaryState) return;
      const counts = (summaryState?.trend?.buckets || []).map((bucket) => bucket.count || 0);
      const totalUpdates = counts.reduce((sum, value) => sum + value, 0);

      content.innerHTML = "";
      const kpiRow = el(
        "div",
        { style: "display:grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap:8px;" },
        el("div", { style: `padding:8px; border-radius:8px; background:${WIDGET_SURFACE}; border:1px solid ${WIDGET_BORDER};` },
          el("div", { class: "muted", text: "Total" }),
          el("div", { style: "font-size:20px; font-weight:600;", text: summaryState.total ?? 0 }),
        ),
        el("div", { style: `padding:8px; border-radius:8px; background:${WIDGET_SURFACE}; border:1px solid ${WIDGET_BORDER};` },
          el("div", { class: "muted", text: "Critical" }),
          el("div", { style: "font-size:20px; font-weight:600; color:#b91c1c;", text: summaryState.by_severity?.Critical ?? 0 }),
        ),
        el("div", { style: `padding:8px; border-radius:8px; background:${WIDGET_SURFACE}; border:1px solid ${WIDGET_BORDER};` },
          el("div", { class: "muted", text: "High" }),
          el("div", { style: "font-size:20px; font-weight:600; color:#b45309;", text: summaryState.by_severity?.High ?? 0 }),
        ),
      );

      const trendBlock = el(
        "div",
        { style: `display:flex; align-items:center; gap:12px; padding:8px; border-radius:8px; background:${WIDGET_SURFACE}; border:1px solid ${WIDGET_BORDER};` },
        el("div", { style: "display:flex; flex-direction:column; gap:4px;" },
          el("div", { class: "muted", text: `Updates (${widgetSettings.range})` }),
          el("div", { style: "font-size:16px; font-weight:600;", text: `${totalUpdates} updates` }),
        ),
        renderSparkline(counts),
      );

      content.append(kpiRow, trendBlock);
    };

    const load = async () => {
      if (syncing) return;
      syncing = true;
      content.innerHTML = "";
      content.appendChild(el("div", { class: "muted", text: "Loading risk overview..." }));
      try {
        const statusFilters = parseFilterList(widgetSettings.filter, STATUS_OPTIONS);
        summaryState = await getDashboardSummary({
          status: statusFilters?.length ? statusFilters.join(",") : undefined,
          group_by: widgetSettings.grouping || "Severity",
          range: widgetSettings.range,
        });
        renderSummary();
      } catch (error) {
        content.innerHTML = "";
        console.warn("Unable to load risk overview.", error);
        content.appendChild(el("div", { class: "muted", text: "Unable to load risk overview." }));
      } finally {
        syncing = false;
      }
    };

    subscribe((state) => {
      const events = state?.liveNotifications || [];
      for (const event of events) {
        const key = `${event.sent_at || ""}-${event.type || ""}-${event.payload?.vulnerability_id || ""}`;
        if (seenEvents.has(key)) continue;
        seenEvents.add(key);
        if (event?.type !== "dashboard_metric_change") continue;
        summaryState = applyDashboardMetricDelta(summaryState, event, widgetSettings);
        renderSummary();
      }
      if (seenEvents.size > 120) {
        seenEvents = new Set([...seenEvents].slice(-60));
      }
    });

    load();
    setInterval(load, DASHBOARD_SUMMARY_POLL_MS);
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
        const withDueDates = (data.items || [])
          .map((item) => {
            const dueDate = item?.sla_due_at ? new Date(item.sla_due_at) : null;
            if (!dueDate || Number.isNaN(dueDate.getTime())) return null;
            return { ...item, dueDate };
          })
          .filter(Boolean);
        const dueSoon = withDueDates
          .filter((item) => (horizon ? item.dueDate <= horizon : true))
          .sort((a, b) => a.dueDate - b.dueDate)
          .slice(0, 8);

        const breached = withDueDates.filter((item) => item.sla_state === "breached");
        const bySeverity = breached.reduce((acc, item) => {
          const key = item.severity || "Unknown";
          acc[key] = (acc[key] || 0) + 1;
          return acc;
        }, {});
        const users = await ensureActiveUsers();
        const userMap = new Map(users.map((u) => [u.id, u]));
        const byOwner = breached.reduce((acc, item) => {
          const user = item.assigned_to ? userMap.get(item.assigned_to) : null;
          const label = user ? (user.full_name || user.username || user.email || `User ${user.id}`) : "Unassigned";
          acc[label] = (acc[label] || 0) + 1;
          return acc;
        }, {});

        list.innerHTML = "";
        const rollup = el("div", { style: `display:grid; grid-template-columns: 1fr 1fr; gap:10px; padding:8px; border:1px solid ${WIDGET_BORDER}; border-radius:8px; background:${WIDGET_SURFACE};` });
        rollup.append(
          el("div", {},
            el("div", { style: "font-weight:600;", text: "Breaches by severity" }),
            ...(Object.entries(bySeverity).length
              ? Object.entries(bySeverity).sort((a, b) => b[1] - a[1]).map(([severity, count]) => el("div", { class: "muted", text: `${severity}: ${count}` }))
              : [el("div", { class: "muted", text: "No breaches." })]),
          ),
          el("div", {},
            el("div", { style: "font-weight:600;", text: "Breaches by owner" }),
            ...(Object.entries(byOwner).length
              ? Object.entries(byOwner).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([owner, count]) => el("div", { class: "muted", text: `${owner}: ${count}` }))
              : [el("div", { class: "muted", text: "No breaches." })]),
          ),
        );
        list.appendChild(rollup);
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


  function renderRiskTrendsWidget(widgetSettings) {
    const container = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });
    const body = el("div", { class: "muted", text: "Loading risk trend data..." });
    container.append(body);

    const load = async () => {
      try {
        const data = await loadRiskTrendData(widgetSettings);
        body.innerHTML = "";
        const grouped = (data.items || []).reduce((acc, item) => {
          const key = `${item.product_name || "Unknown"} ${item.product_version || ""}`.trim();
          if (!acc[key]) acc[key] = [];
          acc[key].push(item);
          return acc;
        }, {});
        const topSeries = Object.entries(grouped)
          .map(([name, items]) => ({
            name,
            items: items.sort((a, b) => a.bucket.localeCompare(b.bucket)),
            score: items.reduce((sum, item) => sum + (item.weighted_risk_score || 0), 0),
          }))
          .sort((a, b) => b.score - a.score)
          .slice(0, 3);
        if (!topSeries.length) {
          body.appendChild(el("div", { class: "muted", text: "No risk trend data for selected filters." }));
          return;
        }
        topSeries.forEach((series) => {
          const spark = renderSparkline(series.items.map((row) => row.weighted_risk_score || 0));
          body.append(
            el("div", { style: `padding:8px; border:1px solid ${WIDGET_BORDER}; border-radius:8px; background:${WIDGET_SURFACE};` },
              el("div", { style: "font-weight:600;", text: series.name }),
              el("div", { class: "muted", text: `Buckets: ${series.items.length} • Total score: ${series.score}` }),
              spark,
            ),
          );
        });
      } catch (error) {
        body.innerHTML = "";
        body.appendChild(el("div", { class: "muted", text: "Unable to load risk trends." }));
      }
    };
    load();
    return container;
  }

  function renderTopRiskProductsWidget(widgetSettings) {
    const container = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });
    const body = el("div", { class: "muted", text: "Loading top-risk products..." });
    container.append(body);

    const load = async () => {
      try {
        const data = await loadRiskTrendData(widgetSettings);
        const rows = data.top_risk_products || [];
        body.innerHTML = "";
        if (!rows.length) {
          body.appendChild(el("div", { class: "muted", text: "No top-risk products for selected filters." }));
          return;
        }
        rows.forEach((item, idx) => {
          const label = `${item.product_name || "Unknown"} ${item.product_version || ""}`.trim();
          body.append(
            el("div", { style: `display:grid; grid-template-columns:32px 1.4fr 0.8fr 0.8fr 1fr; gap:8px; padding:6px 0; border-top:1px solid ${WIDGET_BORDER}; align-items:center;` },
              el("div", { text: `${idx + 1}.` }),
              el("div", { text: label }),
              el("div", { class: "muted", text: `Critical: ${item.open_critical_count}` }),
              el("div", { class: "muted", text: `Overdue: ${item.overdue_sla_count}` }),
              el("div", { style: "font-weight:600;", text: `Score: ${item.weighted_risk_score}` }),
            ),
          );
        });
      } catch (error) {
        body.innerHTML = "";
        body.appendChild(el("div", { class: "muted", text: "Unable to load top-risk products." }));
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


  const widgetRegistry = createWidgetRegistry({
    "high-risk-open": () => renderHighRiskWidget(),
    "risk-overview": (settings) => renderRiskOverviewWidget(settings),
    "recent-updates": (settings) => renderRecentlyUpdatedWidget(settings),
    "sla-due": (settings) => renderSlaWidget(settings),
    "top-assets": (settings) => renderTopAssetsWidget(settings),
    "risk-trends": (settings) => renderRiskTrendsWidget(settings),
    "top-risk-products": (settings) => renderTopRiskProductsWidget(settings),
    "my-work": (settings) => renderMyWorkWidget(settings),
  });
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

      const widgetRenderer = widgetRegistry.get(widgetId);
      const details = widgetRenderer
        ? widgetRenderer(widgetSettings)
        : el(
          "div",
          { style: "display:flex; flex-direction:column; gap:4px;" },
          el("div", { class: "muted", text: `Filter: ${widgetSettings.filter}` }),
          el("div", { class: "muted", text: `Date range: ${widgetSettings.range}` }),
          el("div", { class: "muted", text: `Grouping: ${widgetSettings.grouping || "None"}` }),
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

  persistState();
  try {
    await loadPresetsFromApi();
    presetsOnline = true;
  } catch (error) {
    presetsOnline = false;
    presets = loadLocalPresets();
    console.warn("Unable to load dashboard presets from API.", error);
    toast({ title: "Offline mode", message: "Dashboard preset API unavailable; using local fallback." });
  }
  renderPresetOptions();
  renderGrid();

  const controlsRow = el(
    "div",
    { style: "display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap;" },
    el("h2", { text: "Widget layout" }),
    el(
      "div",
      { style: "display:flex; gap:8px; flex-wrap:wrap; align-items:center;" },
      presetSelect,
      el("button", { class: "btn", text: "Load", onClick: () => applySelectedPreset() }),
      presetNameInput,
      presetVisibilitySelect,
      el("button", { class: "btn", text: "Save layout", onClick: () => savePreset({ markDefault: false }) }),
      el("button", { class: "btn", text: "Save as default", onClick: () => savePreset({ markDefault: true }) }),
      el("button", {
        class: "btn",
        text: "Mark selected default",
        onClick: async () => {
          const value = presetSelect.value;
          if (!value || value === "local-current") {
            toast({ title: "Select a preset", message: "Choose a saved preset to mark as default." });
            return;
          }
          try {
            if (presetsOnline) {
              await updateDashboardLayoutPreset(Number(value), { is_default: true });
              presets = presets.map((preset) => ({
                ...preset,
                is_default: String(preset.id) === String(value),
              }));
            } else {
              const local = loadLocalPresets();
              local.forEach((item) => {
                item.is_default = String(item.id) === String(value);
              });
              saveLocalPresets(local);
            }
            renderPresetOptions();
            toast({ title: "Default updated", message: "Selected layout is now default." });
          } catch (error) {
            toast({ title: "Unable to update default", message: error?.message || "Failed to update preset default." });
          }
        },
      }),
      el("button", {
        class: "btn",
        text: "Reset layout",
        onClick: () => {
          layoutState.order = getDefaultLayoutState(DEFAULT_WIDGETS).order;
          layoutState.visibility = {};
          layoutState.settings = {};
          persistState();
          renderGrid();
        },
      }),
    ),
  );

  gridWrapper.append(
    controlsRow,
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
