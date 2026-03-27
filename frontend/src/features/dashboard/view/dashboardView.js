import { el } from "../../../ui/dom/el.js";
import { canWrite } from "../../../state/permissions.js";
import { getState } from "../../../state/store.js";
import { downloadReportArtifact, exportDashboardSummary } from "../../../api/reports.js";
import {
  createDashboardLayoutPreset,
  getDefaultDashboardLayoutPreset,
  listDashboardLayoutPresets,
  updateDashboardLayoutPreset,
} from "../../../api/dashboardLayoutPresets.js";
import { toast } from "../../../ui/components/toast.js";
import { getDefaultLayoutState, loadDashboardState, loadLocalPresets, normalizeLayoutState, saveDashboardState, saveLocalPresets } from "../state/layoutState.js";
import { createWidgetRegistry } from "../widgets/widgetRegistry.js";
import {
  DEFAULT_WIDGETS,
  STATUS_OPTIONS,
  SEVERITY_OPTIONS,
  RANGE_OPTIONS,
  WIDGET_BORDER,
  WIDGET_BORDER_HIGHLIGHT,
} from "./dashboardConstants.js";
import {
  renderHighRiskWidget,
  renderRiskOverviewWidget,
  renderRecentlyUpdatedWidget,
  renderSlaWidget,
  renderTopAssetsWidget,
  renderRiskTrendsWidget,
  renderTopRiskProductsWidget,
  renderMyWorkWidget,
} from "./dashboardWidgets.js";

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
  const ctx = { user, writable };

  const layoutState = {
    order: savedState.order.filter((id) => widgetById.has(id)),
    visibility: { ...savedState.visibility },
    settings: { ...savedState.settings },
  };

  const container = el("div", { class: "card flex-col-16" });

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
    { class: "flex-col-6" },
    el("h1", { class: "page-title", text: "Dashboard" }),
    el("p", { class: "muted", text: `Signed in as ${user?.username || "?"} (${user?.role || "?"}).` }),
    el("p", { class: "muted", text: "Drag widgets to reorder or use the move controls for keyboard access." }),
    el("div", { class: "row flex-wrap" }, exportStatusSelect, exportSeveritySelect, exportFormatSelect, exportBtn),
  );

  const gridWrapper = el("div", { class: "flex-col-12" });
  const grid = el("div", { class: "widget-grid" });
  const hiddenList = el("div", { class: "flex-col-8" });

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
      class: "modal-backdrop",
      onClick: (event) => {
        if (event.target === overlay) closeModal();
      },
    });

    const modal = el(
      "div",
      {
        class: "modal-panel modal-sm",
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
      el("div", { class: "flex-col-6" },
        el("label", { text: "Filter" }),
        filterInput,
      ),
      el("div", { class: "flex-col-6" },
        el("label", { text: "Product filter" }),
        productFilterInput,
      ),
      el("div", { class: "flex-col-6" },
        el("label", { text: "Date range" }),
        rangeSelect,
      ),
      el("div", { class: "flex-col-6" },
        el("label", { text: "Grouping" }),
        groupingSelect,
      ),
      el("label", { class: "flex-row-8" },
        visibleToggle,
        el("span", { text: "Widget visible" }),
      ),
      el("div", { class: "flex-end gap-8" },
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

  const widgetRegistry = createWidgetRegistry({
    "high-risk-open": () => renderHighRiskWidget(ctx),
    "risk-overview": (settings) => renderRiskOverviewWidget(settings),
    "recent-updates": (settings) => renderRecentlyUpdatedWidget(settings),
    "sla-due": (settings) => renderSlaWidget(settings),
    "top-assets": (settings) => renderTopAssetsWidget(settings),
    "risk-trends": (settings) => renderRiskTrendsWidget(settings),
    "top-risk-products": (settings) => renderTopRiskProductsWidget(settings),
    "my-work": (settings) => renderMyWorkWidget(settings, ctx),
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
        class: "widget-card",
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
        text: "\u2807",
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
        { class: "flex-row-6" },
        el("button", {
          class: "btn",
          text: "\u2699\uFE0F",
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
          text: "\u2191",
          title: "Move up",
          "aria-label": `Move ${widget.title} up`,
          onClick: () => moveWidget(widgetId, -1),
        }),
        el("button", {
          class: "btn",
          text: "\u2193",
          title: "Move down",
          "aria-label": `Move ${widget.title} down`,
          onClick: () => moveWidget(widgetId, 1),
        }),
      );

      const headerRow = el(
        "div",
        { class: "flex-between gap-8" },
        el("div", { class: "flex-row-8" },
          dragHandle,
          el("div", { class: "flex-col" },
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
          { class: "flex-col-4" },
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
        el("div", { class: "flex-row-8 flex-wrap" },
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
    { class: "flex-between gap-8 flex-wrap" },
    el("h2", { text: "Widget layout" }),
    el(
      "div",
      { class: "flex-row-8 flex-wrap" },
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
