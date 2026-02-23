export const STORAGE_KEY = "uvt.dashboard.widgets.v1";
export const LOCAL_PRESETS_KEY = "uvt.dashboard.layout_presets.v1";

export function getDefaultLayoutState(defaultWidgets) {
  return { order: defaultWidgets.map((widget) => widget.id), visibility: {}, settings: {} };
}

export function normalizeLayoutState(state, defaultWidgets) {
  if (!state || typeof state !== "object") return getDefaultLayoutState(defaultWidgets);
  const widgetIds = new Set(defaultWidgets.map((widget) => widget.id));
  const order = Array.isArray(state.order) ? state.order.filter((id) => widgetIds.has(id)) : [];
  const completeOrder = [...order, ...defaultWidgets.map((w) => w.id).filter((id) => !order.includes(id))];
  return {
    order: completeOrder,
    visibility: state.visibility && typeof state.visibility === "object" ? { ...state.visibility } : {},
    settings: state.settings && typeof state.settings === "object" ? { ...state.settings } : {},
  };
}

export function loadDashboardState(defaultWidgets) {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return null;
    return normalizeLayoutState(JSON.parse(stored), defaultWidgets);
  } catch (error) {
    console.warn("Unable to load dashboard layout.", error);
    return null;
  }
}

export function saveDashboardState(state, defaultWidgets) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(normalizeLayoutState(state, defaultWidgets)));
  } catch (error) {
    console.warn("Unable to save dashboard layout.", error);
  }
}

export function loadLocalPresets() {
  try {
    const raw = localStorage.getItem(LOCAL_PRESETS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    console.warn("Unable to load local dashboard presets.", error);
    return [];
  }
}

export function saveLocalPresets(presets) {
  try {
    localStorage.setItem(LOCAL_PRESETS_KEY, JSON.stringify(Array.isArray(presets) ? presets : []));
  } catch (error) {
    console.warn("Unable to save local dashboard presets.", error);
  }
}
