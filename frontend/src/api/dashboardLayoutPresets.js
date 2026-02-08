import { apiFetch } from "./client.js";

export function listDashboardLayoutPresets() {
  return apiFetch("/api/dashboard/layout-presets", { method: "GET" });
}

export function getDefaultDashboardLayoutPreset() {
  return apiFetch("/api/dashboard/layout-presets/default", { method: "GET" });
}

export function createDashboardLayoutPreset(payload) {
  return apiFetch("/api/dashboard/layout-presets", { method: "POST", body: payload });
}

export function updateDashboardLayoutPreset(presetId, payload) {
  return apiFetch(`/api/dashboard/layout-presets/${presetId}`, { method: "PUT", body: payload });
}

export function deleteDashboardLayoutPreset(presetId) {
  return apiFetch(`/api/dashboard/layout-presets/${presetId}`, { method: "DELETE" });
}
