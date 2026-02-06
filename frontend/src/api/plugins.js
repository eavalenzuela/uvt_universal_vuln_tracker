import { apiFetch } from "./client.js";

export function listPlugins() {
  return apiFetch("/api/plugins");
}

export function updatePluginConfig(pluginId, payload) {
  return apiFetch(`/api/plugins/${pluginId}/config`, {
    method: "POST",
    body: payload,
  });
}

export function listPluginImportSources() {
  return apiFetch("/api/plugins/import/sources");
}

export function validatePluginImport(payload) {
  return apiFetch("/api/plugins/import/validate", {
    method: "POST",
    body: payload,
  });
}

export function registerPluginImport(payload) {
  return apiFetch("/api/plugins/import/register", {
    method: "POST",
    body: payload,
  });
}
