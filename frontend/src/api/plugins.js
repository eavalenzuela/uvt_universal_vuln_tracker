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
