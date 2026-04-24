import { apiFetch } from "./client.js";

export async function getMyPreferences() {
  return apiFetch("/api/me/preferences", { method: "GET" });
}

export async function updateMyPreferences(patch) {
  return apiFetch("/api/me/preferences", {
    method: "PUT",
    body: patch,
  });
}
