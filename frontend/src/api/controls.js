import { apiFetch } from "./client.js";

export async function listControls() {
  return apiFetch("/api/controls", { method: "GET" });
}

export async function getControl(controlId) {
  return apiFetch(`/api/controls/${controlId}`, { method: "GET" });
}

export async function createControl(data) {
  return apiFetch("/api/controls", { method: "POST", body: data });
}

export async function updateControl(controlId, data) {
  return apiFetch(`/api/controls/${controlId}`, { method: "PATCH", body: data });
}

export async function deleteControl(controlId) {
  return apiFetch(`/api/controls/${controlId}`, { method: "DELETE" });
}
