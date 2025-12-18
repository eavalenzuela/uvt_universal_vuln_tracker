import { apiFetch } from "./client.js";

export async function listUsers({ search, role, status } = {}) {
  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (role) params.set("role", role);
  if (status) params.set("status", status);

  const qs = params.toString();
  const suffix = qs ? `?${qs}` : "";
  return apiFetch(`/api/users${suffix}`, { method: "GET" });
}

export async function inviteUser(payload) {
  return apiFetch("/api/users/invite", { method: "POST", body: payload });
}

export async function toggleUserActive(userId) {
  return apiFetch(`/api/users/${userId}/toggle-active`, { method: "POST" });
}

export async function impersonateUser(userId, { reason } = {}) {
  return apiFetch(`/api/users/${userId}/impersonate`, { method: "POST", body: { reason } });
}

export async function updateUser(userId, data) {
  return apiFetch(`/api/users/${userId}`, { method: "PATCH", body: data });
}

export async function exportUsers({ search, role, status } = {}) {
  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (role) params.set("role", role);
  if (status) params.set("status", status);

  const qs = params.toString();
  const suffix = qs ? `?${qs}` : "";
  return apiFetch(`/api/users/export${suffix}`, { method: "GET" });
}

export async function listActiveUsers() {
  return apiFetch("/api/users/active", { method: "GET" });
}
