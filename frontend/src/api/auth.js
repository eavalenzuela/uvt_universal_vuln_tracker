import { apiFetch } from "./client.js";

export async function login(username, password) {
  return apiFetch("/api/auth/login", {
    method: "POST",
    body: { username, password },
  });
}

export async function refresh(refreshToken = null) {
  return apiFetch("/api/auth/refresh", {
    method: "POST",
    body: refreshToken ? { refresh_token: refreshToken } : {},
  });
}

export async function logout(refreshToken = null) {
  return apiFetch("/api/auth/logout", {
    method: "POST",
    body: refreshToken ? { refresh_token: refreshToken } : {},
  });
}

export async function logoutAll() {
  return apiFetch("/api/auth/logout_all", { method: "POST" });
}

export async function me() {
  return apiFetch("/api/auth/me", { method: "GET" });
}

export async function authProviders() {
  return apiFetch("/api/auth/providers", { method: "GET" });
}
