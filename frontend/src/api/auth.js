import { apiFetch } from "./client.js";

export async function login(username, password) {
  return apiFetch("/api/auth/login", {
    method: "POST",
    body: { username, password },
  });
}

export async function me() {
  return apiFetch("/api/auth/me", { method: "GET" });
}

export async function authProviders() {
  return apiFetch("/api/auth/providers", { method: "GET" });
}
