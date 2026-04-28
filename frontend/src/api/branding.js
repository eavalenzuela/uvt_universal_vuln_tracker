import { apiFetch } from "./client.js";

export function getBranding() {
  return apiFetch("/api/admin/branding", { method: "GET" });
}

export function updateBranding(payload) {
  return apiFetch("/api/admin/branding", { method: "PUT", body: payload });
}

export function uploadBrandingLogo(file) {
  const data = new FormData();
  data.append("logo", file, file.name);
  return apiFetch("/api/admin/branding/logo", { method: "POST", body: data });
}

export function deleteBrandingLogo() {
  return apiFetch("/api/admin/branding/logo", { method: "DELETE" });
}
