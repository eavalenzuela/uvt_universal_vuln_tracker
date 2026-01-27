import { apiFetch } from "./client.js";

export async function listVulnerabilities({
  search,
  severity,
  status,
  attack_complexity,
  sort = "updated_at",
  order = "desc",
  page = 1,
  page_size = 25,
} = {}) {
  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);
  if (attack_complexity) params.set("attack_complexity", attack_complexity);
  if (sort) params.set("sort", sort);
  if (order) params.set("order", order);
  params.set("page", page);
  params.set("page_size", page_size);

  return apiFetch(`/api/vulnerabilities?${params.toString()}`, { method: "GET" });
}

export async function createVulnerability(data) {
  return apiFetch("/api/vulnerabilities", { method: "POST", body: data });
}

export async function getVulnerability(id) {
  return apiFetch(`/api/vulnerabilities/${id}`, { method: "GET" });
}

export async function updateVulnerability(id, data) {
  return apiFetch(`/api/vulnerabilities/${id}`, { method: "PUT", body: data });
}

export async function deleteVulnerability(id) {
  return apiFetch(`/api/vulnerabilities/${id}`, { method: "DELETE" });
}

export async function listProductVersions({ includeInactive = false } = {}) {
  const params = new URLSearchParams();
  if (includeInactive) params.set("include_inactive", "true");
  return apiFetch(`/api/product_versions?${params.toString()}`, { method: "GET" });
}

export async function listAttackVectors() {
  return apiFetch("/api/attack_vectors", { method: "GET" });
}

export async function attachVulnerabilityVersions(id, productVersionIds) {
  return apiFetch(`/api/vulnerabilities/${id}/versions`, {
    method: "POST",
    body: { product_version_ids: productVersionIds },
  });
}

export async function updateVulnerabilityVersion(id, mappingId, data) {
  return apiFetch(`/api/vulnerabilities/${id}/versions/${mappingId}`, { method: "PATCH", body: data });
}

export async function deleteVulnerabilityVersion(id, mappingId) {
  return apiFetch(`/api/vulnerabilities/${id}/versions/${mappingId}`, { method: "DELETE" });
}

export async function attachVulnerabilityAttackVectors(id, mappings) {
  return apiFetch(`/api/vulnerabilities/${id}/attack_vectors`, {
    method: "POST",
    body: { mappings },
  });
}

export async function updateVulnerabilityAttackVector(id, mappingId, data) {
  return apiFetch(`/api/vulnerabilities/${id}/attack_vectors/${mappingId}`, { method: "PATCH", body: data });
}

export async function deleteVulnerabilityAttackVector(id, mappingId) {
  return apiFetch(`/api/vulnerabilities/${id}/attack_vectors/${mappingId}`, { method: "DELETE" });
}
