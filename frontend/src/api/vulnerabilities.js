import { apiFetch } from "./client.js";

export async function listVulnerabilities({
  search,
  severity,
  status,
  attack_complexity,
  confidentiality_impact,
  integrity_impact,
  availability_impact,
  assigned_to,
  component_ecosystem,
  component_name,
  component_depth_max,
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
  if (confidentiality_impact) params.set("confidentiality_impact", confidentiality_impact);
  if (integrity_impact) params.set("integrity_impact", integrity_impact);
  if (availability_impact) params.set("availability_impact", availability_impact);
  if (assigned_to !== undefined && assigned_to !== null && assigned_to !== "") params.set("assigned_to", assigned_to);
  if (component_ecosystem) params.set("component_ecosystem", component_ecosystem);
  if (component_name) params.set("component_name", component_name);
  if (component_depth_max !== undefined && component_depth_max !== null && component_depth_max !== "") params.set("component_depth_max", component_depth_max);
  if (sort) params.set("sort", sort);
  if (order) params.set("order", order);
  params.set("page", page);
  params.set("page_size", page_size);

  return apiFetch(`/api/vulnerabilities?${params.toString()}`, { method: "GET" });
}

export async function listOpenHighCriticalVulnerabilities({ page = 1, page_size = 10, sort = "updated_at", order = "desc" } = {}) {
  const [critical, high] = await Promise.all([
    listVulnerabilities({ severity: "Critical", status: "Open", page, page_size, sort, order }),
    listVulnerabilities({ severity: "High", status: "Open", page, page_size, sort, order }),
  ]);

  const items = [...(critical?.items || []), ...(high?.items || [])];
  items.sort((a, b) => {
    const left = a?.[sort] ? new Date(a[sort]).getTime() : 0;
    const right = b?.[sort] ? new Date(b[sort]).getTime() : 0;
    return order.toLowerCase() === "asc" ? left - right : right - left;
  });

  return {
    items: items.slice(0, page_size),
    page,
    page_size,
    total: (critical?.total || 0) + (high?.total || 0),
  };
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

export async function listVulnerabilityActivity(id) {
  return apiFetch(`/api/vulnerabilities/${id}/activity`, { method: "GET" });
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

export async function listTerminalImpacts() {
  return apiFetch("/api/terminal_impacts", { method: "GET" });
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

export async function attachVulnerabilityTerminalImpacts(id, terminalImpactIds) {
  return apiFetch(`/api/vulnerabilities/${id}/terminal_impacts`, {
    method: "POST",
    body: { terminal_impact_ids: terminalImpactIds },
  });
}

export async function updateVulnerabilityTerminalImpact(id, mappingId, data) {
  return apiFetch(`/api/vulnerabilities/${id}/terminal_impacts/${mappingId}`, { method: "PATCH", body: data });
}

export async function deleteVulnerabilityTerminalImpact(id, mappingId) {
  return apiFetch(`/api/vulnerabilities/${id}/terminal_impacts/${mappingId}`, { method: "DELETE" });
}

export async function listSavedVulnerabilityFilters() {
  return apiFetch("/api/vulnerabilities/filters", { method: "GET" });
}

export async function getDefaultVulnerabilityFilter() {
  return apiFetch("/api/vulnerabilities/filters/default", { method: "GET" });
}

export async function createSavedVulnerabilityFilter(data) {
  return apiFetch("/api/vulnerabilities/filters", { method: "POST", body: data });
}

export async function updateSavedVulnerabilityFilter(id, data) {
  return apiFetch(`/api/vulnerabilities/filters/${id}`, { method: "PUT", body: data });
}

export async function deleteSavedVulnerabilityFilter(id) {
  return apiFetch(`/api/vulnerabilities/filters/${id}`, { method: "DELETE" });
}
