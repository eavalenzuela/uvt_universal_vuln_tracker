import { apiFetch } from "./client.js";

export async function listVulnerabilities({ search, severity, status, sort = "updated_at", order = "desc", page = 1, page_size = 25 } = {}) {
  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);
  if (sort) params.set("sort", sort);
  if (order) params.set("order", order);
  params.set("page", page);
  params.set("page_size", page_size);

  return apiFetch(`/api/vulnerabilities?${params.toString()}`, { method: "GET" });
}
