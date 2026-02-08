import { apiFetch } from "./client.js";

export async function listAuditLogs({ page = 1, page_size = 100, action, table } = {}) {
  const params = new URLSearchParams();
  if (page) params.set("page", page);
  if (page_size) params.set("page_size", page_size);
  if (action) params.set("action", action);
  if (table) params.set("table", table);

  const qs = params.toString();
  const suffix = qs ? `?${qs}` : "";
  return apiFetch(`/api/audit-logs${suffix}`, { method: "GET" });
}
