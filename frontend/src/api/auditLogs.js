import { apiFetch } from "./client.js";

export async function listAuditLogs({ limit = 100, action, table } = {}) {
  const params = new URLSearchParams();
  if (limit) params.set("limit", limit);
  if (action) params.set("action", action);
  if (table) params.set("table", table);

  const qs = params.toString();
  const suffix = qs ? `?${qs}` : "";
  return apiFetch(`/api/audit-logs${suffix}`, { method: "GET" });
}
