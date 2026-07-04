import { apiFetch } from "./client.js";
import { CONFIG } from "../config.js";

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

export async function exportAuditLogsCsv({ action, table } = {}) {
  const params = new URLSearchParams();
  if (action) params.set("action", action);
  if (table) params.set("table", table);
  const qs = params.toString();
  const url = `${CONFIG.API_BASE}/api/audit-logs/export.csv${qs ? `?${qs}` : ""}`;

  // Raw fetch: the response is CSV, not JSON, so apiFetch's parsing doesn't apply.
  // Auth rides on the session cookie like report artifact downloads.
  const response = await fetch(url, { credentials: "include" });
  if (!response.ok) throw new Error(`Export failed (HTTP ${response.status})`);
  return response.blob();
}
