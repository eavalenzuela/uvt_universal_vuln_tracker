import { apiFetch } from "./client.js";

function withParams(base, params = {}) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") qs.set(key, value);
  });
  const suffix = qs.toString();
  return suffix ? `${base}?${suffix}` : base;
}

export function exportVulnerabilitiesCsv(filters = {}) {
  return apiFetch(withParams("/api/reports/vulnerabilities/export", filters), { method: "GET" });
}

export function exportDashboardSummaryCsv(filters = {}) {
  return apiFetch(withParams("/api/reports/dashboard/export", filters), { method: "GET" });
}

export function listReportSchedules() {
  return apiFetch("/api/reports/schedules", { method: "GET" });
}

export function createReportSchedule(payload) {
  return apiFetch("/api/reports/schedules", { method: "POST", body: payload });
}

export function runReportSchedule(id) {
  return apiFetch(`/api/reports/schedules/${id}/run`, { method: "POST" });
}

export function getDashboardSummary(params = {}) {
  return apiFetch(withParams("/api/dashboard/summary", params), { method: "GET" });
}
