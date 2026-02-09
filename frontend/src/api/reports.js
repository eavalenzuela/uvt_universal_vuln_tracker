import { apiFetch } from "./client.js";
import { CONFIG } from "../config.js";

function withParams(base, params = {}) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") qs.set(key, value);
  });
  const suffix = qs.toString();
  return suffix ? `${base}?${suffix}` : base;
}

export function exportVulnerabilities(filters = {}, format = "csv") {
  return apiFetch(withParams("/api/reports/vulnerabilities/export", { ...filters, format }), { method: "GET" });
}

export function exportDashboardSummary(filters = {}, format = "csv") {
  return apiFetch(withParams("/api/reports/dashboard/export", { ...filters, format }), { method: "GET" });
}

export async function downloadReportArtifact(downloadUrl) {
  const finalUrl = downloadUrl.startsWith("http") ? downloadUrl : `${CONFIG.API_BASE}${downloadUrl}`;
  const response = await fetch(finalUrl, {
    credentials: "include",
  });
  if (!response.ok) throw new Error(`Download failed (HTTP ${response.status})`);
  return response.blob();
}

export function listReportSchedules() {
  return apiFetch("/api/reports/schedules", { method: "GET" });
}

export function createReportSchedule(payload) {
  return apiFetch("/api/reports/schedules", { method: "POST", body: payload });
}

export function updateReportSchedule(id, payload) {
  return apiFetch(`/api/reports/schedules/${id}`, { method: "PATCH", body: payload });
}

export function deleteReportSchedule(id) {
  return apiFetch(`/api/reports/schedules/${id}`, { method: "DELETE" });
}

export function runReportSchedule(id) {
  return apiFetch(`/api/reports/schedules/${id}/run`, { method: "POST" });
}

export function getDashboardSummary(params = {}) {
  return apiFetch(withParams("/api/dashboard/summary", params), { method: "GET" });
}

export function getRiskTrends(params = {}) {
  return apiFetch(withParams("/api/reports/risk-trends", params), { method: "GET" });
}
