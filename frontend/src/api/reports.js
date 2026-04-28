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

export function exportVulnerabilities(filters = {}, format = "csv", options = {}) {
  const params = { ...filters, format };
  if (options.pdfLayout) params.pdf_layout = options.pdfLayout;
  return apiFetch(withParams("/api/reports/vulnerabilities/export", params), { method: "GET" });
}

export function exportDashboardSummary(filters = {}, format = "csv", options = {}) {
  const params = { ...filters, format };
  if (options.pdfLayout) params.pdf_layout = options.pdfLayout;
  return apiFetch(withParams("/api/reports/dashboard/export", params), { method: "GET" });
}

export function getReportArtifact(artifactId) {
  return apiFetch(`/api/reports/artifacts/${artifactId}`, { method: "GET" });
}

/**
 * Poll a report artifact's status endpoint until it reaches `ready` or `failed`.
 * Returns the final artifact payload, or rejects if it fails / times out.
 * F17 Slice 2: PDF rendering moves to Celery; the export route returns
 * status=pending and the frontend waits here.
 */
export async function waitForReportArtifact(artifactId, { intervalMs = 1000, timeoutMs = 120000 } = {}) {
  const start = Date.now();
  // Skip the first poll if status is already ready (sync code path).
  while (Date.now() - start < timeoutMs) {
    const { artifact } = await getReportArtifact(artifactId);
    if (!artifact) throw new Error("Artifact not found");
    if (artifact.status === "ready") return artifact;
    if (artifact.status === "failed") {
      throw new Error(artifact.error || "Report generation failed");
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error("Timed out waiting for report to render");
}

export async function downloadReportArtifact(downloadUrl) {
  const finalUrl = downloadUrl.startsWith("http") ? downloadUrl : `${CONFIG.API_BASE}${downloadUrl}`;
  const response = await fetch(finalUrl, {
    credentials: "include",
  });
  if (!response.ok) throw new Error(`Download failed (HTTP ${response.status})`);
  return response.blob();
}


export function listReportTemplates() {
  return apiFetch("/api/reports/templates", { method: "GET" });
}

export function createReportTemplate(payload) {
  return apiFetch("/api/reports/templates", { method: "POST", body: payload });
}

export function updateReportTemplate(id, payload) {
  return apiFetch(`/api/reports/templates/${id}`, { method: "PATCH", body: payload });
}

export function deleteReportTemplate(id) {
  return apiFetch(`/api/reports/templates/${id}`, { method: "DELETE" });
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
