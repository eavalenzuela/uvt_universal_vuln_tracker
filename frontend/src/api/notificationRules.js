import { apiFetch } from "./client.js";

export function listNotificationRules() {
  return apiFetch("/api/notification-rules", { method: "GET" });
}

export function createNotificationRule(payload) {
  return apiFetch("/api/notification-rules", { method: "POST", body: payload });
}

export function updateNotificationRule(ruleId, payload) {
  return apiFetch(`/api/notification-rules/${ruleId}`, { method: "PUT", body: payload });
}

export function deleteNotificationRule(ruleId) {
  return apiFetch(`/api/notification-rules/${ruleId}`, { method: "DELETE" });
}

export function testSendNotificationRule(ruleId) {
  return apiFetch(`/api/notification-rules/${ruleId}/test-send`, { method: "POST" });
}

export function listNotificationDeliveryLogs(limit = 50) {
  const params = new URLSearchParams({ limit: `${limit}` });
  return apiFetch(`/api/notification-delivery-logs?${params.toString()}`, { method: "GET" });
}
