import { apiFetch } from "./client.js";

export function listNotificationDeliveryAttempts({ limit = 100, failedOnly = false } = {}) {
  const params = new URLSearchParams({
    limit: `${limit}`,
    failed_only: failedOnly ? "true" : "false",
  });
  return apiFetch(`/api/notification-delivery-attempts?${params.toString()}`, { method: "GET" });
}

export function retryNotificationDeliveryAttempt(attemptId) {
  return apiFetch(`/api/notification-delivery-attempts/${attemptId}/retry`, { method: "POST" });
}

export function replayNotificationDeliveryAttempt(attemptId) {
  return apiFetch(`/api/notification-delivery-attempts/${attemptId}/replay`, { method: "POST" });
}
