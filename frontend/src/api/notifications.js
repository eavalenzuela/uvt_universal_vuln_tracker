import { apiFetch } from "./client.js";

function qp(params = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") return;
    query.set(key, String(value));
  });
  const s = query.toString();
  return s ? `?${s}` : "";
}

export async function listNotifications(params = {}) {
  return apiFetch(`/api/notifications${qp(params)}`);
}

export async function markNotificationRead(notificationId, isRead) {
  return apiFetch(`/api/notifications/${notificationId}`, {
    method: "PATCH",
    body: { is_read: !!isRead },
  });
}

export async function markAllNotificationsRead() {
  return apiFetch("/api/notifications/read-all", { method: "POST" });
}

export async function deleteNotification(notificationId, mode = "delete") {
  return apiFetch(`/api/notifications/${notificationId}${qp({ mode })}`, { method: "DELETE" });
}
