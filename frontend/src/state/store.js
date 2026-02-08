import { loadSession, saveSession, clearSession } from "./session.js";

const persistedSession = loadSession();

const state = {
  session: {
    token: null,
    refreshToken: null,
    user: persistedSession.user,
  },
  liveNotifications: [],
  notifications: {
    items: [],
    unreadCount: 0,
    pagination: null,
  },
};

const listeners = new Set();

export function getState() {
  return state;
}

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function emit() {
  for (const fn of listeners) fn(state);
}

export function setSession(session) {
  state.session = {
    token: session?.token || null,
    refreshToken: session?.refreshToken || null,
    user: session?.user || null,
  };
  saveSession({ user: state.session.user });
  emit();
}

export function logoutSession() {
  state.session = { token: null, refreshToken: null, user: null };
  state.liveNotifications = [];
  state.notifications = { items: [], unreadCount: 0, pagination: null };
  clearSession();
  emit();
}

export function pushLiveNotification(event) {
  if (!event || typeof event !== "object") return;
  state.liveNotifications = [event, ...state.liveNotifications].slice(0, 30);
  const maybeNotification = event?.payload?.notification;
  if (maybeNotification && typeof maybeNotification === "object") {
    upsertNotification({ ...maybeNotification, is_read: maybeNotification.is_read ?? false });
  }
  emit();
}

export function clearLiveNotifications() {
  state.liveNotifications = [];
  emit();
}

export function setNotifications(payload) {
  const data = payload?.data || payload || {};
  state.notifications.items = Array.isArray(data.items) ? data.items : [];
  state.notifications.unreadCount = Number(data.unread_count || 0);
  state.notifications.pagination = data.pagination || null;
  emit();
}

export function upsertNotification(notification) {
  if (!notification || typeof notification !== "object") return;
  const id = notification.id;
  if (!id) {
    state.notifications.items = [notification, ...state.notifications.items].slice(0, 50);
  } else {
    const next = [...state.notifications.items];
    const idx = next.findIndex((item) => item.id === id);
    if (idx >= 0) {
      next[idx] = { ...next[idx], ...notification };
    } else {
      next.unshift(notification);
    }
    state.notifications.items = next.slice(0, 50);
  }
  state.notifications.unreadCount = state.notifications.items.filter((item) => !item.is_read).length;
}

export function removeNotification(notificationId) {
  state.notifications.items = state.notifications.items.filter((item) => item.id !== notificationId);
  state.notifications.unreadCount = state.notifications.items.filter((item) => !item.is_read).length;
  emit();
}

export function markAllNotificationsReadLocal() {
  state.notifications.items = state.notifications.items.map((item) => ({ ...item, is_read: true }));
  state.notifications.unreadCount = 0;
  emit();
}
