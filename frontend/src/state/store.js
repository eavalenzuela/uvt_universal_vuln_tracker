import { loadSession, saveSession, clearSession } from "./session.js";

const persistedSession = loadSession();

const state = {
  session: {
    token: null,
    refreshToken: null,
    user: persistedSession.user,
    teams: persistedSession.teams || [],
    currentTeamId: persistedSession.currentTeamId || null,
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
  const teams = Array.isArray(session?.teams) ? session.teams : state.session.teams || [];
  const teamIds = new Set(teams.map((t) => t.id));
  let currentTeamId = session?.currentTeamId;
  if (!Number.isInteger(currentTeamId)) {
    currentTeamId = state.session.currentTeamId;
  }
  if (!teamIds.has(currentTeamId)) {
    const def = teams.find((t) => t.is_default) || teams[0];
    currentTeamId = def ? def.id : null;
  }
  state.session = {
    token: session?.token || null,
    refreshToken: session?.refreshToken || null,
    user: session?.user || null,
    teams,
    currentTeamId,
  };
  saveSession({
    user: state.session.user,
    teams: state.session.teams,
    currentTeamId: state.session.currentTeamId,
  });
  emit();
}

export function setCurrentTeam(teamId) {
  const normalized = Number.isInteger(teamId) ? teamId : null;
  if (state.session.currentTeamId === normalized) return;
  const teams = state.session.teams || [];
  if (normalized !== null && !teams.some((t) => t.id === normalized)) return;
  state.session = { ...state.session, currentTeamId: normalized };
  saveSession({
    user: state.session.user,
    teams: state.session.teams,
    currentTeamId: state.session.currentTeamId,
  });
  emit();
}

export function setSessionTeams(teams, currentTeamId) {
  const list = Array.isArray(teams) ? teams : [];
  const ids = new Set(list.map((t) => t.id));
  let current = Number.isInteger(currentTeamId) ? currentTeamId : state.session.currentTeamId;
  if (!ids.has(current)) {
    const def = list.find((t) => t.is_default) || list[0];
    current = def ? def.id : null;
  }
  state.session = { ...state.session, teams: list, currentTeamId: current };
  saveSession({
    user: state.session.user,
    teams: state.session.teams,
    currentTeamId: state.session.currentTeamId,
  });
  emit();
}

export function logoutSession() {
  state.session = { token: null, refreshToken: null, user: null, teams: [], currentTeamId: null };
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
  emit();
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
