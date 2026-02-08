import { loadSession, saveSession, clearSession } from "./session.js";

const state = {
  session: loadSession(), // { token, refreshToken, user }
  liveNotifications: [],
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
  saveSession(state.session);
  emit();
}

export function logoutSession() {
  state.session = { token: null, refreshToken: null, user: null };
  state.liveNotifications = [];
  clearSession();
  emit();
}

export function pushLiveNotification(event) {
  if (!event || typeof event !== "object") return;
  state.liveNotifications = [event, ...state.liveNotifications].slice(0, 30);
  emit();
}

export function clearLiveNotifications() {
  state.liveNotifications = [];
  emit();
}
