import { loadSession, saveSession, clearSession } from "./session.js";

const state = {
  session: loadSession(), // { token, user }
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
  state.session = session;
  saveSession(session);
  emit();
}

export function logoutSession() {
  state.session = { token: null, user: null };
  clearSession();
  emit();
}
