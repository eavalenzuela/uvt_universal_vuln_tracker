import { getState } from "../state/store.js";
import { isAuthed, role } from "../state/permissions.js";

export function requireAuth() {
  const state = getState();
  return isAuthed(state);
}

export function requireRole(...roles) {
  const state = getState();
  return roles.includes(role(state));
}
