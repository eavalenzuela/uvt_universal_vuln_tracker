export function isAuthed(state) {
  return Boolean(state?.session?.token || state?.session?.user);
}

export function role(state) {
  return state?.session?.user?.role || null;
}

export function canWrite(state) {
  const r = role(state);
  return r === "Admin" || r === "Analyst";
}

export function isAdmin(state) {
  return role(state) === "Admin";
}
