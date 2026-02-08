const KEY = "uvt_session_v1";

function emptySession() {
  return { user: null };
}

export function loadSession() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return emptySession();
    const parsed = JSON.parse(raw);
    return {
      user: parsed?.user || null,
    };
  } catch {
    return emptySession();
  }
}

export function saveSession({ user }) {
  localStorage.setItem(KEY, JSON.stringify({ user: user || null }));
}

export function clearSession() {
  localStorage.removeItem(KEY);
}
