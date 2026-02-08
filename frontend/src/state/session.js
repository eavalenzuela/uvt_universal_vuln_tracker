const KEY = "uvt_session_v1";

export function loadSession() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { token: null, refreshToken: null, user: null };
    const parsed = JSON.parse(raw);
    return {
      token: parsed.token || null,
      refreshToken: parsed.refreshToken || null,
      user: parsed.user || null,
    };
  } catch {
    return { token: null, refreshToken: null, user: null };
  }
}

export function saveSession({ token, refreshToken, user }) {
  localStorage.setItem(KEY, JSON.stringify({ token, refreshToken, user }));
}

export function clearSession() {
  localStorage.removeItem(KEY);
}
