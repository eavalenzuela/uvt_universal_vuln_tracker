const KEY = "uvt_session_v1";

function emptySession() {
  return { user: null, teams: [], currentTeamId: null };
}

export function loadSession() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return emptySession();
    const parsed = JSON.parse(raw);
    return {
      user: parsed?.user || null,
      teams: Array.isArray(parsed?.teams) ? parsed.teams : [],
      currentTeamId: Number.isInteger(parsed?.currentTeamId) ? parsed.currentTeamId : null,
    };
  } catch {
    return emptySession();
  }
}

export function saveSession({ user, teams, currentTeamId }) {
  localStorage.setItem(
    KEY,
    JSON.stringify({
      user: user || null,
      teams: Array.isArray(teams) ? teams : [],
      currentTeamId: Number.isInteger(currentTeamId) ? currentTeamId : null,
    }),
  );
}

export function clearSession() {
  localStorage.removeItem(KEY);
}
