import { CONFIG } from "../config.js";
import { getState, logoutSession, setSession } from "../state/store.js";

let refreshInFlight = null;

export async function parsePayload(res) {
  if (res.status === 204 || res.status === 205) return null;
  const contentType = res.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  if (isJson) {
    return res.json().catch(() => null);
  }
  const text = await res.text().catch(() => null);
  return text === "" ? null : text;
}

export async function tryRefreshToken() {
  if (refreshInFlight) return refreshInFlight;

  const state = getState();
  const refreshToken = state?.session?.refreshToken;
  if (!refreshToken) return false;

  refreshInFlight = (async () => {
    const url = `${CONFIG.API_BASE}/api/auth/refresh`;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
      credentials: "include",
    });
    const payload = await parsePayload(res);
    if (!res.ok || !payload?.token) {
      logoutSession();
      return false;
    }

    setSession({
      token: payload.token,
      refreshToken: payload.refresh_token || refreshToken || null,
      user: payload.user || state?.session?.user || null,
    });
    return true;
  })();

  try {
    return await refreshInFlight;
  } finally {
    refreshInFlight = null;
  }
}
