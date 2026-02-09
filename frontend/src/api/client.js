import { CONFIG } from "../config.js";
import { getState, logoutSession, setSession } from "../state/store.js";

export class ApiError extends Error {
  constructor(message, status, payload) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_RETRIES = 1;
const RETRY_STATUS = new Set([502, 503, 504]);
let refreshInFlight = null;

function getCookieValue(name) {
  if (typeof document === "undefined" || !document.cookie) return null;
  const prefix = `${encodeURIComponent(name)}=`;
  for (const part of document.cookie.split(";")) {
    const cookie = part.trim();
    if (cookie.startsWith(prefix)) {
      return decodeURIComponent(cookie.slice(prefix.length));
    }
  }
  return null;
}

function isWriteMethod(method) {
  const normalized = String(method || "GET").toUpperCase();
  return !["GET", "HEAD", "OPTIONS", "TRACE"].includes(normalized);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getErrorMessage(payload, status) {
  return (
    (payload && payload.error) ||
    (payload && payload.message) ||
    (typeof payload === "string" && payload) ||
    `HTTP ${status}`
  );
}

async function parsePayload(res) {
  if (res.status === 204 || res.status === 205) return null;
  const contentType = res.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  if (isJson) {
    return res.json().catch(() => null);
  }
  const text = await res.text().catch(() => null);
  return text === "" ? null : text;
}

async function tryRefreshToken() {
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

export async function apiFetch(
  path,
  {
    method = "GET",
    headers = {},
    body = null,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    retries = DEFAULT_RETRIES,
    retryDelayMs = 500,
    signal,
    _skipRefresh = false,
  } = {},
) {
  const url = `${CONFIG.API_BASE}${path.startsWith("/") ? "" : "/"}${path}`;

  const finalHeaders = {
    "Accept": "application/json",
    ...headers,
  };

  if (isWriteMethod(method) && !Object.keys(finalHeaders).some((h) => h.toLowerCase() === "x-csrf-token")) {
    const csrfToken = getCookieValue("uvt_csrf_token");
    if (csrfToken) finalHeaders["X-CSRF-Token"] = csrfToken;
  }

  let finalBody = body;
  if (body && typeof body === "object" && !(body instanceof FormData)) {
    finalHeaders["Content-Type"] = "application/json";
    finalBody = JSON.stringify(body);
  }

  let attempt = 0;
  let lastError;
  let activeController = null;
  let callerAborted = Boolean(signal?.aborted);

  const onCallerAbort = () => {
    callerAborted = true;
    if (activeController) {
      activeController.abort();
    }
  };

  if (signal) {
    if (callerAborted) {
      throw new ApiError("Request cancelled", 0, null);
    }
    signal.addEventListener("abort", onCallerAbort);
  }

  try {
    while (attempt <= retries) {
      attempt += 1;
      const controller = new AbortController();
      activeController = controller;
      let didTimeout = false;
      let timeoutId = null;

      if (timeoutMs) {
        timeoutId = setTimeout(() => {
          didTimeout = true;
          controller.abort();
        }, timeoutMs);
      }

      if (callerAborted) {
        throw new ApiError("Request cancelled", 0, null);
      }

      try {
        const res = await fetch(url, {
          method,
          headers: finalHeaders,
          body: finalBody,
          signal: controller.signal,
          credentials: "include",
        });

        const payload = await parsePayload(res);

        if (!res.ok) {
          if (res.status === 401 && !_skipRefresh && !path.endsWith("/auth/refresh") && !path.endsWith("/auth/login")) {
            const refreshed = await tryRefreshToken();
            if (refreshed) {
              return apiFetch(path, {
                method,
                headers,
                body,
                timeoutMs,
                retries,
                retryDelayMs,
                signal,
                _skipRefresh: true,
              });
            }
          }

          if (RETRY_STATUS.has(res.status) && attempt <= retries) {
            await sleep(retryDelayMs * attempt);
            continue;
          }
          throw new ApiError(getErrorMessage(payload, res.status), res.status, payload);
        }

        return payload;
      } catch (err) {
        if (timeoutId) clearTimeout(timeoutId);

        if (err?.name === "AbortError") {
          if (didTimeout) {
            lastError = new ApiError("Request timed out", 408, null);
          } else {
            lastError = new ApiError("Request cancelled", 0, null);
          }
        } else if (err instanceof ApiError) {
          lastError = err;
        } else {
          lastError = new ApiError("Network error", 0, null);
        }

        if (attempt <= retries && (lastError.status === 0 || RETRY_STATUS.has(lastError.status))) {
          await sleep(retryDelayMs * attempt);
          continue;
        }

        throw lastError;
      } finally {
        if (timeoutId) clearTimeout(timeoutId);
        if (activeController === controller) {
          activeController = null;
        }
      }
    }
  } finally {
    if (signal) {
      signal.removeEventListener("abort", onCallerAbort);
    }
  }

  throw lastError || new ApiError("Request failed", 0, null);
}
