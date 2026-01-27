import { CONFIG } from "../config.js";
import { getState } from "../state/store.js";

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
  } = {},
) {
  const url = `${CONFIG.API_BASE}${path.startsWith("/") ? "" : "/"}${path}`;

  const state = getState();
  const token = state?.session?.token;

  const finalHeaders = {
    "Accept": "application/json",
    ...headers,
  };

  if (token) finalHeaders["Authorization"] = `Bearer ${token}`;

  let finalBody = body;
  if (body && typeof body === "object" && !(body instanceof FormData)) {
    finalHeaders["Content-Type"] = "application/json";
    finalBody = JSON.stringify(body);
  }

  let attempt = 0;
  let lastError;

  while (attempt <= retries) {
    attempt += 1;
    const controller = new AbortController();
    let didTimeout = false;
    let timeoutId = null;

    if (timeoutMs) {
      timeoutId = setTimeout(() => {
        didTimeout = true;
        controller.abort();
      }, timeoutMs);
    }

    if (signal) {
      if (signal.aborted) {
        throw new ApiError("Request cancelled", 0, null);
      }
      signal.addEventListener("abort", () => controller.abort(), { once: true });
    }

    try {
      const res = await fetch(url, {
        method,
        headers: finalHeaders,
        body: finalBody,
        signal: controller.signal,
      });

      const payload = await parsePayload(res);

      if (!res.ok) {
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
    }
  }

  throw lastError || new ApiError("Request failed", 0, null);
}
