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

export async function apiFetch(path, { method = "GET", headers = {}, body = null } = {}) {
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

  const res = await fetch(url, { method, headers: finalHeaders, body: finalBody });

  const contentType = res.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  const payload = isJson ? await res.json().catch(() => null) : await res.text().catch(() => null);

  if (!res.ok) {
    const msg =
      (payload && payload.error) ||
      (typeof payload === "string" && payload) ||
      `HTTP ${res.status}`;
    throw new ApiError(msg, res.status, payload);
  }

  return payload;
}
