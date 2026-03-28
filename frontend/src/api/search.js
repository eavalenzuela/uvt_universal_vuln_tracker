import { apiFetch } from "./client.js";

export async function globalSearch(query) {
  return apiFetch(`/api/search?q=${encodeURIComponent(query)}`);
}
