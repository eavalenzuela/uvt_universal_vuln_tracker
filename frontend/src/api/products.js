import { apiFetch } from "./client.js";

export async function listProducts() {
  return apiFetch("/api/products", { method: "GET" });
}
