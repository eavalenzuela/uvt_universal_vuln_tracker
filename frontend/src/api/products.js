import { apiFetch } from "./client.js";

export async function listProducts() {
  return apiFetch("/api/products", { method: "GET" });
}

export async function createProduct(data) {
  return apiFetch("/api/products", { method: "POST", body: data });
}
