import { apiFetch } from "./client.js";

export async function listProducts() {
  return apiFetch("/api/products", { method: "GET" });
}

export async function createProduct(data) {
  return apiFetch("/api/products", { method: "POST", body: data });
}

export async function getProduct(productId) {
  return apiFetch(`/api/products/${productId}`, { method: "GET" });
}

export async function updateProduct(productId, data) {
  return apiFetch(`/api/products/${productId}`, { method: "PATCH", body: data });
}

export async function deleteProduct(productId) {
  return apiFetch(`/api/products/${productId}`, { method: "DELETE" });
}

export async function createProductVersion(productId, data) {
  return apiFetch(`/api/products/${productId}/versions`, { method: "POST", body: data });
}

export async function updateProductVersion(productId, versionId, data) {
  return apiFetch(`/api/products/${productId}/versions/${versionId}`, { method: "PATCH", body: data });
}

export async function deleteProductVersion(productId, versionId) {
  return apiFetch(`/api/products/${productId}/versions/${versionId}`, { method: "DELETE" });
}
