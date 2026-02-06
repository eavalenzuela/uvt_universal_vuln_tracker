import { apiFetch } from "./client.js";

export function listComponents(productVersionId) {
  return apiFetch(`/api/product_versions/${productVersionId}/components`, { method: "GET" });
}

export function importSbom(productVersionId, { format, sbom }) {
  return apiFetch(`/api/product_versions/${productVersionId}/sbom`, {
    method: "POST",
    body: { format, sbom },
  });
}
