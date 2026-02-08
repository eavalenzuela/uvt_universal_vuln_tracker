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


export function compareProductVersionComponents({ fromProductVersionId, toProductVersionId }) {
  const params = new URLSearchParams();
  params.set("from_product_version_id", String(fromProductVersionId));
  params.set("to_product_version_id", String(toProductVersionId));
  return apiFetch(`/api/product_versions/compare/components?${params.toString()}`, { method: "GET" });
}
