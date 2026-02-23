import { listVulnerabilities, getVulnerability, listOpenHighCriticalVulnerabilities } from "../../../api/vulnerabilities.js";
import { getRiskTrends } from "../../../api/reports.js";

export async function listVulnerabilitiesWithFilters({ statusFilters, severityFilters, ...params }) {
  return listVulnerabilities({
    ...params,
    status: statusFilters?.length ? statusFilters.join(",") : undefined,
    severity: severityFilters?.length ? severityFilters.join(",") : undefined,
  });
}

export async function loadRiskTrendData(widgetSettings) {
  const range = widgetSettings.range || "Last 30 days";
  const productFilter = (widgetSettings.productFilter || "").trim();
  return getRiskTrends({ range, bucket: widgetSettings.grouping || "week", product_ids: productFilter || undefined });
}

export async function loadHighRiskVulnerabilityDetails(params) {
  const data = await listOpenHighCriticalVulnerabilities(params);
  const details = await Promise.all((data.items || []).map(async (item) => {
    try {
      const detail = await getVulnerability(item.id);
      return { ...item, detail };
    } catch {
      return { ...item, detail: null };
    }
  }));
  return details;
}
