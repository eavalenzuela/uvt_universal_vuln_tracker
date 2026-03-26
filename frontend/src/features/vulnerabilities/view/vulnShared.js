import { el } from "../../../ui/dom/el.js";
import { toast } from "../../../ui/components/toast.js";
import {
  listProductVersions,
  listAttackVectors,
  listTerminalImpacts,
} from "../../../api/vulnerabilities.js";
import { severityPalette, slaPalette } from "../selectors/formatters.js";

export const STATUS_OPTIONS = ["Open", "In Progress", "Resolved", "Closed"];
export const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low", "None"];
export const ATTACK_COMPLEXITY_OPTIONS = ["Not Defined", "Low", "High"];
export const IMPACT_OPTIONS = ["Not Defined", "None", "Low", "Medium", "High"];
export const MITIGATION_OPTIONS = ["Not Started", "Investigating", "In Progress", "Mitigated", "Not Applicable"];

const CACHE_TTL_MS = 5 * 60 * 1000;
let cachedProductVersions = null;
let cachedProductVersionsAt = 0;
let cachedAttackVectors = null;
let cachedAttackVectorsAt = 0;
let cachedTerminalImpacts = null;
let cachedTerminalImpactsAt = 0;

export function severityBadge(severity) {
  const palette = severityPalette(severity);
  return el("span", { class: "badge", style: `background: ${palette.bg}; color: ${palette.color}; border: 1px solid #e2e8f0;` }, severity || "Unknown");
}

export function slaBadge(state) {
  const cfg = slaPalette(state);
  return el("span", { class: "badge", style: `background:${cfg.bg}; color:${cfg.color}; border:1px solid ${cfg.border};` }, cfg.label);
}

export function statusPill(status) {
  return el(
    "span",
    {
      class: "badge",
      style: "background: #eef2ff; color: #312e81; border: 1px solid #c7d2fe;",
    },
    status || "-",
  );
}

export async function ensureProductVersions() {
  if (cachedProductVersions && Date.now() - cachedProductVersionsAt < CACHE_TTL_MS) return cachedProductVersions;
  try {
    cachedProductVersions = await listProductVersions();
    cachedProductVersionsAt = Date.now();
    return cachedProductVersions;
  } catch (err) {
    toast({ title: "Failed to load versions", message: err?.message || "Unable to list product versions" });
    cachedProductVersions = [];
    return cachedProductVersions;
  }
}

export async function ensureAttackVectors() {
  if (cachedAttackVectors && Date.now() - cachedAttackVectorsAt < CACHE_TTL_MS) return cachedAttackVectors;
  try {
    cachedAttackVectors = await listAttackVectors();
    cachedAttackVectorsAt = Date.now();
    return cachedAttackVectors;
  } catch (err) {
    toast({ title: "Failed to load attack vectors", message: err?.message || "Unable to list attack vectors" });
    cachedAttackVectors = [];
    return cachedAttackVectors;
  }
}

export async function ensureTerminalImpacts() {
  if (cachedTerminalImpacts && Date.now() - cachedTerminalImpactsAt < CACHE_TTL_MS) return cachedTerminalImpacts;
  try {
    cachedTerminalImpacts = await listTerminalImpacts();
    cachedTerminalImpactsAt = Date.now();
    return cachedTerminalImpacts;
  } catch (err) {
    toast({ title: "Failed to load terminal impacts", message: err?.message || "Unable to list terminal impacts" });
    cachedTerminalImpacts = [];
    return cachedTerminalImpacts;
  }
}
