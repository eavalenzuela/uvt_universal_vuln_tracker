import { el } from "../../../ui/dom/el.js";
import { toast } from "../../../ui/components/toast.js";
import {
  listProductVersions,
  listAttackVectors,
  listTerminalImpacts,
} from "../../../api/vulnerabilities.js";


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
  const cls = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low", None: "badge-none" };
  return el("span", { class: `badge ${cls[severity] || "badge-none"}` }, severity || "Unknown");
}

export function slaBadge(state) {
  const cls = { breached: "badge-sla-breached", due_soon: "badge-sla-due-soon", on_track: "badge-sla-on-track", met: "badge-sla-met" };
  const label = { breached: "SLA breached", due_soon: "Due soon", on_track: "On track", met: "SLA met" };
  return el("span", { class: `badge ${cls[state] || "badge-sla-on-track"}` }, label[state] || "On track");
}

export function statusPill(status) {
  const cls = { Open: "pill-open", "In Progress": "pill-in-progress", Resolved: "pill-resolved", Closed: "pill-closed" };
  return el("span", { class: `badge ${cls[status] || "pill-open"}` }, status || "-");
}

export function kevBadge(vuln) {
  if (!vuln?.known_exploited) return null;
  const title = vuln.kev_date_added
    ? `In the CISA Known Exploited Vulnerabilities catalog since ${vuln.kev_date_added}`
    : "In the CISA Known Exploited Vulnerabilities catalog";
  return el("span", { class: "badge badge-kev", title }, "KEV");
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
