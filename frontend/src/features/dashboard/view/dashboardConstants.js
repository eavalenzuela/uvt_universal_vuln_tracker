import { el } from "../../../ui/dom/el.js";
import { listActiveUsers } from "../../../api/users.js";

export const DEFAULT_WIDGETS = [
  {
    id: "risk-overview",
    title: "Risk Overview Summary",
    description: "KPI snapshot with trend insights.",
    settings: { filter: "Open", range: "Last 14 days", grouping: "Severity" },
    groupings: ["Severity", "Status"],
  },
  {
    id: "recent-updates",
    title: "Recently Updated Vulns",
    description: "Latest changes across the program.",
    settings: { filter: "All", range: "Last 7 days", grouping: "Severity" },
    groupings: ["Severity", "Status"],
  },
  {
    id: "sla-due",
    title: "SLA / Due Soon",
    description: "Deadlines based on severity SLA windows.",
    settings: { filter: "Open,In Progress", range: "Last 14 days", grouping: "Severity" },
    groupings: ["Severity", "Status", "Assignee"],
  },
  {
    id: "top-assets",
    title: "Top Affected Assets/Apps",
    description: "Most impacted products and versions.",
    settings: { filter: "All", range: "Last 30 days", grouping: "Product" },
    groupings: ["Product", "Product Version"],
  },
  {
    id: "risk-trends",
    title: "Risk Trends by Product",
    description: "Trend chart by product and version risk metrics.",
    settings: { filter: "All", range: "Last 30 days", grouping: "week", productFilter: "" },
    groupings: ["day", "week", "month"],
  },
  {
    id: "top-risk-products",
    title: "Top Risk Products",
    description: "Product versions with highest weighted risk posture.",
    settings: { filter: "All", range: "Last 30 days", grouping: "week", productFilter: "" },
    groupings: ["day", "week", "month"],
  },
  {
    id: "my-work",
    title: "My Assigned Work",
    description: "Items assigned to you right now.",
    settings: { filter: "Open,In Progress", range: "Last 30 days", grouping: "Status" },
    groupings: ["Status", "Severity"],
  },
];

export const STATUS_OPTIONS = ["Open", "In Progress", "Resolved", "Closed"];
export const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low", "None"];
export const RANGE_OPTIONS = ["Last 7 days", "Last 14 days", "Last 30 days", "Quarter to date", "Month to date"];
export const WIDGET_BORDER = "rgba(148, 163, 184, 0.25)";
export const WIDGET_BG = "rgba(15, 23, 42, 0.7)";
export const WIDGET_SURFACE = "rgba(30, 41, 59, 0.7)";
export const WIDGET_SUBTLE = "rgba(148, 163, 184, 0.18)";
export const WIDGET_BORDER_HIGHLIGHT = "rgba(106, 169, 255, 0.9)";
export const DASHBOARD_SUMMARY_POLL_MS = 30000;

export function renderSparkline(values) {
  const width = 140;
  const height = 38;
  if (!values.length) {
    return el("div", { class: "muted", text: "No trend data." });
  }
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const scale = max - min || 1;
  const points = values.map((value, index) => {
    const x = (index / (values.length - 1 || 1)) * (width - 8) + 4;
    const y = height - ((value - min) / scale) * (height - 8) - 4;
    return `${x},${y}`;
  });
  const svg = el("svg", { width, height, viewBox: `0 0 ${width} ${height}`, style: "display:block;" });
  svg.append(
    el("polyline", {
      points: points.join(" "),
      fill: "none",
      stroke: "#2563eb",
      "stroke-width": "2",
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
    }),
  );
  return svg;
}

export function severityBadge(severity) {
  const cls = {
    Critical: "badge-critical",
    High: "badge-high",
    Medium: "badge-medium",
    Low: "badge-low",
    None: "badge-none",
  };
  return el(
    "span",
    { class: `badge ${cls[severity] || "badge-none"}` },
    severity || "Unknown",
  );
}

let cachedUsers = null;
export async function ensureActiveUsers() {
  if (cachedUsers) return cachedUsers;
  try {
    cachedUsers = await listActiveUsers();
    return cachedUsers;
  } catch (error) {
    console.warn("Unable to load active users.", error);
    cachedUsers = [];
    return cachedUsers;
  }
}
