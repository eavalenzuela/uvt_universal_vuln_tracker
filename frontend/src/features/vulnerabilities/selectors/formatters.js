export function formatDate(value) {
  return value ? value.slice(0, 10) : "-";
}

export function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString();
}

export function severityPalette(severity) {
  const colors = { Critical: "#7f1d1d", High: "#b45309", Medium: "#92400e", Low: "#365314", None: "#334155" };
  const bg = { Critical: "#fef2f2", High: "#fffbeb", Medium: "#fffbeb", Low: "#f0fdf4", None: "#f8fafc" };
  return { color: colors[severity] || "#0f172a", bg: bg[severity] || "#f8fafc" };
}

export function slaPalette(state) {
  const palette = {
    breached: { bg: "#fef2f2", color: "#991b1b", border: "#fecaca", label: "SLA breached" },
    due_soon: { bg: "#fffbeb", color: "#92400e", border: "#fde68a", label: "Due soon" },
    on_track: { bg: "#ecfeff", color: "#155e75", border: "#a5f3fc", label: "On track" },
    met: { bg: "#f0fdf4", color: "#166534", border: "#bbf7d0", label: "SLA met" },
  };
  return palette[state] || palette.on_track;
}
