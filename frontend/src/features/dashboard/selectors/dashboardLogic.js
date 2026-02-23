const STATUS_OPTIONS = ["Open", "In Progress", "Resolved", "Closed"];

export function formatAge(value, nowMs = Date.now()) {
  if (!value) return "-";
  const deltaMs = nowMs - new Date(value).getTime();
  if (Number.isNaN(deltaMs)) return "-";
  const days = Math.floor(deltaMs / (1000 * 60 * 60 * 24));
  if (days <= 0) return "Today";
  return `${days}d`;
}

export function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleDateString();
}

export function parseRange(range, now = new Date()) {
  if (range === "Month to date") return new Date(now.getFullYear(), now.getMonth(), 1);
  if (range === "Quarter to date") {
    const quarterStartMonth = Math.floor(now.getMonth() / 3) * 3;
    return new Date(now.getFullYear(), quarterStartMonth, 1);
  }
  const match = range?.match(/Last\s+(\d+)\s+days/i);
  if (!match) return null;
  const start = new Date(now);
  start.setDate(start.getDate() - Number(match[1]));
  return start;
}

export function parseDueHorizon(range, now = new Date()) {
  if (range === "Month to date") return new Date(now.getFullYear(), now.getMonth() + 1, 0);
  if (range === "Quarter to date") {
    const quarterStartMonth = Math.floor(now.getMonth() / 3) * 3;
    return new Date(now.getFullYear(), quarterStartMonth + 3, 0);
  }
  const match = range?.match(/Last\s+(\d+)\s+days/i);
  if (!match) return null;
  const end = new Date(now);
  end.setDate(end.getDate() + Number(match[1]));
  return end;
}

export function filterByRange(items, range, field) {
  const start = parseRange(range);
  if (!start) return items;
  return (items || []).filter((item) => {
    const value = item?.[field];
    if (!value) return false;
    const date = new Date(value);
    return !Number.isNaN(date.getTime()) && date >= start;
  });
}

export function parseFilterList(filter, options = STATUS_OPTIONS) {
  if (!filter || filter === "All") return [];
  return filter.split(/[,/]/).map((entry) => entry.trim()).filter((entry) => options.includes(entry));
}

function updateTrendCount(summary, delta) {
  const buckets = Array.isArray(summary?.trend?.buckets) ? [...summary.trend.buckets] : [];
  if (!buckets.length || !delta) return buckets;
  const lastIndex = buckets.length - 1;
  const last = buckets[lastIndex] || {};
  const current = Number(last.count || 0);
  buckets[lastIndex] = { ...last, count: Math.max(0, current + delta) };
  return buckets;
}

export function applyDashboardMetricDelta(summary, event, widgetSettings = {}) {
  if (!summary || !event || event?.type !== "dashboard_metric_change") return summary;
  const payload = event.payload || {};
  const statusFilters = parseFilterList(widgetSettings.filter, STATUS_OPTIONS);
  const hasFilter = statusFilters.length > 0;
  const previousStatus = payload.previous_status;
  const nextStatus = payload.status;
  const wasIncluded = hasFilter ? statusFilters.includes(previousStatus) : previousStatus != null;
  const isIncluded = hasFilter ? statusFilters.includes(nextStatus) : nextStatus != null;

  let totalDelta = 0;
  if (payload.action === "created") totalDelta = isIncluded ? 1 : 0;
  else if (payload.action === "updated" || payload.action === "resolved") totalDelta = (isIncluded ? 1 : 0) - (wasIncluded ? 1 : 0);

  if (!totalDelta && payload.previous_severity === payload.severity) return summary;

  const bySeverity = { ...(summary.by_severity || {}) };
  if (payload.action === "created") {
    if (isIncluded && payload.severity) bySeverity[payload.severity] = (bySeverity[payload.severity] || 0) + 1;
  } else {
    if (wasIncluded && payload.previous_severity) bySeverity[payload.previous_severity] = Math.max(0, (bySeverity[payload.previous_severity] || 0) - 1);
    if (isIncluded && payload.severity) bySeverity[payload.severity] = (bySeverity[payload.severity] || 0) + 1;
  }

  return {
    ...summary,
    total: Math.max(0, Number(summary.total || 0) + totalDelta),
    by_severity: bySeverity,
    trend: { ...(summary.trend || {}), buckets: updateTrendCount(summary, totalDelta) },
  };
}
