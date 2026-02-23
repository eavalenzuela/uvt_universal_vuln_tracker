import test from "node:test";
import assert from "node:assert/strict";
import { parseRange, parseDueHorizon, applyDashboardMetricDelta, parseFilterList } from "../../../src/features/dashboard/selectors/dashboardLogic.js";

test("parseRange handles last days", () => {
  const now = new Date("2026-01-15T00:00:00Z");
  const start = parseRange("Last 7 days", now);
  assert.equal(start.toISOString().slice(0, 10), "2026-01-08");
});

test("parseDueHorizon handles month to date", () => {
  const now = new Date("2026-02-10T00:00:00Z");
  const end = parseDueHorizon("Month to date", now);
  assert.equal(end.toISOString().slice(0, 10), "2026-02-28");
});

test("applyDashboardMetricDelta updates totals and severity", () => {
  const summary = { total: 2, by_severity: { High: 1 }, trend: { buckets: [{ count: 2 }] } };
  const event = { type: "dashboard_metric_change", payload: { action: "created", status: "Open", severity: "High" } };
  const next = applyDashboardMetricDelta(summary, event, { filter: "Open" });
  assert.equal(next.total, 3);
  assert.equal(next.by_severity.High, 2);
  assert.equal(next.trend.buckets[0].count, 3);
});

test("parseFilterList normalizes All", () => {
  assert.deepEqual(parseFilterList("All", ["Open"]), []);
});
