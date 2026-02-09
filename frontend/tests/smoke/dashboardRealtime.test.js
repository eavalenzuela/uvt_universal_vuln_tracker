import test from 'node:test';
import assert from 'node:assert/strict';

const storage = new Map();
globalThis.window = { __UVT_API_BASE__: 'http://api.local' };
globalThis.localStorage = {
  getItem: (k) => (storage.has(k) ? storage.get(k) : null),
  setItem: (k, v) => storage.set(k, String(v)),
  removeItem: (k) => storage.delete(k),
};

test('dashboard metric delta incrementally updates overview totals', async () => {
  const { applyDashboardMetricDelta } = await import('../../src/views/dashboard/dashboardView.js');

  const summary = {
    total: 2,
    by_severity: { Critical: 1, High: 1 },
    trend: { buckets: [{ label: '2026-01-01', count: 2 }] },
  };

  const created = applyDashboardMetricDelta(
    summary,
    {
      type: 'dashboard_metric_change',
      payload: { action: 'created', status: 'Open', severity: 'High' },
    },
    { filter: 'Open,In Progress' },
  );

  assert.equal(created.total, 3);
  assert.equal(created.by_severity.High, 2);
  assert.equal(created.trend.buckets[0].count, 3);

  const resolved = applyDashboardMetricDelta(
    created,
    {
      type: 'dashboard_metric_change',
      payload: {
        action: 'resolved',
        previous_status: 'Open',
        status: 'Resolved',
        previous_severity: 'High',
        severity: 'High',
      },
    },
    { filter: 'Open,In Progress' },
  );

  assert.equal(resolved.total, 2);
  assert.equal(resolved.by_severity.High, 1);
  assert.equal(resolved.trend.buckets[0].count, 2);
});
