import test from 'node:test';
import assert from 'node:assert/strict';

const storage = new Map();
globalThis.window = { __UVT_API_BASE__: 'http://api.local' };
globalThis.localStorage = {
  getItem: (k) => (storage.has(k) ? storage.get(k) : null),
  setItem: (k, v) => storage.set(k, String(v)),
  removeItem: (k) => storage.delete(k),
};

const { setSession } = await import('../../src/state/store.js');
const { exportVulnerabilities } = await import('../../src/api/reports.js');

test('reports API adapter smoke: builds query string and auth header', async () => {
  setSession({ token: 'smoke-token', user: { id: 1, role: 'Admin' } });

  let captured;
  globalThis.fetch = async (url, options) => {
    captured = { url, options };
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ ok: true }),
      text: async () => '',
    };
  };

  await exportVulnerabilities({ severity: 'High', status: 'Open', empty: '' }, 'csv');

  assert.equal(captured.url, 'http://api.local/api/reports/vulnerabilities/export?severity=High&status=Open&format=csv');
  assert.equal(captured.options.method, 'GET');
  assert.equal(captured.options.headers.Authorization, 'Bearer smoke-token');
});
