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
const { listOpenHighCriticalVulnerabilities } = await import('../../src/api/vulnerabilities.js');

test('vulnerabilities API helper uses a single multi-severity request', async () => {
  setSession({ token: 'smoke-token', user: { id: 1, role: 'Admin' } });

  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ items: [], total: 4, page: 2, page_size: 2 }),
      text: async () => '',
    };
  };

  const payload = await listOpenHighCriticalVulnerabilities({ page: 2, page_size: 2, sort: 'updated_at', order: 'desc' });

  assert.equal(calls.length, 1);
  assert.equal(
    calls[0].url,
    'http://api.local/api/vulnerabilities?severity=Critical%2CHigh&status=Open&sort=updated_at&order=desc&page=2&page_size=2'
  );
  assert.equal(payload.total, 4);
  assert.equal(payload.page, 2);
  assert.equal(payload.page_size, 2);
});
