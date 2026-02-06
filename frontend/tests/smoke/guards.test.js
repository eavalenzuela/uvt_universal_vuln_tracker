import test from 'node:test';
import assert from 'node:assert/strict';

const storage = new Map();
globalThis.window = { __UVT_API_BASE__: 'http://127.0.0.1:5000' };
globalThis.localStorage = {
  getItem: (k) => (storage.has(k) ? storage.get(k) : null),
  setItem: (k, v) => storage.set(k, String(v)),
  removeItem: (k) => storage.delete(k),
};

const { setSession } = await import('../../src/state/store.js');
const { requireAuth, requireRole } = await import('../../src/router/guards.js');

test('route guard smoke: requires auth and expected role', () => {
  setSession({ token: null, user: null });
  assert.equal(requireAuth(), false);

  setSession({ token: 'test-token', user: { id: 1, role: 'Analyst' } });
  assert.equal(requireAuth(), true);
  assert.equal(requireRole('Admin'), false);
  assert.equal(requireRole('Admin', 'Analyst'), true);
});
