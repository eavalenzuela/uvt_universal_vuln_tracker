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
const { getMyPreferences, updateMyPreferences } = await import('../../src/api/userPreferences.js');

test('getMyPreferences issues a GET to /api/me/preferences', async () => {
  setSession({ token: 'smoke-token', user: { id: 1, role: 'Analyst' } });
  let captured;
  globalThis.fetch = async (url, options) => {
    captured = { url, options };
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ theme: 'auto' }),
      text: async () => '',
    };
  };
  const out = await getMyPreferences();
  assert.equal(out.theme, 'auto');
  assert.equal(captured.options.method, 'GET');
  assert.ok(captured.url.endsWith('/api/me/preferences'));
});

test('updateMyPreferences sends PUT with JSON body', async () => {
  setSession({ token: 'smoke-token', user: { id: 1, role: 'Analyst' } });
  let captured;
  globalThis.fetch = async (url, options) => {
    captured = { url, options };
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ theme: 'dark' }),
      text: async () => '',
    };
  };
  const out = await updateMyPreferences({ theme: 'dark' });
  assert.equal(out.theme, 'dark');
  assert.equal(captured.options.method, 'PUT');
  assert.equal(JSON.parse(captured.options.body).theme, 'dark');
});
