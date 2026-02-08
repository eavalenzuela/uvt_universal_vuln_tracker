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
const { listMyApiTokens, createMyApiToken, revokeMyApiToken } = await import('../../src/api/users.js');

test('users API token helpers hit expected endpoints', async () => {
  setSession({ token: 'smoke-token', user: { id: 2, role: 'Analyst' } });

  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ([]),
      text: async () => '',
    };
  };

  await listMyApiTokens();
  await createMyApiToken({ name: 'cli', scopes: ['products:read'], expires_in_days: 30 });
  await revokeMyApiToken(55);

  assert.equal(calls[0].url, 'http://api.local/api/users/me/api-tokens');
  assert.equal(calls[0].options.method, 'GET');

  assert.equal(calls[1].url, 'http://api.local/api/users/me/api-tokens');
  assert.equal(calls[1].options.method, 'POST');
  assert.equal(calls[1].options.body, JSON.stringify({ name: 'cli', scopes: ['products:read'], expires_in_days: 30 }));

  assert.equal(calls[2].url, 'http://api.local/api/users/me/api-tokens/55/revoke');
  assert.equal(calls[2].options.method, 'POST');
});
