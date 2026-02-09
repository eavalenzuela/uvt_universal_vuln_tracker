import test from 'node:test';
import assert from 'node:assert/strict';

const storage = new Map();
globalThis.window = { __UVT_API_BASE__: 'http://api.local' };
globalThis.localStorage = {
  getItem: (k) => (storage.has(k) ? storage.get(k) : null),
  setItem: (k, v) => storage.set(k, String(v)),
  removeItem: (k) => storage.delete(k),
};

test('api client uses a single caller abort bridge across retries', async () => {
  const { apiFetch } = await import('../../src/api/client.js');

  const externalController = new AbortController();
  const signal = externalController.signal;

  const originalAdd = signal.addEventListener.bind(signal);
  const originalRemove = signal.removeEventListener.bind(signal);
  let activeAbortListeners = 0;
  let maxAbortListeners = 0;

  signal.addEventListener = (type, listener, options) => {
    if (type === 'abort') {
      activeAbortListeners += 1;
      maxAbortListeners = Math.max(maxAbortListeners, activeAbortListeners);
    }
    return originalAdd(type, listener, options);
  };

  signal.removeEventListener = (type, listener, options) => {
    if (type === 'abort') {
      activeAbortListeners = Math.max(0, activeAbortListeners - 1);
    }
    return originalRemove(type, listener, options);
  };

  let attempts = 0;
  globalThis.fetch = async () => {
    attempts += 1;
    if (attempts < 3) {
      return {
        ok: false,
        status: 503,
        headers: { get: () => 'application/json' },
        json: async () => ({ error: 'retry please' }),
        text: async () => '',
      };
    }
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ ok: true }),
      text: async () => '',
    };
  };

  const payload = await apiFetch('/api/test', {
    retries: 2,
    retryDelayMs: 1,
    signal,
  });

  assert.deepEqual(payload, { ok: true });
  assert.equal(attempts, 3);
  assert.equal(maxAbortListeners, 1);
  assert.equal(activeAbortListeners, 0);
});

test('api client distinguishes timeout abort from caller abort', async () => {
  const { apiFetch } = await import('../../src/api/client.js');

  globalThis.fetch = async (_url, { signal }) => {
    await new Promise((resolve, reject) => {
      signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true });
      setTimeout(resolve, 40);
    });

    return {
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ ok: true }),
      text: async () => '',
    };
  };

  await assert.rejects(
    () => apiFetch('/api/timeout', { timeoutMs: 5, retries: 0 }),
    (err) => err?.message === 'Request timed out' && err?.status === 408,
  );

  const callerController = new AbortController();
  setTimeout(() => callerController.abort(), 5);

  await assert.rejects(
    () => apiFetch('/api/cancel', { timeoutMs: 100, retries: 0, signal: callerController.signal }),
    (err) => err?.message === 'Request cancelled' && err?.status === 0,
  );
});
