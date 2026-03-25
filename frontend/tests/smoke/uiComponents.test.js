import test from 'node:test';
import assert from 'node:assert/strict';

// Minimal DOM shim for node:test
globalThis.document = {
  createElement(tag) {
    const attrs = {};
    const children = [];
    const listeners = {};
    return {
      tagName: tag,
      className: '',
      textContent: '',
      disabled: false,
      style: {},
      setAttribute(k, v) { attrs[k] = v; },
      getAttribute(k) { return attrs[k]; },
      appendChild(c) { children.push(c); },
      addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
      dispatchEvent(type) { (listeners[type] || []).forEach(fn => fn({ currentTarget: this })); },
      _listeners: listeners,
      _children: children,
    };
  },
  createTextNode(text) { return { text }; },
};
globalThis.window = {};

test('withLoading disables button and shows loading text during async handler', async () => {
  const { withLoading } = await import('../../src/ui/components/loading.js');

  const btn = document.createElement('button');
  btn.textContent = 'Save';

  let resolveHandler;
  const handler = withLoading(
    () => new Promise((resolve) => { resolveHandler = resolve; }),
    { loadingText: 'Saving…' },
  );

  const promise = handler({ currentTarget: btn });

  assert.equal(btn.disabled, true);
  assert.equal(btn.textContent, 'Saving…');

  resolveHandler();
  await promise;

  assert.equal(btn.disabled, false);
  assert.equal(btn.textContent, 'Save');
});

test('withLoading restores button state on error', async () => {
  const { withLoading } = await import('../../src/ui/components/loading.js');

  const btn = document.createElement('button');
  btn.textContent = 'Delete';

  const handler = withLoading(
    () => Promise.reject(new Error('fail')),
    { loadingText: 'Deleting…' },
  );

  await handler({ currentTarget: btn }).catch(() => {});

  assert.equal(btn.disabled, false);
  assert.equal(btn.textContent, 'Delete');
});

test('withLoading skips if button is already disabled', async () => {
  const { withLoading } = await import('../../src/ui/components/loading.js');

  const btn = document.createElement('button');
  btn.textContent = 'Go';
  btn.disabled = true;

  let called = false;
  const handler = withLoading(() => { called = true; return Promise.resolve(); });

  await handler({ currentTarget: btn });
  assert.equal(called, false);
});
