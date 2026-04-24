import test from 'node:test';
import assert from 'node:assert/strict';

// Minimal DOM shim for the keybindings module under node:test.
globalThis.window = globalThis.window || { __UVT_API_BASE__: 'http://api.local' };
globalThis.document = globalThis.document || {
  body: {
    _attrs: {},
    getAttribute(k) { return this._attrs[k] ?? null; },
    setAttribute(k, v) { this._attrs[k] = v; },
    removeAttribute(k) { delete this._attrs[k]; },
  },
  addEventListener() {},
  removeEventListener() {},
  querySelector() { return null; },
  createElement() {
    return {
      _attrs: {},
      className: '',
      style: '',
      textContent: '',
      appendChild() {},
      addEventListener() {},
      remove() {},
      setAttribute(k, v) { this._attrs[k] = v; },
    };
  },
};

test('BINDINGS includes Dashboard navigation chord', async () => {
  const mod = await import('../../src/ui/keybindings.js');
  const { BINDINGS } = mod.__test;
  const dashboard = BINDINGS.find((b) => b.chord && b.chord[0] === 'g' && b.chord[1] === 'd');
  assert.ok(dashboard, 'expected g-d binding');
  assert.equal(dashboard.label, 'Go to Dashboard');
});

test('matchChord matches a defined chord and rejects undefined ones', async () => {
  const { matchChord } = (await import('../../src/ui/keybindings.js')).__test;
  assert.ok(matchChord('g', 'v'), 'g v should match Vulnerabilities');
  assert.equal(matchChord('g', 'q'), null, 'g q should not match');
});

test('matchSingle requires shift for ? binding', async () => {
  const { matchSingle } = (await import('../../src/ui/keybindings.js')).__test;
  const withShift = matchSingle({ key: '?', shiftKey: true, ctrlKey: false, metaKey: false, altKey: false });
  assert.ok(withShift);
  assert.equal(withShift.label, 'Show keyboard shortcuts');
});

test('admin-only chords require Admin role', async () => {
  const { matchChord } = (await import('../../src/ui/keybindings.js')).__test;
  // Non-admin: should not match admin chord
  globalThis.document.body.setAttribute('data-user-role', 'Viewer');
  assert.equal(matchChord('g', 'u'), null, 'Viewer should not access admin/users chord');

  // Admin: should match
  globalThis.document.body.setAttribute('data-user-role', 'Admin');
  const match = matchChord('g', 'u');
  assert.ok(match);
  assert.equal(match.label, 'Admin: Users');
});
