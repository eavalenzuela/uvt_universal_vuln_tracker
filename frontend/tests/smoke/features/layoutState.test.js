import test from 'node:test';
import assert from 'node:assert/strict';

const storage = new Map();
globalThis.window = {};
globalThis.localStorage = {
  getItem: (k) => (storage.has(k) ? storage.get(k) : null),
  setItem: (k, v) => storage.set(k, String(v)),
  removeItem: (k) => storage.delete(k),
};

const {
  STORAGE_KEY,
  LOCAL_PRESETS_KEY,
  getDefaultLayoutState,
  normalizeLayoutState,
  loadDashboardState,
  saveDashboardState,
  loadLocalPresets,
  saveLocalPresets,
} = await import('../../../src/features/dashboard/state/layoutState.js');

const defaultWidgets = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];

test('getDefaultLayoutState returns all widget ids in order', () => {
  const state = getDefaultLayoutState(defaultWidgets);
  assert.deepEqual(state.order, ['a', 'b', 'c']);
  assert.deepEqual(state.visibility, {});
  assert.deepEqual(state.settings, {});
});

test('normalizeLayoutState fills missing widgets', () => {
  const state = normalizeLayoutState({ order: ['b'] }, defaultWidgets);
  assert.deepEqual(state.order, ['b', 'a', 'c']);
});

test('normalizeLayoutState handles null input', () => {
  const state = normalizeLayoutState(null, defaultWidgets);
  assert.deepEqual(state.order, ['a', 'b', 'c']);
});

test('saveDashboardState and loadDashboardState roundtrip', () => {
  storage.clear();
  const state = { order: ['c', 'a', 'b'], visibility: { a: false }, settings: {} };
  saveDashboardState(state, defaultWidgets);
  const loaded = loadDashboardState(defaultWidgets);
  assert.deepEqual(loaded.order, ['c', 'a', 'b']);
  assert.equal(loaded.visibility.a, false);
});

test('loadDashboardState returns null when no stored data', () => {
  storage.clear();
  assert.equal(loadDashboardState(defaultWidgets), null);
});

test('loadDashboardState handles corrupt data gracefully', () => {
  storage.set(STORAGE_KEY, '{{{invalid');
  const result = loadDashboardState(defaultWidgets);
  assert.equal(result, null);
});

test('saveLocalPresets and loadLocalPresets roundtrip', () => {
  storage.clear();
  saveLocalPresets([{ name: 'preset1' }]);
  const loaded = loadLocalPresets();
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].name, 'preset1');
});

test('loadLocalPresets returns empty array on corrupt data', () => {
  storage.set(LOCAL_PRESETS_KEY, '###');
  assert.deepEqual(loadLocalPresets(), []);
});

test('saveDashboardState handles QuotaExceededError gracefully', () => {
  const origSetItem = globalThis.localStorage.setItem;
  globalThis.localStorage.setItem = () => { throw new DOMException('quota exceeded', 'QuotaExceededError'); };
  assert.doesNotThrow(() => saveDashboardState({ order: ['a'] }, defaultWidgets));
  globalThis.localStorage.setItem = origSetItem;
});
