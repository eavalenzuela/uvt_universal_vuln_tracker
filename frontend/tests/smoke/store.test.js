import test from 'node:test';
import assert from 'node:assert/strict';

const storage = new Map();
globalThis.window = { __UVT_API_BASE__: 'http://127.0.0.1:5000' };
globalThis.localStorage = {
  getItem: (k) => (storage.has(k) ? storage.get(k) : null),
  setItem: (k, v) => storage.set(k, String(v)),
  removeItem: (k) => storage.delete(k),
};

const {
  getState,
  setSession,
  logoutSession,
  upsertNotification,
  removeNotification,
  setNotifications,
  markAllNotificationsReadLocal,
  pushLiveNotification,
  subscribe,
} = await import('../../src/state/store.js');

test('upsertNotification inserts new notification', () => {
  logoutSession();
  upsertNotification({ id: 1, message: 'hello', is_read: false });
  const items = getState().notifications.items;
  assert.equal(items.length, 1);
  assert.equal(items[0].message, 'hello');
  assert.equal(getState().notifications.unreadCount, 1);
});

test('upsertNotification updates existing notification by id', () => {
  logoutSession();
  upsertNotification({ id: 10, message: 'original', is_read: false });
  upsertNotification({ id: 10, message: 'updated', is_read: true });
  const items = getState().notifications.items;
  assert.equal(items.length, 1);
  assert.equal(items[0].message, 'updated');
  assert.equal(items[0].is_read, true);
  assert.equal(getState().notifications.unreadCount, 0);
});

test('upsertNotification appends when no id', () => {
  logoutSession();
  upsertNotification({ message: 'a' });
  upsertNotification({ message: 'b' });
  assert.equal(getState().notifications.items.length, 2);
});

test('upsertNotification caps at 50 items', () => {
  logoutSession();
  for (let i = 0; i < 55; i++) {
    upsertNotification({ message: `n${i}` });
  }
  assert.equal(getState().notifications.items.length, 50);
});

test('removeNotification removes by id', () => {
  logoutSession();
  upsertNotification({ id: 1, message: 'keep', is_read: false });
  upsertNotification({ id: 2, message: 'remove', is_read: false });
  removeNotification(2);
  const items = getState().notifications.items;
  assert.equal(items.length, 1);
  assert.equal(items[0].id, 1);
  assert.equal(getState().notifications.unreadCount, 1);
});

test('setNotifications replaces items and unread count', () => {
  logoutSession();
  setNotifications({ items: [{ id: 1, is_read: true }], unread_count: 0 });
  assert.equal(getState().notifications.items.length, 1);
  assert.equal(getState().notifications.unreadCount, 0);
});

test('markAllNotificationsReadLocal marks all as read', () => {
  logoutSession();
  upsertNotification({ id: 1, message: 'a', is_read: false });
  upsertNotification({ id: 2, message: 'b', is_read: false });
  assert.equal(getState().notifications.unreadCount, 2);
  markAllNotificationsReadLocal();
  assert.equal(getState().notifications.unreadCount, 0);
  assert.ok(getState().notifications.items.every((i) => i.is_read));
});

test('pushLiveNotification adds event and upserts notification', () => {
  logoutSession();
  pushLiveNotification({ type: 'mention', payload: { notification: { id: 99, message: 'mention', is_read: false } } });
  assert.equal(getState().liveNotifications.length, 1);
  assert.equal(getState().notifications.items.length, 1);
  assert.equal(getState().notifications.items[0].id, 99);
});

test('pushLiveNotification ignores invalid input', () => {
  logoutSession();
  pushLiveNotification(null);
  pushLiveNotification(undefined);
  assert.equal(getState().liveNotifications.length, 0);
});

test('logoutSession clears all state', () => {
  setSession({ token: 'tok', user: { id: 1, role: 'Admin' } });
  upsertNotification({ id: 1, message: 'n', is_read: false });
  pushLiveNotification({ type: 'test', payload: {} });
  logoutSession();
  const s = getState();
  assert.equal(s.session.token, null);
  assert.equal(s.session.user, null);
  assert.equal(s.notifications.items.length, 0);
  assert.equal(s.liveNotifications.length, 0);
});

test('subscribe emits on state changes', () => {
  let callCount = 0;
  const unsub = subscribe(() => { callCount += 1; });
  setSession({ token: 'x', user: { id: 1 } });
  assert.ok(callCount > 0);
  const before = callCount;
  unsub();
  setSession({ token: 'y', user: { id: 2 } });
  assert.equal(callCount, before);
});
