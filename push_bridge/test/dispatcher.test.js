// test/dispatcher.test.js — on a new event for a pubkey the dispatcher pushes to
// each of its devices, coalesces bursts within a window, and prunes subscriptions
// the push service reports as gone (410/404). Uses an injected sender + clock.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Dispatcher } from '../src/dispatcher.js';

function fakeRegistry(initial) {
  const map = new Map(Object.entries(initial));
  return {
    get: (pk) => map.get(pk) || [],
    remove: (pk, endpoint) => {
      const subs = (map.get(pk) || []).filter((s) => s.endpoint !== endpoint);
      if (subs.length) map.set(pk, subs); else map.delete(pk);
      return true;
    },
    _map: map,
  };
}
const sub = (e) => ({ endpoint: e, keys: {} });

test('pushes to every subscription of the pubkey', async () => {
  const reg = fakeRegistry({ pk1: [sub('a'), sub('b')] });
  const sent = [];
  const d = new Dispatcher({ registry: reg, send: async (s) => { sent.push(s.endpoint); }, now: () => 0 });
  const r = await d.notify('pk1');
  assert.deepEqual(sent.sort(), ['a', 'b']);
  assert.equal(r.sent, 2);
  assert.equal(r.skipped, false);
});

test('coalesces a second notify within the window', async () => {
  const reg = fakeRegistry({ pk1: [sub('a')] });
  let t = 1000; const sent = [];
  const d = new Dispatcher({ registry: reg, send: async (s) => { sent.push(s.endpoint); }, now: () => t, coalesceMs: 4000 });
  await d.notify('pk1');            // t=1000 → sends
  t = 2000; const r = await d.notify('pk1'); // within 4s → skipped
  assert.equal(r.skipped, true);
  t = 6000; await d.notify('pk1');  // window elapsed → sends again
  assert.deepEqual(sent, ['a', 'a']);
});

test('removes a subscription the push service reports as 410 Gone', async () => {
  const reg = fakeRegistry({ pk1: [sub('gone'), sub('ok')] });
  const send = async (s) => { if (s.endpoint === 'gone') { const e = new Error('gone'); e.statusCode = 410; throw e; } };
  const d = new Dispatcher({ registry: reg, send, now: () => 0 });
  await d.notify('pk1');
  assert.deepEqual(reg.get('pk1').map((s) => s.endpoint), ['ok']); // 'gone' pruned
});

test('a send failure other than 410/404 does not prune the subscription', async () => {
  const reg = fakeRegistry({ pk1: [sub('flaky')] });
  const send = async () => { const e = new Error('boom'); e.statusCode = 500; throw e; };
  const d = new Dispatcher({ registry: reg, send, now: () => 0 });
  await d.notify('pk1');
  assert.deepEqual(reg.get('pk1').map((s) => s.endpoint), ['flaky']); // kept
});
