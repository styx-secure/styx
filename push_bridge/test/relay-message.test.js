// test/relay-message.test.js — the bridge only reacts to *new* kind-1059 events
// addressed (p-tag) to a *watched* pubkey. Ephemeral (20000), unwatched, wrong
// kind, non-EVENT, and replayed events must all be ignored.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleRelayMessage } from '../src/relay-message.js';

const watched = new Set(['pkA']);
const ev = (kind, pTag, id) => ['EVENT', 'sub', { id, kind, tags: [['p', pTag]] }];

test('returns recipient + eventId for a new kind-1059 to a watched pubkey', () => {
  const seen = new Set();
  assert.deepEqual(handleRelayMessage(ev(1059, 'pkA', 'e1'), seen, watched), { pubkey: 'pkA', eventId: 'e1' });
});

test('ignores ephemeral kind 20000', () => {
  assert.equal(handleRelayMessage(ev(20000, 'pkA', 'e2'), new Set(), watched), null);
});

test('ignores an event addressed to an unwatched pubkey', () => {
  assert.equal(handleRelayMessage(ev(1059, 'pkZ', 'e3'), new Set(), watched), null);
});

test('ignores a replayed event id (already seen)', () => {
  const seen = new Set(['e4']);
  assert.equal(handleRelayMessage(ev(1059, 'pkA', 'e4'), seen, watched), null);
});

test('marks an event id as seen so the next identical replay is ignored', () => {
  const seen = new Set();
  handleRelayMessage(ev(1059, 'pkA', 'e5'), seen, watched);
  assert.equal(seen.has('e5'), true);
  assert.equal(handleRelayMessage(ev(1059, 'pkA', 'e5'), seen, watched), null);
});

test('ignores non-EVENT relay frames (EOSE/NOTICE)', () => {
  assert.equal(handleRelayMessage(['EOSE', 'sub'], new Set(), watched), null);
  assert.equal(handleRelayMessage(['NOTICE', 'hi'], new Set(), watched), null);
});
