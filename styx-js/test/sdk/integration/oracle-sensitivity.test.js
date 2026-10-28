import { describe, test, expect } from '@jest/globals';
import { assertSixHandles, matches, manualClock, assertWirePublication, assertDedupCounts, assertReceiptBoundary, assertAcceptanceDistinct, assertNoForbiddenPublish, assertClosed, assertFrozen, assertItem } from './loopback-harness.js';

// These are assertion sensitivity controls, not claimed production mutation runs.
// The same six-handle oracle is used by the real-client scenario test.
function conformingTrace() {
  return [
    { type: 'event', event: { state: 'LOST_ON_SHUTDOWN', deliveryId: 'a' } },
    { type: 'event', event: { state: 'LOST_ON_SHUTDOWN', deliveryId: 'b' } },
    ...[1, 2, 3, 4, 5, 6].map((handle) => ({ type: 'clear', handle })),
    { type: 'event', event: { clientState: 'STOPPED' } },
  ];
}
describe('T-RELAY assertion sensitivity (not runtime evidence)', () => {
  const handles = [1, 2, 3, 4, 5, 6];
  test('six-handle original accepted', () => assertSixHandles(conformingTrace(), handles));
  test.each(['omitted', 'duplicate-instead-of-other', 'before-LOST', 'after-STOPPED'])('six-handle %s rejected', (mutation) => {
    const trace = conformingTrace();
    if (mutation === 'omitted') trace.splice(4, 1);
    if (mutation === 'duplicate-instead-of-other') trace[4] = { type: 'clear', handle: 1 };
    if (mutation === 'before-LOST') trace.unshift(trace.splice(4, 1)[0]);
    if (mutation === 'after-STOPPED') trace.push(trace.splice(4, 1)[0]);
    expect(() => assertSixHandles(trace, handles)).toThrow();
  });
  test('filter isolates ids, kinds, #p and since, not only one permissive field', () => {
    const event = { id: 'id-a', kind: 4741, created_at: 12, tags: [['p', 'recipient-a']] };
    const filter = { ids: ['id-a'], kinds: [4741], '#p': ['recipient-a'], since: 12 };
    expect(matches(filter, event)).toBe(true);
    for (const wrong of [{ id: 'id-b' }, { kind: 4742 }, { created_at: 11 }, { tags: [['p', 'recipient-b']] }]) {
      expect(matches(filter, { ...event, ...wrong })).toBe(false);
    }
  });
  test('clock fires at exact boundaries, clear really removes and captured callback remains observable', async () => {
    const clock = manualClock(); const seen = [];
    const first = clock.clock.setTimer(() => seen.push(clock.now), 12);
    const second = clock.clock.setTimer(() => seen.push('forbidden'), 12);
    clock.clock.clearTimer(second); await clock.to(11); expect(seen).toEqual([]);
    await clock.to(12); expect(seen).toEqual([12]); expect(clock.timers.size).toBe(0);
    expect(clock.captured.has(first)).toBe(true); expect(clock.captured.has(second)).toBe(true);
    expect(clock.trace.filter((t) => t.type === 'fire').map((t) => t.handle)).toEqual([first]);
  });
  test('wire original accepted; REQ instead of EVENT and wrong relay rejected', () => {
    const observation = { relayIndex: 0, row: { type: 'in', frame: ['EVENT', { id: 'event-a' }] } };
    assertWirePublication(observation, 'event-a', 0);
    expect(() => assertWirePublication({ ...observation, relayIndex: 1 }, 'event-a', 0)).toThrow();
    expect(() => assertWirePublication({ ...observation, row: { type: 'in', frame: ['REQ', { id: 'event-a' }] } }, 'event-a', 0)).toThrow();
  });
  test.each(['opens', 'messages', 'receipts'])('dedup original accepted and duplicate %s rejected', (key) => {
    const counts = { opens: 2, messages: 2, receipts: 2, unique: 2 }; assertDedupCounts(counts);
    expect(() => assertDedupCounts({ ...counts, [key]: 3 })).toThrow();
  });
  test('acceptance is not a receipt or a terminal state', () => {
    assertAcceptanceDistinct({ state: 'RELAY_ACCEPTED_AWAITING_RECEIPT', terminal: false });
    expect(() => assertAcceptanceDistinct({ state: 'RECIPIENT_RECEIPT_RECEIVED', terminal: true })).toThrow();
  });
  test('deadline equality original late; altered equality acceptance rejected', () => {
    assertReceiptBoundary({ at: 132000, deadline: 132000, successful: false });
    assertReceiptBoundary({ at: 131999, deadline: 132000, successful: true });
    expect(() => assertReceiptBoundary({ at: 132000, deadline: 132000, successful: true })).toThrow();
  });
  test('forbidden publication, reopened terminal, wrong or unmapped recipient and leaked socket rejected by runtime oracles', () => {
    const recipient = '11'.repeat(32);
    const snapshot = { deliveryId: 'delivery-a', recipient, state: 'FAILED_NO_RECEIPT', terminal: true,
      attempts: 1, createdAt: 12000, deadlineAt: 132000, lastCode: null,
      relayOutcomes: [{ relayIndex: 0, outcome: 'ACCEPTED' }, { relayIndex: 1, outcome: 'ACCEPTED' }] };
    const role = { id: 'delivery-a', recipient, state: 'FAILED_NO_RECEIPT', outcomes: ['ACCEPTED', 'ACCEPTED'] };
    assertItem(snapshot, role);
    expect(() => assertItem({ ...snapshot, recipient: '22'.repeat(32) }, role)).toThrow();
    expect(() => assertItem(snapshot, { ...role, recipient: undefined })).toThrow();
    assertNoForbiddenPublish([]); expect(() => assertNoForbiddenPublish([['EVENT', {}]])).toThrow();
    const frozen = { state: 'FAILED_NO_RECEIPT', terminal: true }; assertFrozen({ ...frozen }, frozen);
    expect(() => assertFrozen({ state: 'RECIPIENT_RECEIPT_RECEIVED', terminal: true }, frozen)).toThrow();
    assertClosed({ sockets: 0, tcp: 0 });
    expect(() => assertClosed({ sockets: 1, tcp: 0 })).toThrow();
    expect(() => assertClosed({ sockets: 0, tcp: 1 })).toThrow();
  });
});
