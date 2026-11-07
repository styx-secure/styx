// test/chat/inbound-payload.test.js — the validation predicates shared by the
// inbound path and by the load-time cleaning of stored records.
import { describe, test, expect } from '@jest/globals';
import {
  INBOUND_DISCARD_REASONS,
  MAX_MESSAGE_ID_LENGTH,
  MAX_MESSAGE_TEXT_LENGTH,
  MAX_MESSAGE_TS,
  MIN_MESSAGE_TS,
  classifyInboundPayload,
  isValidMessageTs,
  normalizeStoredMessages,
} from '../../src/chat/inbound-payload.js';

const PEER = 'b'.repeat(64);
const TS = 1_780_000_000_000;

describe('inbound-payload', () => {
  test('bounds', () => {
    expect(MAX_MESSAGE_ID_LENGTH).toBe(128);
    expect(MAX_MESSAGE_TEXT_LENGTH).toBe(65_536);
    expect(MIN_MESSAGE_TS).toBe(1);
    expect(MAX_MESSAGE_TS).toBe(8_640_000_000_000_000);
    expect(isValidMessageTs(MIN_MESSAGE_TS)).toBe(true);
    expect(isValidMessageTs(MIN_MESSAGE_TS - 1)).toBe(false);
    expect(isValidMessageTs(MAX_MESSAGE_TS)).toBe(true);
    expect(isValidMessageTs(MAX_MESSAGE_TS + 1)).toBe(false);
    expect(isValidMessageTs(Number.MAX_SAFE_INTEGER)).toBe(false);
    expect(isValidMessageTs(1.5)).toBe(false);
  });

  test('discard reasons are a fixed, frozen list', () => {
    expect(INBOUND_DISCARD_REASONS).toEqual([
      'malformed-payload', 'unknown-type', 'invalid-id', 'invalid-text',
      'invalid-ts', 'invalid-receipt', 'invalid-intro',
    ]);
    expect(Object.isFrozen(INBOUND_DISCARD_REASONS)).toBe(true);
  });

  test('classifies the three payload types', () => {
    expect(classifyInboundPayload({ t: 'msg', id: 'a', text: 'b', ts: TS }))
      .toEqual({ kind: 'msg', id: 'a', text: 'b', ts: TS });
    expect(classifyInboundPayload({ t: 'intro', alias: 'x' })).toEqual({ kind: 'intro', alias: 'x' });
    expect(classifyInboundPayload({ t: 'receipt', ref: 'a', kind: 'delivered' }))
      .toEqual({ kind: 'receipt', ref: 'a', receipt: 'delivered' });
    expect(classifyInboundPayload(null)).toEqual({ kind: 'discard', reason: 'malformed-payload' });
  });

  test('accessor and inherited fields are not read', () => {
    let ran = false;
    const accessor = { t: 'msg', id: 'id-1', text: 'ciao', get ts() { ran = true; return TS; } };
    expect(classifyInboundPayload(accessor)).toEqual({ kind: 'discard', reason: 'invalid-ts' });
    expect(ran).toBe(false);
    const inherited = Object.assign(Object.create({ ts: TS }), { t: 'msg', id: 'id-1', text: 'ciao' });
    expect(classifyInboundPayload(inherited)).toEqual({ kind: 'discard', reason: 'malformed-payload' });
  });

  test('normalizeStoredMessages keeps valid records and drops malformed ones', () => {
    const good = { id: 'g1', contactPubkey: PEER, direction: 'in', text: 'ok', ts: TS, state: 'delivered' };
    const { messages, dropped } = normalizeStoredMessages({
      [PEER]: [
        good,
        { ...good, id: 'p1', ts: { valueOf: 0, toString: 0 } },
        { ...good, id: { toString: 0 } },
        { ...good, id: 'p3', text: { toString: 0 } },
        { ...good, id: 'p4', contactPubkey: 'c'.repeat(64) },
        { ...good, id: 'p5', direction: 'sideways' },
        null,
      ],
      other: 'not a list',
    });
    expect(messages).toEqual({ [PEER]: [good] });
    expect(dropped).toBe(6);
    expect(normalizeStoredMessages(null)).toEqual({ messages: {}, dropped: 0 });
    expect(normalizeStoredMessages([good])).toEqual({ messages: {}, dropped: 0 });
    expect(normalizeStoredMessages({ [PEER]: [{ ...good, state: 7 }] }).messages[PEER][0].state).toBeNull();
  });
});
