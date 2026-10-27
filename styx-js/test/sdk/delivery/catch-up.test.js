import { describe, test, expect, jest } from '@jest/globals';
import { createCatchUp } from '../../../src/sdk/delivery/catch-up.js';

function harness(count = 2) {
  let now = 200000;
  let live = true;
  let id = 0;
  const timers = new Map();
  const connected = new Set([0, 1]);
  let module;
  const resubscribe = jest.fn((index) => { if (connected.has(index)) module.subscriptionSince(index); });
  const clock = {
    now: () => now,
    setTimer: (fn, ms) => { timers.set(++id, { fn, ms }); return id; },
    clearTimer: (handle) => { timers.delete(handle); },
  };
  module = createCatchUp({ relayCount: count, subscriptionId: 'sub', clock, isRunning: () => live, resubscribe });
  return {
    module, clock, timers, connected, resubscribe,
    time(value) { now = value; },
    stop() { live = false; },
    tick() { const [key, timer] = timers.entries().next().value; timers.delete(key); timer.fn(); },
    eose(index = 0, sub = 'sub') { module.observe({ relayIndex: index, data: ['EOSE', sub] }); },
  };
}

describe('local-clock per-relay catch-up cursor', () => {
  test('no cursor before EOSE; earliest outstanding time, monotone cursor and 120-second margin', () => {
    const h = harness();
    expect(h.module.subscriptionSince(0)).toBeNull();
    h.time(240000);
    expect(h.module.subscriptionSince(0)).toBeNull();
    h.eose();
    expect(h.module.since(0)).toBe(80);
    h.eose(); // no outstanding: not the current clock
    expect(h.module.since(0)).toBe(80);
    h.time(190000); h.module.subscriptionSince(0); h.eose();
    expect(h.module.since(0)).toBe(80);
    h.time(260000); h.module.subscriptionSince(0); h.eose();
    expect(h.module.since(0)).toBe(140);
  });

  test('relays are independent; unrelated EOSE and all EVENT contents are irrelevant', () => {
    const h = harness();
    h.module.subscriptionSince(0);
    h.time(400000); h.module.subscriptionSince(1);
    h.eose(0, 'other'); h.eose(8);
    const event = { get created_at() { throw new Error('must not read EVENT'); } };
    h.module.observe({ relayIndex: 0, data: ['EVENT', 'sub', event] });
    expect(h.module.since(0)).toBeNull();
    h.eose(1);
    expect(h.module.since(1)).toBe(280);
    expect(h.module.since(0)).toBeNull();
    h.eose(0);
    expect(h.module.since(0)).toBe(80);
  });

  test.each([NaN, Infinity, -Infinity, '200000', null, undefined])('invalid clock %s records no request', (value) => {
    const h = harness(); h.time(value);
    h.module.subscriptionSince(0); h.eose();
    expect(h.module.since(0)).toBeNull();
  });

  test('throwing/rejecting clock is ignored and never installs a cursor', async () => {
    const h = harness();
    h.clock.now = () => { throw new Error('clock'); };
    expect(() => h.module.subscriptionSince(0)).not.toThrow(); h.eose();
    expect(h.module.since(0)).toBeNull();
    h.clock.now = () => Promise.reject(new Error('clock rejection'));
    h.module.subscriptionSince(0); h.eose();
    await Promise.resolve();
    expect(h.module.since(0)).toBeNull();
  });

  test('finite negative local clock is not narrowed; since is clamped at zero', () => {
    const h = harness(); h.time(-1);
    h.module.subscriptionSince(0); h.eose();
    expect(h.module.since(0)).toBe(0);
  });

  test('timer is armed on start only, repeats at 10000ms, with cursor or null; disconnected relay issues none', () => {
    const h = harness();
    expect(h.timers.size).toBe(0); // a failed client start never calls start
    h.module.subscriptionSince(0); h.eose();
    h.module.start(); h.module.start();
    expect(h.timers.size).toBe(1);
    expect([...h.timers.values()][0].ms).toBe(10000);
    h.tick();
    expect(h.resubscribe.mock.calls).toEqual([[0, 80], [1, null]]);
    h.eose(1); expect(h.module.since(1)).toBe(80);
    h.connected.delete(1); h.time(500000); h.tick(); h.eose(1);
    expect(h.module.since(1)).toBe(80);
    expect(h.timers.size).toBe(1);
    h.module.dispose(); expect(h.timers.size).toBe(0);
  });

  test('shutdown step 1 makes queued callback inert; step 4 clears the opaque handle', () => {
    const h = harness(); h.module.start();
    const callback = [...h.timers.values()][0].fn;
    h.stop(); h.module.freeze(); callback();
    expect(h.resubscribe).not.toHaveBeenCalled();
    expect(h.timers.size).toBe(1);
    h.module.dispose(); callback(); h.module.start();
    expect(h.timers.size).toBe(0);
    expect(h.resubscribe).not.toHaveBeenCalled();
  });

  test('null is a live opaque timer handle and is cleared on disposal', () => {
    const h = harness(); const clear = jest.fn();
    h.clock.setTimer = () => null; h.clock.clearTimer = clear;
    h.module.start(); h.module.dispose();
    expect(clear).toHaveBeenCalledWith(null);
  });

  test('model B: resubscribe throw/rejection/malformed return never records EOSE as success', async () => {
    const h = harness();
    h.resubscribe.mockImplementation(() => { throw new Error('seam'); });
    h.module.start(); expect(() => h.tick()).not.toThrow(); h.eose();
    expect(h.module.since(0)).toBeNull();
    h.resubscribe.mockImplementation(() => Promise.reject(new Error('seam')));
    h.tick(); await Promise.resolve(); h.eose();
    expect(h.module.since(0)).toBeNull();
    h.resubscribe.mockImplementation(() => ({ wrong: true })); h.tick(); h.eose();
    expect(h.module.since(0)).toBeNull();
    h.module.dispose(); expect(h.timers.size).toBe(0);
  });
});
