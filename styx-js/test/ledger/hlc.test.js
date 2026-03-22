// test/ledger/hlc.test.js
import { describe, test, expect } from '@jest/globals';
import { HybridLogicalClock } from '../../src/ledger/hlc.js';

describe('HybridLogicalClock', () => {
  test('constructor sets timestamp, counter, nodeId', () => {
    const ts = new Date('2026-01-15T10:00:00.000Z');
    const hlc = new HybridLogicalClock(ts, 5, 'a1b2c3d4');
    expect(hlc.timestamp).toEqual(ts);
    expect(hlc.counter).toBe(5);
    expect(hlc.nodeId).toBe('a1b2c3d4');
  });

  test('is frozen after construction', () => {
    const hlc = new HybridLogicalClock(new Date(), 0, 'node1');
    expect(Object.isFrozen(hlc)).toBe(true);
  });
});

describe('HybridLogicalClock.now()', () => {
  test('with null previous, counter is 0', () => {
    const hlc = HybridLogicalClock.now(null, 'node1');
    expect(hlc.counter).toBe(0);
    expect(hlc.nodeId).toBe('node1');
    expect(hlc.timestamp).toBeInstanceOf(Date);
  });

  test('with previous in the past, counter resets to 0', () => {
    const past = new HybridLogicalClock(
      new Date(Date.now() - 10000),
      42,
      'node1'
    );
    const hlc = HybridLogicalClock.now(past, 'node1');
    expect(hlc.counter).toBe(0);
    expect(hlc.timestamp.getTime()).toBeGreaterThan(past.timestamp.getTime());
  });

  test('with previous at same or future time, counter increments', () => {
    const future = new HybridLogicalClock(
      new Date(Date.now() + 60000),
      7,
      'node1'
    );
    const hlc = HybridLogicalClock.now(future, 'node1');
    expect(hlc.counter).toBe(8);
    expect(hlc.timestamp.getTime()).toBe(future.timestamp.getTime());
  });
});

describe('HybridLogicalClock.toCanonical() / fromCanonical()', () => {
  test('roundtrip preserves all fields', () => {
    const ts = new Date('2026-03-15T14:30:00.000Z');
    const original = new HybridLogicalClock(ts, 66, 'deadbeef');
    const canonical = original.toCanonical();
    const restored = HybridLogicalClock.fromCanonical(canonical);

    expect(restored.timestamp.toISOString()).toBe(ts.toISOString());
    expect(restored.counter).toBe(66);
    expect(restored.nodeId).toBe('deadbeef');
  });

  test('canonical format matches expected pattern', () => {
    const ts = new Date('2026-02-24T12:00:00.000Z');
    const hlc = new HybridLogicalClock(ts, 42, 'a1b2c3d4');
    const canonical = hlc.toCanonical();
    expect(canonical).toBe('2026-02-24T12:00:00.000Z-0042-a1b2c3d4');
  });

  test('fromCanonical throws on invalid format', () => {
    expect(() => HybridLogicalClock.fromCanonical('invalid')).toThrow();
  });
});

describe('HybridLogicalClock.compareTo()', () => {
  test('earlier timestamp returns -1', () => {
    const a = new HybridLogicalClock(new Date('2026-01-01T00:00:00Z'), 0, 'a');
    const b = new HybridLogicalClock(new Date('2026-01-02T00:00:00Z'), 0, 'a');
    expect(a.compareTo(b)).toBe(-1);
  });

  test('later timestamp returns 1', () => {
    const a = new HybridLogicalClock(new Date('2026-01-02T00:00:00Z'), 0, 'a');
    const b = new HybridLogicalClock(new Date('2026-01-01T00:00:00Z'), 0, 'a');
    expect(a.compareTo(b)).toBe(1);
  });

  test('same timestamp, lower counter returns -1', () => {
    const ts = new Date('2026-01-01T00:00:00Z');
    const a = new HybridLogicalClock(ts, 1, 'a');
    const b = new HybridLogicalClock(ts, 5, 'a');
    expect(a.compareTo(b)).toBe(-1);
  });

  test('same timestamp and counter, compares by nodeId', () => {
    const ts = new Date('2026-01-01T00:00:00Z');
    const a = new HybridLogicalClock(ts, 0, 'aaa');
    const b = new HybridLogicalClock(ts, 0, 'bbb');
    expect(a.compareTo(b)).toBe(-1);
    expect(b.compareTo(a)).toBe(1);
  });

  test('identical HLCs return 0', () => {
    const ts = new Date('2026-01-01T00:00:00Z');
    const a = new HybridLogicalClock(ts, 3, 'node1');
    const b = new HybridLogicalClock(ts, 3, 'node1');
    expect(a.compareTo(b)).toBe(0);
  });
});

describe('HybridLogicalClock.toBytes()', () => {
  test('returns Uint8Array', () => {
    const hlc = new HybridLogicalClock(new Date(), 0, 'node1');
    const bytes = hlc.toBytes();
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.byteLength).toBeGreaterThan(0);
  });

  test('deterministic output for same HLC', () => {
    const ts = new Date('2026-01-01T00:00:00.000Z');
    const hlc = new HybridLogicalClock(ts, 0, 'node1');
    const a = hlc.toBytes();
    const b = hlc.toBytes();
    expect(Array.from(a)).toEqual(Array.from(b));
  });
});
