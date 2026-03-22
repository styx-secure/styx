// test/ledger/vector-clock.test.js
import { describe, test, expect } from '@jest/globals';
import { VectorClock, CausalRelation, CausalityChecker } from '../../src/ledger/vector-clock.js';

describe('VectorClock', () => {
  test('constructor sets a and b', () => {
    const vc = new VectorClock(3, 5);
    expect(vc.a).toBe(3);
    expect(vc.b).toBe(5);
  });

  test('is frozen after construction', () => {
    const vc = new VectorClock(3, 5);
    expect(Object.isFrozen(vc)).toBe(true);
  });

  test('zero() creates (0, 0)', () => {
    const vc = VectorClock.zero();
    expect(vc.a).toBe(0);
    expect(vc.b).toBe(0);
  });
});

describe('VectorClock.increment()', () => {
  test('increment A returns new VC with a+1', () => {
    const vc = new VectorClock(3, 5);
    const next = vc.increment('A');
    expect(next.a).toBe(4);
    expect(next.b).toBe(5);
  });

  test('increment B returns new VC with b+1', () => {
    const vc = new VectorClock(3, 5);
    const next = vc.increment('B');
    expect(next.a).toBe(3);
    expect(next.b).toBe(6);
  });

  test('original is unchanged after increment', () => {
    const vc = new VectorClock(3, 5);
    vc.increment('A');
    expect(vc.a).toBe(3);
    expect(vc.b).toBe(5);
  });

  test('increment with invalid role throws', () => {
    const vc = new VectorClock(1, 1);
    expect(() => vc.increment('C')).toThrow('Invalid peer role');
  });
});

describe('VectorClock.merge()', () => {
  test('component-wise max', () => {
    const a = new VectorClock(3, 7);
    const b = new VectorClock(5, 2);
    const merged = a.merge(b);
    expect(merged.a).toBe(5);
    expect(merged.b).toBe(7);
  });

  test('merge with self yields same values', () => {
    const vc = new VectorClock(4, 6);
    const merged = vc.merge(vc);
    expect(merged.a).toBe(4);
    expect(merged.b).toBe(6);
  });
});

describe('VectorClock.causalRelation()', () => {
  test('EQUAL when both components match', () => {
    const a = new VectorClock(3, 5);
    const b = new VectorClock(3, 5);
    expect(a.causalRelation(b)).toBe(CausalRelation.EQUAL);
  });

  test('BEFORE when a<=a2 and b<=b2 (not equal)', () => {
    const a = new VectorClock(2, 3);
    const b = new VectorClock(4, 5);
    expect(a.causalRelation(b)).toBe(CausalRelation.BEFORE);
  });

  test('AFTER when a>=a2 and b>=b2 (not equal)', () => {
    const a = new VectorClock(4, 5);
    const b = new VectorClock(2, 3);
    expect(a.causalRelation(b)).toBe(CausalRelation.AFTER);
  });

  test('CONCURRENT when a>a2 and b<b2', () => {
    const a = new VectorClock(5, 2);
    const b = new VectorClock(3, 7);
    expect(a.causalRelation(b)).toBe(CausalRelation.CONCURRENT);
  });

  test('CONCURRENT when a<a2 and b>b2', () => {
    const a = new VectorClock(1, 9);
    const b = new VectorClock(8, 1);
    expect(a.causalRelation(b)).toBe(CausalRelation.CONCURRENT);
  });
});

describe('VectorClock.total', () => {
  test('returns a + b', () => {
    const vc = new VectorClock(3, 5);
    expect(vc.total).toBe(8);
  });

  test('zero VC total is 0', () => {
    expect(VectorClock.zero().total).toBe(0);
  });
});

describe('VectorClock.toBytes() / fromBytes() roundtrip', () => {
  test('serializes to 8 bytes', () => {
    const vc = new VectorClock(100, 200);
    const bytes = vc.toBytes();
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.byteLength).toBe(8);
  });

  test('roundtrip preserves values', () => {
    const vc = new VectorClock(12345, 67890);
    const restored = VectorClock.fromBytes(vc.toBytes());
    expect(restored.a).toBe(12345);
    expect(restored.b).toBe(67890);
  });
});

describe('VectorClock.toJSON() / fromJSON() roundtrip', () => {
  test('roundtrip preserves values', () => {
    const vc = new VectorClock(42, 99);
    const json = vc.toJSON();
    expect(json).toEqual({ a: 42, b: 99 });
    const restored = VectorClock.fromJSON(json);
    expect(restored.a).toBe(42);
    expect(restored.b).toBe(99);
  });
});

describe('VectorClock.equals()', () => {
  test('returns true for same components', () => {
    const a = new VectorClock(3, 5);
    const b = new VectorClock(3, 5);
    expect(a.equals(b)).toBe(true);
  });

  test('returns false for different components', () => {
    const a = new VectorClock(3, 5);
    const b = new VectorClock(3, 6);
    expect(a.equals(b)).toBe(false);
  });
});

describe('CausalityChecker', () => {
  const checker = new CausalityChecker();

  test('compare delegates to causalRelation', () => {
    const a = new VectorClock(1, 2);
    const b = new VectorClock(3, 4);
    expect(checker.compare(a, b)).toBe(CausalRelation.BEFORE);
  });

  test('isAfter returns true when first is after second', () => {
    const a = new VectorClock(5, 5);
    const b = new VectorClock(2, 3);
    expect(checker.isAfter(a, b)).toBe(true);
  });

  test('isAfter returns false when not after', () => {
    const a = new VectorClock(1, 1);
    const b = new VectorClock(2, 3);
    expect(checker.isAfter(a, b)).toBe(false);
  });

  test('isConcurrent returns true for concurrent VCs', () => {
    const a = new VectorClock(5, 1);
    const b = new VectorClock(1, 5);
    expect(checker.isConcurrent(a, b)).toBe(true);
  });

  test('isConcurrent returns false for causal VCs', () => {
    const a = new VectorClock(1, 1);
    const b = new VectorClock(2, 3);
    expect(checker.isConcurrent(a, b)).toBe(false);
  });
});
