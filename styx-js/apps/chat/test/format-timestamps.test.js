// test/format-timestamps.test.js — the date/time helpers never throw on a
// malformed timestamp: anything that is not a finite, representable number
// formats as '' and is never on the same day as anything.
import { describe, test, expect, jest } from '@jest/globals';
import { hhmm, relTime, dayLabel, sameDay } from '../src/lib/format.js';

const poisoned = { valueOf: 0, toString: 0 };
const bad = [poisoned, '1780000000000', null, undefined, NaN, Infinity, 8.64e15 + 1e6, {}, [], true];

describe('format helpers on malformed timestamps', () => {
  test.each(bad.map((v) => [v]))('%p formats as the empty string', (ts) => {
    expect(hhmm(ts)).toBe('');
    expect(relTime(ts)).toBe('');
    expect(dayLabel(ts)).toBe('');
    expect(sameDay(ts, Date.now())).toBe(false);
    expect(sameDay(Date.now(), ts)).toBe(false);
  });

  test('valid timestamps keep their previous formatting', () => {
    // A fixed local noon, so the checks cannot straddle midnight.
    const now = new Date(2026, 10, 7, 12, 0, 0).getTime();
    const spy = jest.spyOn(Date, 'now').mockReturnValue(now);
    try {
      expect(relTime(now)).toBe('ora');
      expect(relTime(now - 5 * 60000)).toBe('5m');
      expect(dayLabel(now)).toBe('Oggi');
      expect(dayLabel(now - 86400000)).toBe('Ieri');
      expect(hhmm(now)).toBe('12:00');
      expect(sameDay(now, now)).toBe(true);
      expect(relTime(0)).toBe('');
    } finally {
      spy.mockRestore();
    }
  });
});
