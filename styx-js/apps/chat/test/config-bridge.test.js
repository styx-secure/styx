// test/config-bridge.test.js — the bridge URL is opt-in: read from ?bridge= (or a
// build-time default), '' when absent. Pure parser so it's testable without a DOM.
import { describe, test, expect } from '@jest/globals';
import { parseBridgeUrl } from '../src/lib/config.js';

describe('parseBridgeUrl', () => {
  test('reads the bridge param from a query string', () => {
    expect(parseBridgeUrl('?bridge=https://b.example')).toBe('https://b.example');
  });
  test('strips a trailing slash', () => {
    expect(parseBridgeUrl('?bridge=https://b.example/')).toBe('https://b.example');
  });
  test('returns the fallback when no param is present', () => {
    expect(parseBridgeUrl('', 'https://default.example')).toBe('https://default.example');
    expect(parseBridgeUrl('')).toBe('');
  });
});
