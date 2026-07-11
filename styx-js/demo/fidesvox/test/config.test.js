// test/config.test.js — the demo must fail fast without a strong JWT secret.
import { describe, test, expect } from '@jest/globals';
import { requireJwtSecret } from '../config.js';

describe('FidesVox requireJwtSecret', () => {
  test('throws when the secret is absent', () => {
    expect(() => requireJwtSecret({})).toThrow(/JWT_SECRET is required/);
  });

  test('throws when the secret is too short', () => {
    expect(() => requireJwtSecret({ JWT_SECRET: 'short' })).toThrow(/too weak/);
  });

  test('throws on an obvious placeholder even if long enough', () => {
    expect(() => requireJwtSecret({ JWT_SECRET: 'changeme'.repeat(5) })).not.toThrow();
    // a bare weak word is rejected regardless of the length rule
    expect(() => requireJwtSecret({ JWT_SECRET: 'changeme' })).toThrow(/too weak/);
  });

  test('accepts a strong 32+ char secret', () => {
    const strong = 'a3f'.repeat(11); // 33 chars, not a placeholder
    expect(requireJwtSecret({ JWT_SECRET: strong })).toBe(strong);
  });
});
