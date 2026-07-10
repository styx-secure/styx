// test/push/registration-digest.test.js — the canonical, deterministic digest
// both the client and the bridge sign/verify. Binding the action, identity and
// endpoint prevents a signature being replayed for a different registration.
import { describe, test, expect } from '@jest/globals';
import { registrationDigest } from '../../src/push/registration-digest.js';
import { bytesToHex } from '../../src/utils.js';

describe('registrationDigest', () => {
  test('is 32 bytes and deterministic for the same inputs', () => {
    const a = registrationDigest('register', 'pk1', 'https://push/abc');
    const b = registrationDigest('register', 'pk1', 'https://push/abc');
    expect(a).toBeInstanceOf(Uint8Array);
    expect(a.length).toBe(32);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  test('changes when action, pubkey or endpoint changes', () => {
    const base = bytesToHex(registrationDigest('register', 'pk1', 'https://push/abc'));
    expect(bytesToHex(registrationDigest('unregister', 'pk1', 'https://push/abc'))).not.toBe(base);
    expect(bytesToHex(registrationDigest('register', 'pk2', 'https://push/abc'))).not.toBe(base);
    expect(bytesToHex(registrationDigest('register', 'pk1', 'https://push/xyz'))).not.toBe(base);
  });
});
