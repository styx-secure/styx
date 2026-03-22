import { describe, test, expect } from '@jest/globals';
import { KeyDerivation, DirectionalKeys } from '../../src/crypto/key-derivation.js';
import { bytesToHex, randomBytes } from '../../src/utils.js';

describe('KeyDerivation', () => {
  const kd = new KeyDerivation();

  describe('deriveKey', () => {
    test('returns deterministic output for same inputs', () => {
      const secret = randomBytes(32);
      const info = new TextEncoder().encode('test-info');
      const k1 = kd.deriveKey(secret, info);
      const k2 = kd.deriveKey(secret, info);
      expect(bytesToHex(k1)).toBe(bytesToHex(k2));
    });

    test('defaults to 32-byte output', () => {
      const secret = randomBytes(32);
      const info = new TextEncoder().encode('info');
      const key = kd.deriveKey(secret, info);
      expect(key.length).toBe(32);
    });

    test('respects configurable output length', () => {
      const secret = randomBytes(32);
      const info = new TextEncoder().encode('info');
      const key16 = kd.deriveKey(secret, info, undefined, 16);
      const key64 = kd.deriveKey(secret, info, undefined, 64);
      expect(key16.length).toBe(16);
      expect(key64.length).toBe(64);
    });

    test('different info produces different keys', () => {
      const secret = randomBytes(32);
      const k1 = kd.deriveKey(secret, new TextEncoder().encode('info-a'));
      const k2 = kd.deriveKey(secret, new TextEncoder().encode('info-b'));
      expect(bytesToHex(k1)).not.toBe(bytesToHex(k2));
    });

    test('different salt produces different keys', () => {
      const secret = randomBytes(32);
      const info = new TextEncoder().encode('info');
      const k1 = kd.deriveKey(secret, info, new Uint8Array([1]));
      const k2 = kd.deriveKey(secret, info, new Uint8Array([2]));
      expect(bytesToHex(k1)).not.toBe(bytesToHex(k2));
    });
  });

  describe('deriveDirectionalKeys', () => {
    test('returns DirectionalKeys with 32-byte keys', () => {
      const secret = randomBytes(32);
      const pubA = randomBytes(32);
      const pubB = randomBytes(32);
      const keys = kd.deriveDirectionalKeys(secret, pubA, pubB);
      expect(keys).toBeInstanceOf(DirectionalKeys);
      expect(keys.sendKey.length).toBe(32);
      expect(keys.receiveKey.length).toBe(32);
    });

    test('sendKey and receiveKey are different', () => {
      const secret = randomBytes(32);
      const pubA = randomBytes(32);
      const pubB = randomBytes(32);
      const keys = kd.deriveDirectionalKeys(secret, pubA, pubB);
      expect(bytesToHex(keys.sendKey)).not.toBe(bytesToHex(keys.receiveKey));
    });

    test('A sendKey equals B receiveKey (symmetry)', () => {
      const secret = randomBytes(32);
      const pubA = randomBytes(32);
      const pubB = randomBytes(32);
      const keysA = kd.deriveDirectionalKeys(secret, pubA, pubB);
      const keysB = kd.deriveDirectionalKeys(secret, pubB, pubA);
      expect(bytesToHex(keysA.sendKey)).toBe(bytesToHex(keysB.receiveKey));
      expect(bytesToHex(keysA.receiveKey)).toBe(bytesToHex(keysB.sendKey));
    });
  });
});

describe('DirectionalKeys', () => {
  test('destroy zeroes both keys', () => {
    const keys = new DirectionalKeys(
      randomBytes(32),
      randomBytes(32),
    );
    expect(keys.isDestroyed).toBe(false);
    keys.destroy();
    expect(keys.isDestroyed).toBe(true);
  });

  test('accessing sendKey after destroy throws', () => {
    const keys = new DirectionalKeys(randomBytes(32), randomBytes(32));
    keys.destroy();
    expect(() => keys.sendKey).toThrow('destroyed');
  });

  test('accessing receiveKey after destroy throws', () => {
    const keys = new DirectionalKeys(randomBytes(32), randomBytes(32));
    keys.destroy();
    expect(() => keys.receiveKey).toThrow('destroyed');
  });
});
