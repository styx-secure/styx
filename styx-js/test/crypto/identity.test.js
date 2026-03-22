import { describe, test, expect } from '@jest/globals';
import {
  StyxPublicKey,
  StyxPrivateKey,
  StyxKeyPair,
  IdentityManager,
} from '../../src/crypto/identity.js';
import { bytesToHex, hexToBytes } from '../../src/utils.js';

describe('StyxPublicKey', () => {
  const validBytes = new Uint8Array(32).fill(0xab);

  test('constructor validates 32 bytes', () => {
    expect(() => new StyxPublicKey(validBytes)).not.toThrow();
  });

  test('constructor rejects non-32-byte input', () => {
    expect(() => new StyxPublicKey(new Uint8Array(16))).toThrow('exactly 32 bytes');
    expect(() => new StyxPublicKey(new Uint8Array(33))).toThrow('exactly 32 bytes');
  });

  test('constructor rejects non-Uint8Array', () => {
    expect(() => new StyxPublicKey([1, 2, 3])).toThrow('exactly 32 bytes');
  });

  test('fromHex creates from hex string', () => {
    const hex = bytesToHex(validBytes);
    const key = StyxPublicKey.fromHex(hex);
    expect(key.bytes).toEqual(validBytes);
  });

  test('toHex returns hex string', () => {
    const key = new StyxPublicKey(validBytes);
    expect(key.toHex()).toBe(bytesToHex(validBytes));
  });

  test('nodeId returns first 8 hex characters', () => {
    const key = new StyxPublicKey(validBytes);
    const hex = key.toHex();
    expect(key.nodeId).toBe(hex.slice(0, 8));
    expect(key.nodeId.length).toBe(8);
  });

  test('equals returns true for same bytes', () => {
    const a = new StyxPublicKey(validBytes);
    const b = new StyxPublicKey(new Uint8Array(validBytes));
    expect(a.equals(b)).toBe(true);
  });

  test('equals returns false for different bytes', () => {
    const a = new StyxPublicKey(new Uint8Array(32).fill(0xaa));
    const b = new StyxPublicKey(new Uint8Array(32).fill(0xbb));
    expect(a.equals(b)).toBe(false);
  });

  test('equals returns false for non-StyxPublicKey', () => {
    const key = new StyxPublicKey(validBytes);
    expect(key.equals(validBytes)).toBe(false);
    expect(key.equals(null)).toBe(false);
  });

  test('toJSON returns hex string', () => {
    const key = new StyxPublicKey(validBytes);
    expect(key.toJSON()).toBe(key.toHex());
    expect(JSON.stringify(key)).toBe(`"${key.toHex()}"`);
  });

  test('bytes returns a copy, not the internal buffer', () => {
    const key = new StyxPublicKey(validBytes);
    const bytes1 = key.bytes;
    bytes1[0] = 0x00;
    expect(key.bytes[0]).toBe(0xab);
  });
});

describe('StyxPrivateKey', () => {
  test('constructor requires Uint8Array', () => {
    expect(() => new StyxPrivateKey(new Uint8Array(32))).not.toThrow();
    expect(() => new StyxPrivateKey([1, 2, 3])).toThrow('requires Uint8Array');
    expect(() => new StyxPrivateKey('abc')).toThrow('requires Uint8Array');
  });

  test('bytes are accessible before destruction', () => {
    const raw = new Uint8Array(32).fill(0xcc);
    const key = new StyxPrivateKey(raw);
    expect(key.bytes).toEqual(raw);
  });

  test('destroy zeroes bytes and marks as destroyed', () => {
    const key = new StyxPrivateKey(new Uint8Array(32).fill(0xff));
    expect(key.isDestroyed).toBe(false);
    key.destroy();
    expect(key.isDestroyed).toBe(true);
  });

  test('accessing bytes after destroy throws', () => {
    const key = new StyxPrivateKey(new Uint8Array(32).fill(0xff));
    key.destroy();
    expect(() => key.bytes).toThrow('has been destroyed');
  });
});

describe('StyxKeyPair', () => {
  test('holds publicKey and privateKey', () => {
    const pub = new StyxPublicKey(new Uint8Array(32).fill(1));
    const priv = new StyxPrivateKey(new Uint8Array(32).fill(2));
    const kp = new StyxKeyPair(pub, priv);
    expect(kp.publicKey).toBe(pub);
    expect(kp.privateKey).toBe(priv);
  });
});

describe('IdentityManager', () => {
  const im = new IdentityManager();

  test('generate returns a valid keypair', async () => {
    const kp = await im.generate();
    expect(kp).toBeInstanceOf(StyxKeyPair);
    expect(kp.publicKey).toBeInstanceOf(StyxPublicKey);
    expect(kp.privateKey).toBeInstanceOf(StyxPrivateKey);
    expect(kp.publicKey.bytes.length).toBe(32);
  });

  test('exportPublicKey / importPublicKey roundtrip', async () => {
    const kp = await im.generate();
    const exported = im.exportPublicKey(kp.publicKey);
    const imported = im.importPublicKey(exported);
    expect(kp.publicKey.equals(imported)).toBe(true);
  });

  test('exportPrivateKey returns bytes', async () => {
    const kp = await im.generate();
    const exported = im.exportPrivateKey(kp.privateKey);
    expect(exported).toBeInstanceOf(Uint8Array);
    expect(exported.length).toBeGreaterThan(0);
  });

  test('importPrivateKey recovers the same public key', async () => {
    const kp = await im.generate();
    const privBytes = im.exportPrivateKey(kp.privateKey);
    const recovered = await im.importPrivateKey(privBytes);
    expect(recovered.publicKey.equals(kp.publicKey)).toBe(true);
  });

  test('two generated keypairs are different', async () => {
    const kp1 = await im.generate();
    const kp2 = await im.generate();
    expect(kp1.publicKey.equals(kp2.publicKey)).toBe(false);
  });
});
