import { describe, test, expect } from '@jest/globals';
import { KeyConverter, DiffieHellman, X25519KeyPair } from '../../src/crypto/key-exchange.js';
import { IdentityManager } from '../../src/crypto/identity.js';
import { bytesToHex, constantTimeEqual } from '../../src/utils.js';

describe('KeyConverter', () => {
  const converter = new KeyConverter();
  const im = new IdentityManager();

  test('ed25519PublicToX25519 returns 32 bytes', async () => {
    const kp = await im.generate();
    const x25519Pub = converter.ed25519PublicToX25519(kp.publicKey);
    expect(x25519Pub).toBeInstanceOf(Uint8Array);
    expect(x25519Pub.length).toBe(32);
  });

  test('ed25519PrivateToX25519 returns 32 bytes', async () => {
    const kp = await im.generate();
    const x25519Priv = converter.ed25519PrivateToX25519(kp.privateKey);
    expect(x25519Priv).toBeInstanceOf(Uint8Array);
    expect(x25519Priv.length).toBe(32);
  });

  test('conversion is deterministic', async () => {
    const kp = await im.generate();
    const pub1 = converter.ed25519PublicToX25519(kp.publicKey);
    const pub2 = converter.ed25519PublicToX25519(kp.publicKey);
    expect(bytesToHex(pub1)).toBe(bytesToHex(pub2));
  });
});

describe('DiffieHellman', () => {
  const dh = new DiffieHellman();

  test('generateEphemeralKeyPair returns X25519KeyPair', () => {
    const kp = dh.generateEphemeralKeyPair();
    expect(kp).toBeInstanceOf(X25519KeyPair);
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey.length).toBe(32);
    expect(kp.privateKey).toBeInstanceOf(Uint8Array);
    expect(kp.privateKey.length).toBe(32);
  });

  test('computeSharedSecret returns 32 bytes', () => {
    const kp1 = dh.generateEphemeralKeyPair();
    const kp2 = dh.generateEphemeralKeyPair();
    const secret = dh.computeSharedSecret(kp1.privateKey, kp2.publicKey);
    expect(secret).toBeInstanceOf(Uint8Array);
    expect(secret.length).toBe(32);
  });

  test('both sides compute the same shared secret', () => {
    const kp1 = dh.generateEphemeralKeyPair();
    const kp2 = dh.generateEphemeralKeyPair();
    const secret1 = dh.computeSharedSecret(kp1.privateKey, kp2.publicKey);
    const secret2 = dh.computeSharedSecret(kp2.privateKey, kp1.publicKey);
    expect(bytesToHex(secret1)).toBe(bytesToHex(secret2));
  });

  test('different keypairs produce different shared secrets', () => {
    const kpA = dh.generateEphemeralKeyPair();
    const kpB = dh.generateEphemeralKeyPair();
    const kpC = dh.generateEphemeralKeyPair();
    const secretAB = dh.computeSharedSecret(kpA.privateKey, kpB.publicKey);
    const secretAC = dh.computeSharedSecret(kpA.privateKey, kpC.publicKey);
    expect(bytesToHex(secretAB)).not.toBe(bytesToHex(secretAC));
  });
});

describe('X25519KeyPair.destroy', () => {
  test('zeroes private key and marks as destroyed', () => {
    const dh = new DiffieHellman();
    const kp = dh.generateEphemeralKeyPair();
    expect(kp.isDestroyed).toBe(false);
    kp.destroy();
    expect(kp.isDestroyed).toBe(true);
  });

  test('accessing privateKey after destroy throws', () => {
    const dh = new DiffieHellman();
    const kp = dh.generateEphemeralKeyPair();
    kp.destroy();
    expect(() => kp.privateKey).toThrow('has been destroyed');
  });

  test('publicKey remains accessible after destroy', () => {
    const dh = new DiffieHellman();
    const kp = dh.generateEphemeralKeyPair();
    const pubBefore = new Uint8Array(kp.publicKey);
    kp.destroy();
    expect(kp.publicKey).toEqual(pubBefore);
  });
});
