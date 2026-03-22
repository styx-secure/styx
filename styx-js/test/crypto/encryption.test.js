import { describe, test, expect } from '@jest/globals';
import { StyxEncryptor } from '../../src/crypto/encryption.js';
import { randomBytes, constantTimeEqual, utf8Encode, utf8Decode } from '../../src/utils.js';

describe('StyxEncryptor', () => {
  const sendKey = randomBytes(32);
  const receiveKey = randomBytes(32);

  const encryptor = new StyxEncryptor(sendKey, receiveKey);
  const decryptor = new StyxEncryptor(receiveKey, sendKey);

  test('encrypt returns nonce (12 bytes) + ciphertext + tag', () => {
    const plaintext = utf8Encode('hello world');
    const encrypted = encryptor.encrypt(plaintext);
    expect(encrypted).toBeInstanceOf(Uint8Array);
    // 12 nonce + plaintext + 16 poly1305 tag
    expect(encrypted.length).toBe(12 + plaintext.length + 16);
  });

  test('encrypt then decrypt roundtrip works', () => {
    const plaintext = utf8Encode('secret message');
    const encrypted = encryptor.encrypt(plaintext);
    const decrypted = decryptor.decrypt(encrypted);
    expect(utf8Decode(decrypted)).toBe('secret message');
  });

  test('different nonces each time', () => {
    const plaintext = utf8Encode('same message');
    const enc1 = encryptor.encrypt(plaintext);
    const enc2 = encryptor.encrypt(plaintext);
    const nonce1 = enc1.slice(0, 12);
    const nonce2 = enc2.slice(0, 12);
    expect(constantTimeEqual(nonce1, nonce2)).toBe(false);
  });

  test('decrypt with wrong key throws', () => {
    const wrongKey = randomBytes(32);
    const wrongDecryptor = new StyxEncryptor(wrongKey, wrongKey);
    const plaintext = utf8Encode('test');
    const encrypted = encryptor.encrypt(plaintext);
    expect(() => wrongDecryptor.decrypt(encrypted)).toThrow();
  });

  test('ciphertext too short throws', () => {
    const shortData = new Uint8Array(20); // less than 12 + 16 = 28
    expect(() => decryptor.decrypt(shortData)).toThrow('Ciphertext too short');
  });

  test('empty plaintext works', () => {
    const plaintext = new Uint8Array([]);
    const encrypted = encryptor.encrypt(plaintext);
    const decrypted = decryptor.decrypt(encrypted);
    expect(decrypted).toEqual(new Uint8Array([]));
  });

  test('large plaintext roundtrip', () => {
    const plaintext = randomBytes(10000);
    const encrypted = encryptor.encrypt(plaintext);
    const decrypted = decryptor.decrypt(encrypted);
    expect(constantTimeEqual(decrypted, plaintext)).toBe(true);
  });
});
