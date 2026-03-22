import { describe, test, expect } from '@jest/globals';
import { Hasher } from '../../src/crypto/hasher.js';
import { bytesToHex, utf8Encode } from '../../src/utils.js';

describe('Hasher', () => {
  const hasher = new Hasher();

  describe('hash', () => {
    test('SHA-256 of empty input matches known test vector', () => {
      const result = hasher.hash(new Uint8Array([]));
      const hex = bytesToHex(result);
      expect(hex).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    test('returns 32 bytes', () => {
      const result = hasher.hash(utf8Encode('hello'));
      expect(result.length).toBe(32);
    });

    test('is deterministic', () => {
      const data = utf8Encode('test data');
      const h1 = hasher.hash(data);
      const h2 = hasher.hash(data);
      expect(bytesToHex(h1)).toBe(bytesToHex(h2));
    });

    test('different inputs produce different hashes', () => {
      const h1 = hasher.hash(utf8Encode('a'));
      const h2 = hasher.hash(utf8Encode('b'));
      expect(bytesToHex(h1)).not.toBe(bytesToHex(h2));
    });
  });

  describe('chainHash', () => {
    test('with null previousHash equals hash of payload only', () => {
      const payload = utf8Encode('genesis');
      const chained = hasher.chainHash(null, payload);
      const direct = hasher.hash(payload);
      expect(bytesToHex(chained)).toBe(bytesToHex(direct));
    });

    test('with undefined previousHash equals hash of payload only', () => {
      const payload = utf8Encode('genesis');
      const chained = hasher.chainHash(undefined, payload);
      const direct = hasher.hash(payload);
      expect(bytesToHex(chained)).toBe(bytesToHex(direct));
    });

    test('with previous hash produces different result than hash alone', () => {
      const payload = utf8Encode('event data');
      const prevHash = hasher.hash(utf8Encode('previous'));
      const chained = hasher.chainHash(prevHash, payload);
      const direct = hasher.hash(payload);
      expect(bytesToHex(chained)).not.toBe(bytesToHex(direct));
    });

    test('is deterministic with same inputs', () => {
      const prevHash = hasher.hash(utf8Encode('prev'));
      const payload = utf8Encode('data');
      const h1 = hasher.chainHash(prevHash, payload);
      const h2 = hasher.chainHash(prevHash, payload);
      expect(bytesToHex(h1)).toBe(bytesToHex(h2));
    });
  });

  describe('compositeHash', () => {
    test('single segment equals hash of that segment', () => {
      const segment = utf8Encode('only segment');
      const composite = hasher.compositeHash([segment]);
      const direct = hasher.hash(segment);
      expect(bytesToHex(composite)).toBe(bytesToHex(direct));
    });

    test('multiple segments are concatenated and hashed', () => {
      const a = utf8Encode('seg1');
      const b = utf8Encode('seg2');
      const c = utf8Encode('seg3');
      const composite = hasher.compositeHash([a, b, c]);
      expect(composite.length).toBe(32);
    });

    test('order of segments matters', () => {
      const a = utf8Encode('first');
      const b = utf8Encode('second');
      const h1 = hasher.compositeHash([a, b]);
      const h2 = hasher.compositeHash([b, a]);
      expect(bytesToHex(h1)).not.toBe(bytesToHex(h2));
    });
  });
});
