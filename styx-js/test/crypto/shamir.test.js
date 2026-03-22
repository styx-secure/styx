import { describe, test, expect } from '@jest/globals';
import * as fc from 'fast-check';
import {
  ShamirSplitter,
  ShamirReconstructor,
  ShamirShare,
  InsufficientSharesException,
  KeyBackup,
} from '../../src/crypto/shamir.js';
import { IdentityManager } from '../../src/crypto/identity.js';
import { bytesToHex, randomBytes, constantTimeEqual } from '../../src/utils.js';

describe('ShamirSplitter', () => {
  const splitter = new ShamirSplitter();
  const reconstructor = new ShamirReconstructor();

  test('split(secret, 2, 3) returns 3 shares', () => {
    const secret = randomBytes(32);
    const shares = splitter.split(secret, 2, 3);
    expect(shares.length).toBe(3);
    shares.forEach((share) => {
      expect(share).toBeInstanceOf(ShamirShare);
      expect(share.data.length).toBe(32);
    });
  });

  test('shares have indices 1, 2, 3', () => {
    const shares = splitter.split(randomBytes(16), 2, 3);
    expect(shares.map((s) => s.index)).toEqual([1, 2, 3]);
  });

  test('reconstruct with any 2 shares of 3 recovers original', () => {
    const secret = randomBytes(32);
    const shares = splitter.split(secret, 2, 3);

    // Try all 2-combinations: [0,1], [0,2], [1,2]
    const combos = [
      [shares[0], shares[1]],
      [shares[0], shares[2]],
      [shares[1], shares[2]],
    ];

    for (const combo of combos) {
      const recovered = reconstructor.reconstruct(combo);
      expect(bytesToHex(recovered)).toBe(bytesToHex(secret));
    }
  });

  test('reconstruct with 3 of 5 (threshold 3, total 5)', () => {
    const secret = randomBytes(16);
    const shares = splitter.split(secret, 3, 5);
    expect(shares.length).toBe(5);

    // Pick shares [0, 2, 4]
    const recovered = reconstructor.reconstruct([shares[0], shares[2], shares[4]]);
    expect(bytesToHex(recovered)).toBe(bytesToHex(secret));
  });

  test('reconstruct with all shares works', () => {
    const secret = randomBytes(32);
    const shares = splitter.split(secret, 2, 3);
    const recovered = reconstructor.reconstruct(shares);
    expect(bytesToHex(recovered)).toBe(bytesToHex(secret));
  });
});

describe('InsufficientSharesException', () => {
  test('thrown when fewer than 2 shares provided', () => {
    const reconstructor = new ShamirReconstructor();
    const splitter = new ShamirSplitter();
    const shares = splitter.split(randomBytes(16), 2, 3);

    expect(() => reconstructor.reconstruct([shares[0]])).toThrow(
      InsufficientSharesException
    );
    expect(() => reconstructor.reconstruct([])).toThrow(
      InsufficientSharesException
    );
  });
});

describe('ShamirSplitter validation', () => {
  const splitter = new ShamirSplitter();

  test('threshold < 2 throws', () => {
    expect(() => splitter.split(randomBytes(8), 1, 3)).toThrow('Threshold must be at least 2');
  });

  test('totalShares < threshold throws', () => {
    expect(() => splitter.split(randomBytes(8), 3, 2)).toThrow('totalShares must be >= threshold');
  });
});

describe('ShamirShare serialization', () => {
  test('serialize and deserialize roundtrip', () => {
    const share = new ShamirShare(5, randomBytes(32));
    const serialized = share.serialize();
    expect(typeof serialized).toBe('string');

    const deserialized = ShamirShare.deserialize(serialized);
    expect(deserialized.index).toBe(5);
    expect(bytesToHex(deserialized.data)).toBe(bytesToHex(share.data));
  });

  test('multiple shares serialize/deserialize correctly', () => {
    const splitter = new ShamirSplitter();
    const secret = randomBytes(16);
    const shares = splitter.split(secret, 2, 3);

    const serialized = shares.map((s) => s.serialize());
    const deserialized = serialized.map((s) => ShamirShare.deserialize(s));

    const reconstructor = new ShamirReconstructor();
    const recovered = reconstructor.reconstruct(deserialized);
    expect(bytesToHex(recovered)).toBe(bytesToHex(secret));
  });
});

describe('ShamirShare index validation', () => {
  test('index 0 throws', () => {
    expect(() => new ShamirShare(0, randomBytes(8))).toThrow('Share index must be 1-255');
  });

  test('index 256 throws', () => {
    expect(() => new ShamirShare(256, randomBytes(8))).toThrow('Share index must be 1-255');
  });

  test('index 1 is valid', () => {
    expect(() => new ShamirShare(1, randomBytes(8))).not.toThrow();
  });

  test('index 255 is valid', () => {
    expect(() => new ShamirShare(255, randomBytes(8))).not.toThrow();
  });
});

describe('KeyBackup', () => {
  const backup = new KeyBackup();
  const im = new IdentityManager();

  test('backupPrivateKey and restoreFromShares roundtrip', async () => {
    const kp = await im.generate();
    const shares = backup.backupPrivateKey(kp.privateKey, 2, 3);
    expect(shares.length).toBe(3);

    const restored = await backup.restoreFromShares([shares[0], shares[2]], im);
    expect(restored.publicKey.equals(kp.publicKey)).toBe(true);
  });

  test('restoreFromShares with all shares works', async () => {
    const kp = await im.generate();
    const shares = backup.backupPrivateKey(kp.privateKey, 2, 3);
    const restored = await backup.restoreFromShares(shares, im);
    expect(restored.publicKey.equals(kp.publicKey)).toBe(true);
  });
});

describe('property-based test with fast-check', () => {
  const splitter = new ShamirSplitter();
  const reconstructor = new ShamirReconstructor();

  test('random secret with random threshold always reconstructs correctly', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 64 }), // secret length
        fc.integer({ min: 2, max: 5 }),   // threshold
        fc.integer({ min: 0, max: 3 }),   // extra shares beyond threshold
        (secretLen, threshold, extra) => {
          const totalShares = threshold + extra;
          const secret = randomBytes(secretLen);
          const shares = splitter.split(secret, threshold, totalShares);

          // Pick exactly `threshold` shares (first `threshold`)
          const subset = shares.slice(0, threshold);
          const recovered = reconstructor.reconstruct(subset);
          return bytesToHex(recovered) === bytesToHex(secret);
        }
      ),
      { numRuns: 20 }
    );
  });
});
