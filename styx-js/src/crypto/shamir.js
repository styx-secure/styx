// styx-js/src/crypto/shamir.js
// Shamir's Secret Sharing over GF(256) — split and reconstruct secrets

import { bytesToBase64, base64ToBytes, randomBytes } from '../utils.js';

// GF(256) arithmetic using the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)

/**
 * GF(256) addition (same as XOR)
 */
function gfAdd(a, b) {
  return a ^ b;
}

/**
 * GF(256) multiplication using Russian Peasant algorithm
 */
function gfMul(a, b) {
  let result = 0;
  let aa = a;
  let bb = b;
  while (bb > 0) {
    if (bb & 1) result ^= aa;
    aa <<= 1;
    if (aa & 0x100) aa ^= 0x11b;
    bb >>= 1;
  }
  return result;
}

/**
 * GF(256) multiplicative inverse using extended Euclidean / Fermat's little theorem
 * a^254 = a^(-1) in GF(256)
 */
function gfInv(a) {
  if (a === 0) throw new Error('Cannot invert zero in GF(256)');
  let result = a;
  for (let i = 0; i < 6; i++) {
    result = gfMul(result, result);
    result = gfMul(result, a);
  }
  result = gfMul(result, result);
  return result;
}

/**
 * GF(256) division
 */
function gfDiv(a, b) {
  return gfMul(a, gfInv(b));
}

// --- Shamir Share ---

/**
 * Custom errors for Shamir operations
 */
export class InsufficientSharesException extends Error {
  constructor(message) {
    super(message);
    this.name = 'InsufficientSharesException';
  }
}

export class InvalidShareException extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidShareException';
  }
}

/**
 * Immutable Shamir secret share.
 */
export class ShamirShare {
  /**
   * @param {number} index - Share index (1-based)
   * @param {Uint8Array} data - Share data bytes
   */
  constructor(index, data) {
    if (index < 1 || index > 255) throw new Error('Share index must be 1-255');
    this.index = index;
    this.data = new Uint8Array(data);
  }

  /**
   * Serialize to string for storage/transmission.
   * Format: styx-share-v1:{index}:{base64_data}
   * @returns {string}
   */
  serialize() {
    return `styx-share-v1:${this.index}:${bytesToBase64(this.data)}`;
  }

  /**
   * Deserialize from string
   * @param {string} encoded - Format: styx-share-v1:{index}:{base64_data}
   * @returns {ShamirShare}
   */
  static deserialize(encoded) {
    const parts = encoded.split(':');
    if (parts.length !== 3 || parts[0] !== 'styx-share-v1') {
      throw new InvalidShareException('Invalid share format');
    }
    const index = parseInt(parts[1], 10);
    if (isNaN(index)) throw new InvalidShareException('Invalid share index');
    const data = base64ToBytes(parts[2]);
    return new ShamirShare(index, data);
  }
}

// --- Splitter ---

/**
 * Splits secrets using Shamir's Secret Sharing over GF(256).
 */
export class ShamirSplitter {
  /**
   * Split a secret into shares
   * @param {Uint8Array} secret - The secret to split
   * @param {number} [threshold=2] - Minimum shares to reconstruct
   * @param {number} [totalShares=3] - Total shares to create
   * @returns {ShamirShare[]}
   */
  split(secret, threshold = 2, totalShares = 3) {
    if (threshold < 2) throw new Error('Threshold must be at least 2');
    if (totalShares < threshold) throw new Error('totalShares must be >= threshold');
    if (totalShares > 255) throw new Error('Maximum 255 shares');

    const shares = [];
    for (let s = 0; s < totalShares; s++) {
      shares.push(new Uint8Array(secret.length));
    }

    // For each byte of the secret, create a random polynomial
    for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
      // coefficients[0] = secret byte, coefficients[1..threshold-1] = random
      const coefficients = new Uint8Array(threshold);
      coefficients[0] = secret[byteIdx];
      const randCoeffs = randomBytes(threshold - 1);
      for (let i = 1; i < threshold; i++) {
        coefficients[i] = randCoeffs[i - 1];
      }

      // Evaluate polynomial at x = 1, 2, ..., totalShares
      for (let s = 0; s < totalShares; s++) {
        const x = s + 1; // 1-based
        let y = 0;
        for (let k = threshold - 1; k >= 0; k--) {
          y = gfAdd(gfMul(y, x), coefficients[k]);
        }
        shares[s][byteIdx] = y;
      }
    }

    return shares.map((data, i) => new ShamirShare(i + 1, data));
  }
}

// --- Reconstructor ---

/**
 * Reconstructs secrets from Shamir shares using Lagrange interpolation.
 */
export class ShamirReconstructor {
  /**
   * Reconstruct the original secret from shares
   * @param {ShamirShare[]} shares
   * @returns {Uint8Array}
   */
  reconstruct(shares) {
    if (shares.length < 2) {
      throw new InsufficientSharesException('At least 2 shares required');
    }

    const len = shares[0].data.length;
    for (const share of shares) {
      if (share.data.length !== len) {
        throw new InvalidShareException('All shares must have the same length');
      }
    }

    const secret = new Uint8Array(len);
    const xs = shares.map((s) => s.index);

    for (let byteIdx = 0; byteIdx < len; byteIdx++) {
      let result = 0;

      for (let i = 0; i < shares.length; i++) {
        const xi = xs[i];
        const yi = shares[i].data[byteIdx];

        // Lagrange basis polynomial evaluated at x = 0
        let basis = 1;
        for (let j = 0; j < shares.length; j++) {
          if (i === j) continue;
          const xj = xs[j];
          // basis *= (0 - xj) / (xi - xj)  in GF(256)
          // Since 0 - xj = xj in GF(256) (XOR with 0)
          basis = gfMul(basis, gfDiv(xj, gfAdd(xi, xj)));
        }

        result = gfAdd(result, gfMul(yi, basis));
      }

      secret[byteIdx] = result;
    }

    return secret;
  }
}

// --- High-level KeyBackup service ---

/**
 * High-level service for creating and restoring Shamir backups of private keys.
 */
export class KeyBackup {
  constructor() {
    this._splitter = new ShamirSplitter();
    this._reconstructor = new ShamirReconstructor();
  }

  /**
   * Split a private key into Shamir shares
   * @param {import('./identity.js').StyxPrivateKey} privateKey
   * @param {number} [threshold=2]
   * @param {number} [totalShares=3]
   * @returns {ShamirShare[]}
   */
  backupPrivateKey(privateKey, threshold = 2, totalShares = 3) {
    return this._splitter.split(privateKey.bytes, threshold, totalShares);
  }

  /**
   * Reconstruct keypair from Shamir shares
   * @param {ShamirShare[]} shares
   * @param {import('./identity.js').IdentityManager} identityManager
   * @returns {Promise<import('./identity.js').StyxKeyPair>}
   */
  async restoreFromShares(shares, identityManager) {
    const secretBytes = this._reconstructor.reconstruct(shares);
    return identityManager.importPrivateKey(secretBytes);
  }

  /**
   * Verify that shares can reconstruct a valid keypair
   * @param {ShamirShare[]} shares
   * @param {import('./identity.js').IdentityManager} identityManager
   * @returns {Promise<boolean>}
   */
  async verifyShares(shares, identityManager) {
    try {
      const kp = await this.restoreFromShares(shares, identityManager);
      return kp.publicKey.bytes.length === 32;
    } catch {
      return false;
    }
  }
}
