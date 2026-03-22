// styx-js/src/crypto/signer.js
// Ed25519 signing and verification

import * as ed from '@noble/ed25519';

/**
 * Signs data with Ed25519 private keys.
 */
export class Signer {
  /**
   * Create an Ed25519 signature (64 bytes)
   * @param {Uint8Array} payload - Data to sign
   * @param {import('./identity.js').StyxPrivateKey} privateKey
   * @returns {Promise<Uint8Array>} 64-byte signature
   */
  async sign(payload, privateKey) {
    return ed.signAsync(payload, privateKey.bytes);
  }
}

/**
 * Verifies Ed25519 signatures.
 */
export class Verifier {
  /**
   * Verify an Ed25519 signature
   * @param {Uint8Array} payload - Original data
   * @param {Uint8Array} signatureBytes - 64-byte signature
   * @param {import('./identity.js').StyxPublicKey} publicKey
   * @returns {Promise<boolean>}
   */
  async verify(payload, signatureBytes, publicKey) {
    try {
      return await ed.verifyAsync(signatureBytes, payload, publicKey.bytes);
    } catch {
      return false;
    }
  }
}
