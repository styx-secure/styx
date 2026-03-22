// styx-js/src/crypto/key-exchange.js
// Ed25519 ↔ X25519 conversion and Diffie-Hellman key exchange

import { edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';
import { x25519 } from '@noble/curves/ed25519';
import { secureZero, randomBytes } from '../utils.js';

/**
 * Converts Ed25519 keys to X25519 format for Diffie-Hellman.
 */
export class KeyConverter {
  /**
   * Convert Ed25519 public key to X25519
   * @param {import('./identity.js').StyxPublicKey} publicKey
   * @returns {Uint8Array} X25519 public key (32 bytes)
   */
  ed25519PublicToX25519(publicKey) {
    return edwardsToMontgomeryPub(publicKey.bytes);
  }

  /**
   * Convert Ed25519 private key to X25519
   * @param {import('./identity.js').StyxPrivateKey} privateKey
   * @returns {Uint8Array} X25519 private key (32 bytes)
   */
  ed25519PrivateToX25519(privateKey) {
    return edwardsToMontgomeryPriv(privateKey.bytes);
  }
}

/**
 * Ephemeral X25519 key pair with secure destruction.
 */
export class X25519KeyPair {
  constructor(publicKey, privateKey) {
    this.publicKey = publicKey;
    this._privateKey = privateKey;
    this._destroyed = false;
  }

  get privateKey() {
    if (this._destroyed) throw new Error('X25519 key pair has been destroyed');
    return this._privateKey;
  }

  get isDestroyed() {
    return this._destroyed;
  }

  destroy() {
    secureZero(this._privateKey);
    this._destroyed = true;
  }
}

/**
 * X25519 Diffie-Hellman key exchange.
 */
export class DiffieHellman {
  /**
   * Generate an ephemeral X25519 key pair
   * @returns {X25519KeyPair}
   */
  generateEphemeralKeyPair() {
    const privKey = randomBytes(32);
    const pubKey = x25519.getPublicKey(privKey);
    return new X25519KeyPair(pubKey, privKey);
  }

  /**
   * Compute shared secret from local private and remote public X25519 keys
   * @param {Uint8Array} localPrivateKey - X25519 private key
   * @param {Uint8Array} remotePublicKey - X25519 public key
   * @returns {Uint8Array} 32-byte shared secret
   */
  computeSharedSecret(localPrivateKey, remotePublicKey) {
    return x25519.getSharedSecret(localPrivateKey, remotePublicKey);
  }
}
