// styx-js/src/crypto/identity.js
// Ed25519 identity management — key generation, import/export

import * as ed from '@noble/ed25519';
import { bytesToHex, hexToBytes, secureZero, constantTimeEqual } from '../utils.js';

/**
 * Immutable Ed25519 public key (32 bytes).
 */
export class StyxPublicKey {
  /** @param {Uint8Array} bytes - Raw 32-byte public key */
  constructor(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
      throw new Error('StyxPublicKey requires exactly 32 bytes');
    }
    this._bytes = new Uint8Array(bytes);
  }

  /** Create from hex string */
  static fromHex(hex) {
    return new StyxPublicKey(hexToBytes(hex));
  }

  /** Raw bytes (copy to prevent mutation) */
  get bytes() {
    return new Uint8Array(this._bytes);
  }

  /** Hex-encoded string */
  toHex() {
    return bytesToHex(this._bytes);
  }

  /** First 8 hex characters — used as Node ID */
  get nodeId() {
    return this.toHex().slice(0, 8);
  }

  /** Constant-time equality check */
  equals(other) {
    if (!(other instanceof StyxPublicKey)) return false;
    return constantTimeEqual(this._bytes, other._bytes);
  }

  toString() {
    return this.toHex();
  }

  toJSON() {
    return this.toHex();
  }
}

/**
 * Ed25519 private key with secure destruction support.
 */
export class StyxPrivateKey {
  /** @param {Uint8Array} bytes - Raw private key bytes */
  constructor(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new Error('StyxPrivateKey requires Uint8Array');
    }
    this._bytes = new Uint8Array(bytes);
    this._destroyed = false;
  }

  /** Raw bytes — throws if destroyed */
  get bytes() {
    if (this._destroyed) throw new Error('Private key has been destroyed');
    return new Uint8Array(this._bytes);
  }

  get isDestroyed() {
    return this._destroyed;
  }

  /** Securely zero the key material */
  destroy() {
    secureZero(this._bytes);
    this._destroyed = true;
  }
}

/**
 * Container for Ed25519 public/private key pair.
 */
export class StyxKeyPair {
  /**
   * @param {StyxPublicKey} publicKey
   * @param {StyxPrivateKey} privateKey
   */
  constructor(publicKey, privateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }
}

/**
 * Generates and imports Ed25519 key pairs.
 */
export class IdentityManager {
  /** Generate a new Ed25519 keypair */
  async generate() {
    const privBytes = ed.utils.randomPrivateKey();
    const pubBytes = await ed.getPublicKeyAsync(privBytes);
    return new StyxKeyPair(
      new StyxPublicKey(pubBytes),
      new StyxPrivateKey(privBytes)
    );
  }

  /** Export public key as raw bytes */
  exportPublicKey(publicKey) {
    return publicKey.bytes;
  }

  /** Import public key from raw bytes */
  importPublicKey(bytes) {
    return new StyxPublicKey(bytes);
  }

  /** Export private key as raw bytes */
  exportPrivateKey(privateKey) {
    return privateKey.bytes;
  }

  /** Reconstruct full keypair from raw private key bytes */
  async importPrivateKey(bytes) {
    const pubBytes = await ed.getPublicKeyAsync(bytes);
    return new StyxKeyPair(
      new StyxPublicKey(pubBytes),
      new StyxPrivateKey(bytes)
    );
  }
}
