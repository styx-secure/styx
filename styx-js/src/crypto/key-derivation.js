// styx-js/src/crypto/key-derivation.js
// HKDF-based key derivation with directional send/receive keys

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { secureZero, concatBytes } from '../utils.js';

/**
 * Send and receive key pair with secure destruction.
 */
export class DirectionalKeys {
  constructor(sendKey, receiveKey) {
    this._sendKey = sendKey;
    this._receiveKey = receiveKey;
    this._destroyed = false;
  }

  get sendKey() {
    if (this._destroyed) throw new Error('Keys have been destroyed');
    return this._sendKey;
  }

  get receiveKey() {
    if (this._destroyed) throw new Error('Keys have been destroyed');
    return this._receiveKey;
  }

  get isDestroyed() {
    return this._destroyed;
  }

  destroy() {
    secureZero(this._sendKey);
    secureZero(this._receiveKey);
    this._destroyed = true;
  }
}

/**
 * HKDF-based key derivation.
 */
export class KeyDerivation {
  /**
   * Derive a key using HKDF-SHA256
   * @param {Uint8Array} sharedSecret - Input key material
   * @param {Uint8Array} info - Context/application info
   * @param {Uint8Array} [salt] - Optional salt
   * @param {number} [outputLength=32] - Output key length
   * @returns {Uint8Array}
   */
  deriveKey(sharedSecret, info, salt, outputLength = 32) {
    return hkdf(sha256, sharedSecret, salt || new Uint8Array(0), info, outputLength);
  }

  /**
   * Derive directional send/receive keys based on lexicographic pubkey order.
   * The peer with the lexicographically smaller pubkey gets keyA as sendKey.
   * @param {Uint8Array} sharedSecret
   * @param {Uint8Array} localPubKey
   * @param {Uint8Array} remotePubKey
   * @returns {DirectionalKeys}
   */
  deriveDirectionalKeys(sharedSecret, localPubKey, remotePubKey) {
    // Sort pubkeys by raw byte comparison (same as Dart _comparePubKeys)
    const cmp = _comparePubKeys(localPubKey, remotePubKey);
    const lowerKey = cmp < 0 ? localPubKey : remotePubKey;
    const higherKey = cmp < 0 ? remotePubKey : localPubKey;

    const sendInfo = concatBytes(
      new TextEncoder().encode('styx-send-'), lowerKey, higherKey
    );
    const recvInfo = concatBytes(
      new TextEncoder().encode('styx-recv-'), lowerKey, higherKey
    );

    const key1 = this.deriveKey(sharedSecret, sendInfo);
    const key2 = this.deriveKey(sharedSecret, recvInfo);

    const localIsLower = cmp < 0;
    return localIsLower
      ? new DirectionalKeys(key1, key2)
      : new DirectionalKeys(key2, key1);
  }
}

/** Lexicographic byte comparison (same as Dart _comparePubKeys) */
function _comparePubKeys(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
