// styx-js/src/crypto/encryption.js
// ChaCha20-Poly1305 encryption — compatible with Dart implementation

import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes, concatBytes } from '../utils.js';

const NONCE_LENGTH = 12; // ChaCha20-Poly1305 standard nonce
const TAG_LENGTH = 16;   // Poly1305 auth tag

/**
 * Encrypts/decrypts messages using ChaCha20-Poly1305.
 * Format: nonce(12) || ciphertext || tag(16)
 * Compatible with Dart's cryptography package.
 */
export class StyxEncryptor {
  /**
   * @param {Uint8Array} sendKey - 32-byte key for outgoing messages
   * @param {Uint8Array} receiveKey - 32-byte key for incoming messages
   */
  constructor(sendKey, receiveKey) {
    this._sendKey = sendKey;
    this._receiveKey = receiveKey;
  }

  /**
   * Encrypt plaintext with the send key.
   * @param {Uint8Array} plaintext
   * @returns {Uint8Array} nonce(12) || ciphertext || tag(16)
   */
  encrypt(plaintext) {
    const nonce = randomBytes(NONCE_LENGTH);
    const cipher = chacha20poly1305(this._sendKey, nonce);
    const ciphertextWithTag = cipher.encrypt(plaintext);
    return concatBytes(nonce, ciphertextWithTag);
  }

  /**
   * Decrypt ciphertext with the receive key.
   * @param {Uint8Array} data - nonce(12) || ciphertext || tag(16)
   * @returns {Uint8Array} plaintext
   * @throws {Error} if authentication fails
   */
  decrypt(data) {
    if (data.length < NONCE_LENGTH + TAG_LENGTH) {
      throw new Error('Ciphertext too short');
    }
    const nonce = data.slice(0, NONCE_LENGTH);
    const ciphertextWithTag = data.slice(NONCE_LENGTH);
    const cipher = chacha20poly1305(this._receiveKey, nonce);
    return cipher.decrypt(ciphertextWithTag);
  }
}
