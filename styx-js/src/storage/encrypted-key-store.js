// styx-js/src/storage/encrypted-key-store.js
// Password-protected identity storage: encrypts a secret at rest with a key
// derived from the user's password (PBKDF2-SHA256 → AES-GCM-256, via WebCrypto).
// Backend-agnostic: persists a JSON-serializable record through a KV backend.

import { bytesToBase64, base64ToBytes, randomBytes } from '../utils.js';

const RECORD_KEY = 'styx:identity';
const RECORD_VERSION = 1;
const PBKDF2_ITERATIONS = 210000; // OWASP 2023 guidance for PBKDF2-SHA256
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

/**
 * Encrypted, password-protected store for a single identity secret.
 */
export class EncryptedKeyStore {
  /**
   * @param {object} options
   * @param {{get: Function, set: Function, delete: Function}} options.backend
   *   Async KV backend. `get(key)` returns the stored value or null.
   */
  constructor({ backend }) {
    if (!backend) throw new Error('EncryptedKeyStore requires a backend');
    this._backend = backend;
  }

  /**
   * Whether an identity record already exists.
   * @returns {Promise<boolean>}
   */
  async hasIdentity() {
    const record = await this._backend.get(RECORD_KEY);
    return record != null;
  }

  /**
   * Encrypt and persist the secret under the given password.
   * @param {object} options
   * @param {string} options.password
   * @param {Uint8Array} options.secret
   * @throws {Error} if an identity already exists.
   */
  async initialize({ password, secret }) {
    if (await this.hasIdentity()) {
      throw new Error('Identity already initialized');
    }
    const record = await this._encryptRecord(password, secret);
    await this._backend.set(RECORD_KEY, record);
  }

  /**
   * Decrypt and return the stored secret.
   * @param {object} options
   * @param {string} options.password
   * @returns {Promise<Uint8Array>}
   * @throws {Error} if not initialized or the password is wrong.
   */
  async unlock({ password }) {
    const record = await this._backend.get(RECORD_KEY);
    if (record == null) throw new Error('Identity not initialized');
    return this._decryptRecord(password, record);
  }

  /**
   * Re-encrypt the stored secret under a new password.
   * @param {object} options
   * @param {string} options.oldPassword
   * @param {string} options.newPassword
   * @throws {Error} if not initialized or the old password is wrong.
   */
  async changePassword({ oldPassword, newPassword }) {
    const secret = await this.unlock({ password: oldPassword });
    const record = await this._encryptRecord(newPassword, secret);
    await this._backend.set(RECORD_KEY, record);
  }

  /** @private */
  async _encryptRecord(password, secret) {
    const salt = randomBytes(SALT_LENGTH);
    const iv = randomBytes(IV_LENGTH);
    const key = await this._deriveKey(password, salt);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, secret),
    );
    return {
      v: RECORD_VERSION,
      iterations: PBKDF2_ITERATIONS,
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      ct: bytesToBase64(ciphertext),
    };
  }

  /** @private */
  async _decryptRecord(password, record) {
    const salt = base64ToBytes(record.salt);
    const iv = base64ToBytes(record.iv);
    const ciphertext = base64ToBytes(record.ct);
    const key = await this._deriveKey(password, salt, record.iterations);
    let plaintext;
    try {
      plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext,
      );
    } catch {
      throw new Error('Invalid password');
    }
    return new Uint8Array(plaintext);
  }

  /** @private */
  async _deriveKey(password, salt, iterations = PBKDF2_ITERATIONS) {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey'],
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  }
}
