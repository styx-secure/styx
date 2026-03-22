// styx-js/src/crypto/spake2.js
// SPAKE2 Password-Authenticated Key Exchange on NIST P-256
// Compatible with the Dart Styx implementation

import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { concatBytes, randomBytes, bytesToHex, secureZero } from '../utils.js';

// SPAKE2 fixed points M and N for P-256 (RFC 9382 test vectors)
const M = p256.ProjectivePoint.fromHex(
  '02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f'
);
const N = p256.ProjectivePoint.fromHex(
  '03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49'
);

/** @enum {string} */
export const Spake2Role = {
  INITIATOR: 'initiator',
  RESPONDER: 'responder',
};

/** @enum {string} */
export const Spake2State = {
  INIT: 'init',
  MESSAGE_SENT: 'messageSent',
  COMPLETED: 'completed',
  FAILED: 'failed',
};

/**
 * A SPAKE2 session that progresses through init → messageSent → completed.
 * Compatible with the Dart implementation.
 */
export class Spake2Session {
  /**
   * @param {string} role - Spake2Role.INITIATOR or Spake2Role.RESPONDER
   * @param {Uint8Array} password - Password bytes (UTF-8 mnemonic)
   */
  constructor(role, password) {
    this.role = role;
    this.state = Spake2State.INIT;
    this._passwordScalar = _passwordToScalar(password);
    this._scalar = null;
    this._myPoint = null;
    this._myPointBytes = null;
    this._peerPointBytes = null;
    this._sessionKey = null;
    this._confirmationKey = null;
  }

  /**
   * Generate the SPAKE2 message to send to the peer.
   * Returns uncompressed point bytes (65 bytes: 04 || x || y).
   * @returns {Uint8Array}
   */
  generateMessage() {
    if (this.state !== Spake2State.INIT) {
      throw new Error(`Cannot generate message in state ${this.state}`);
    }

    // Generate random scalar x
    this._scalar = p256.utils.randomPrivateKey();
    const xG = p256.ProjectivePoint.BASE.multiply(_bytesToBigInt(this._scalar));

    // Compute blinded point: T = xG + pw*M (initiator) or S = xG + pw*N (responder)
    const blindPoint = this.role === Spake2Role.INITIATOR ? M : N;
    const pwBlind = blindPoint.multiply(this._passwordScalar);
    this._myPoint = xG.add(pwBlind);

    // Uncompressed format (65 bytes) — compatible with Dart
    this._myPointBytes = this._myPoint.toRawBytes(false);

    this.state = Spake2State.MESSAGE_SENT;
    return new Uint8Array(this._myPointBytes);
  }

  /**
   * Process the peer's SPAKE2 message and derive the shared session key.
   * @param {Uint8Array} peerMessage - Peer's uncompressed point bytes (65 bytes)
   * @returns {boolean} true if session key was derived
   */
  processMessage(peerMessage) {
    if (this.state !== Spake2State.MESSAGE_SENT) {
      throw new Error(`Cannot process message in state ${this.state}`);
    }

    try {
      this._peerPointBytes = new Uint8Array(peerMessage);
      const peerPoint = p256.ProjectivePoint.fromHex(peerMessage);

      // Remove peer's blinding
      const peerBlindPoint = this.role === Spake2Role.INITIATOR ? N : M;
      const pwBlind = peerBlindPoint.multiply(this._passwordScalar);
      const unblinded = peerPoint.add(pwBlind.negate());

      // Compute shared point K = x * unblinded
      const K = unblinded.multiply(_bytesToBigInt(this._scalar));
      const kBytes = K.toRawBytes(false); // uncompressed

      // Transcript: SHA-256(pA || pB || K) — Dart compatible
      const pABytes = this.role === Spake2Role.INITIATOR
        ? this._myPointBytes
        : this._peerPointBytes;
      const pBBytes = this.role === Spake2Role.INITIATOR
        ? this._peerPointBytes
        : this._myPointBytes;

      const transcript = concatBytes(pABytes, pBBytes, kBytes);
      const hashBytes = sha256(transcript);

      // Session key = first 32 bytes of hash
      this._sessionKey = new Uint8Array(hashBytes);

      // Confirmation key = SHA-256(hashBytes || "styx-spake2-confirm")
      this._confirmationKey = sha256(
        concatBytes(hashBytes, new TextEncoder().encode('styx-spake2-confirm'))
      );

      this.state = Spake2State.COMPLETED;
      return true;
    } catch (e) {
      this.state = Spake2State.FAILED;
      return false;
    }
  }

  /**
   * Get the derived shared session key
   * @returns {Uint8Array} 32-byte session key
   */
  getSessionKey() {
    if (this.state !== Spake2State.COMPLETED) {
      throw new Error('Session key not available — SPAKE2 not completed');
    }
    return new Uint8Array(this._sessionKey);
  }

  /**
   * Get HMAC confirmation value for the session.
   * HMAC(confirmationKey, roleByte || ourMessage || peerMessage)
   * @returns {Uint8Array}
   */
  getConfirmation() {
    if (this.state !== Spake2State.COMPLETED) {
      throw new Error('Confirmation not available');
    }
    const roleByte = this.role === Spake2Role.INITIATOR ? 0x01 : 0x02;
    const data = concatBytes(
      new Uint8Array([roleByte]),
      this._myPointBytes,
      this._peerPointBytes
    );
    return hmac(sha256, this._confirmationKey, data);
  }

  /**
   * Verify peer's HMAC confirmation.
   * @param {Uint8Array} peerConfirmation
   * @returns {boolean}
   */
  verifyConfirmation(peerConfirmation) {
    if (this.state !== Spake2State.COMPLETED) return false;

    const peerRoleByte = this.role === Spake2Role.INITIATOR ? 0x02 : 0x01;
    const data = concatBytes(
      new Uint8Array([peerRoleByte]),
      this._peerPointBytes,
      this._myPointBytes
    );
    const expected = hmac(sha256, this._confirmationKey, data);

    // Constant-time comparison
    if (expected.length !== peerConfirmation.length) return false;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) {
      diff |= expected[i] ^ peerConfirmation[i];
    }
    return diff === 0;
  }

  /**
   * Securely destroy all session secrets.
   */
  destroy() {
    if (this._scalar) secureZero(this._scalar);
    if (this._sessionKey) secureZero(this._sessionKey);
    if (this._confirmationKey) secureZero(this._confirmationKey);
    this._myPoint = null;
    this._myPointBytes = null;
    this._peerPointBytes = null;
    this.state = Spake2State.FAILED;
  }
}

/**
 * Factory for creating SPAKE2 sessions.
 */
export class Spake2Protocol {
  createInitiatorSession(password) {
    return new Spake2Session(Spake2Role.INITIATOR, password);
  }

  createResponderSession(password) {
    return new Spake2Session(Spake2Role.RESPONDER, password);
  }

  /**
   * Convert a BIP-39 mnemonic to a password for SPAKE2.
   * Compatible with Dart: utf8(mnemonic.trim().toLowerCase())
   * @param {string} mnemonic
   * @returns {Uint8Array}
   */
  mnemonicToPassword(mnemonic) {
    const normalized = mnemonic.trim().toLowerCase();
    return new TextEncoder().encode(normalized);
  }
}

// --- Internal helpers ---

function _bytesToBigInt(bytes) {
  let hex = bytesToHex(bytes);
  return BigInt('0x' + hex);
}

function _passwordToScalar(password) {
  const hash = sha256(password);
  const n = p256.CURVE.n;
  const num = _bytesToBigInt(hash);
  const result = num % n;
  return result === 0n ? 1n : result;
}
