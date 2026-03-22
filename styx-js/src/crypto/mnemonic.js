// styx-js/src/crypto/mnemonic.js
// BIP-39 mnemonic generation and Double Check verification codes

import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { pbkdf2Async } from '@noble/hashes/pbkdf2';
import { randomBytes, concatBytes } from '../utils.js';

// BIP-39 English wordlist (2048 words) - we load a minimal subset inline
// In production, import the full wordlist from a separate file
// For now, we provide a loader mechanism
let _wordlist = null;

/**
 * Set the BIP-39 wordlist. Must be called before using MnemonicGenerator.
 * @param {string[]} wordlist - Array of 2048 words
 */
export function setBip39Wordlist(wordlist) {
  if (wordlist.length !== 2048) {
    throw new Error('BIP-39 wordlist must have exactly 2048 words');
  }
  _wordlist = wordlist;
}

/**
 * Get the current BIP-39 wordlist
 * @returns {string[]}
 */
export function getBip39Wordlist() {
  if (!_wordlist) {
    throw new Error(
      'BIP-39 wordlist not loaded. Call setBip39Wordlist() first or import styx-js/wordlist'
    );
  }
  return _wordlist;
}

/**
 * Generates and validates BIP-39 mnemonics.
 */
export class MnemonicGenerator {
  /**
   * Generate a random mnemonic
   * @param {number} [wordCount=6] - Number of words
   * @returns {string} Space-separated mnemonic
   */
  generate(wordCount = 6) {
    const wordlist = getBip39Wordlist();
    const words = [];
    for (let i = 0; i < wordCount; i++) {
      const idx = _secureRandomIndex(wordlist.length);
      words.push(wordlist[idx]);
    }
    return words.join(' ');
  }

  /**
   * Validate that all words exist in the BIP-39 wordlist
   * @param {string} mnemonic
   * @returns {boolean}
   */
  validate(mnemonic) {
    const wordlist = getBip39Wordlist();
    const words = mnemonic.trim().toLowerCase().split(/\s+/);
    if (words.length === 0) return false;
    return words.every((w) => wordlist.includes(w));
  }

  /**
   * Derive a 32-byte seed from mnemonic via PBKDF2
   * @param {string} mnemonic
   * @returns {Promise<Uint8Array>} 32-byte seed
   */
  async mnemonicToSeed(mnemonic) {
    const password = new TextEncoder().encode(mnemonic);
    const salt = new TextEncoder().encode('mnemonic');
    return pbkdf2Async(sha512, password, salt, {
      c: 2048,
      dkLen: 64,
    });
  }

  get supportedLanguages() {
    return ['english'];
  }
}

/**
 * Derives 6-digit Double Check verification codes from SPAKE2 session keys.
 */
export class SessionVerifier {
  /**
   * Generate a 6-digit code from a session key
   * @param {Uint8Array} sessionKey
   * @returns {string} 6-digit string, e.g. "483291"
   */
  generateDoubleCheckCode(sessionKey) {
    const hash = sha256(
      concatBytes(sessionKey, new TextEncoder().encode('styx-double-check-v1'))
    );
    // Take first 3 bytes (24-bit), modulo 1,000,000 — compatible with Dart
    const num = (hash[0] << 16) | (hash[1] << 8) | hash[2];
    return String(num % 1000000).padStart(6, '0');
  }
}

/**
 * Double Check code verifier with formatting utilities.
 */
export class DoubleCheckVerifier {
  constructor() {
    this._sessionVerifier = new SessionVerifier();
  }

  /**
   * Generate code from session key
   * @param {Uint8Array} sessionKey
   * @returns {string}
   */
  generateCode(sessionKey) {
    return this._sessionVerifier.generateDoubleCheckCode(sessionKey);
  }

  /**
   * Format code for display: "483291" → "483 291"
   * @param {string} code
   * @returns {string}
   */
  formatForDisplay(code) {
    const normalized = this.normalize(code);
    return normalized.slice(0, 3) + ' ' + normalized.slice(3);
  }

  /**
   * Check if input is exactly 6 digits (ignoring spaces/dashes)
   * @param {string} input
   * @returns {boolean}
   */
  isValidFormat(input) {
    const normalized = this.normalize(input);
    return /^\d{6}$/.test(normalized);
  }

  /**
   * Remove spaces and dashes from input
   * @param {string} input
   * @returns {string}
   */
  normalize(input) {
    return input.replace(/[\s-]/g, '');
  }
}

// --- Internal helpers ---

function _secureRandomIndex(max) {
  const bytes = randomBytes(4);
  const num = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  return num % max;
}
