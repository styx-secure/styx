// styx-js/src/utils.js
// Shared utility functions for the Styx library

/**
 * Convert Uint8Array to hex string
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to Uint8Array
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to Base64 string
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToBase64(bytes) {
  if (typeof btoa === 'function') {
    return btoa(String.fromCharCode(...bytes));
  }
  return Buffer.from(bytes).toString('base64');
}

/**
 * Convert Base64 string to Uint8Array
 * @param {string} b64
 * @returns {Uint8Array}
 */
export function base64ToBytes(b64) {
  if (typeof atob === 'function') {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

/**
 * Concatenate multiple Uint8Arrays
 * @param  {...Uint8Array} arrays
 * @returns {Uint8Array}
 */
export function concatBytes(...arrays) {
  const totalLength = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Constant-time comparison of two Uint8Arrays
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Generate cryptographically secure random bytes
 * @param {number} length
 * @returns {Uint8Array}
 */
export function randomBytes(length) {
  const bytes = new Uint8Array(length);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else if (typeof globalThis.crypto !== 'undefined') {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    throw new Error('No secure random source available');
  }
  return bytes;
}

/**
 * Generate a UUID v4
 * @returns {string}
 */
export function uuidv4() {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 1
  const hex = bytesToHex(bytes);
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

/**
 * Encode a string to UTF-8 bytes
 * @param {string} str
 * @returns {Uint8Array}
 */
export function utf8Encode(str) {
  return new TextEncoder().encode(str);
}

/**
 * Decode UTF-8 bytes to string
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function utf8Decode(bytes) {
  return new TextDecoder().decode(bytes);
}

/**
 * Write a 32-bit unsigned integer as big-endian bytes
 * @param {number} value
 * @returns {Uint8Array}
 */
export function uint32BE(value) {
  const buf = new Uint8Array(4);
  buf[0] = (value >>> 24) & 0xff;
  buf[1] = (value >>> 16) & 0xff;
  buf[2] = (value >>> 8) & 0xff;
  buf[3] = value & 0xff;
  return buf;
}

/**
 * Read a 32-bit unsigned integer from big-endian bytes
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @returns {number}
 */
export function readUint32BE(bytes, offset = 0) {
  return (
    ((bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3]) >>>
    0
  );
}

/**
 * Zero out a Uint8Array in place (secure erase)
 * @param {Uint8Array} bytes
 */
export function secureZero(bytes) {
  bytes.fill(0);
}

/**
 * Simple EventEmitter for browser environments
 */
export class EventEmitter {
  constructor() {
    this._listeners = new Map();
  }

  on(event, fn) {
    if (!this._listeners.has(event)) this._listeners.set(event, new Set());
    this._listeners.get(event).add(fn);
    return () => this.off(event, fn);
  }

  off(event, fn) {
    const set = this._listeners.get(event);
    if (set) set.delete(fn);
  }

  emit(event, ...args) {
    const set = this._listeners.get(event);
    if (set) set.forEach((fn) => fn(...args));
  }

  once(event, fn) {
    const wrapper = (...args) => {
      this.off(event, wrapper);
      fn(...args);
    };
    return this.on(event, wrapper);
  }

  removeAllListeners(event) {
    if (event) {
      this._listeners.delete(event);
    } else {
      this._listeners.clear();
    }
  }
}
