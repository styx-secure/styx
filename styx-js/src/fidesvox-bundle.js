/**
 * FidesVox browser bundle — tree-shaken subset of styx-js.
 * Only includes what FidesVox forms and dashboard need.
 */

// Crypto primitives
export { schnorr } from '@noble/curves/secp256k1';
export { x25519 } from '@noble/curves/ed25519';
export { sha256 } from '@noble/hashes/sha256';
export { hkdf } from '@noble/hashes/hkdf';
export { chacha20poly1305 } from '@noble/ciphers/chacha';

// Styx utilities
export {
  bytesToHex, hexToBytes, bytesToBase64, base64ToBytes,
  concatBytes, randomBytes, utf8Encode, utf8Decode,
  constantTimeEqual, secureZero, EventEmitter,
} from './utils.js';

// Styx crypto
export { StyxEncryptor } from './crypto/encryption.js';
export {
  ShamirSplitter, ShamirReconstructor, ShamirShare,
  KeyBackup, InsufficientSharesException, InvalidShareException,
} from './crypto/shamir.js';
export {
  MnemonicGenerator, SessionVerifier, DoubleCheckVerifier,
  setBip39Wordlist, getBip39Wordlist,
} from './crypto/mnemonic.js';

// Styx transport
export { RelayPool } from './transport/nostr-transport.js';
