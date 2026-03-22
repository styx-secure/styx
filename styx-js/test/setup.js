// test/setup.js — Shared test helpers for styx-js

import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { StyxPublicKey, StyxPrivateKey, StyxKeyPair, IdentityManager } from '../src/crypto/identity.js';
import { Hasher } from '../src/crypto/hasher.js';
import { Signer } from '../src/crypto/signer.js';
import { EventFactory } from '../src/ledger/event-factory.js';
import { EventType } from '../src/ledger/event.js';
import { VectorClock } from '../src/ledger/vector-clock.js';
import { setBip39Wordlist } from '../src/crypto/mnemonic.js';
import { bytesToHex, utf8Encode } from '../src/utils.js';

// --- BIP-39 Wordlist (minimal 2048-word test list) ---
// Generate a deterministic 2048-word test list
const TEST_WORDLIST = [];
for (let i = 0; i < 2048; i++) {
  TEST_WORDLIST.push('word' + String(i).padStart(4, '0'));
}
// Replace first few with real BIP-39 words for readable tests
const realWords = [
  'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
  'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
  'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actual', 'adapt',
  'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance', 'advice',
  'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent', 'agree',
  'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album', 'alcohol',
];
for (let i = 0; i < realWords.length; i++) {
  TEST_WORDLIST[i] = realWords[i];
}

/**
 * Load the test BIP-39 wordlist into the mnemonic module.
 */
export function loadTestWordlist() {
  setBip39Wordlist(TEST_WORDLIST);
}

/**
 * Create a test Ed25519 keypair.
 * @returns {Promise<StyxKeyPair>}
 */
export async function createTestKeyPair() {
  const im = new IdentityManager();
  return im.generate();
}

/**
 * Create a test LedgerEvent with valid chain linkage.
 * @param {object} [opts]
 * @param {StyxKeyPair} [opts.keyPair] - keypair to sign with
 * @param {import('../src/ledger/event.js').LedgerEvent} [opts.previousEvent] - preceding event
 * @param {VectorClock} [opts.vectorClock] - current VC
 * @param {string} [opts.peerRole] - 'A' or 'B'
 * @param {string} [opts.type] - EventType
 * @param {Uint8Array} [opts.payload]
 * @returns {Promise<import('../src/ledger/event.js').LedgerEvent>}
 */
export async function createTestEvent(opts = {}) {
  const keyPair = opts.keyPair || await createTestKeyPair();
  const signer = new Signer();
  const hasher = new Hasher();
  const factory = new EventFactory(signer, hasher);
  const vc = opts.vectorClock || VectorClock.zero();
  const peerRole = opts.peerRole || 'A';
  const type = opts.type || EventType.MESSAGE;
  const payload = opts.payload || utf8Encode('test payload');

  if (opts.previousEvent) {
    return factory.createEvent({
      type,
      payload,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      previousEvent: opts.previousEvent,
      currentVectorClock: vc,
      localPeerRole: peerRole,
    });
  }

  return factory.createGenesisEvent({
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    nodeId: keyPair.publicKey.nodeId,
  });
}

/**
 * Create a chain of N events.
 * @param {number} n
 * @returns {Promise<{events: LedgerEvent[], keyPair: StyxKeyPair}>}
 */
export async function createTestChain(n) {
  const keyPair = await createTestKeyPair();
  const events = [];
  let vc = VectorClock.zero();

  const genesis = await createTestEvent({ keyPair });
  events.push(genesis);
  vc = vc.increment('A');

  for (let i = 1; i < n; i++) {
    const event = await createTestEvent({
      keyPair,
      previousEvent: events[i - 1],
      vectorClock: vc,
      payload: utf8Encode(`message ${i}`),
    });
    events.push(event);
    vc = vc.increment('A');
  }

  return { events, keyPair };
}

export { TEST_WORDLIST };
