// styx-js/src/storage/memory-store.js
// In-memory storage implementations for ephemeral mode

import { LedgerStore, PeerStore, OutboxStore, SecureKeyStore } from './store-interface.js';
import { VectorClock } from '../ledger/vector-clock.js';

/**
 * In-memory ledger store — data is lost when the page/tab closes.
 */
export class MemoryLedgerStore extends LedgerStore {
  constructor() {
    super();
    this._events = [];
    this._vectorClock = VectorClock.zero();
  }

  async appendEvent(event) {
    this._events.push(event);
    // Update vector clock to component-wise max
    this._vectorClock = this._vectorClock.merge(event.vectorClock);
    // Keep sorted by HLC
    this._events.sort((a, b) => a.hlc.compareTo(b.hlc));
  }

  async getAllEvents() {
    return [...this._events];
  }

  async getLatestEvent() {
    return this._events.length > 0 ? this._events[this._events.length - 1] : null;
  }

  async getEventById(eventId) {
    return this._events.find((e) => e.eventId === eventId) || null;
  }

  async getEventsByType(eventType) {
    return this._events.filter((e) => e.eventType === eventType);
  }

  async getCurrentVectorClock() {
    return this._vectorClock;
  }

  async pruneEvent(eventId) {
    const idx = this._events.findIndex((e) => e.eventId === eventId);
    if (idx >= 0) {
      this._events[idx] = this._events[idx].toPruned();
    }
  }

  async clear() {
    this._events = [];
    this._vectorClock = VectorClock.zero();
  }

  async count() {
    return this._events.length;
  }
}

/**
 * In-memory peer store.
 */
export class MemoryPeerStore extends PeerStore {
  constructor() {
    super();
    this._peers = new Map();
    this._rekeyHistory = [];
  }

  async addPeer({ pubkeyHex, alias, pairedAt }) {
    this._peers.set(pubkeyHex, {
      publicKey: pubkeyHex,
      alias,
      pairedAt,
      isActive: true,
    });
  }

  async getPeerByPubkey(pubkeyHex) {
    return this._peers.get(pubkeyHex) || null;
  }

  async getActivePeers() {
    return [...this._peers.values()].filter((p) => p.isActive);
  }

  async deactivatePeer(pubkeyHex) {
    const peer = this._peers.get(pubkeyHex);
    if (peer) peer.isActive = false;
  }

  async updatePeerKey({ oldPubkeyHex, newPubkeyHex }) {
    const peer = this._peers.get(oldPubkeyHex);
    if (peer) {
      this._peers.delete(oldPubkeyHex);
      peer.publicKey = newPubkeyHex;
      this._peers.set(newPubkeyHex, peer);
    }
  }

  async addRekeyEntry({ oldKeyHex, newKeyHex, timestamp }) {
    this._rekeyHistory.push({ oldKey: oldKeyHex, newKey: newKeyHex, timestamp });
  }

  async getRekeyHistory(currentKeyHex) {
    return this._rekeyHistory.filter(
      (r) => r.newKey === currentKeyHex || r.oldKey === currentKeyHex
    );
  }
}

/**
 * In-memory outbox store.
 */
export class MemoryOutboxStore extends OutboxStore {
  constructor() {
    super();
    this._entries = new Map();
  }

  async addEntry(eventId) {
    this._entries.set(eventId, {
      eventId,
      status: 'pending',
      retryCount: 0,
      createdAt: new Date(),
      nextRetryAt: null,
    });
  }

  async getReadyToSend() {
    const now = Date.now();
    return [...this._entries.values()].filter(
      (e) =>
        e.status === 'pending' ||
        (e.status === 'failed' && e.nextRetryAt && e.nextRetryAt.getTime() <= now)
    );
  }

  async markSent({ eventId, transport }) {
    const entry = this._entries.get(eventId);
    if (entry) {
      entry.status = 'sent';
      entry.transport = transport;
    }
  }

  async markFailed({ eventId }) {
    const entry = this._entries.get(eventId);
    if (entry) {
      entry.status = 'failed';
      entry.retryCount++;
      // Exponential backoff: min(100ms * 2^attempt, 5000ms)
      const delayMs = Math.min(100 * Math.pow(2, entry.retryCount), 5000);
      entry.nextRetryAt = new Date(Date.now() + delayMs);
    }
  }

  async pendingCount() {
    return [...this._entries.values()].filter(
      (e) => e.status === 'pending' || e.status === 'failed'
    ).length;
  }
}

/**
 * In-memory secure key store.
 */
export class MemoryKeyStore extends SecureKeyStore {
  constructor() {
    super();
    this._keyPairs = new Map();
    this._secrets = new Map();
  }

  async storeKeyPair({ keyId, keyPair }) {
    this._keyPairs.set(keyId, keyPair);
  }
  async retrieveKeyPair(keyId) {
    return this._keyPairs.get(keyId) || null;
  }
  async deleteKeyPair(keyId) {
    this._keyPairs.delete(keyId);
  }
  async hasKeyPair(keyId) {
    return this._keyPairs.has(keyId);
  }
  async storeSecret({ key, value }) {
    this._secrets.set(key, new Uint8Array(value));
  }
  async retrieveSecret(key) {
    return this._secrets.get(key) || null;
  }
  async deleteSecret(key) {
    this._secrets.delete(key);
  }
  async deleteAll() {
    this._keyPairs.clear();
    this._secrets.clear();
  }
}
