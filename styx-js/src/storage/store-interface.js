// styx-js/src/storage/store-interface.js
// Abstract storage interface for the ledger

import { VectorClock } from '../ledger/vector-clock.js';

/**
 * Abstract interface for ledger persistence.
 * Implement this for any storage backend (memory, IndexedDB, etc.)
 */
export class LedgerStore {
  /** Append an event to the store */
  async appendEvent(event) { throw new Error('Not implemented'); }

  /** Get all events ordered by HLC */
  async getAllEvents() { throw new Error('Not implemented'); }

  /** Get the latest (most recent) event, or null */
  async getLatestEvent() { throw new Error('Not implemented'); }

  /** Get an event by its eventId */
  async getEventById(eventId) { throw new Error('Not implemented'); }

  /** Get events by type */
  async getEventsByType(eventType) { throw new Error('Not implemented'); }

  /** Get the current vector clock state */
  async getCurrentVectorClock() { throw new Error('Not implemented'); }

  /** Nullify an event's payload (pruning) */
  async pruneEvent(eventId) { throw new Error('Not implemented'); }

  /** Clear all events */
  async clear() { throw new Error('Not implemented'); }

  /** Get event count */
  async count() { throw new Error('Not implemented'); }
}

/**
 * Abstract interface for peer persistence.
 */
export class PeerStore {
  async addPeer({ pubkeyHex, alias, pairedAt }) { throw new Error('Not implemented'); }
  async getPeerByPubkey(pubkeyHex) { throw new Error('Not implemented'); }
  async getActivePeers() { throw new Error('Not implemented'); }
  async deactivatePeer(pubkeyHex) { throw new Error('Not implemented'); }
  async updatePeerKey({ oldPubkeyHex, newPubkeyHex }) { throw new Error('Not implemented'); }
  async addRekeyEntry({ oldKeyHex, newKeyHex, timestamp }) { throw new Error('Not implemented'); }
  async getRekeyHistory(currentKeyHex) { throw new Error('Not implemented'); }
}

/**
 * Abstract interface for outbox persistence.
 */
export class OutboxStore {
  async addEntry(eventId) { throw new Error('Not implemented'); }
  async getReadyToSend() { throw new Error('Not implemented'); }
  async markSent({ eventId, transport }) { throw new Error('Not implemented'); }
  async markFailed({ eventId }) { throw new Error('Not implemented'); }
  async pendingCount() { throw new Error('Not implemented'); }
}

/**
 * Abstract interface for secure key storage.
 */
export class SecureKeyStore {
  async storeKeyPair({ keyId, keyPair }) { throw new Error('Not implemented'); }
  async retrieveKeyPair(keyId) { throw new Error('Not implemented'); }
  async deleteKeyPair(keyId) { throw new Error('Not implemented'); }
  async hasKeyPair(keyId) { throw new Error('Not implemented'); }
  async storeSecret({ key, value }) { throw new Error('Not implemented'); }
  async retrieveSecret(key) { throw new Error('Not implemented'); }
  async deleteSecret(key) { throw new Error('Not implemented'); }
  async deleteAll() { throw new Error('Not implemented'); }
}
