// nostr-chat-transport.js — real network transport for StyxChat over Nostr relays.
//
// Implements the orchestrator's transport interface (send/onMessage) on top of
// RelayPool. Each message is a kind:30078 event p-tagged to the recipient's
// Nostr pubkey, schnorr-signed with the sender's key; the payload (an opaque
// StyxChat envelope, already MLS-protected) rides in `content` as base64.
// Relays store the events, so pairing and messages reach peers that reconnect
// later. Metadata (who ↔ who, timing) is visible to relays — acceptable for a
// test; production would NIP-44 gift-wrap it.

import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { RelayPool } from './nostr-transport.js';
import { bytesToHex, bytesToBase64, base64ToBytes, utf8Encode, uuidv4 } from '../utils.js';

const KIND = 30078;

export class NostrChatTransport {
  /**
   * @param {object} opts
   * @param {Uint8Array} opts.secretKey 32-byte secp256k1 private key
   * @param {string} opts.pubkey hex x-only Nostr pubkey (this peer's address)
   * @param {string[]} opts.relays relay WebSocket URLs
   */
  constructor({ secretKey, pubkey, relays }) {
    this._sk = secretKey;
    this._pk = pubkey;
    this._pool = new RelayPool(relays);
    this._handler = null;
    this._poolHandler = null;
    this._subId = null;
  }

  onMessage(cb) {
    this._handler = cb;
    return () => { this._handler = null; };
  }

  /** Connect to relays and subscribe to events addressed to us (incl. stored history). */
  async connect() {
    const n = await this._pool.connectAll();
    if (n === 0) throw new Error('NostrChatTransport: could not connect to any relay');
    this._poolHandler = ({ data }) => this._onRelay(data);
    this._pool.messages.on('message', this._poolHandler);
    this._subId = `sc-${this._pk.slice(0, 12)}`;
    this._pool.subscribe(this._subId, { kinds: [KIND], '#p': [this._pk] });
  }

  async send(toPubkey, bytes) {
    const event = {
      kind: KIND,
      pubkey: this._pk,
      created_at: Math.floor(Date.now() / 1000),
      tags: [['p', toPubkey], ['nonce', uuidv4()]],
      content: bytesToBase64(bytes),
    };
    this._sign(event);
    this._pool.publish(event);
  }

  close() {
    if (this._poolHandler) this._pool.messages.off('message', this._poolHandler);
    this._pool.disconnectAll();
  }

  /** @private NIP-01 id + schnorr signature. */
  _sign(event) {
    const serialized = JSON.stringify([
      0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
    ]);
    const id = sha256(utf8Encode(serialized));
    event.id = bytesToHex(id);
    event.sig = bytesToHex(schnorr.sign(id, this._sk));
  }

  /** @private Handle a raw relay message: ['EVENT', subId, event]. */
  _onRelay(data) {
    if (!Array.isArray(data) || data[0] !== 'EVENT') return;
    const ev = data[2];
    if (!ev || !ev.content || ev.pubkey === this._pk) return;
    const addressedToUs = (ev.tags || []).some((t) => t[0] === 'p' && t[1] === this._pk);
    if (!addressedToUs) return;
    try {
      this._handler?.(ev.pubkey, base64ToBytes(ev.content));
    } catch (e) {
      console.error('[NostrChatTransport] handler error:', e);
    }
  }
}
