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
import { bytesToHex, hexToBytes, bytesToBase64, base64ToBytes, utf8Encode, uuidv4 } from '../utils.js';

// Kind 1059 (NIP-59 "gift wrap" range) is a REGULAR event: relays store every
// one, so multiple messages and offline delivery survive. (Kind 30078 is
// parameterized-replaceable — newer events would overwrite older ones.)
const KIND = 1059; // regular/stored: pairing + messages survive offline
const EPHEMERAL_KIND = 20000; // ephemeral (20000-29999): relays don't store — for typing/presence

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
    this._seen = new Set(); // processed Nostr event ids (dedup on relay replay)
    this._rejected = 0; // inbound events dropped by signature verification
  }

  /** Number of inbound events dropped because they failed verification. */
  get rejectedCount() { return this._rejected; }

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
    this._pool.subscribe(this._subId, { kinds: [KIND, EPHEMERAL_KIND], '#p': [this._pk] });
  }

  /**
   * @param {string} toPubkey
   * @param {Uint8Array} bytes
   * @param {object} [opts]
   * @param {boolean} [opts.ephemeral] send on an ephemeral kind (not stored by
   *   relays) — used for typing/presence so they aren't replayed on reconnect.
   */
  async send(toPubkey, bytes, { ephemeral = false } = {}) {
    const event = {
      kind: ephemeral ? EPHEMERAL_KIND : KIND,
      pubkey: this._pk,
      created_at: Math.floor(Date.now() / 1000),
      tags: [['p', toPubkey], ['nonce', uuidv4()]],
      content: bytesToBase64(bytes),
    };
    this._sign(event);
    this._pool.publish(event);
  }

  /** Force reconnect + re-subscribe (call when returning to the foreground). */
  async reconnect() {
    await this._pool.reconnect();
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

  /**
   * @private Recompute the NIP-01 id from the canonical serialization and verify
   * the schnorr signature over it. Without this the relay could put any pubkey on
   * any event, and `from` would be a relay-supplied hint rather than an identity.
   * @param {object} ev raw Nostr event
   * @returns {boolean} true iff the id binds the content AND the sig verifies
   */
  _verifyEvent(ev) {
    if (typeof ev.id !== 'string' || typeof ev.sig !== 'string' || typeof ev.pubkey !== 'string') {
      return false;
    }
    try {
      const serialized = JSON.stringify([
        0, ev.pubkey, ev.created_at, ev.kind, ev.tags || [], ev.content,
      ]);
      const id = sha256(utf8Encode(serialized));
      if (bytesToHex(id) !== ev.id) return false;
      return schnorr.verify(hexToBytes(ev.sig), id, hexToBytes(ev.pubkey));
    } catch {
      return false; // malformed hex / wrong lengths
    }
  }

  /** @private Handle a raw relay message: ['EVENT', subId, event]. */
  _onRelay(data) {
    if (!Array.isArray(data) || data[0] !== 'EVENT') return;
    const ev = data[2];
    if (!ev || !ev.content || ev.pubkey === this._pk) return;
    const addressedToUs = (ev.tags || []).some((t) => t[0] === 'p' && t[1] === this._pk);
    if (!addressedToUs) return;
    // The relay is untrusted: prove the event really is from ev.pubkey and that its
    // content is intact. Checked before the dedup set so a forgery bearing a genuine
    // event's id cannot suppress the real one.
    if (!this._verifyEvent(ev)) { this._rejected += 1; return; }
    // Drop stale ephemeral events (typing/presence) replayed by relays that
    // wrongly store the ephemeral kind — they are real-time only.
    if (ev.kind === EPHEMERAL_KIND && Math.floor(Date.now() / 1000) - (ev.created_at || 0) > 20) return;
    if (ev.id) {
      if (this._seen.has(ev.id)) return; // replayed on reconnect — already handled
      this._seen.add(ev.id);
      if (this._seen.size > 5000) this._seen = new Set([ev.id]); // bound memory
    }
    try {
      this._handler?.(ev.pubkey, base64ToBytes(ev.content));
    } catch (e) {
      console.error('[NostrChatTransport] handler error:', e);
    }
  }
}
