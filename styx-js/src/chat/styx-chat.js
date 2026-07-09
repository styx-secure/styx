// styx-chat.js — the multi-contact orchestrator.
//
// Ties together per-contact MLS sessions (MlsEngine/MlsSession), the contact
// roster (ContactRoster), a message store, and a transport, exposing the
// StyxChat contract consumed by the frontend. Dependency-injected so it can be
// unit-tested with an in-memory transport and store; the browser wiring
// (EncryptedKeyStore + IndexedDB + WebRTC/Nostr transport) is assembled on top.
//
// Wire protocol (opaque bytes over the transport, JSON envelope):
//   { t:'welcome', from:{pubkey,alias}, welcome, tree }  — group join material
//   { t:'app',     ct }                                   — encrypted app message
//   { t:'typing',  on }                                   — ephemeral typing signal

import {
  bytesToBase64, base64ToBytes, utf8Encode, utf8Decode, uuidv4, EventEmitter,
} from '../utils.js';

/** Minimal in-memory message log (swap for an IndexedDB-backed store later). */
export class MemoryMessageStore {
  constructor() { this._byContact = new Map(); }
  async append(msg) {
    const list = this._byContact.get(msg.contactPubkey) || [];
    list.push(msg);
    this._byContact.set(msg.contactPubkey, list);
  }
  async list(pubkey, { before, limit = 25 } = {}) {
    const all = (this._byContact.get(pubkey) || []).slice();
    const arr = before ? all.filter((m) => m.ts < before) : all;
    return arr.slice(Math.max(0, arr.length - limit));
  }
  async remove(pubkey) { this._byContact.delete(pubkey); }
}

export class StyxChat {
  /**
   * @param {object} deps
   * @param {{pubkey:string, alias:string}} deps.identity local identity
   * @param {import('../crypto/mls/mls-engine.js').MlsEngine} deps.engine
   * @param {import('./contact-roster.js').ContactRoster} deps.roster (loaded)
   * @param {{send:Function, onMessage:Function}} deps.transport
   * @param {object} [deps.store] message store (defaults to in-memory)
   */
  constructor({ identity, engine, roster, transport, store }) {
    this._identity = { ...identity };
    this._engine = engine;
    this._roster = roster;
    this._transport = transport;
    this._store = store || new MemoryMessageStore();
    this._emitter = new EventEmitter();
    this._unsubs = [roster.onChanged((list) => this._emitter.emit('contacts', list))];
  }

  /** Wire up the transport receive handler. Call once after construction. */
  async start() {
    this._offTransport = this._transport.onMessage((from, bytes) => this._onWire(from, bytes));
  }

  get me() { return { pubkey: this._identity.pubkey, alias: this._identity.alias }; }

  async setAlias(alias) {
    this._identity.alias = String(alias);
    return this.me;
  }

  async listContacts() { return this._roster.list(); }
  onContactsChanged(cb) { return this._emitter.on('contacts', cb); }
  onMessage(cb) { return this._emitter.on('message', cb); }
  onMessageState(cb) { return this._emitter.on('state', cb); }
  onTyping(cb) { return this._emitter.on('typing', cb); }

  // ---- pairing (QR) ----
  async createQrInvite() {
    const payload = {
      pubkey: this._identity.pubkey,
      alias: this._identity.alias,
      kp: bytesToBase64(this._engine.keyPackageBytes()),
    };
    return { qr: 'styx://invite/' + bytesToBase64(utf8Encode(JSON.stringify(payload))) };
  }

  async acceptQrInvite(qr) {
    const inv = JSON.parse(utf8Decode(base64ToBytes(String(qr).replace('styx://invite/', ''))));
    const { welcome, ratchetTree } = this._engine.startSession(inv.pubkey, base64ToBytes(inv.kp));
    await this._send(inv.pubkey, {
      t: 'welcome',
      from: { pubkey: this._identity.pubkey, alias: this._identity.alias },
      welcome: bytesToBase64(welcome),
      tree: bytesToBase64(ratchetTree),
    });
    this._pendingAlias = { [inv.pubkey]: inv.alias };
    return { contactPubkey: inv.pubkey };
  }

  async confirmPairing({ contactPubkey, alias }) {
    await this._roster.add({ pubkey: contactPubkey, alias: alias || contactPubkey });
    return { contactPubkey };
  }

  async removeContact(pubkey) {
    await this._roster.remove(pubkey);
    await this._store.remove(pubkey);
  }

  // Remote (mnemonic → SPAKE2) pairing is a later phase.
  async startRemotePairing() { throw new Error('remote pairing not implemented yet'); }
  async joinRemotePairing() { throw new Error('remote pairing not implemented yet'); }

  // ---- messaging ----
  async sendText(pubkey, text) {
    const session = this._engine.session(pubkey);
    if (!session) throw new Error(`No MLS session for ${pubkey}`);
    const msg = {
      id: uuidv4(), contactPubkey: pubkey, direction: 'out',
      text: String(text), ts: Date.now(), state: 'sending',
    };
    await this._store.append(msg);
    this._emitter.emit('message', msg);
    await this._touch(pubkey, text, msg.ts, false);

    const ct = session.encrypt(utf8Encode(String(text)));
    try {
      await this._send(pubkey, { t: 'app', ct: bytesToBase64(ct) });
      this._setState(msg, 'sent');
    } catch {
      this._setState(msg, 'failed');
    }
    return msg;
  }

  async listMessages(pubkey, opts) { return this._store.list(pubkey, opts); }

  async markRead(pubkey) {
    try { await this._roster.clearUnread(pubkey); } catch { /* unknown contact */ }
  }

  async setTyping(pubkey, on) {
    if (this._engine.session(pubkey)) await this._send(pubkey, { t: 'typing', on: !!on });
  }

  destroy() {
    this._offTransport?.();
    this._unsubs.forEach((u) => u());
    this._unsubs = [];
  }

  // ---- internals ----
  async _send(toPubkey, obj) {
    await this._transport.send(toPubkey, utf8Encode(JSON.stringify(obj)));
  }

  _setState(msg, state) {
    msg.state = state;
    this._emitter.emit('state', msg.id, state);
  }

  async _touch(pubkey, preview, ts, incrementUnread) {
    try { await this._roster.touch(pubkey, { preview, ts, incrementUnread }); } catch { /* not yet a contact */ }
  }

  async _onWire(from, bytes) {
    let env;
    try { env = JSON.parse(utf8Decode(bytes)); } catch { return; }

    if (env.t === 'welcome') {
      this._engine.joinSession(from, base64ToBytes(env.welcome), base64ToBytes(env.tree));
      if (!(await this._roster.get(from))) {
        await this._roster.add({ pubkey: from, alias: env.from?.alias || from });
      }
      return;
    }
    if (env.t === 'app') {
      const session = this._engine.session(from);
      if (!session) return;
      const res = session.decrypt(base64ToBytes(env.ct));
      if (res.kind !== 'application') return;
      const text = utf8Decode(res.plaintext);
      const msg = {
        id: uuidv4(), contactPubkey: from, direction: 'in',
        text, ts: Date.now(), state: 'delivered',
      };
      await this._store.append(msg);
      await this._touch(from, text, msg.ts, true);
      this._emitter.emit('message', msg);
      return;
    }
    if (env.t === 'typing') {
      this._emitter.emit('typing', from, !!env.on);
    }
  }
}
