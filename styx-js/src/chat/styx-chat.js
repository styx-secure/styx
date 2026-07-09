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
  bytesToHex, bytesToBase64, base64ToBytes, utf8Encode, utf8Decode, uuidv4, EventEmitter,
} from '../utils.js';
import { schnorr } from '@noble/curves/secp256k1';
import { MlsEngine } from '../crypto/mls/mls-engine.js';
import { ContactRoster } from './contact-roster.js';
import { EncryptedKeyStore } from '../storage/encrypted-key-store.js';
import { LocalStorageBackend } from '../storage/local-storage-backend.js';
import { BroadcastChannelTransport } from '../transport/broadcast-channel-transport.js';
import { NostrChatTransport } from '../transport/nostr-chat-transport.js';

function defaultBackend(ns) {
  if (typeof localStorage !== 'undefined') {
    return new LocalStorageBackend(`styxchat:${ns ? `${ns}:` : ''}`);
  }
  throw new Error('StyxChat: no storage backend available — inject one via init({ backend })');
}

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
  /** Plain-object snapshot for persistence. */
  snapshot() { return Object.fromEntries(this._byContact); }
  /** Load a snapshot produced by snapshot(). */
  hydrate(obj) { this._byContact = new Map(Object.entries(obj || {})); }
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
  /**
   * Two modes:
   * - Dependency-injected (tests): pass { identity, engine, roster, transport, store }.
   * - App: `new StyxChat()` then `await init({ password })` assembles real deps.
   */
  constructor(deps = {}) {
    this._emitter = new EventEmitter();
    this._unsubs = [];
    this._started = false;
    this._assembled = false;
    this._store = deps.store || new MemoryMessageStore();
    this._groups = {}; // contactPubkey -> MLS groupId (persisted in app mode)
    if (deps.identity && deps.engine && deps.roster && deps.transport) {
      this._identity = { ...deps.identity };
      this._engine = deps.engine;
      this._roster = deps.roster;
      this._transport = deps.transport;
      this._wireRoster();
      this._assembled = true;
    }
  }

  /**
   * Whether an identity already exists in the given (or default) backend.
   * @param {object} [opts] @param {object} [opts.backend]
   * @returns {Promise<boolean>}
   */
  static async hasIdentity({ backend, ns } = {}) {
    const be = backend || defaultBackend(ns);
    return new EncryptedKeyStore({ backend: be }).hasIdentity();
  }

  /**
   * Assemble real dependencies (first run creates an Ed25519 identity, else
   * unlocks it) and start. On the app path pass only { password }; tests may
   * override { backend, channelName, alias }.
   * @returns {Promise<{pubkey:string, alias:string}>}
   */
  async init({ password, backend, channelName, alias, ns, relays } = {}) {
    if (!this._assembled) {
      const be = backend || defaultBackend(ns);
      const keyStore = new EncryptedKeyStore({ backend: be });
      // The addressable identity is a secp256k1 (Nostr) key: pubkey doubles as
      // the Nostr address and the MLS credential label.
      let sk;
      let aliasVal;
      if (await keyStore.hasIdentity()) {
        sk = await keyStore.unlock({ password }); // throws on wrong password
        aliasVal = (await be.get('alias')) || 'Io';
      } else {
        sk = schnorr.utils.randomPrivateKey();
        await keyStore.initialize({ password, secret: sk });
        aliasVal = alias || 'Io';
        await be.set('alias', aliasVal);
      }
      const pubkey = bytesToHex(schnorr.getPublicKey(sk));
      this._identity = { pubkey, alias: aliasVal };
      this._nostrSecret = sk;
      this._backend = be;
      this._keyStore = keyStore;

      // Restore MLS state (identity + groups) if present, else create fresh.
      const savedState = await be.get('mls:state');
      const savedIdPk = await be.get('mls:idpk');
      if (savedState && savedIdPk) {
        this._engine = await MlsEngine.restore({
          name: pubkey,
          stateBytes: base64ToBytes(savedState),
          identityPubKey: base64ToBytes(savedIdPk),
        });
      } else {
        this._engine = await MlsEngine.create({ name: pubkey });
        await be.set('mls:idpk', bytesToBase64(this._engine.identityPublicKey()));
      }

      this._roster = new ContactRoster({ backend: be });
      await this._roster.load();

      // Restore message history.
      this._store.hydrate(await be.get('msgs'));

      // Reload previously-established sessions from the restored state.
      this._groups = (await be.get('mls:groups')) || {};
      for (const [contactPubkey, groupId] of Object.entries(this._groups)) {
        this._engine.loadSession(contactPubkey, groupId);
      }

      this._transport = relays && relays.length
        ? new NostrChatTransport({ secretKey: sk, pubkey, relays })
        : new BroadcastChannelTransport(pubkey, channelName ? { channelName } : {});
      this._wireRoster();
      this._assembled = true;
    }
    await this.start();
    return this.me;
  }

  /** Wire up the transport receive handler and connect it. Idempotent. */
  async start() {
    if (this._started) return;
    this._offTransport = this._transport.onMessage((from, bytes) => this._onWire(from, bytes));
    await this._transport.connect?.(); // relays: connect + subscribe; BroadcastChannel: no-op

    // Mobile browsers suspend backgrounded tabs and kill the relay socket; force
    // a reconnect + re-subscribe when the app returns to the foreground so
    // messages that arrived meanwhile are delivered.
    if (typeof document !== 'undefined' && this._transport.reconnect) {
      this._onWake = () => {
        if (document.visibilityState === 'visible') Promise.resolve(this._transport.reconnect()).catch(() => {});
      };
      document.addEventListener('visibilitychange', this._onWake);
      window.addEventListener('online', this._onWake);
      window.addEventListener('focus', this._onWake);
    }
    this._started = true;
  }

  /** @private */
  _wireRoster() {
    this._unsubs.push(this._roster.onChanged((list) => this._emitter.emit('contacts', list)));
  }

  get me() { return { pubkey: this._identity.pubkey, alias: this._identity.alias }; }

  async setAlias(alias) {
    this._identity.alias = String(alias);
    if (this._backend) await this._backend.set('alias', this._identity.alias);
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
    const { welcome, ratchetTree, groupId } = this._engine.startSession(inv.pubkey, base64ToBytes(inv.kp));
    this._groups[inv.pubkey] = groupId;
    await this._persistMls();
    await this._send(inv.pubkey, {
      t: 'welcome',
      from: { pubkey: this._identity.pubkey, alias: this._identity.alias },
      welcome: bytesToBase64(welcome),
      tree: bytesToBase64(ratchetTree),
      groupId,
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
    await this._persistMessages();
    this._emitter.emit('message', msg);
    await this._touch(pubkey, text, msg.ts, false);

    const ct = session.encrypt(utf8Encode(String(text)));
    await this._persistMls(); // the ratchet advanced on encrypt
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
    if (this._onWake && typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', this._onWake);
      window.removeEventListener('online', this._onWake);
      window.removeEventListener('focus', this._onWake);
      this._onWake = null;
    }
    this._transport?.close?.();
    this._started = false;
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

  /** Persist MLS state + group map so sessions survive a reload. No-op without a backend (DI/tests). */
  async _persistMls() {
    if (!this._backend || !this._engine?.serializeState) return;
    await this._backend.set('mls:state', bytesToBase64(this._engine.serializeState()));
    await this._backend.set('mls:groups', this._groups);
  }

  /** Persist message history. No-op without a backend (DI/tests). */
  async _persistMessages() {
    if (!this._backend || !this._store.snapshot) return;
    await this._backend.set('msgs', this._store.snapshot());
  }

  async _onWire(from, bytes) {
    let env;
    try { env = JSON.parse(utf8Decode(bytes)); } catch { return; }

    if (env.t === 'welcome') {
      this._engine.joinSession(from, base64ToBytes(env.welcome), base64ToBytes(env.tree));
      if (env.groupId) this._groups[from] = env.groupId;
      await this._persistMls();
      if (!(await this._roster.get(from))) {
        await this._roster.add({ pubkey: from, alias: env.from?.alias || from });
      }
      return;
    }
    if (env.t === 'app') {
      const session = this._engine.session(from);
      if (!session) return;
      const res = session.decrypt(base64ToBytes(env.ct));
      await this._persistMls(); // the ratchet advanced on decrypt
      if (res.kind !== 'application') return;
      const text = utf8Decode(res.plaintext);
      const msg = {
        id: uuidv4(), contactPubkey: from, direction: 'in',
        text, ts: Date.now(), state: 'delivered',
      };
      await this._store.append(msg);
      await this._persistMessages();
      await this._touch(from, text, msg.ts, true);
      this._emitter.emit('message', msg);
      return;
    }
    if (env.t === 'typing') {
      this._emitter.emit('typing', from, !!env.on);
    }
  }
}
