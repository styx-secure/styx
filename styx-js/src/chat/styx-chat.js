// styx-chat.js — the multi-contact orchestrator.
//
// Ties together per-contact MLS sessions (MlsEngine/MlsSession), the contact
// roster (ContactRoster), a message store, and a transport, exposing the
// StyxChat contract consumed by the frontend. Dependency-injected so it can be
// unit-tested with an in-memory transport and store; the browser wiring
// (EncryptedKeyStore + IndexedDB + WebRTC/Nostr transport) is assembled on top.
//
// Wire protocol (opaque bytes over the transport, JSON envelope):
//   { t:'welcome', from:{pubkey}, welcome, tree, groupId, hmac } — group join material.
//       `hmac` is HMAC-SHA256 over the invite nonce (see createQrInvite): it proves
//       the sender scanned our QR. Without it the welcome is dropped.
//   { t:'app',     ct }                                   — encrypted app message
//   { t:'typing',  on }                                   — ephemeral typing signal

import {
  bytesToHex, bytesToBase64, base64ToBytes, utf8Encode, utf8Decode, uuidv4, EventEmitter,
  concatBytes, constantTimeEqual, randomBytes,
} from '../utils.js';
import { schnorr } from '@noble/curves/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { MlsEngine } from '../crypto/mls/mls-engine.js';
import { ContactRoster } from './contact-roster.js';
import { EncryptedKeyStore } from '../storage/encrypted-key-store.js';
import { registrationDigest } from '../push/registration-digest.js';
import { LocalStorageBackend } from '../storage/local-storage-backend.js';
import { BroadcastChannelTransport } from '../transport/broadcast-channel-transport.js';
import { NostrChatTransport } from '../transport/nostr-chat-transport.js';

/** Where the outstanding QR invite's nonce is kept, so it survives a reload. */
const INVITE_NONCE_KEY = 'invite:nonce';

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

/**
 * Normalise an alias received from the network. Strips C0/C1 control characters
 * and Unicode bidirectional overrides (which let an attacker render a misleading
 * name), then trims and caps the length.
 * @param {unknown} raw
 * @returns {string} '' when nothing legible remains
 */
export function sanitizeAlias(raw) {
  const stripped = String(raw ?? '')
    // Strip characters that let an attacker forge a misleading display name:
    // C0 (0000-001F), DEL+C1 (007F-009F), Arabic letter mark (061C), zero-width
    // and directional marks (200B-200F), word joiner (2060), bidi isolates
    // (2066-2069) and embeddings/overrides (202A-202E), and the BOM (FEFF).
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001F\u007F-\u009F\u061C\u200B-\u200F\u2060\u2066-\u2069\u202A-\u202E\uFEFF]/g, '')
    .trim();
  // Cap by code point so an astral char (emoji) is never split into a lone surrogate.
  return [...stripped].slice(0, 64).join('');
}

/**
 * Render 32 secret bytes as 60 decimal digits grouped in fives — short enough to
 * read over the phone, wide enough that a collision is not findable.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function formatSafetyNumber(bytes) {
  let n = 0n;
  for (const byte of bytes) n = (n << 8n) | BigInt(byte);
  let digits = '';
  for (let i = 0; i < 60; i += 1) {
    digits = String(n % 10n) + digits;
    n /= 10n;
  }
  return digits.match(/.{5}/g).join(' ');
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
    this._pendingApp = {}; // from -> [envelopes] not yet decryptable (arrived before Welcome)
    this._seenIncoming = new Set(); // inbound message ids already surfaced (dedup relay replay)
    this._readSent = new Set(); // inbound message ids we've already sent a 'read' receipt for
    this._inviteNonce = null; // nonce of the outstanding QR invite, if any (single-use)
    this._pending = new Map(); // pubkey -> { pubkey, alias? } authenticated, not yet a contact
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
   * @param {boolean} [opts.allowInsecureTransport=false] permit the unauthenticated
   *   BroadcastChannel fallback when no relays are given (development only).
   * @returns {Promise<{pubkey:string, alias:string}>}
   */
  async init({ password, backend, channelName, alias, ns, relays, allowInsecureTransport = false } = {}) {
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

      // An invite shown before a reload must still be joinable: restore its nonce.
      const savedNonce = await be.get(INVITE_NONCE_KEY);
      if (savedNonce) this._inviteNonce = base64ToBytes(savedNonce);

      // Reload previously-established sessions from the restored state.
      this._groups = (await be.get('mls:groups')) || {};
      for (const [contactPubkey, groupId] of Object.entries(this._groups)) {
        this._engine.loadSession(contactPubkey, groupId);
      }

      if (relays && relays.length) {
        this._transport = new NostrChatTransport({ secretKey: sk, pubkey, relays });
      } else if (allowInsecureTransport) {
        // Dev/offline only: BroadcastChannel carries no signatures (see its docs).
        this._transport = new BroadcastChannelTransport(pubkey, {
          ...(channelName ? { channelName } : {}),
          allowInsecure: true,
        });
      } else {
        throw new Error(
          'StyxChat: no authenticated transport — pass relays, or allowInsecureTransport:true for dev',
        );
      }
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
      let lastWake = 0;
      this._onWake = () => {
        if (document.visibilityState !== 'visible') return;
        const now = Date.now();
        if (now - lastWake < 3000) return; // debounce: avoid reconnect churn
        lastWake = now;
        Promise.resolve(this._transport.reconnect()).catch(() => {});
      };
      document.addEventListener('visibilitychange', this._onWake);
      window.addEventListener('online', this._onWake);
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

  /**
   * Sign a push-bridge registration with the internal Nostr secret. Keeps the
   * secret key encapsulated — callers get only a signature over the exact
   * (action, our pubkey, endpoint) digest, never a general signing oracle.
   * @param {'register'|'unregister'} action
   * @param {string} endpoint the Web Push subscription endpoint
   * @returns {Promise<string>} schnorr signature, hex
   */
  async signBridgeRegistration(action, endpoint) {
    if (!this._nostrSecret) throw new Error('No identity to sign with');
    const digest = registrationDigest(action, this._identity.pubkey, endpoint);
    return bytesToHex(schnorr.sign(digest, this._nostrSecret));
  }

  async listContacts() { return this._roster.list(); }
  onContactsChanged(cb) { return this._emitter.on('contacts', cb); }
  onMessage(cb) { return this._emitter.on('message', cb); }
  onMessageState(cb) { return this._emitter.on('state', cb); }
  onTyping(cb) { return this._emitter.on('typing', cb); }
  /** An authenticated peer joined our group and awaits an explicit confirmPairing. */
  onPairing(cb) { return this._emitter.on('pairing', cb); }
  /**
   * A Welcome was dropped because the group's MLS credential did not match the peer
   * who sent it. The QR invite is spent and the user needs a fresh one — the UI should
   * say so rather than leaving them staring at a code that can no longer work.
   */
  onInviteRejected(cb) { return this._emitter.on('invite-rejected', cb); }

  /** Pairings authenticated but not yet accepted into the roster. */
  listPendingPairings() { return [...this._pending.values()]; }

  // ---- pairing (QR) ----
  async createQrInvite() {
    // The nonce exists only in this QR and in our memory. Whoever joins must MAC
    // the welcome under it, proving they actually looked at this screen. The QR is
    // therefore the trust anchor, and it is single-use.
    const nonce = randomBytes(32);
    this._inviteNonce = nonce;
    const payload = {
      pubkey: this._identity.pubkey,
      alias: this._identity.alias,
      kp: bytesToBase64(this._engine.keyPackageBytes()),
      nonce: bytesToBase64(nonce),
    };
    // Generating a KeyPackage stores its private key in the MLS provider; persist
    // it, and the nonce, so the invite still works if we reload before the peer joins.
    await this._persistMls();
    await this._backend?.set(INVITE_NONCE_KEY, bytesToBase64(nonce));
    return { qr: 'styx://invite/' + bytesToBase64(utf8Encode(JSON.stringify(payload))) };
  }

  async acceptQrInvite(qr) {
    const inv = JSON.parse(utf8Decode(base64ToBytes(String(qr).replace('styx://invite/', ''))));
    // A3, scanner side: accepting an invite for a pubkey we already have a session
    // with would replace an established (possibly verified) conversation. Refuse —
    // re-pairing is a deliberate act (removeContact first).
    if (this._groups[inv.pubkey] || this._engine.session(inv.pubkey)) {
      throw new Error('A session with this contact already exists — remove it before re-pairing');
    }
    const { welcome, ratchetTree, groupId } = this._engine.startSession(inv.pubkey, base64ToBytes(inv.kp));
    // N2, scanner side: bind the KeyPackage credential to the pubkey the QR claims.
    // This is a consistency check, not the trust anchor — both values come from the
    // (possibly forged) QR, so an attacker who forges *both* to agree passes it. What
    // actually protects the scanner is (a) the in-person scan itself and (b) our
    // Welcome being addressed to inv.pubkey's Nostr address, so a forged-but-consistent
    // KeyPackage yields a group nobody can talk to, not a MITM. The check still earns
    // its place: it turns a merely-inconsistent forgery into an immediate, explained
    // rejection instead of a silently mislabelled contact.
    if (this._engine.peerIdentity(inv.pubkey) !== inv.pubkey) {
      this._engine.removeSession(inv.pubkey);
      throw new Error('Invite rejected: the KeyPackage credential does not match the invite pubkey');
    }
    this._groups[inv.pubkey] = groupId;
    await this._persistMls();
    const nonce = inv.nonce ? base64ToBytes(inv.nonce) : new Uint8Array(0);
    await this._send(inv.pubkey, {
      t: 'welcome',
      from: { pubkey: this._identity.pubkey },
      welcome: bytesToBase64(welcome),
      tree: bytesToBase64(ratchetTree),
      groupId,
      hmac: bytesToBase64(this._welcomeMac(nonce, welcome, ratchetTree, groupId)),
    });
    // The inviter's alias came over the QR — the in-person channel — so it is a
    // trustworthy default here. Ours goes back encrypted, never on the wire.
    this._pending.set(inv.pubkey, { pubkey: inv.pubkey, alias: sanitizeAlias(inv.alias) });
    await this._sendIntro(inv.pubkey);
    return { contactPubkey: inv.pubkey };
  }

  /**
   * Accept a pending pairing into the roster. Nothing else creates a contact: a
   * valid welcome alone must not, or a stranger could add themselves silently.
   */
  async confirmPairing({ contactPubkey, alias }) {
    const pending = this._pending.get(contactPubkey);
    const finalAlias = sanitizeAlias(alias) || pending?.alias || contactPubkey;
    await this._roster.add({ pubkey: contactPubkey, alias: finalAlias });
    this._pending.delete(contactPubkey);
    return { contactPubkey };
  }

  async removeContact(pubkey) {
    await this._roster.remove(pubkey);
    await this._store.remove(pubkey);
    // Drop the MLS session and group mapping too, so the pubkey can be paired
    // again later. Without this, re-pairing would hit the A3 guard forever.
    this._engine.removeSession(pubkey);
    delete this._groups[pubkey];
    this._pending.delete(pubkey);
    await this._persistMls();
  }

  /**
   * A user-verifiable safety number for a contact, in the Signal tradition. It is
   * derived from the shared MLS group secret, so both genuine peers compute the
   * same 60 digits — while anyone sitting in the middle holds a different group
   * and cannot make the two sides agree. Read it aloud to detect a MITM.
   * @param {string} pubkey the contact's pubkey
   * @returns {string} 60 decimal digits in groups of five
   */
  safetyNumber(pubkey) {
    const session = this._engine.session(pubkey);
    if (!session) throw new Error(`No MLS session for ${pubkey}`);
    // Sort the pubkeys so both sides bind the same context.
    const [a, b] = [this._identity.pubkey, pubkey].sort();
    const secret = session.exportSecret('styx:safety-number:v1', utf8Encode(a + b), 32);
    return formatSafetyNumber(secret);
  }

  /** Record that this contact's safety number was compared out-of-band. */
  async setVerified(pubkey, verified) {
    return this._roster.setVerified(pubkey, verified);
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

    // The MLS plaintext is a typed payload: the sender's id + send time travel
    // (encrypted) so the recipient shows the real send time and can correlate
    // delivery/read receipts back to this exact message.
    const ct = session.encrypt(utf8Encode(JSON.stringify({
      t: 'msg', id: msg.id, text: msg.text, ts: msg.ts,
    })));
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
    // Acknowledge reading: one 'read' receipt per inbound message not yet acked.
    // Encrypted through MLS like any message — the relay only sees ciphertext.
    let history = [];
    try { history = await this._store.list(pubkey, { limit: 1000 }); } catch { history = []; }
    for (const m of history) {
      if (m.direction !== 'in' || this._readSent.has(m.id)) continue;
      this._readSent.add(m.id);
      // eslint-disable-next-line no-await-in-loop
      await this._sendReceipt(pubkey, m.id, 'read');
    }
  }

  /**
   * @private Introduce ourselves over the established session. The alias is an
   * application message inside MLS, so the relay never learns who is who.
   * Best-effort: a failed intro only costs a display name.
   */
  async _sendIntro(toPubkey) {
    const session = this._engine.session(toPubkey);
    if (!session) return;
    try {
      const ct = session.encrypt(utf8Encode(JSON.stringify({ t: 'intro', alias: this._identity.alias })));
      await this._persistMls(); // the ratchet advanced on encrypt
      await this._send(toPubkey, { t: 'app', ct: bytesToBase64(ct) });
    } catch { /* transport/session hiccup */ }
  }

  /** Send an encrypted delivery/read receipt for message `ref`. Best-effort. @private */
  async _sendReceipt(toPubkey, ref, kind) {
    const session = this._engine.session(toPubkey);
    if (!session) return;
    try {
      const ct = session.encrypt(utf8Encode(JSON.stringify({ t: 'receipt', ref, kind })));
      await this._persistMls(); // the ratchet advanced on encrypt
      await this._send(toPubkey, { t: 'app', ct: bytesToBase64(ct) });
    } catch { /* transport/session hiccup — receipts are best-effort */ }
  }

  async setTyping(pubkey, on) {
    // Ephemeral: typing must not be stored/replayed by relays (would get stuck).
    if (this._engine.session(pubkey)) await this._send(pubkey, { t: 'typing', on: !!on }, { ephemeral: true });
  }

  destroy() {
    this._offTransport?.();
    this._unsubs.forEach((u) => u());
    this._unsubs = [];
    if (this._onWake && typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', this._onWake);
      window.removeEventListener('online', this._onWake);
      this._onWake = null;
    }
    this._transport?.close?.();
    this._started = false;
  }

  /**
   * Irreversibly wipe this identity from its backend.
   *
   * Order matters: tear down the transport and drop the in-RAM crypto engine first, so
   * nothing can write state back after the erase, then delete every key the backend
   * owns. This is the library half of a factory reset — the browser-global surfaces
   * (push subscription, Cache Storage, service worker, IndexedDB) are the caller's job,
   * because the library does not own them.
   */
  async wipe() {
    try { this.destroy(); } catch { /* best effort — we are erasing anyway */ }
    this._engine = null;
    this._groups = {};
    await this._backend?.clear?.();
  }

  // ---- internals ----
  async _send(toPubkey, obj, opts) {
    await this._transport.send(toPubkey, utf8Encode(JSON.stringify(obj)), opts);
  }

  /**
   * @private The pairing proof: HMAC-SHA256(qr nonce, welcome ‖ tree ‖ groupId).
   * Covering the group material means a spliced welcome fails the check.
   */
  _welcomeMac(nonce, welcomeBytes, treeBytes, groupId) {
    return hmac(sha256, nonce, concatBytes(welcomeBytes, treeBytes, utf8Encode(String(groupId))));
  }

  /**
   * @private Retire the outstanding QR invite.
   *
   * Called once a Welcome has been processed under this invite's nonce — whether we
   * kept the resulting group or rejected it. Either way the invite is spent: MLS
   * consumes the KeyPackage's private init key when it decrypts the Welcome, so no
   * further Welcome for this QR can ever be decrypted. Leaving the nonce behind would
   * advertise a pairing that cannot succeed.
   */
  async _retireInvite() {
    this._inviteNonce = null;
    await this._backend?.delete(INVITE_NONCE_KEY);
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
      // A welcome must never replace an established session (silent-MITM vector).
      if (this._groups[from] || this._engine.session(from)) return;
      // It must also prove the sender saw our QR: no pending invite, or a MAC that
      // does not verify under its nonce, means we are being injected into.
      if (!this._inviteNonce || !env.hmac) return;
      const welcomeBytes = base64ToBytes(env.welcome);
      const treeBytes = base64ToBytes(env.tree);
      const expected = this._welcomeMac(this._inviteNonce, welcomeBytes, treeBytes, env.groupId);
      if (!constantTimeEqual(expected, base64ToBytes(env.hmac))) return;
      // Join first: if the welcome bytes are malformed and joinSession throws, the
      // nonce must survive so the legitimate joiner (who saw the QR) can retry.
      this._engine.joinSession(from, welcomeBytes, treeBytes);
      // N2: the MLS credential in the group we just joined must be the peer who sent
      // it. A valid MAC only proves the sender saw our QR — it does not prove the
      // group is theirs. Somebody who photographed the QR can relay a group built by
      // (or for) a third party, and we would file that conversation under the wrong
      // name: the safety number, the verified badge and "who am I talking to" would
      // all describe someone who is not in the room.
      if (this._engine.peerIdentity(from) !== from) {
        this._engine.removeSession(from);
        // The invite is spent even though we rejected the group: processing the
        // Welcome made MLS consume the KeyPackage's private init key, so no later
        // Welcome for this QR can be decrypted. Retire the nonce too, rather than
        // leaving a pending invite that can no longer work, and tell the app so it
        // can ask the user for a fresh QR.
        await this._retireInvite();
        this._emitter.emit('invite-rejected', { from, reason: 'identity-mismatch' });
        return;
      }
      await this._retireInvite(); // single-use: a photographed QR cannot be replayed
      if (env.groupId) this._groups[from] = env.groupId;
      await this._persistMls();
      // A welcome buys a pending pairing, not a contact: the user decides. Our
      // alias travels back encrypted (an intro), never in the cleartext envelope.
      if (!(await this._roster.get(from))) {
        if (!this._pending.has(from)) this._pending.set(from, { pubkey: from });
        this._emitter.emit('pairing', { pubkey: from });
      }
      await this._sendIntro(from);
      await this._drainPending(from); // messages that arrived before this Welcome
      return;
    }
    if (env.t === 'app') {
      const handled = await this._processApp(from, env);
      if (!handled) (this._pendingApp[from] ||= []).push(env); // wait for the Welcome
      return;
    }
    if (env.t === 'typing') {
      this._emitter.emit('typing', from, !!env.on);
    }
  }

  /** Decrypt + surface one app envelope. @returns {Promise<boolean>} handled (false = no session / not yet decryptable). */
  async _processApp(from, env) {
    const session = this._engine.session(from);
    if (!session) return false;
    let res;
    try { res = session.decrypt(base64ToBytes(env.ct)); } catch { return false; }
    await this._persistMls(); // ratchet advanced on decrypt
    if (res.kind !== 'application') return true;

    // Decode the typed payload; tolerate a bare-string legacy plaintext.
    let payload;
    try { payload = JSON.parse(utf8Decode(res.plaintext)); } catch { payload = null; }
    if (!payload || typeof payload !== 'object') {
      payload = { t: 'msg', id: uuidv4(), text: utf8Decode(res.plaintext), ts: Date.now() };
    }

    if (payload.t === 'intro') {
      // The peer's display name, arriving encrypted. Untrusted: sanitize it.
      const alias = sanitizeAlias(payload.alias);
      if (alias) {
        if (await this._roster.get(from)) await this._roster.update(from, { alias });
        else this._pending.set(from, { pubkey: from, alias });
      }
      return true;
    }

    if (payload.t === 'receipt') {
      // A delivery/read acknowledgement for one of our outgoing messages.
      // Never acknowledge a receipt — that would loop.
      if (payload.ref && (payload.kind === 'delivered' || payload.kind === 'read')) {
        this._emitter.emit('state', payload.ref, payload.kind);
      }
      return true;
    }

    // A chat message. Use the sender's id + send time; dedup relay replay.
    if (this._seenIncoming.has(payload.id)) return true;
    this._seenIncoming.add(payload.id);
    const msg = {
      id: payload.id, contactPubkey: from, direction: 'in',
      text: String(payload.text ?? ''), ts: payload.ts || Date.now(), state: 'delivered',
    };
    await this._store.append(msg);
    await this._persistMessages();
    await this._touch(from, msg.text, msg.ts, true);
    this._emitter.emit('message', msg);
    // Auto-acknowledge delivery (encrypted through MLS, opaque on the wire).
    await this._sendReceipt(from, payload.id, 'delivered');
    return true;
  }

  /** Re-process queued app messages once a session exists (e.g. after the Welcome). */
  async _drainPending(from) {
    const queue = this._pendingApp[from];
    if (!queue || !queue.length) return;
    this._pendingApp[from] = [];
    for (const env of queue) {
      // eslint-disable-next-line no-await-in-loop
      const handled = await this._processApp(from, env);
      if (!handled) (this._pendingApp[from] ||= []).push(env);
    }
  }
}
