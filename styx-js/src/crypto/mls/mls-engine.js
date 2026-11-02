// mls-engine.js — thin wrapper over the vendored OpenMLS-WASM engine.
//
// Isolates OpenMLS behind a stable interface for the rest of styx-js. One
// MlsEngine holds the local device's crypto+storage Provider and MLS Identity;
// each 1:1 contact is a 2-member MLS group exposed as an MlsSession.
//
// Every session is registered only after the engine has checked its group: exactly
// two members, us and one peer, and — when the caller names one — exactly the
// expected peer. The session then stays bound to that peer for every later use.
// start/join/load never register a group that fails this check, never replace an
// existing session, and never register the same group under two contacts.
//
// State is in-memory for now (the OpenMLS Provider keeps group state in RAM);
// persistence across reloads is a follow-up (serialize/restore the provider
// storage — needs a small Rust extension to the vendored crate).

import initWasm, {
  Provider,
  Identity,
  Group,
  KeyPackage,
  RatchetTree,
} from '../../../vendor/openmls-wasm/openmls_wasm.js';
import { uuidv4 } from '../../utils.js';
import { MlsBindingError, MlsSession, soleOtherMember } from './mls-session.js';

export { MlsBindingError };

// Exporter label used only to compare two group handles in memory: two handles
// derive the same value only if they are the same group at the same epoch.
const SAME_GROUP_LABEL = 'styx/engine/same-group-check';
const SAME_GROUP_CONTEXT = new Uint8Array(0);
const SAME_GROUP_LENGTH = 32;

function sameGroupValue(group, provider) {
  return group.export_key(provider, SAME_GROUP_LABEL, SAME_GROUP_CONTEXT, SAME_GROUP_LENGTH);
}

function equalBytes(x, y) {
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i += 1) diff |= x[i] ^ y[i];
  return diff === 0;
}

function freeHandle(group) {
  if (group && typeof group.free === 'function') group.free();
}

let _wasmReady = null;

export class MlsEngine {
  /**
   * Initialize the WASM module once (idempotent).
   * @param {object} [opts]
   * @param {Uint8Array} [opts.wasmBytes] Raw wasm bytes (Node/tests). In the
   *   browser, omit to let the bundler resolve the wasm asset.
   * @returns {Promise<void>}
   */
  static async initWasm({ wasmBytes } = {}) {
    if (!_wasmReady) {
      _wasmReady = wasmBytes ? initWasm({ module_or_path: wasmBytes }) : initWasm();
    }
    await _wasmReady;
  }

  /**
   * Create a fresh local identity (Provider + MLS credential).
   * @param {object} options
   * @param {string} options.name credential identity (e.g. the pubkey hex)
   * @returns {Promise<MlsEngine>}
   */
  static async create({ name }) {
    await MlsEngine.initWasm();
    const provider = new Provider();
    const identity = new Identity(provider, name);
    return new MlsEngine(provider, identity, name);
  }

  /**
   * Restore an engine (identity + all group state) from persisted bytes so
   * sessions survive a page reload.
   * @param {object} options
   * @param {string} options.name credential identity (the pubkey hex)
   * @param {Uint8Array} options.stateBytes output of a prior serializeState()
   * @param {Uint8Array} options.identityPubKey output of a prior identityPublicKey()
   * @returns {Promise<MlsEngine>}
   */
  static async restore({ name, stateBytes, identityPubKey }) {
    await MlsEngine.initWasm();
    const provider = new Provider();
    provider.restore_state(stateBytes);
    const identity = Identity.load(provider, name, identityPubKey);
    if (!identity) throw new Error('MlsEngine.restore: identity not found in state');
    return new MlsEngine(provider, identity, name);
  }

  /** Serialize all MLS state (groups + keys) for persistence. @returns {Uint8Array} */
  serializeState() {
    return this._provider.serialize_state();
  }

  /** The MLS signature public key (needed to reload the identity). @returns {Uint8Array} */
  identityPublicKey() {
    return this._identity.public_key();
  }

  /**
   * Reload a previously-established session's group from restored state.
   *
   * The reloaded group is checked exactly like a new one before it is registered:
   * it must be exactly {us, one peer} — the expected peer when one is given — and
   * must not already be registered under another contact. An existing session for
   * the contact is never replaced.
   * @param {string} contactId
   * @param {string} groupId the group id used when the session was created
   * @param {object} [options]
   * @param {string} [options.expectedPeer] the peer credential the group must hold
   * @returns {MlsSession|null} null when no group with that id is stored
   * @throws {MlsBindingError} when the group cannot be bound to this contact
   */
  loadSession(contactId, groupId, { expectedPeer } = {}) {
    this._requireNoSession(contactId);
    const group = Group.load(this._provider, groupId);
    if (!group) return null;
    return this._register(contactId, group, expectedPeer, 'loadSession');
  }

  /** @private */
  constructor(provider, identity, name) {
    this._provider = provider;
    this._identity = identity;
    this._name = name; // our MLS credential string (the pubkey hex)
    this._sessions = new Map(); // contactId -> MlsSession
  }

  /** @private */
  _requireNoSession(contactId) {
    if (this._sessions.has(contactId)) {
      throw new Error(`MlsEngine: session already exists for ${contactId}`);
    }
  }

  /**
   * @private Check a group and register it as the session for `contactId`, or
   * throw MlsBindingError and register nothing. The handle is freed on refusal.
   */
  _register(contactId, group, expectedPeer, operation) {
    try {
      const peer = soleOtherMember(group.member_identities(), this._name);
      if (peer === null) {
        throw new MlsBindingError(`MlsEngine.${operation}: the group is not exactly two members (us and one peer)`);
      }
      if (expectedPeer !== undefined && peer !== expectedPeer) {
        throw new MlsBindingError(`MlsEngine.${operation}: the group's peer is not the expected peer`);
      }
      const value = sameGroupValue(group, this._provider);
      for (const [otherId, other] of this._sessions) {
        if (equalBytes(sameGroupValue(other._group, this._provider), value)) {
          throw new MlsBindingError(`MlsEngine.${operation}: the group is already the session of ${otherId}`);
        }
      }
      const session = new MlsSession(this, group, peer);
      this._sessions.set(contactId, session);
      return session;
    } catch (e) {
      freeHandle(group);
      throw e;
    }
  }

  get provider() { return this._provider; }
  get identity() { return this._identity; }
  /** Our own MLS credential string (the pubkey hex). @returns {string} */
  get name() { return this._name; }

  /**
   * Our KeyPackage bytes, to be published so a peer can add us to a group.
   * @returns {Uint8Array}
   */
  keyPackageBytes() {
    return this._identity.key_package(this._provider).to_bytes();
  }

  /**
   * Start a 1:1 session by creating a group and adding the peer.
   * @param {string} contactId a stable local id for the contact
   * @param {Uint8Array} peerKeyPackageBytes the peer's published KeyPackage
   * @param {object} [options]
   * @param {string} [options.expectedPeer] the credential the KeyPackage must carry
   * @returns {{ session: MlsSession, welcome: Uint8Array, ratchetTree: Uint8Array, groupId: string }}
   *   `welcome` + `ratchetTree` + `groupId` must be delivered to the peer so it
   *   can join and later reload the session.
   * @throws {MlsBindingError} when the resulting group is not exactly {us, the
   *   expected peer}; nothing is registered and nothing should be sent
   */
  startSession(contactId, peerKeyPackageBytes, { expectedPeer } = {}) {
    this._requireNoSession(contactId);
    const groupId = `styx:${uuidv4()}`;
    const group = Group.create_new(this._provider, this._identity, groupId);
    const peerKp = KeyPackage.from_bytes(peerKeyPackageBytes);
    const add = group.propose_and_commit_add(this._provider, this._identity, peerKp);
    group.merge_pending_commit(this._provider);
    const welcome = add.welcome;
    const ratchetTree = group.export_ratchet_tree().to_bytes();
    const session = this._register(contactId, group, expectedPeer, 'startSession');
    return { session, welcome, ratchetTree, groupId };
  }

  /**
   * Join a 1:1 session created by a peer, from its Welcome + ratchet tree.
   * Refuses to replace an existing session: swapping out an established group is
   * how a silent MITM takes over a live conversation. Re-pairing must be an
   * explicit local action (drop the contact, then accept a new invite).
   *
   * The joined group is registered only if it is exactly {us, one peer} — the
   * expected peer when one is given — and, when the caller declares the group id
   * it will later reload the session with, only if that id names this very group.
   * @param {string} contactId
   * @param {Uint8Array} welcomeBytes
   * @param {Uint8Array} ratchetTreeBytes
   * @param {object} [options]
   * @param {string} [options.expectedPeer] the peer credential the group must hold
   * @param {string} [options.groupId] the declared group id to verify
   * @returns {MlsSession}
   * @throws {MlsBindingError} when the joined group cannot be bound; nothing is
   *   registered (the Welcome has still been processed)
   */
  joinSession(contactId, welcomeBytes, ratchetTreeBytes, { expectedPeer, groupId } = {}) {
    this._requireNoSession(contactId);
    const group = Group.join(
      this._provider,
      welcomeBytes,
      RatchetTree.from_bytes(ratchetTreeBytes),
    );
    if (groupId !== undefined && !this._isStoredAs(group, groupId)) {
      freeHandle(group);
      throw new MlsBindingError('MlsEngine.joinSession: the declared group id does not name the joined group');
    }
    return this._register(contactId, group, expectedPeer, 'joinSession');
  }

  /**
   * @private Whether `groupId` names the stored state of `group` itself: a
   * separate handle loaded under that id must derive the same epoch-bound value.
   */
  _isStoredAs(group, groupId) {
    if (typeof groupId !== 'string' || groupId.length === 0) return false;
    const stored = Group.load(this._provider, groupId);
    if (!stored) return false;
    try {
      return equalBytes(sameGroupValue(stored, this._provider), sameGroupValue(group, this._provider));
    } finally {
      freeHandle(stored);
    }
  }

  /** @param {string} contactId @returns {MlsSession|undefined} */
  session(contactId) {
    return this._sessions.get(contactId);
  }

  /**
   * The one member of this session's group that is not us, identified by MLS
   * credential (== the peer's pubkey hex).
   *
   * This is the anchor for binding an MLS group to a transport identity: a group is
   * only trustworthy if the peer inside it is the same peer who sent it to us. Null
   * when the session is unknown, or when the membership is no longer exactly {us,
   * the peer the session was bound to}: exactly two leaves, one with our own
   * credential and one with that peer's credential. A third leaf — even one that
   * repeats our own credential — must never be silently accepted.
   *
   * @param {string} contactId
   * @returns {string|null}
   */
  peerIdentity(contactId) {
    const session = this._sessions.get(contactId);
    if (!session || !session.isOneToOne()) return null;
    return session.peer;
  }

  /**
   * Drop a session handle — used both for a deliberate re-pair (after removeContact)
   * and to roll back a join that failed identity binding.
   *
   * This forgets the JS handle only. The group's key material stays in the WASM
   * provider storage: the crate exposes no delete, and `serialize_state` dumps the
   * ENTIRE provider map, so on the next persist the orphaned group — including a
   * rejected peer's credential — is written into `mls:state` and stays there. It is
   * unreachable at runtime (`_groups[contactId]` is never set on the reject path, so
   * it is never reloaded), but it IS durable at-rest residue. That matters for a
   * seized-device threat model: the blob records who attempted to pair. A real
   * per-group delete in the crate is tracked for the storage work (Blocco 3/5).
   * @param {string} contactId
   * @returns {boolean} whether a session existed
   */
  removeSession(contactId) {
    return this._sessions.delete(contactId);
  }
}
