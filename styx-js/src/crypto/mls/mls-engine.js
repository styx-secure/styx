// mls-engine.js — thin wrapper over the vendored OpenMLS-WASM engine.
//
// Isolates OpenMLS behind a stable interface for the rest of styx-js. One
// MlsEngine holds the local device's crypto+storage Provider and MLS Identity;
// each 1:1 contact is a 2-member MLS group exposed as an MlsSession.
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
import { MlsSession } from './mls-session.js';

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
    return new MlsEngine(provider, identity);
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
    return new MlsEngine(provider, identity);
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
   * @param {string} contactId
   * @param {string} groupId the group id used when the session was created
   * @returns {MlsSession|null}
   */
  loadSession(contactId, groupId) {
    const group = Group.load(this._provider, groupId);
    if (!group) return null;
    const session = new MlsSession(this, group);
    this._sessions.set(contactId, session);
    return session;
  }

  /** @private */
  constructor(provider, identity) {
    this._provider = provider;
    this._identity = identity;
    this._sessions = new Map(); // contactId -> MlsSession
  }

  get provider() { return this._provider; }
  get identity() { return this._identity; }

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
   * @returns {{ session: MlsSession, welcome: Uint8Array, ratchetTree: Uint8Array, groupId: string }}
   *   `welcome` + `ratchetTree` + `groupId` must be delivered to the peer so it
   *   can join and later reload the session.
   */
  startSession(contactId, peerKeyPackageBytes) {
    if (this._sessions.has(contactId)) {
      throw new Error(`MlsEngine: session already exists for ${contactId}`);
    }
    const groupId = `styx:${uuidv4()}`;
    const group = Group.create_new(this._provider, this._identity, groupId);
    const peerKp = KeyPackage.from_bytes(peerKeyPackageBytes);
    const add = group.propose_and_commit_add(this._provider, this._identity, peerKp);
    group.merge_pending_commit(this._provider);
    const welcome = add.welcome;
    const ratchetTree = group.export_ratchet_tree().to_bytes();
    const session = new MlsSession(this, group);
    this._sessions.set(contactId, session);
    return { session, welcome, ratchetTree, groupId };
  }

  /**
   * Join a 1:1 session created by a peer, from its Welcome + ratchet tree.
   * Refuses to replace an existing session: swapping out an established group is
   * how a silent MITM takes over a live conversation. Re-pairing must be an
   * explicit local action (drop the contact, then accept a new invite).
   * @param {string} contactId
   * @param {Uint8Array} welcomeBytes
   * @param {Uint8Array} ratchetTreeBytes
   * @returns {MlsSession}
   */
  joinSession(contactId, welcomeBytes, ratchetTreeBytes) {
    if (this._sessions.has(contactId)) {
      throw new Error(`MlsEngine: session already exists for ${contactId}`);
    }
    const group = Group.join(
      this._provider,
      welcomeBytes,
      RatchetTree.from_bytes(ratchetTreeBytes),
    );
    const session = new MlsSession(this, group);
    this._sessions.set(contactId, session);
    return session;
  }

  /** @param {string} contactId @returns {MlsSession|undefined} */
  session(contactId) {
    return this._sessions.get(contactId);
  }

  /**
   * Drop a session handle so the contact can be paired again (deliberate re-pair
   * after removeContact). The group's key material stays in provider storage —
   * the WASM crate exposes no delete — but it is unreachable and gets pruned when
   * state is next re-serialized around remaining sessions.
   * @param {string} contactId
   * @returns {boolean} whether a session existed
   */
  removeSession(contactId) {
    return this._sessions.delete(contactId);
  }
}
