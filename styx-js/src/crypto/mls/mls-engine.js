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
   * @returns {{ session: MlsSession, welcome: Uint8Array, ratchetTree: Uint8Array }}
   *   `welcome` + `ratchetTree` must be delivered to the peer so it can join.
   */
  startSession(contactId, peerKeyPackageBytes) {
    const group = Group.create_new(this._provider, this._identity, `styx:${uuidv4()}`);
    const peerKp = KeyPackage.from_bytes(peerKeyPackageBytes);
    const add = group.propose_and_commit_add(this._provider, this._identity, peerKp);
    group.merge_pending_commit(this._provider);
    const welcome = add.welcome;
    const ratchetTree = group.export_ratchet_tree().to_bytes();
    const session = new MlsSession(this, group);
    this._sessions.set(contactId, session);
    return { session, welcome, ratchetTree };
  }

  /**
   * Join a 1:1 session created by a peer, from its Welcome + ratchet tree.
   * @param {string} contactId
   * @param {Uint8Array} welcomeBytes
   * @param {Uint8Array} ratchetTreeBytes
   * @returns {MlsSession}
   */
  joinSession(contactId, welcomeBytes, ratchetTreeBytes) {
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
}
