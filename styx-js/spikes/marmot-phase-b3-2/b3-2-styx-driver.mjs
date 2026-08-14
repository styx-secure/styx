// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — isolated B3.2 wrapper and durability driver.

import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { schnorr } from '@noble/curves/secp256k1';

import { createAccountIdentityProofV2 } from '../marmot-phase-b1/identity-proof-v2.js';
import {
  B31_LEAF_COMPONENT_IDS,
  B31_SUPPORTED_COMPONENT_IDS,
} from '../marmot-phase-b3-1/b3-1-canonical.mjs';
import {
  B32_ERROR,
  B32_STATE,
  b32ProjectionBytes,
  bytesEqual,
  bytesToHex,
  failB32,
  hexToBytes,
  projectB32Native,
  sha256Hex,
} from './b3-2-canonical.mjs';
import { openB32FileJournal } from './b3-2-journal.mjs';

const PROOF_CREATED_AT = 1_786_680_000;

function free(value) {
  if (value && typeof value.free === 'function') value.free();
}

function accountSecret() {
  for (;;) {
    const candidate = Uint8Array.from(randomBytes(32));
    try {
      schnorr.getPublicKey(candidate);
      return candidate;
    } catch {
      // Rejection sampling for the negligible invalid-scalar case.
    }
  }
}

function exactArray(actual, expected, label) {
  const value = [...actual];
  if (value.length !== expected.length
    || value.some((item, index) => item !== expected[index])) {
    failB32(B32_ERROR.ENGINE_REJECTED, `${label} differs from the B3.1 writer profile`);
  }
  return Object.freeze(value);
}

function rethrowNative(error, operation) {
  const message = String(error?.message ?? error);
  const nativeCode = message.match(/PHASE_B32_[A-Z0-9_]+/)?.[0] ?? null;
  if (nativeCode !== null) {
    failB32(B32_ERROR.ENGINE_REJECTED, `${operation} rejected by the isolated wrapper`, {
      nativeCode,
    }, error);
  }
  throw error;
}

async function loadWasm(cacheTag) {
  const wasmPath = new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url);
  const moduleUrl = new URL('../../vendor/openmls-wasm/openmls_wasm.js', import.meta.url);
  moduleUrl.searchParams.set('b3-2', `${cacheTag}-${process.pid}-${Date.now()}-${Math.random()}`);
  const wasmBytes = Uint8Array.from(readFileSync(wasmPath));
  const wasm = await import(moduleUrl.href);
  await wasm.default({ module_or_path: wasmBytes });
  for (const name of [
    'Provider', 'PhaseB2Identity', 'PhaseB31KeyPackage',
    'PhaseB32PendingWelcome', 'PhaseB32Group',
  ]) {
    if (typeof wasm[name] !== 'function') {
      failB32(B32_ERROR.ENGINE_REJECTED, `installed WASM lacks ${name}`);
    }
  }
  return Object.freeze({ wasm, wasmBytes });
}

export class StyxB32Peer {
  #privateDirectory;
  #journal;
  #wasm;
  #wasmBytes;

  static async create(privateDirectory, expectedAuthorHex) {
    const peer = new StyxB32Peer(privateDirectory);
    await peer.#initialize(expectedAuthorHex);
    return peer;
  }

  static async open(privateDirectory) {
    const peer = new StyxB32Peer(privateDirectory);
    const loaded = await loadWasm('restart');
    peer.#wasm = loaded.wasm;
    peer.#wasmBytes = loaded.wasmBytes;
    return peer;
  }

  constructor(privateDirectory) {
    this.#privateDirectory = privateDirectory;
    this.#journal = openB32FileJournal(`${privateDirectory}/journal`);
  }

  async #initialize(expectedAuthorHex) {
    const loaded = await loadWasm('create');
    this.#wasm = loaded.wasm;
    this.#wasmBytes = loaded.wasmBytes;
    const accountPrivateKey = accountSecret();
    const accountPublicKey = Uint8Array.from(schnorr.getPublicKey(accountPrivateKey));
    const provider = new this.#wasm.Provider();
    const identity = new this.#wasm.PhaseB2Identity(provider, accountPublicKey);
    let keyPackage;
    try {
      const leafSignatureKey = Uint8Array.from(identity.leaf_signature_key());
      const proof = createAccountIdentityProofV2(
        accountPrivateKey,
        leafSignatureKey,
        PROOF_CREATED_AT,
      );
      keyPackage = identity.b3_1_key_package(provider, proof);
      const keyPackageBytes = Uint8Array.from(keyPackage.to_framed_bytes());
      const predecessorState = Uint8Array.from(provider.serialize_state());
      await this.#journal.initializeStable({
        predecessorState,
        keyPackage: keyPackageBytes,
        accountIdentityHex: bytesToHex(accountPublicKey),
        leafSignatureKeyHex: bytesToHex(leafSignatureKey),
        expectedAuthorHex,
      });
    } finally {
      free(keyPackage);
      free(identity);
      free(provider);
    }
  }

  async publicKeyPackage() {
    const bundle = await this.#journal.read();
    if (bundle.head.state !== B32_STATE.STABLE_ADVERTISED) {
      failB32(B32_ERROR.STATE_CONFLICT, 'KeyPackage exposure requires STABLE_ADVERTISED');
    }
    const keyPackageBytes = bundle.blobs.keyPackageBlobSha256Hex;
    const parsed = this.#wasm.PhaseB31KeyPackage.from_framed_bytes(keyPackageBytes);
    try {
      if (parsed.is_last_resort() || parsed.ciphersuite_id() !== 1) {
        failB32(B32_ERROR.ENGINE_REJECTED, 'durable B3.1 KeyPackage profile changed');
      }
      return Object.freeze({
        accountIdentityHex: bytesToHex(Uint8Array.from(parsed.credential_identity())),
        ciphersuite: parsed.ciphersuite_id(),
        componentIds: exactArray(parsed.component_ids(), B31_LEAF_COMPONENT_IDS, 'component ids'),
        identityProofHex: bytesToHex(Uint8Array.from(parsed.identity_proof())),
        isLastResort: parsed.is_last_resort(),
        keyPackageHex: bytesToHex(keyPackageBytes),
        keyPackageSha256: sha256Hex(keyPackageBytes),
        leafSignatureKeyHex: bytesToHex(Uint8Array.from(parsed.leaf_signature_key())),
        predecessorStateSha256: sha256Hex(bundle.blobs.predecessorBlobSha256Hex),
        supportedComponentIds: exactArray(
          parsed.supported_component_ids(), B31_SUPPORTED_COMPONENT_IDS, 'supported components',
        ),
        wasmSha256: sha256Hex(this.#wasmBytes),
      });
    } finally {
      free(parsed);
    }
  }

  async recordWelcome(welcomeHex) {
    const welcome = hexToBytes('MDK Welcome', welcomeHex, { min: 1, max: 1024 * 1024 });
    return this.#journal.recordWelcome(welcome);
  }

  async #prepareFromDurablePredecessor(bundle) {
    const provider = new this.#wasm.Provider();
    provider.restore_state(bundle.blobs.predecessorBlobSha256Hex);
    const account = hexToBytes('local account identity', bundle.head.accountIdentityHex, {
      min: 32, max: 32,
    });
    const leaf = hexToBytes('local leaf signature key', bundle.head.leafSignatureKeyHex, {
      min: 32, max: 32,
    });
    const author = hexToBytes('expected Welcome author', bundle.head.expectedAuthorHex, {
      min: 32, max: 32,
    });
    const identity = this.#wasm.PhaseB2Identity.load(provider, account, leaf);
    if (!identity) {
      free(provider);
      failB32(B32_ERROR.CORRUPT, 'bound identity is absent from predecessor Provider');
    }
    let pending;
    let nativeProjection;
    try {
      pending = this.#wasm.PhaseB32PendingWelcome.prepare(
        provider,
        identity,
        bundle.blobs.welcomeBlobSha256Hex,
        bundle.blobs.keyPackageBlobSha256Hex,
        author,
      );
      nativeProjection = pending.projection();
      const projection = projectB32Native(nativeProjection);
      if (projection.members.find((member) => member.leafIndex === projection.ownLeafIndex)?.identityHex
          !== bundle.head.accountIdentityHex) {
        failB32(B32_ERROR.PROJECTION_MISMATCH, 'native own leaf does not bind the durable identity');
      }
      return { provider, identity, pending, nativeProjection, projection };
    } catch (error) {
      free(nativeProjection);
      free(pending);
      free(identity);
      free(provider);
      rethrowNative(error, 'Welcome preparation');
    }
  }

  async joinRecordedWelcome() {
    const bundle = await this.#journal.read();
    if (bundle.head.state !== B32_STATE.WELCOME_RECORDED) {
      failB32(B32_ERROR.STATE_CONFLICT, 'join preparation requires WELCOME_RECORDED');
    }
    const first = await this.#prepareFromDurablePredecessor(bundle);
    const second = await this.#prepareFromDurablePredecessor(bundle);
    let candidate;
    try {
      if (!bytesEqual(b32ProjectionBytes(first.projection), b32ProjectionBytes(second.projection))) {
        failB32(B32_ERROR.PROJECTION_MISMATCH, 'independent preparations disagree');
      }
      second.pending.discard(second.provider);
      candidate = Uint8Array.from(first.pending.release_candidate_state(
        first.provider,
        hexToBytes('native projection digest', first.projection.nativeProjectionSha256Hex, {
          min: 32, max: 32,
        }),
        hexToBytes('expected author', bundle.head.expectedAuthorHex, { min: 32, max: 32 }),
      ));
      if (!first.pending.is_consumed() || sha256Hex(candidate) !== first.projection.candidateStateSha256Hex) {
        failB32(B32_ERROR.PROJECTION_MISMATCH, 'one-use candidate release changed its commitment');
      }
      await this.#verifyCandidateBytes(candidate, first.projection);
      const head = await this.#journal.commitJoined(candidate, first.projection);
      const restarted = await this.verifyJoined();
      return Object.freeze({
        head,
        projection: first.projection,
        restartedProjectionRecordSha256: restarted.projectionRecordSha256,
        independentPreparationsEqual: true,
      });
    } finally {
      if (candidate) candidate.fill(0);
      for (const prepared of [first, second]) {
        free(prepared.nativeProjection);
        free(prepared.pending);
        free(prepared.identity);
        free(prepared.provider);
      }
    }
  }

  async #verifyCandidateBytes(candidate, projection) {
    const provider = new this.#wasm.Provider();
    let group;
    let nativeProjection;
    try {
      provider.restore_state(candidate);
      group = this.#wasm.PhaseB32Group.load(
        provider,
        hexToBytes('group id', projection.groupIdHex, { min: 1, max: 64 }),
      );
      if (!group) failB32(B32_ERROR.CORRUPT, 'candidate group is absent after scratch restore');
      nativeProjection = group.projection(
        provider,
        projection.welcomeAuthor.leafIndex,
        hexToBytes('expected author', projection.welcomeAuthor.identityHex, { min: 32, max: 32 }),
        hexToBytes('Welcome digest', projection.welcomeSha256Hex, { min: 32, max: 32 }),
        hexToBytes('KeyPackage digest', projection.expectedKeyPackageSha256Hex, { min: 32, max: 32 }),
        hexToBytes('predecessor digest', projection.predecessorStateSha256Hex, { min: 32, max: 32 }),
        hexToBytes('candidate digest', projection.candidateStateSha256Hex, { min: 32, max: 32 }),
      );
      const restored = projectB32Native(nativeProjection);
      if (!bytesEqual(b32ProjectionBytes(restored), b32ProjectionBytes(projection))) {
        failB32(B32_ERROR.PROJECTION_MISMATCH, 'scratch restore changed the canonical projection');
      }
    } finally {
      free(nativeProjection);
      free(group);
      free(provider);
    }
  }

  async verifyJoined() {
    const activation = await this.#journal.activationState();
    if (activation.state !== B32_STATE.JOINED) {
      failB32(B32_ERROR.STATE_CONFLICT, 'fresh activation did not select JOINED');
    }
    await this.#verifyCandidateBytes(activation.bytes, activation.head.projection);
    return Object.freeze({
      groupIdHex: activation.head.groupIdHex,
      projectionRecordSha256: activation.head.projectionRecordSha256Hex,
      state: activation.state,
    });
  }
}
