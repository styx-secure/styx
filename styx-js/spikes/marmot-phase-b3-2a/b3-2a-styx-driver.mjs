// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — exact-profile durable-input B3.2a peer.

import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { schnorr } from '@noble/curves/secp256k1';

import { createAccountIdentityProofV2 } from '../marmot-phase-b1/identity-proof-v2.js';
import {
  B32A_ERROR,
  B32A_STATE,
  bytesToHex,
  failB32a,
  hexToBytes,
  sha256Hex,
} from './b3-2a-canonical.mjs';
import { B32aDurableJoinDriver, WasmB32aEngine } from './b3-2a-driver.mjs';
import { openB32aFileJournal } from './b3-2a-journal.mjs';

const PROOF_CREATED_AT = 1_786_680_000;
const STYX_DICTIONARY_IDS = Object.freeze([0x0001, 0x8009]);
const SUPPORTED_COMPONENT_IDS = Object.freeze([0x0001, 0x8001, 0x8003, 0x8009, 0x800c]);

function free(value) {
  try { value?.free?.(); } catch { /* best-effort WASM handle cleanup */ }
}

function accountSecret() {
  for (;;) {
    const candidate = Uint8Array.from(randomBytes(32));
    try {
      schnorr.getPublicKey(candidate);
      return candidate;
    } catch {
      candidate.fill(0);
    }
  }
}

function exactArray(actual, expected, label) {
  const value = [...actual];
  if (value.length !== expected.length
    || value.some((item, index) => item !== expected[index])) {
    failB32a(B32A_ERROR.ENGINE_REJECTED, `${label} differs from the exact Styx B3.2a profile`);
  }
  return Object.freeze(value);
}

async function loadWasm(cacheTag) {
  const wasmPath = new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url);
  const moduleUrl = new URL('../../vendor/openmls-wasm/openmls_wasm.js', import.meta.url);
  moduleUrl.searchParams.set('b3-2a', `${cacheTag}-${process.pid}-${Date.now()}-${Math.random()}`);
  const wasmBytes = Uint8Array.from(readFileSync(wasmPath));
  const wasm = await import(moduleUrl.href);
  await wasm.default({ module_or_path: wasmBytes });
  for (const name of [
    'Provider', 'PhaseB2Identity', 'PhaseB32aKeyPackage',
    'PhaseB32aPendingWelcome', 'PhaseB32aGroup',
  ]) {
    if (typeof wasm[name] !== 'function') {
      failB32a(B32A_ERROR.ENGINE_REJECTED, `installed WASM lacks ${name}`);
    }
  }
  return Object.freeze({ wasm, wasmBytes });
}

export class StyxB32aPeer {
  #journal;
  #wasm;
  #wasmBytes;

  static async create(privateDirectory, expectedAuthorHex) {
    const peer = new StyxB32aPeer(privateDirectory);
    await peer.#initialize(expectedAuthorHex);
    return peer;
  }

  static async open(privateDirectory) {
    const peer = new StyxB32aPeer(privateDirectory);
    const loaded = await loadWasm('restart');
    peer.#wasm = loaded.wasm;
    peer.#wasmBytes = loaded.wasmBytes;
    return peer;
  }

  constructor(privateDirectory) {
    this.#journal = openB32aFileJournal(`${privateDirectory}/journal`);
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
    let proof;
    let keyPackageBytes;
    let predecessorState;
    let leafSignatureKey;
    try {
      leafSignatureKey = Uint8Array.from(identity.leaf_signature_key());
      proof = createAccountIdentityProofV2(accountPrivateKey, leafSignatureKey, PROOF_CREATED_AT);
      keyPackage = identity.b3_2a_key_package(provider, proof);
      keyPackageBytes = Uint8Array.from(keyPackage.to_framed_bytes());
      predecessorState = Uint8Array.from(provider.serialize_state());
      await this.#journal.initializeStable({
        predecessorState,
        keyPackage: keyPackageBytes,
        accountIdentityHex: bytesToHex(accountPublicKey),
        leafSignatureKeyHex: bytesToHex(leafSignatureKey),
        expectedAuthorHex,
      });
    } finally {
      accountPrivateKey.fill(0);
      proof?.fill?.(0);
      keyPackageBytes?.fill?.(0);
      predecessorState?.fill?.(0);
      leafSignatureKey?.fill?.(0);
      free(keyPackage);
      free(identity);
      free(provider);
    }
  }

  async publicKeyPackage() {
    const bundle = await this.#journal.read();
    if (bundle.head.state !== B32A_STATE.STABLE_ADVERTISED) {
      failB32a(B32A_ERROR.STATE_CONFLICT, 'KeyPackage exposure requires STABLE_ADVERTISED');
    }
    const keyPackageBytes = bundle.blobs.keyPackageBlobSha256Hex;
    const parsed = this.#wasm.PhaseB32aKeyPackage.from_framed_bytes(keyPackageBytes);
    try {
      if (parsed.is_last_resort() || parsed.ciphersuite_id() !== 1) {
        failB32a(B32A_ERROR.ENGINE_REJECTED, 'durable B3.2a KeyPackage profile changed');
      }
      return Object.freeze({
        accountIdentityHex: bytesToHex(Uint8Array.from(parsed.credential_identity())),
        capabilityExtensionIds: Object.freeze([...parsed.capability_extension_ids()]),
        capabilityProposalIds: Object.freeze([...parsed.capability_proposal_ids()]),
        ciphersuite: parsed.ciphersuite_id(),
        componentIds: exactArray(parsed.component_ids(), STYX_DICTIONARY_IDS, 'dictionary ids'),
        identityProofHex: bytesToHex(Uint8Array.from(parsed.identity_proof())),
        isLastResort: parsed.is_last_resort(),
        keyPackageHex: bytesToHex(keyPackageBytes),
        keyPackageSha256: sha256Hex(keyPackageBytes),
        leafSignatureKeyHex: bytesToHex(Uint8Array.from(parsed.leaf_signature_key())),
        predecessorStateSha256: sha256Hex(bundle.blobs.predecessorBlobSha256Hex),
        supportedComponentIds: exactArray(
          parsed.supported_component_ids(), SUPPORTED_COMPONENT_IDS, 'supported components',
        ),
        wasmSha256: sha256Hex(this.#wasmBytes),
      });
    } finally {
      bundle.blobs.predecessorBlobSha256Hex.fill(0);
      bundle.blobs.keyPackageBlobSha256Hex.fill(0);
      free(parsed);
    }
  }

  async recordWelcome(welcomeHex) {
    const welcome = hexToBytes('MDK Welcome', welcomeHex, { min: 1, max: 1024 * 1024 });
    try { return await this.#journal.recordWelcome(welcome); } finally { welcome.fill(0); }
  }

  async joinRecordedWelcome() {
    return new B32aDurableJoinDriver(this.#journal, new WasmB32aEngine(this.#wasm))
      .joinRecordedWelcome();
  }

  async verifyJoined() {
    return new B32aDurableJoinDriver(this.#journal, new WasmB32aEngine(this.#wasm))
      .verifyJoined();
  }
}
