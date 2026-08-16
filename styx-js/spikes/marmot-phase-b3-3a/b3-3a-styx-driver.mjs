// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — exact-candidate B3.3a durable Styx peer.

import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { realpathSync, statSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import { createAccountIdentityProofV2 }
  from '../marmot-phase-b1/identity-proof-v2.js';
import {
  B32A_ERROR,
  B32A_STATE,
  bytesToHex as b32aBytesToHex,
  failB32a,
  hexToBytes as b32aHexToBytes,
  sha256Hex as b32aSha256Hex,
} from '../marmot-phase-b3-2a/b3-2a-canonical.mjs';
import { B32aDurableJoinDriver, WasmB32aEngine }
  from '../marmot-phase-b3-2a/b3-2a-driver.mjs';
import { openB32aFileJournal }
  from '../marmot-phase-b3-2a/b3-2a-journal.mjs';
import {
  B33A_BUILD_ROOT,
  B33A_ERROR,
  B33A_PRIVATE_ROOT,
  bytesToHex,
  clearBytes,
  failB33a,
  hexToBytes,
  sha256Hex,
} from './b3-3a-canonical.mjs';
import { B33aApplicationAdapter } from './b3-3a-engine-adapter.mjs';
import { readExactRegularFile } from './b3-3a-artifact-reader.mjs';
import { openB33aFileJournal } from './b3-3a-journal.mjs';

const PROOF_CREATED_AT = 1_786_680_000;
const STYX_DICTIONARY_IDS = Object.freeze([0x0001, 0x8009]);
const SUPPORTED_COMPONENT_IDS = Object.freeze([0x0001, 0x8001, 0x8003, 0x8009, 0x800c]);
const scriptPath = fileURLToPath(import.meta.url);
const RPC_TIMEOUT_MS = 60_000;

function safeFree(value) {
  try { value?.free?.(); } catch { /* cleanup cannot alter durable authority */ }
}

function privateKey() {
  for (;;) {
    const candidate = Uint8Array.from(randomBytes(32));
    try { schnorr.getPublicKey(candidate); return candidate; } catch { candidate.fill(0); }
  }
}

function exactArray(actual, expected, label) {
  const value = [...actual];
  if (value.length !== expected.length
    || value.some((item, index) => item !== expected[index])) {
    failB32a(B32A_ERROR.ENGINE_REJECTED, `${label} differs from the exact B3.2a profile`);
  }
  return Object.freeze(value);
}

function candidateDirectory(path) {
  const root = realpathSync(B33A_BUILD_ROOT);
  const candidate = realpathSync(path);
  const rel = relative(root, candidate);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)
    || !statSync(candidate).isDirectory()) {
    failB33a(B33A_ERROR.INVALID, 'candidate artifact directory escaped its frozen root');
  }
  return candidate;
}

function exactCandidateTuple(value) {
  exactFields(value, [
    'openmls_wasm.js', 'openmls_wasm.d.ts', 'openmls_wasm_bg.wasm',
    'openmls_wasm_bg.wasm.d.ts', 'package.json',
  ], 'candidate tuple');
  for (const digest of Object.values(value)) {
    if (typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest)) {
      failB33a(B33A_ERROR.INVALID, 'candidate tuple contains an invalid digest');
    }
  }
  return Object.freeze({ ...value });
}

async function loadCandidateWasm(candidatePath, expectedTuple, cacheTag) {
  const directory = candidateDirectory(candidatePath);
  const wasmPath = resolve(directory, 'openmls_wasm_bg.wasm');
  const modulePath = resolve(directory, 'openmls_wasm.js');
  const tuple = exactCandidateTuple(expectedTuple);
  const wasmBytes = readExactRegularFile(
    wasmPath, tuple['openmls_wasm_bg.wasm'],
  ).bytes;
  const moduleBytes = readExactRegularFile(modulePath, tuple['openmls_wasm.js']).bytes;
  try {
    const nonce = randomBytes(16).toString('hex');
    const moduleUrl = `data:text/javascript;base64,${Buffer.from(moduleBytes).toString('base64')}`
      + `#b3-3a-${cacheTag}-${process.pid}-${nonce}`;
    const wasm = await import(moduleUrl);
    await wasm.default({ module_or_path: wasmBytes });
    for (const name of [
      'Provider', 'PhaseB2Identity', 'PhaseB32aKeyPackage',
      'PhaseB32aPendingWelcome', 'PhaseB32aGroup', 'PhaseB33aGroup',
    ]) {
      if (typeof wasm[name] !== 'function') {
        failB33a(B33A_ERROR.ENGINE_REJECTED, `candidate WASM lacks ${name}`);
      }
    }
    return Object.freeze({ wasm, wasmBytes });
  } catch (error) {
    clearBytes(wasmBytes);
    throw error;
  } finally {
    clearBytes(moduleBytes);
  }
}

export class StyxB33aPeer {
  #artifactDirectory;
  #artifactTuple;
  #b32aJournal;
  #b33aJournal;
  #adapter;
  #wasm;
  #wasmBytes;

  static async create(privateDirectory, artifactDirectory, artifactTuple, expectedAuthorHex) {
    const peer = new StyxB33aPeer(privateDirectory, artifactDirectory, artifactTuple);
    await peer.#load('create');
    await peer.#initializeB32a(expectedAuthorHex);
    return peer;
  }

  static async open(privateDirectory, artifactDirectory, artifactTuple) {
    const peer = new StyxB33aPeer(privateDirectory, artifactDirectory, artifactTuple);
    await peer.#load('restart');
    await peer.verifyActive();
    return peer;
  }

  constructor(privateDirectory, artifactDirectory, artifactTuple) {
    this.#artifactDirectory = artifactDirectory;
    this.#artifactTuple = exactCandidateTuple(artifactTuple);
    this.#b32aJournal = openB32aFileJournal(
      resolve(privateDirectory, 'b32a-journal'), B33A_PRIVATE_ROOT,
    );
    this.#b33aJournal = openB33aFileJournal(
      resolve(privateDirectory, 'b33a-journal'), B33A_PRIVATE_ROOT,
    );
  }

  async #load(cacheTag) {
    const loaded = await loadCandidateWasm(
      this.#artifactDirectory, this.#artifactTuple, cacheTag,
    );
    this.#wasm = loaded.wasm;
    this.#wasmBytes = loaded.wasmBytes;
    this.#adapter = new B33aApplicationAdapter({ journal: this.#b33aJournal, wasm: this.#wasm });
  }

  async #initializeB32a(expectedAuthorHex) {
    const accountPrivateKey = privateKey();
    const accountPublicKey = Uint8Array.from(schnorr.getPublicKey(accountPrivateKey));
    const provider = new this.#wasm.Provider();
    const identity = new this.#wasm.PhaseB2Identity(provider, accountPublicKey);
    let proof;
    let keyPackage;
    let keyPackageBytes;
    let predecessorState;
    let leafSignatureKey;
    try {
      leafSignatureKey = Uint8Array.from(identity.leaf_signature_key());
      proof = createAccountIdentityProofV2(accountPrivateKey, leafSignatureKey, PROOF_CREATED_AT);
      keyPackage = identity.b3_2a_key_package(provider, proof);
      keyPackageBytes = Uint8Array.from(keyPackage.to_framed_bytes());
      predecessorState = Uint8Array.from(provider.serialize_state());
      await this.#b32aJournal.initializeStable({
        predecessorState,
        keyPackage: keyPackageBytes,
        accountIdentityHex: b32aBytesToHex(accountPublicKey),
        leafSignatureKeyHex: b32aBytesToHex(leafSignatureKey),
        expectedAuthorHex,
      });
    } finally {
      clearBytes(accountPrivateKey);
      clearBytes(proof);
      clearBytes(keyPackageBytes);
      clearBytes(predecessorState);
      clearBytes(leafSignatureKey);
      safeFree(keyPackage);
      safeFree(identity);
      safeFree(provider);
    }
  }

  async publicKeyPackage() {
    const bundle = await this.#b32aJournal.read();
    if (bundle.head.state !== B32A_STATE.STABLE_ADVERTISED) {
      failB32a(B32A_ERROR.STATE_CONFLICT, 'KeyPackage exposure requires STABLE_ADVERTISED');
    }
    const keyPackageBytes = bundle.blobs.keyPackageBlobSha256Hex;
    const parsed = this.#wasm.PhaseB32aKeyPackage.from_framed_bytes(keyPackageBytes);
    try {
      return Object.freeze({
        accountIdentityHex: b32aBytesToHex(Uint8Array.from(parsed.credential_identity())),
        capabilityExtensionIds: Object.freeze([...parsed.capability_extension_ids()]),
        capabilityProposalIds: Object.freeze([...parsed.capability_proposal_ids()]),
        ciphersuite: parsed.ciphersuite_id(),
        componentIds: exactArray(parsed.component_ids(), STYX_DICTIONARY_IDS, 'dictionary ids'),
        identityProofHex: b32aBytesToHex(Uint8Array.from(parsed.identity_proof())),
        isLastResort: parsed.is_last_resort(),
        keyPackageHex: b32aBytesToHex(keyPackageBytes),
        keyPackageSha256: b32aSha256Hex(keyPackageBytes),
        leafSignatureKeyHex: b32aBytesToHex(Uint8Array.from(parsed.leaf_signature_key())),
        predecessorStateSha256: b32aSha256Hex(bundle.blobs.predecessorBlobSha256Hex),
        supportedComponentIds: exactArray(
          parsed.supported_component_ids(), SUPPORTED_COMPONENT_IDS, 'supported components',
        ),
        wasmSha256: sha256Hex(this.#wasmBytes),
      });
    } finally {
      clearBytes(bundle.blobs.predecessorBlobSha256Hex);
      clearBytes(bundle.blobs.keyPackageBlobSha256Hex);
      safeFree(parsed);
    }
  }

  async recordWelcome(welcomeHex) {
    const welcome = b32aHexToBytes('MDK Welcome', welcomeHex, { min: 1, max: 1024 * 1024 });
    try { return await this.#b32aJournal.recordWelcome(welcome); } finally { clearBytes(welcome); }
  }

  async joinAndActivate() {
    const joined = await new B32aDurableJoinDriver(
      this.#b32aJournal, new WasmB32aEngine(this.#wasm),
    ).joinRecordedWelcome();
    const activation = await this.#b32aJournal.activationState();
    try {
      const activeHead = await this.#adapter.initializeFromB32a(activation.head, activation.bytes);
      return Object.freeze({ ...joined, activeHead });
    } finally {
      clearBytes(activation.bytes);
    }
  }

  async verifyActive() {
    const current = await this.#b33aJournal.readCurrent();
    try {
      return Object.freeze({
        accountIdentityHex: current.head.accountIdentityHex,
        epochDec: current.head.epochDec,
        groupIdHex: current.head.groupIdHex,
        headDigestHex: current.head.headDigestHex,
        sequence: current.head.sequence,
        wasmSha256: sha256Hex(this.#wasmBytes),
      });
    } finally {
      clearBytes(current.stateBytes);
    }
  }

  async send(requestId, eventBytes) { return this.#adapter.send(requestId, eventBytes); }

  async receive(ciphertextBytes) { return this.#adapter.receive(ciphertextBytes); }
}

function exactFields(value, fields, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    failB33a(B33A_ERROR.INVALID, `${label} is not an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length
    || actual.some((field, index) => field !== expected[index])) {
    failB33a(B33A_ERROR.INVALID, `${label} fields are not exact`);
  }
}

async function serve() {
  let peer;
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    let request;
    let shouldExit = false;
    let response;
    try {
      if (Buffer.byteLength(line, 'utf8') > 4 * 1024 * 1024) {
        failB33a(B33A_ERROR.RESOURCE_LIMIT, 'RPC line exceeds its resource envelope');
      }
      request = JSON.parse(line);
      if (!Number.isSafeInteger(request?.id) || request.id < 1 || typeof request?.op !== 'string') {
        failB33a(B33A_ERROR.INVALID, 'RPC id or operation is invalid');
      }
      let result;
      switch (request.op) {
        case 'initialize_new':
          exactFields(request, [
            'artifact_directory', 'artifact_tuple', 'expected_author_hex', 'id', 'op',
            'private_directory',
          ], 'initialize_new request');
          if (peer) failB33a(B33A_ERROR.STATE_CONFLICT, 'peer is already initialized');
          peer = await StyxB33aPeer.create(
            request.private_directory, request.artifact_directory, request.artifact_tuple,
            request.expected_author_hex,
          );
          result = { disposition: 'new_peer_initialized' };
          break;
        case 'initialize_existing':
          exactFields(request, [
            'artifact_directory', 'artifact_tuple', 'id', 'op', 'private_directory',
          ], 'initialize_existing request');
          if (peer) failB33a(B33A_ERROR.STATE_CONFLICT, 'peer is already initialized');
          peer = await StyxB33aPeer.open(
            request.private_directory, request.artifact_directory, request.artifact_tuple,
          );
          result = { disposition: 'durable_peer_restored' };
          break;
        case 'public_key_package':
          exactFields(request, ['id', 'op'], 'public_key_package request');
          if (!peer) failB33a(B33A_ERROR.STATE_CONFLICT, 'peer is not initialized');
          result = await peer.publicKeyPackage();
          break;
        case 'record_welcome':
          exactFields(request, ['id', 'op', 'welcome_hex'], 'record_welcome request');
          if (!peer) failB33a(B33A_ERROR.STATE_CONFLICT, 'peer is not initialized');
          result = await peer.recordWelcome(request.welcome_hex);
          break;
        case 'join_activate': {
          exactFields(request, ['id', 'op'], 'join_activate request');
          if (!peer) failB33a(B33A_ERROR.STATE_CONFLICT, 'peer is not initialized');
          const joined = await peer.joinAndActivate();
          result = {
            activeHeadDigestHex: joined.activeHead.headDigestHex,
            b32aHeadDigestHex: joined.head.headDigestHex,
            disposition: 'joined_and_activated',
            groupIdHex: joined.projection.groupIdHex,
            memberProfiles: joined.projection.members.map((member) => member.profileTag),
            projectionRecordSha256Hex: joined.head.projectionRecordSha256Hex,
          };
          break;
        }
        case 'send_application': {
          exactFields(request, ['event_hex', 'id', 'op', 'request_id'], 'send request');
          if (!peer) failB33a(B33A_ERROR.STATE_CONFLICT, 'peer is not initialized');
          const event = hexToBytes('outbound event', request.event_hex);
          try {
            const sent = await peer.send(request.request_id, event);
            result = { ...sent,
              ciphertext_hex: sent.ciphertextBytes ? bytesToHex(sent.ciphertextBytes) : null };
            delete result.ciphertextBytes;
          } finally { clearBytes(event); }
          break;
        }
        case 'receive_application': {
          exactFields(request, ['ciphertext_hex', 'id', 'op'], 'receive request');
          if (!peer) failB33a(B33A_ERROR.STATE_CONFLICT, 'peer is not initialized');
          const ciphertext = hexToBytes('inbound ciphertext', request.ciphertext_hex);
          try {
            const received = await peer.receive(ciphertext);
            result = { ...received,
              plaintext_hex: received.plaintextBytes ? bytesToHex(received.plaintextBytes) : null };
            delete result.plaintextBytes;
          } finally { clearBytes(ciphertext); }
          break;
        }
        case 'verify_active':
          exactFields(request, ['id', 'op'], 'verify_active request');
          if (!peer) failB33a(B33A_ERROR.STATE_CONFLICT, 'peer is not initialized');
          result = await peer.verifyActive();
          break;
        case 'checkpoint_and_exit':
          exactFields(request, ['id', 'op'], 'checkpoint request');
          result = { checkpointed: true };
          shouldExit = true;
          break;
        default:
          failB33a(B33A_ERROR.INVALID, 'unknown Styx B3.3a RPC operation');
      }
      response = { id: request.id, ok: true, result };
    } catch (error) {
      response = {
        id: Number.isSafeInteger(request?.id) ? request.id : null,
        ok: false,
        error: {
          code: typeof error?.code === 'string' ? error.code : 'B33A_PEER_ERROR',
          message: String(error?.message ?? error).slice(0, 512),
        },
      };
    }
    process.stdout.write(`${JSON.stringify(response)}\n`);
    if (shouldExit) break;
  }
}

export class StyxB33aProcess {
  #child;
  #nextId = 1;
  #pending = new Map();
  #stderr = '';

  constructor() {
    this.#child = spawn(process.execPath, [scriptPath, '--serve'], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    createInterface({ input: this.#child.stdout, crlfDelay: Infinity })
      .on('line', (line) => this.#receive(line));
    this.#child.stderr.setEncoding('utf8');
    this.#child.stderr.on('data', (chunk) => {
      this.#stderr = `${this.#stderr}${chunk}`.slice(-8192);
    });
    this.#child.on('exit', (code, signal) => {
      const error = new Error(`Styx peer exited code=${code} signal=${signal}; stderr=${this.#stderr}`);
      for (const pending of this.#pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(error);
      }
      this.#pending.clear();
    });
  }

  #receive(line) {
    let response;
    try {
      response = JSON.parse(line);
      if (!Number.isSafeInteger(response?.id) || response.id < 1
        || typeof response?.ok !== 'boolean') {
        failB33a(B33A_ERROR.INVALID, 'Styx response id or disposition is invalid');
      }
      exactFields(response, ['id', 'ok', response.ok ? 'result' : 'error'], 'Styx response');
      if (!response.ok) {
        exactFields(response.error, ['code', 'message'], 'Styx error response');
        if (typeof response.error.code !== 'string' || typeof response.error.message !== 'string') {
          failB33a(B33A_ERROR.INVALID, 'Styx error response fields are invalid');
        }
      }
    } catch (error) {
      for (const pending of this.#pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(error);
      }
      this.#pending.clear();
      return;
    }
    const pending = this.#pending.get(response.id);
    if (!pending) {
      const error = new Error('Styx peer returned an unexpected response id');
      error.code = B33A_ERROR.INVALID;
      for (const request of this.#pending.values()) {
        clearTimeout(request.timer);
        request.reject(error);
      }
      this.#pending.clear();
      return;
    }
    this.#pending.delete(response.id);
    clearTimeout(pending.timer);
    if (response.ok) pending.resolve(response.result);
    else {
      const error = new Error(response.error?.message ?? 'Styx peer rejected the request');
      error.code = response.error?.code ?? 'B33A_PEER_ERROR';
      pending.reject(error);
    }
  }

  request(op, fields = {}) {
    const id = this.#nextId++;
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`Styx peer timed out during ${op}; stderr=${this.#stderr}`));
      }, RPC_TIMEOUT_MS);
      this.#pending.set(id, { reject, resolve: resolvePromise, timer });
      this.#child.stdin.write(`${JSON.stringify({ ...fields, id, op })}\n`, (error) => {
        if (error) {
          clearTimeout(timer);
          this.#pending.delete(id);
          reject(error);
        }
      });
    });
  }

  async close() {
    if (this.#child.exitCode === null) {
      try { await this.request('checkpoint_and_exit'); } finally { this.#child.stdin.end(); }
    }
  }
}

if (process.argv[1] === scriptPath && process.argv[2] === '--serve') await serve();
