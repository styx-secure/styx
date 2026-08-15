// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — private, one-join B3.2a durability journal.

import { randomUUID } from 'node:crypto';
import {
  chmodSync, closeSync, existsSync, fsyncSync, linkSync, mkdirSync, openSync,
  readFileSync, realpathSync, renameSync, rmdirSync, statSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { relative, resolve, sep } from 'node:path';

import {
  B32A_ERROR,
  B32A_FORMAT,
  B32A_PRIVATE_ROOT,
  B32A_PROVIDER_FORMAT,
  B32A_STATE,
  B32A_VERSION,
  B32_LIMITS,
  B32aError,
  assertBytes,
  b32aProjectionRecordSha256,
  canonicalJsonBytes,
  failB32a,
  normalizeB32aPreparationEvidence,
  normalizeB32aProjection,
  sha256Hex,
} from './b3-2a-canonical.mjs';

const HEAD_FIELDS = Object.freeze([
  'format', 'version', 'providerFormat', 'journalIdHex', 'sequence', 'state',
  'previousHeadDigestHex', 'accountIdentityHex', 'leafSignatureKeyHex',
  'expectedAuthorHex', 'groupIdHex', 'predecessorBlobSha256Hex',
  'keyPackageBlobSha256Hex', 'welcomeBlobSha256Hex', 'candidateBlobSha256Hex',
  'projection', 'projectionRecordSha256Hex', 'preparationEvidence', 'headDigestHex',
]);

function exactObject(value, fields, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    failB32a(B32A_ERROR.CORRUPT, `${label} is not an object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string') || keys.length !== fields.length
    || keys.some((key) => !fields.includes(key))) {
    failB32a(B32A_ERROR.CORRUPT, `${label} fields are not exact`);
  }
  const out = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      failB32a(B32A_ERROR.CORRUPT, `${label} contains an accessor or missing field`);
    }
    out[field] = descriptor.value;
  }
  return out;
}

function digest(label, value, optional = false) {
  if (optional && value === null) return null;
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    failB32a(B32A_ERROR.CORRUPT, `${label} is not a SHA-256 digest`);
  }
  return value;
}

function exactHex(label, value, bytes) {
  if (typeof value !== 'string' || value.length !== bytes * 2 || !/^[0-9a-f]+$/.test(value)) {
    failB32a(B32A_ERROR.CORRUPT, `${label} is not exact lowercase hexadecimal`);
  }
  return value;
}

function headPayload(head) {
  return Object.fromEntries(HEAD_FIELDS.filter((field) => field !== 'headDigestHex')
    .map((field) => [field, head[field]]));
}

function projectionOwnBindsHead(projection, head) {
  const own = projection.members.find((member) => member.leafIndex === projection.ownLeafIndex);
  return own?.identityHex === head.accountIdentityHex
    && own?.signatureKeyHex === head.leafSignatureKeyHex;
}

export function parseB32aHead(value) {
  const head = exactObject(value, HEAD_FIELDS, 'B3.2a head');
  if (head.format !== B32A_FORMAT || head.version !== B32A_VERSION
    || head.providerFormat !== B32A_PROVIDER_FORMAT) {
    failB32a(B32A_ERROR.CORRUPT, 'journal head domain, version or Provider format is invalid');
  }
  digest('journal id', head.journalIdHex);
  if (!Number.isSafeInteger(head.sequence) || head.sequence < 1
    || !Object.values(B32A_STATE).includes(head.state)) {
    failB32a(B32A_ERROR.CORRUPT, 'journal sequence or state is invalid');
  }
  digest('previous head', head.previousHeadDigestHex, true);
  exactHex('account identity', head.accountIdentityHex, 32);
  exactHex('leaf signature key', head.leafSignatureKeyHex, 32);
  exactHex('expected Welcome author', head.expectedAuthorHex, 32);
  if (head.groupIdHex !== null
    && (typeof head.groupIdHex !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(head.groupIdHex)
      || head.groupIdHex.length > B32_LIMITS.maxGroupIdBytes * 2)) {
    failB32a(B32A_ERROR.CORRUPT, 'group id is invalid');
  }
  digest('predecessor blob', head.predecessorBlobSha256Hex);
  digest('KeyPackage blob', head.keyPackageBlobSha256Hex);
  digest('Welcome blob', head.welcomeBlobSha256Hex, true);
  digest('candidate blob', head.candidateBlobSha256Hex, true);
  digest('projection record', head.projectionRecordSha256Hex, true);
  digest('head', head.headDigestHex);
  if (head.state === B32A_STATE.JOINED) {
    head.projection = normalizeB32aProjection(head.projection);
    head.preparationEvidence = normalizeB32aPreparationEvidence(
      head.preparationEvidence, head.candidateBlobSha256Hex,
    );
  }
  if (head.state === B32A_STATE.STABLE_ADVERTISED) {
    if (head.sequence !== 1 || head.previousHeadDigestHex !== null || head.groupIdHex !== null
      || head.welcomeBlobSha256Hex !== null || head.candidateBlobSha256Hex !== null
      || head.projection !== null || head.projectionRecordSha256Hex !== null
      || head.preparationEvidence !== null) {
      failB32a(B32A_ERROR.CORRUPT, 'STABLE_ADVERTISED head is incoherent');
    }
  } else if (head.state === B32A_STATE.WELCOME_RECORDED) {
    if (head.sequence !== 2 || head.previousHeadDigestHex === null || head.groupIdHex !== null
      || head.welcomeBlobSha256Hex === null || head.candidateBlobSha256Hex !== null
      || head.projection !== null || head.projectionRecordSha256Hex !== null
      || head.preparationEvidence !== null) {
      failB32a(B32A_ERROR.CORRUPT, 'WELCOME_RECORDED head is incoherent');
    }
  } else {
    if (head.sequence !== 3 || head.previousHeadDigestHex === null || head.groupIdHex === null
      || head.welcomeBlobSha256Hex === null || head.candidateBlobSha256Hex === null
      || head.projection === null || head.projectionRecordSha256Hex === null
      || head.preparationEvidence === null) {
      failB32a(B32A_ERROR.CORRUPT, 'JOINED head is incoherent');
    }
    const projection = head.projection;
    if (projection.groupIdHex !== head.groupIdHex
      || b32aProjectionRecordSha256(projection) !== head.projectionRecordSha256Hex
      || projection.predecessorStateSha256Hex !== head.predecessorBlobSha256Hex
      || projection.expectedKeyPackageSha256Hex !== head.keyPackageBlobSha256Hex
      || projection.welcomeSha256Hex !== head.welcomeBlobSha256Hex
      || projection.candidateStateSha256Hex !== head.candidateBlobSha256Hex
      || projection.welcomeAuthor.identityHex !== head.expectedAuthorHex
      || !projectionOwnBindsHead(projection, head)) {
      failB32a(B32A_ERROR.CORRUPT, 'JOINED projection does not bind the journal');
    }
  }
  if (sha256Hex(canonicalJsonBytes(headPayload(head))) !== head.headDigestHex) {
    failB32a(B32A_ERROR.CORRUPT, 'journal head digest mismatch');
  }
  return Object.freeze({ ...head });
}

function buildHead(fields) {
  const payload = {
    format: B32A_FORMAT,
    version: B32A_VERSION,
    providerFormat: B32A_PROVIDER_FORMAT,
    ...fields,
  };
  return parseB32aHead({
    ...payload,
    headDigestHex: sha256Hex(canonicalJsonBytes(payload)),
  });
}

function copyBytes(bytes) { return Uint8Array.from(bytes); }

export class MemoryB32aStore {
  constructor() {
    this.head = null;
    this.blobs = new Map();
    this.failNext = null;
  }

  async readHead() { return this.head; }

  async readBlob(valueDigest) {
    const value = this.blobs.get(valueDigest);
    return value === undefined ? null : copyBytes(value);
  }

  async compareAndSwap(expectedDigest, nextHead, blobWrites) {
    if (this.failNext !== null) {
      const failure = this.failNext;
      this.failNext = null;
      throw failure;
    }
    if ((this.head?.headDigestHex ?? null) !== expectedDigest) return false;
    const nextBlobs = new Map(this.blobs);
    for (const bytes of blobWrites) {
      const valueDigest = sha256Hex(bytes);
      const existing = nextBlobs.get(valueDigest);
      if (existing !== undefined && !Buffer.from(existing).equals(Buffer.from(bytes))) {
        failB32a(B32A_ERROR.CORRUPT, 'content-addressed blob collision');
      }
      nextBlobs.set(valueDigest, copyBytes(bytes));
    }
    this.blobs = nextBlobs;
    this.head = nextHead;
    return true;
  }
}

export class B32aJournal {
  constructor(store) {
    if (!store || typeof store.readHead !== 'function' || typeof store.readBlob !== 'function'
      || typeof store.compareAndSwap !== 'function') {
      failB32a(B32A_ERROR.INVALID, 'journal store does not implement the closed CAS interface');
    }
    this.store = store;
  }

  async #cas(expectedHead, nextHead, blobs) {
    try {
      const changed = await this.store.compareAndSwap(
        expectedHead?.headDigestHex ?? null, nextHead, blobs,
      );
      if (!changed) failB32a(B32A_ERROR.CAS_CONFLICT, 'journal head changed before CAS');
      return nextHead;
    } catch (error) {
      if (error instanceof B32aError) throw error;
      failB32a(B32A_ERROR.PERSISTENCE_FAILED, 'journal persistence failed closed', {}, error);
    }
  }

  async initializeStable({
    predecessorState, keyPackage, accountIdentityHex, leafSignatureKeyHex, expectedAuthorHex,
  }) {
    try {
      assertBytes('predecessor Provider state', predecessorState, {
        min: 1, max: B32_LIMITS.maxProviderBytes,
      });
      assertBytes('B3.2a KeyPackage', keyPackage, { min: 1, max: B32_LIMITS.maxKeyPackageBytes });
    } catch (error) {
      failB32a(B32A_ERROR.RESOURCE_LIMIT, 'initial durable input exceeds its envelope', {}, error);
    }
    exactHex('account identity', accountIdentityHex, 32);
    exactHex('leaf signature key', leafSignatureKeyHex, 32);
    exactHex('expected Welcome author', expectedAuthorHex, 32);
    const predecessorBlobSha256Hex = sha256Hex(predecessorState);
    const keyPackageBlobSha256Hex = sha256Hex(keyPackage);
    const journalIdHex = sha256Hex(canonicalJsonBytes({
      domain: 'STYX-B32A-JOURNAL-ID-v1', accountIdentityHex, leafSignatureKeyHex,
      keyPackageBlobSha256Hex,
    }));
    const head = buildHead({
      journalIdHex, sequence: 1, state: B32A_STATE.STABLE_ADVERTISED,
      previousHeadDigestHex: null, accountIdentityHex, leafSignatureKeyHex,
      expectedAuthorHex, groupIdHex: null, predecessorBlobSha256Hex,
      keyPackageBlobSha256Hex, welcomeBlobSha256Hex: null,
      candidateBlobSha256Hex: null, projection: null,
      projectionRecordSha256Hex: null, preparationEvidence: null,
    });
    return this.#cas(null, head, [copyBytes(predecessorState), copyBytes(keyPackage)]);
  }

  async read() {
    let rawHead;
    try { rawHead = await this.store.readHead(); } catch (error) {
      if (error instanceof B32aError) throw error;
      failB32a(B32A_ERROR.PERSISTENCE_FAILED, 'journal head read failed', {}, error);
    }
    if (rawHead === null) failB32a(B32A_ERROR.NOT_FOUND, 'journal head is absent');
    const head = parseB32aHead(rawHead);
    const names = ['predecessorBlobSha256Hex', 'keyPackageBlobSha256Hex'];
    if (head.welcomeBlobSha256Hex !== null) names.push('welcomeBlobSha256Hex');
    if (head.candidateBlobSha256Hex !== null) names.push('candidateBlobSha256Hex');
    const blobs = {};
    for (const name of names) {
      let bytes;
      try { bytes = await this.store.readBlob(head[name]); } catch (error) {
        if (error instanceof B32aError) throw error;
        failB32a(B32A_ERROR.PERSISTENCE_FAILED, `journal ${name} read failed`, {}, error);
      }
      if (bytes === null || sha256Hex(bytes) !== head[name]) {
        failB32a(B32A_ERROR.CORRUPT, `journal ${name} is absent or corrupt`);
      }
      blobs[name] = bytes;
    }
    return Object.freeze({ head, blobs: Object.freeze(blobs) });
  }

  async recordWelcome(welcomeBytes) {
    try {
      assertBytes('Welcome', welcomeBytes, { min: 1, max: B32_LIMITS.maxWelcomeBytes });
    } catch (error) {
      failB32a(B32A_ERROR.RESOURCE_LIMIT, 'Welcome exceeds its envelope', {}, error);
    }
    const bundle = await this.read();
    const welcomeBlobSha256Hex = sha256Hex(welcomeBytes);
    if (bundle.head.state !== B32A_STATE.STABLE_ADVERTISED) {
      if (bundle.head.welcomeBlobSha256Hex === welcomeBlobSha256Hex) {
        failB32a(B32A_ERROR.DUPLICATE_REPLAY, 'the exact Welcome was already recorded');
      }
      failB32a(B32A_ERROR.STATE_CONFLICT, 'Welcome requires STABLE_ADVERTISED');
    }
    const head = buildHead({
      ...headPayload(bundle.head), sequence: 2, state: B32A_STATE.WELCOME_RECORDED,
      previousHeadDigestHex: bundle.head.headDigestHex, welcomeBlobSha256Hex,
    });
    return this.#cas(bundle.head, head, [copyBytes(welcomeBytes)]);
  }

  async commitJoined(candidateState, projectionValue, evidenceValue) {
    try {
      assertBytes('candidate Provider state', candidateState, {
        min: 1, max: B32_LIMITS.maxProviderBytes,
      });
    } catch (error) {
      failB32a(B32A_ERROR.RESOURCE_LIMIT, 'candidate exceeds its envelope', {}, error);
    }
    const projection = normalizeB32aProjection(projectionValue);
    const candidateBlobSha256Hex = sha256Hex(candidateState);
    const preparationEvidence = normalizeB32aPreparationEvidence(
      evidenceValue, candidateBlobSha256Hex,
    );
    const bundle = await this.read();
    if (bundle.head.state === B32A_STATE.JOINED) {
      if (bundle.head.welcomeBlobSha256Hex === projection.welcomeSha256Hex) {
        failB32a(B32A_ERROR.DUPLICATE_REPLAY, 'the exact Welcome is already JOINED');
      }
      failB32a(B32A_ERROR.STATE_CONFLICT, 'joined head is terminal');
    }
    if (bundle.head.state !== B32A_STATE.WELCOME_RECORDED) {
      failB32a(B32A_ERROR.STATE_CONFLICT, 'candidate commit requires WELCOME_RECORDED');
    }
    if (projection.predecessorStateSha256Hex !== bundle.head.predecessorBlobSha256Hex
      || projection.expectedKeyPackageSha256Hex !== bundle.head.keyPackageBlobSha256Hex
      || projection.welcomeSha256Hex !== bundle.head.welcomeBlobSha256Hex
      || projection.candidateStateSha256Hex !== candidateBlobSha256Hex
      || projection.welcomeAuthor.identityHex !== bundle.head.expectedAuthorHex
      || !projectionOwnBindsHead(projection, bundle.head)) {
      failB32a(B32A_ERROR.PROJECTION_MISMATCH, 'candidate projection does not bind durable inputs');
    }
    const projectionRecordSha256Hex = b32aProjectionRecordSha256(projection);
    const head = buildHead({
      ...headPayload(bundle.head), sequence: 3, state: B32A_STATE.JOINED,
      previousHeadDigestHex: bundle.head.headDigestHex, groupIdHex: projection.groupIdHex,
      candidateBlobSha256Hex, projection, projectionRecordSha256Hex, preparationEvidence,
    });
    return this.#cas(bundle.head, head, [copyBytes(candidateState)]);
  }

  async activationState() {
    const bundle = await this.read();
    const key = bundle.head.state === B32A_STATE.JOINED
      ? 'candidateBlobSha256Hex' : 'predecessorBlobSha256Hex';
    return Object.freeze({
      state: bundle.head.state, bytes: copyBytes(bundle.blobs[key]), head: bundle.head,
    });
  }
}

function assertPrivateChild(directory, approvedRoot) {
  mkdirSync(approvedRoot, { recursive: true, mode: 0o700 });
  chmodSync(approvedRoot, 0o700);
  const root = realpathSync(approvedRoot);
  const target = resolve(directory);
  const pathFromRoot = relative(root, target);
  if (pathFromRoot === '' || pathFromRoot === '..' || pathFromRoot.startsWith(`..${sep}`)) {
    failB32a(B32A_ERROR.INVALID, 'journal directory is not a strict child of the private root');
  }
  mkdirSync(target, { recursive: true, mode: 0o700 });
  chmodSync(target, 0o700);
  if (relative(root, realpathSync(target)).startsWith('..')) {
    failB32a(B32A_ERROR.INVALID, 'journal directory escaped the private root');
  }
  return target;
}

function durableWrite(path, value) {
  const descriptor = openSync(path, 'wx', 0o600);
  try { writeFileSync(descriptor, value); fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function syncDirectory(directory) {
  const descriptor = openSync(directory, 'r');
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function processIsAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return false;
  try { process.kill(pid, 0); return true; } catch (error) { return error?.code === 'EPERM'; }
}

export class FileB32aStore {
  constructor(directory, approvedRoot = B32A_PRIVATE_ROOT) {
    this.directory = assertPrivateChild(directory, approvedRoot);
    this.blobDirectory = resolve(this.directory, 'blobs');
    mkdirSync(this.blobDirectory, { recursive: true, mode: 0o700 });
    chmodSync(this.blobDirectory, 0o700);
    this.headPath = resolve(this.directory, 'head.json');
    this.lockDirectory = resolve(this.directory, 'cas.lock');
  }

  async readHead() {
    if (!existsSync(this.headPath)) return null;
    try {
      if (statSync(this.headPath).size > B32_LIMITS.maxJournalHeadBytes) {
        failB32a(B32A_ERROR.CORRUPT, 'durable head exceeds the resource envelope');
      }
      const raw = Uint8Array.from(readFileSync(this.headPath));
      const parsed = JSON.parse(Buffer.from(raw).toString('utf8'));
      if (!Buffer.from(raw).equals(Buffer.from(canonicalJsonBytes(parsed)))) {
        failB32a(B32A_ERROR.CORRUPT, 'durable head is not canonical JSON');
      }
      return parsed;
    } catch (error) {
      if (error instanceof B32aError) throw error;
      failB32a(B32A_ERROR.CORRUPT, 'durable head is not JSON', {}, error);
    }
  }

  async readBlob(valueDigest) {
    digest('blob digest', valueDigest);
    const path = resolve(this.blobDirectory, valueDigest);
    if (!existsSync(path)) return null;
    if (statSync(path).size > B32_LIMITS.maxProviderBytes) {
      failB32a(B32A_ERROR.CORRUPT, 'durable blob exceeds the resource envelope');
    }
    return Uint8Array.from(readFileSync(path));
  }

  #acquireLock() {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        mkdirSync(this.lockDirectory, { mode: 0o700 });
        try { durableWrite(resolve(this.lockDirectory, 'owner'), `${process.pid}\n`); }
        catch (error) {
          const ownerPath = resolve(this.lockDirectory, 'owner');
          if (existsSync(ownerPath)) unlinkSync(ownerPath);
          if (existsSync(this.lockDirectory)) rmdirSync(this.lockDirectory);
          throw error;
        }
        return;
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error;
        const ownerPath = resolve(this.lockDirectory, 'owner');
        let owner = null;
        try { owner = Number.parseInt(readFileSync(ownerPath, 'utf8').trim(), 10); }
        catch { failB32a(B32A_ERROR.CAS_CONFLICT, 'CAS lock owner is incomplete'); }
        if (processIsAlive(owner)) failB32a(B32A_ERROR.CAS_CONFLICT, 'another CAS writer is active');
        unlinkSync(ownerPath);
        rmdirSync(this.lockDirectory);
      }
    }
    failB32a(B32A_ERROR.CAS_CONFLICT, 'CAS lock could not be acquired');
  }

  #releaseLock() {
    const ownerPath = resolve(this.lockDirectory, 'owner');
    if (existsSync(ownerPath)) unlinkSync(ownerPath);
    if (existsSync(this.lockDirectory)) rmdirSync(this.lockDirectory);
  }

  #writeImmutableBlob(bytes) {
    const valueDigest = sha256Hex(bytes);
    const finalPath = resolve(this.blobDirectory, valueDigest);
    if (existsSync(finalPath)) {
      if (!Buffer.from(readFileSync(finalPath)).equals(Buffer.from(bytes))) {
        failB32a(B32A_ERROR.CORRUPT, 'immutable blob content-address collision');
      }
      return;
    }
    const temporary = resolve(this.blobDirectory, `.${valueDigest}.${process.pid}.${randomUUID()}.tmp`);
    durableWrite(temporary, bytes);
    try {
      linkSync(temporary, finalPath);
      chmodSync(finalPath, 0o600);
      syncDirectory(this.blobDirectory);
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      if (!Buffer.from(readFileSync(finalPath)).equals(Buffer.from(bytes))) {
        failB32a(B32A_ERROR.CORRUPT, 'immutable blob race disagreed on bytes');
      }
    } finally {
      if (existsSync(temporary)) unlinkSync(temporary);
    }
  }

  async compareAndSwap(expectedDigest, nextHead, blobWrites) {
    this.#acquireLock();
    try {
      const current = await this.readHead();
      if ((current?.headDigestHex ?? null) !== expectedDigest) return false;
      for (const bytes of blobWrites) this.#writeImmutableBlob(bytes);
      const temporary = resolve(this.directory, `.head.${process.pid}.${randomUUID()}.tmp`);
      durableWrite(temporary, canonicalJsonBytes(nextHead));
      renameSync(temporary, this.headPath);
      chmodSync(this.headPath, 0o600);
      syncDirectory(this.directory);
      return true;
    } finally {
      this.#releaseLock();
    }
  }
}

export function openB32aFileJournal(directory, approvedRoot = B32A_PRIVATE_ROOT) {
  return new B32aJournal(new FileB32aStore(directory, approvedRoot));
}
