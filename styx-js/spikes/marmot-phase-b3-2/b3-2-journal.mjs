// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — private, one-join B3.2 durability journal.

import { randomUUID } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { relative, resolve, sep } from 'node:path';

import {
  B32Error,
  B32_ERROR,
  B32_FORMAT,
  B32_LIMITS,
  B32_PRIVATE_ROOT,
  B32_STATE,
  B32_VERSION,
  assertBytes,
  assertDigest,
  assertHexBytes,
  assertSafeInteger,
  b32ProjectionRecordSha256,
  bytesEqual,
  canonicalJsonBytes,
  failB32,
  normalizeB32Projection,
  sha256Hex,
  snapshotClosedObject,
} from './b3-2-canonical.mjs';

const HEAD_FIELDS = Object.freeze([
  'format', 'version', 'journalIdHex', 'sequence', 'state', 'previousHeadDigestHex',
  'accountIdentityHex', 'leafSignatureKeyHex', 'expectedAuthorHex', 'groupIdHex',
  'predecessorBlobSha256Hex', 'keyPackageBlobSha256Hex', 'welcomeBlobSha256Hex',
  'candidateBlobSha256Hex', 'projection', 'projectionRecordSha256Hex', 'headDigestHex',
]);

function optionalDigest(label, value) {
  if (value !== null) assertDigest(label, value);
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

export function parseB32Head(value) {
  const head = snapshotClosedObject(value, HEAD_FIELDS, 'B3.2 head');
  if (head.format !== B32_FORMAT || head.version !== B32_VERSION) {
    failB32(B32_ERROR.CORRUPT, 'journal head domain or version is invalid');
  }
  assertDigest('journal id', head.journalIdHex);
  assertSafeInteger('journal sequence', head.sequence, 1);
  if (!Object.values(B32_STATE).includes(head.state)) {
    failB32(B32_ERROR.CORRUPT, 'journal state is invalid');
  }
  optionalDigest('previous head digest', head.previousHeadDigestHex);
  assertHexBytes('account identity', head.accountIdentityHex, 32);
  assertHexBytes('leaf signature key', head.leafSignatureKeyHex, 32);
  assertHexBytes('expected Welcome author', head.expectedAuthorHex, 32);
  if (head.groupIdHex !== null) {
    if (typeof head.groupIdHex !== 'string' || head.groupIdHex.length < 2
      || head.groupIdHex.length > B32_LIMITS.maxGroupIdBytes * 2
      || !/^(?:[0-9a-f]{2})+$/.test(head.groupIdHex)) {
      failB32(B32_ERROR.CORRUPT, 'joined group id is invalid');
    }
  }
  assertDigest('predecessor blob', head.predecessorBlobSha256Hex);
  assertDigest('KeyPackage blob', head.keyPackageBlobSha256Hex);
  optionalDigest('Welcome blob', head.welcomeBlobSha256Hex);
  optionalDigest('candidate blob', head.candidateBlobSha256Hex);
  optionalDigest('projection record', head.projectionRecordSha256Hex);
  assertDigest('head digest', head.headDigestHex);
  const expectedHeadDigest = sha256Hex(canonicalJsonBytes(headPayload(head)));
  if (expectedHeadDigest !== head.headDigestHex) {
    failB32(B32_ERROR.CORRUPT, 'journal head digest mismatch');
  }

  if (head.state === B32_STATE.STABLE_ADVERTISED) {
    if (head.sequence !== 1 || head.previousHeadDigestHex !== null || head.groupIdHex !== null
      || head.welcomeBlobSha256Hex !== null || head.candidateBlobSha256Hex !== null
      || head.projection !== null || head.projectionRecordSha256Hex !== null) {
      failB32(B32_ERROR.CORRUPT, 'STABLE_ADVERTISED head fields are incoherent');
    }
  } else if (head.state === B32_STATE.WELCOME_RECORDED) {
    if (head.sequence !== 2 || head.previousHeadDigestHex === null || head.groupIdHex !== null
      || head.welcomeBlobSha256Hex === null || head.candidateBlobSha256Hex !== null
      || head.projection !== null || head.projectionRecordSha256Hex !== null) {
      failB32(B32_ERROR.CORRUPT, 'WELCOME_RECORDED head fields are incoherent');
    }
  } else {
    if (head.sequence !== 3 || head.previousHeadDigestHex === null || head.groupIdHex === null
      || head.welcomeBlobSha256Hex === null || head.candidateBlobSha256Hex === null
      || head.projection === null || head.projectionRecordSha256Hex === null) {
      failB32(B32_ERROR.CORRUPT, 'JOINED head fields are incoherent');
    }
    const projection = normalizeB32Projection(head.projection);
    if (projection.groupIdHex !== head.groupIdHex
      || b32ProjectionRecordSha256(projection) !== head.projectionRecordSha256Hex
      || projection.predecessorStateSha256Hex !== head.predecessorBlobSha256Hex
      || projection.expectedKeyPackageSha256Hex !== head.keyPackageBlobSha256Hex
      || projection.welcomeSha256Hex !== head.welcomeBlobSha256Hex
      || projection.candidateStateSha256Hex !== head.candidateBlobSha256Hex
      || projection.welcomeAuthor.identityHex !== head.expectedAuthorHex
      || !projectionOwnBindsHead(projection, head)) {
      failB32(B32_ERROR.CORRUPT, 'JOINED projection does not bind the journal blobs');
    }
    head.projection = projection;
  }
  return Object.freeze({ ...head });
}

function buildHead(fields) {
  const payload = { format: B32_FORMAT, version: B32_VERSION, ...fields };
  return parseB32Head({
    ...payload,
    headDigestHex: sha256Hex(canonicalJsonBytes(payload)),
  });
}

function copyBytes(bytes) {
  return Uint8Array.from(bytes);
}

export class MemoryB32Store {
  constructor() {
    this.head = null;
    this.blobs = new Map();
    this.failNext = null;
  }

  async readHead() {
    // Heads are frozen by the journal before storage. Returning the same
    // immutable value also avoids cross-realm prototypes under Jest VM modules.
    return this.head;
  }

  async readBlob(digest) {
    const value = this.blobs.get(digest);
    return value === undefined ? null : copyBytes(value);
  }

  async compareAndSwap(expectedDigest, nextHead, blobWrites) {
    if (this.failNext !== null) {
      const failure = this.failNext;
      this.failNext = null;
      throw failure;
    }
    const currentDigest = this.head?.headDigestHex ?? null;
    if (currentDigest !== expectedDigest) return false;
    const nextBlobs = new Map(this.blobs);
    for (const bytes of blobWrites) {
      const digest = sha256Hex(bytes);
      const existing = nextBlobs.get(digest);
      if (existing !== undefined && !bytesEqual(existing, bytes)) {
        failB32(B32_ERROR.CORRUPT, 'content-addressed blob collision');
      }
      nextBlobs.set(digest, copyBytes(bytes));
    }
    this.blobs = nextBlobs;
    this.head = nextHead;
    return true;
  }
}

export class B32Journal {
  constructor(store) {
    if (!store || typeof store.readHead !== 'function' || typeof store.readBlob !== 'function'
      || typeof store.compareAndSwap !== 'function') {
      failB32(B32_ERROR.INVALID, 'journal store does not implement the closed CAS interface');
    }
    this.store = store;
  }

  async #cas(expectedHead, nextHead, blobs) {
    try {
      const changed = await this.store.compareAndSwap(
        expectedHead?.headDigestHex ?? null,
        nextHead,
        blobs,
      );
      if (!changed) failB32(B32_ERROR.CAS_CONFLICT, 'journal head changed before CAS');
      return nextHead;
    } catch (error) {
      if (error instanceof B32Error) throw error;
      failB32(B32_ERROR.PERSISTENCE_FAILED, 'journal persistence failed closed', {}, error);
    }
  }

  async initializeStable({
    predecessorState, keyPackage, accountIdentityHex, leafSignatureKeyHex, expectedAuthorHex,
  }) {
    assertBytes('predecessor Provider state', predecessorState, {
      min: 1, max: B32_LIMITS.maxProviderBytes,
    });
    assertBytes('B3.1 KeyPackage', keyPackage, {
      min: 1, max: B32_LIMITS.maxKeyPackageBytes,
    });
    assertHexBytes('account identity', accountIdentityHex, 32);
    assertHexBytes('leaf signature key', leafSignatureKeyHex, 32);
    assertHexBytes('expected Welcome author', expectedAuthorHex, 32);
    const predecessorBlobSha256Hex = sha256Hex(predecessorState);
    const keyPackageBlobSha256Hex = sha256Hex(keyPackage);
    const journalIdHex = sha256Hex(canonicalJsonBytes({
      domain: 'STYX-B32-JOURNAL-ID-v1',
      accountIdentityHex,
      leafSignatureKeyHex,
      keyPackageBlobSha256Hex,
    }));
    const head = buildHead({
      journalIdHex,
      sequence: 1,
      state: B32_STATE.STABLE_ADVERTISED,
      previousHeadDigestHex: null,
      accountIdentityHex,
      leafSignatureKeyHex,
      expectedAuthorHex,
      groupIdHex: null,
      predecessorBlobSha256Hex,
      keyPackageBlobSha256Hex,
      welcomeBlobSha256Hex: null,
      candidateBlobSha256Hex: null,
      projection: null,
      projectionRecordSha256Hex: null,
    });
    return this.#cas(null, head, [copyBytes(predecessorState), copyBytes(keyPackage)]);
  }

  async read() {
    let rawHead;
    try { rawHead = await this.store.readHead(); } catch (error) {
      failB32(B32_ERROR.PERSISTENCE_FAILED, 'journal head read failed', {}, error);
    }
    if (rawHead === null) failB32(B32_ERROR.NOT_FOUND, 'journal head is absent');
    const head = parseB32Head(rawHead);
    const names = ['predecessorBlobSha256Hex', 'keyPackageBlobSha256Hex'];
    if (head.welcomeBlobSha256Hex !== null) names.push('welcomeBlobSha256Hex');
    if (head.candidateBlobSha256Hex !== null) names.push('candidateBlobSha256Hex');
    const blobs = {};
    for (const name of names) {
      let bytes;
      try { bytes = await this.store.readBlob(head[name]); } catch (error) {
        failB32(B32_ERROR.PERSISTENCE_FAILED, `journal ${name} read failed`, {}, error);
      }
      if (bytes === null || sha256Hex(bytes) !== head[name]) {
        failB32(B32_ERROR.CORRUPT, `journal ${name} is absent or corrupt`);
      }
      blobs[name] = bytes;
    }
    return Object.freeze({ head, blobs: Object.freeze(blobs) });
  }

  async recordWelcome(welcomeBytes) {
    assertBytes('Welcome', welcomeBytes, { min: 1, max: B32_LIMITS.maxWelcomeBytes });
    const bundle = await this.read();
    const welcomeBlobSha256Hex = sha256Hex(welcomeBytes);
    if (bundle.head.state !== B32_STATE.STABLE_ADVERTISED) {
      if (bundle.head.welcomeBlobSha256Hex === welcomeBlobSha256Hex) {
        failB32(B32_ERROR.DUPLICATE_REPLAY, 'the exact Welcome was already recorded');
      }
      failB32(B32_ERROR.STATE_CONFLICT, 'Welcome requires STABLE_ADVERTISED');
    }
    const head = buildHead({
      ...headPayload(bundle.head),
      sequence: 2,
      state: B32_STATE.WELCOME_RECORDED,
      previousHeadDigestHex: bundle.head.headDigestHex,
      welcomeBlobSha256Hex,
    });
    return this.#cas(bundle.head, head, [copyBytes(welcomeBytes)]);
  }

  async commitJoined(candidateState, projectionValue) {
    assertBytes('candidate Provider state', candidateState, {
      min: 1, max: B32_LIMITS.maxProviderBytes,
    });
    const projection = normalizeB32Projection(projectionValue);
    const bundle = await this.read();
    if (bundle.head.state === B32_STATE.JOINED) {
      if (bundle.head.welcomeBlobSha256Hex === projection.welcomeSha256Hex) {
        failB32(B32_ERROR.DUPLICATE_REPLAY, 'the exact Welcome is already JOINED');
      }
      failB32(B32_ERROR.STATE_CONFLICT, 'joined head is terminal');
    }
    if (bundle.head.state !== B32_STATE.WELCOME_RECORDED) {
      failB32(B32_ERROR.STATE_CONFLICT, 'candidate commit requires WELCOME_RECORDED');
    }
    const candidateBlobSha256Hex = sha256Hex(candidateState);
    if (projection.predecessorStateSha256Hex !== bundle.head.predecessorBlobSha256Hex
      || projection.expectedKeyPackageSha256Hex !== bundle.head.keyPackageBlobSha256Hex
      || projection.welcomeSha256Hex !== bundle.head.welcomeBlobSha256Hex
      || projection.candidateStateSha256Hex !== candidateBlobSha256Hex
      || projection.welcomeAuthor.identityHex !== bundle.head.expectedAuthorHex
      || !projectionOwnBindsHead(projection, bundle.head)) {
      failB32(B32_ERROR.PROJECTION_MISMATCH, 'candidate projection does not bind the durable inputs');
    }
    const projectionRecordSha256Hex = b32ProjectionRecordSha256(projection);
    const head = buildHead({
      ...headPayload(bundle.head),
      sequence: 3,
      state: B32_STATE.JOINED,
      previousHeadDigestHex: bundle.head.headDigestHex,
      groupIdHex: projection.groupIdHex,
      candidateBlobSha256Hex,
      projection,
      projectionRecordSha256Hex,
    });
    return this.#cas(bundle.head, head, [copyBytes(candidateState)]);
  }

  async activationState() {
    const bundle = await this.read();
    const digest = bundle.head.state === B32_STATE.JOINED
      ? bundle.head.candidateBlobSha256Hex
      : bundle.head.predecessorBlobSha256Hex;
    const key = bundle.head.state === B32_STATE.JOINED
      ? 'candidateBlobSha256Hex'
      : 'predecessorBlobSha256Hex';
    const bytes = bundle.blobs[key];
    if (sha256Hex(bytes) !== digest) failB32(B32_ERROR.CORRUPT, 'activation blob is corrupt');
    return Object.freeze({ state: bundle.head.state, bytes: copyBytes(bytes), head: bundle.head });
  }
}

function assertOwnerOnlyDirectory(path, label) {
  const real = realpathSync(path);
  if ((statSync(real).mode & 0o077) !== 0) {
    failB32(B32_ERROR.PERSISTENCE_FAILED, `${label} is not owner-only`);
  }
  return real;
}

function assertLexicalChild(path, root, label) {
  const candidate = resolve(path);
  const rel = relative(resolve(root), candidate);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) {
    failB32(B32_ERROR.INVALID, `${label} escaped the approved B3.2 private root`);
  }
  return candidate;
}

function assertPrivateChild(path) {
  mkdirSync(B32_PRIVATE_ROOT, { recursive: true, mode: 0o700 });
  chmodSync(B32_PRIVATE_ROOT, 0o700);
  const root = assertOwnerOnlyDirectory(B32_PRIVATE_ROOT, 'B3.2 private root');
  const candidate = assertLexicalChild(path, B32_PRIVATE_ROOT, 'journal directory');
  mkdirSync(candidate, { recursive: true, mode: 0o700 });
  chmodSync(candidate, 0o700);
  const real = assertOwnerOnlyDirectory(candidate, 'B3.2 journal directory');
  const rel = relative(root, real);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) {
    failB32(B32_ERROR.INVALID, 'journal directory escaped the approved B3.2 private root');
  }
  return real;
}

function durableWrite(path, bytes, flag = 'wx') {
  const descriptor = openSync(path, flag, 0o600);
  try {
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  chmodSync(path, 0o600);
}

function syncDirectory(path) {
  const descriptor = openSync(path, 'r');
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function processIsAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === 'EPERM';
  }
}

/**
 * Minimal process-persistent store for the isolated evidence harness.
 *
 * Blob publication uses an atomic hard-link of a synced temporary file. The
 * mutable head is one synced canonical file replaced by rename while an
 * owner-PID lock excludes competing CAS writers. This establishes only the
 * tested local-filesystem primitive, not arbitrary power-loss durability.
 */
export class FileB32Store {
  constructor(directory) {
    this.directory = assertPrivateChild(directory);
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
        failB32(B32_ERROR.CORRUPT, 'durable head exceeds the B3.2 resource envelope');
      }
      return JSON.parse(readFileSync(this.headPath, 'utf8'));
    } catch (error) {
      failB32(B32_ERROR.CORRUPT, 'durable head is not strict JSON', {}, error);
    }
  }

  async readBlob(digest) {
    assertDigest('blob digest', digest);
    const path = resolve(this.blobDirectory, digest);
    if (!existsSync(path)) return null;
    if (statSync(path).size > B32_LIMITS.maxProviderBytes) {
      failB32(B32_ERROR.CORRUPT, 'durable blob exceeds the B3.2 resource envelope');
    }
    return Uint8Array.from(readFileSync(path));
  }

  #acquireLock() {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        mkdirSync(this.lockDirectory, { mode: 0o700 });
        try {
          durableWrite(resolve(this.lockDirectory, 'owner'), `${process.pid}\n`);
        } catch (error) {
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
        try { owner = Number.parseInt(readFileSync(ownerPath, 'utf8').trim(), 10); } catch {
          failB32(B32_ERROR.CAS_CONFLICT, 'CAS lock owner is incomplete');
        }
        if (processIsAlive(owner)) failB32(B32_ERROR.CAS_CONFLICT, 'another CAS writer is active');
        unlinkSync(ownerPath);
        rmdirSync(this.lockDirectory);
      }
    }
    failB32(B32_ERROR.CAS_CONFLICT, 'CAS lock could not be acquired');
  }

  #releaseLock() {
    const ownerPath = resolve(this.lockDirectory, 'owner');
    if (existsSync(ownerPath)) unlinkSync(ownerPath);
    if (existsSync(this.lockDirectory)) rmdirSync(this.lockDirectory);
  }

  #writeImmutableBlob(bytes) {
    const digest = sha256Hex(bytes);
    const finalPath = resolve(this.blobDirectory, digest);
    if (existsSync(finalPath)) {
      if (!bytesEqual(Uint8Array.from(readFileSync(finalPath)), bytes)) {
        failB32(B32_ERROR.CORRUPT, 'immutable blob content-address collision');
      }
      return;
    }
    const temporary = resolve(
      this.blobDirectory,
      `.${digest}.${process.pid}.${randomUUID()}.tmp`,
    );
    durableWrite(temporary, bytes);
    try {
      linkSync(temporary, finalPath);
      chmodSync(finalPath, 0o600);
      syncDirectory(this.blobDirectory);
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      if (!bytesEqual(Uint8Array.from(readFileSync(finalPath)), bytes)) {
        failB32(B32_ERROR.CORRUPT, 'immutable blob race disagreed on bytes');
      }
    } finally {
      if (existsSync(temporary)) unlinkSync(temporary);
    }
  }

  async compareAndSwap(expectedDigest, nextHead, blobWrites) {
    this.#acquireLock();
    try {
      const current = await this.readHead();
      const currentDigest = current?.headDigestHex ?? null;
      if (currentDigest !== expectedDigest) return false;
      for (const bytes of blobWrites) this.#writeImmutableBlob(bytes);
      const temporary = resolve(
        this.directory,
        `.head.${process.pid}.${randomUUID()}.tmp`,
      );
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

export function openB32FileJournal(directory) {
  return new B32Journal(new FileB32Store(directory));
}
