// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — isolated B3.3a authoritative CAS journal.

import { randomUUID } from 'node:crypto';
import {
  chmodSync, closeSync, existsSync, fsyncSync, linkSync, mkdirSync, openSync,
  readSync, realpathSync, renameSync, rmdirSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { relative, resolve, sep } from 'node:path';

import { B32A_STATE } from '../marmot-phase-b3-2a/b3-2a-canonical.mjs';
import { parseB32aHead } from '../marmot-phase-b3-2a/b3-2a-journal.mjs';
import {
  B33A_ERROR,
  B33A_FORMAT,
  B33A_LIMITS,
  B33A_OUTCOME,
  B33A_PRIVATE_ROOT,
  B33A_PROVIDER_FORMAT,
  B33A_STATE,
  B33A_VERSION,
  B33aError,
  assertBytes,
  assertDigest,
  assertHex,
  canonicalJsonBytes,
  clearBytes,
  copyBytes,
  exactObject,
  failB33a,
  sha256Hex,
} from './b3-3a-canonical.mjs';

const HEAD_FIELDS = Object.freeze([
  'format', 'version', 'providerFormat', 'journalIdHex', 'sourceB32aHeadDigestHex',
  'sequence', 'state', 'previousHeadDigestHex', 'accountIdentityHex',
  'leafSignatureKeyHex', 'groupIdHex', 'epochDec', 'stateBlobSha256Hex',
  'sourceB32aHead', 'outboundRecords', 'inboundRecords', 'headDigestHex',
]);
const OUTBOUND_FIELDS = Object.freeze([
  'ordinal', 'requestId', 'eventIdHex', 'stateBlobSha256Hex', 'ciphertextBlobSha256Hex',
  'senderIdentityHex', 'senderSignatureKeyHex',
]);
const INBOUND_FIELDS = Object.freeze([
  'ordinal', 'eventIdHex', 'stateBlobSha256Hex', 'ciphertextBlobSha256Hex',
  'plaintextBlobSha256Hex', 'senderLeafIndex', 'senderIdentityHex',
  'senderSignatureKeyHex', 'verifiedLeafDigestHex',
]);

function headPayload(head) {
  return Object.fromEntries(HEAD_FIELDS.filter((field) => field !== 'headDigestHex')
    .map((field) => [field, head[field]]));
}

function recordOrdinal(value, expected, label) {
  if (!Number.isSafeInteger(value) || value !== expected || value < 1) {
    failB33a(B33A_ERROR.CORRUPT, `${label} ordinal is not contiguous`);
  }
  return value;
}

function parseOutbound(value, expectedOrdinal) {
  const record = exactObject(value, OUTBOUND_FIELDS, 'B3.3a outbound record', B33A_ERROR.CORRUPT);
  recordOrdinal(record.ordinal, expectedOrdinal, 'outbound');
  if (typeof record.requestId !== 'string' || record.requestId.length === 0
    || new TextEncoder().encode(record.requestId).byteLength > B33A_LIMITS.maxRequestIdBytes) {
    failB33a(B33A_ERROR.CORRUPT, 'outbound request id is invalid');
  }
  assertDigest('outbound event id', record.eventIdHex);
  assertDigest('outbound state blob', record.stateBlobSha256Hex);
  assertDigest('outbound ciphertext blob', record.ciphertextBlobSha256Hex);
  assertHex('outbound sender identity', record.senderIdentityHex, 32);
  assertHex('outbound sender signature key', record.senderSignatureKeyHex, 32);
  return Object.freeze({ ...record });
}

function parseInbound(value, expectedOrdinal) {
  const record = exactObject(value, INBOUND_FIELDS, 'B3.3a inbound record', B33A_ERROR.CORRUPT);
  recordOrdinal(record.ordinal, expectedOrdinal, 'inbound');
  assertDigest('inbound event id', record.eventIdHex);
  assertDigest('inbound state blob', record.stateBlobSha256Hex);
  assertDigest('inbound ciphertext blob', record.ciphertextBlobSha256Hex);
  assertDigest('inbound plaintext blob', record.plaintextBlobSha256Hex);
  assertDigest('inbound verified-leaf digest', record.verifiedLeafDigestHex);
  if (!Number.isSafeInteger(record.senderLeafIndex)
    || record.senderLeafIndex < 0 || record.senderLeafIndex > 0xffffffff) {
    failB33a(B33A_ERROR.CORRUPT, 'inbound sender leaf index is invalid');
  }
  assertHex('inbound sender identity', record.senderIdentityHex, 32);
  assertHex('inbound sender signature key', record.senderSignatureKeyHex, 32);
  return Object.freeze({ ...record });
}

export function parseB33aHead(value) {
  const head = exactObject(value, HEAD_FIELDS, 'B3.3a head', B33A_ERROR.CORRUPT);
  if (head.format !== B33A_FORMAT || head.version !== B33A_VERSION
    || head.providerFormat !== B33A_PROVIDER_FORMAT || head.state !== B33A_STATE.ACTIVE) {
    failB33a(B33A_ERROR.CORRUPT, 'B3.3a head domain, version or state is invalid');
  }
  for (const [label, digest] of [
    ['journal id', head.journalIdHex],
    ['source B3.2a head', head.sourceB32aHeadDigestHex],
    ['state blob', head.stateBlobSha256Hex],
    ['head', head.headDigestHex],
  ]) assertDigest(label, digest);
  if (head.previousHeadDigestHex !== null) assertDigest('previous head', head.previousHeadDigestHex);
  if (!Number.isSafeInteger(head.sequence) || head.sequence < 1
    || typeof head.epochDec !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(head.epochDec)) {
    failB33a(B33A_ERROR.CORRUPT, 'B3.3a sequence or epoch is invalid');
  }
  assertHex('account identity', head.accountIdentityHex, 32);
  assertHex('leaf signature key', head.leafSignatureKeyHex, 32);
  assertHex('group id', head.groupIdHex);
  let sourceHead;
  try {
    const wrapper = exactObject(
      head.sourceB32aHead, ['value'], 'B3.2a source-head wrapper', B33A_ERROR.CORRUPT,
    );
    sourceHead = parseB32aHead({ ...wrapper.value });
  } catch (error) {
    if (error instanceof B33aError) throw error;
    failB33a(B33A_ERROR.CORRUPT, 'embedded B3.2a source head is invalid', {}, error);
  }
  if (sourceHead.state !== B32A_STATE.JOINED
    || sourceHead.headDigestHex !== head.sourceB32aHeadDigestHex
    || sourceHead.accountIdentityHex !== head.accountIdentityHex
    || sourceHead.leafSignatureKeyHex !== head.leafSignatureKeyHex
    || sourceHead.groupIdHex !== head.groupIdHex
    || sourceHead.projection.epochDec !== head.epochDec) {
    failB33a(B33A_ERROR.CORRUPT, 'B3.3a head does not bind its B3.2a JOINED authority');
  }
  const outboundRecords = head.outboundRecords.map((record, index) =>
    parseOutbound(record, index + 1));
  const inboundRecords = head.inboundRecords.map((record, index) =>
    parseInbound(record, index + 1));
  if (outboundRecords.length + inboundRecords.length > B33A_LIMITS.maxJournalRecords
    || head.sequence !== 1 + outboundRecords.length + inboundRecords.length
    || (head.sequence === 1) !== (head.previousHeadDigestHex === null)) {
    failB33a(B33A_ERROR.CORRUPT, 'B3.3a record count, sequence or predecessor is incoherent');
  }
  if (new Set(outboundRecords.map((record) => record.requestId)).size !== outboundRecords.length
    || new Set(inboundRecords.map((record) => record.ciphertextBlobSha256Hex)).size
      !== inboundRecords.length) {
    failB33a(B33A_ERROR.CORRUPT, 'B3.3a durable message identity is duplicated');
  }
  const normalized = {
    ...head,
    sourceB32aHead: Object.freeze({ value: sourceHead }),
    outboundRecords: Object.freeze(outboundRecords),
    inboundRecords: Object.freeze(inboundRecords),
  };
  if (sha256Hex(canonicalJsonBytes(headPayload(normalized))) !== head.headDigestHex) {
    failB33a(B33A_ERROR.CORRUPT, 'B3.3a head digest mismatch');
  }
  return Object.freeze(normalized);
}

function buildHead(fields) {
  const payload = { format: B33A_FORMAT, version: B33A_VERSION,
    providerFormat: B33A_PROVIDER_FORMAT, ...fields };
  return parseB33aHead({ ...payload, headDigestHex: sha256Hex(canonicalJsonBytes(payload)) });
}

export class MemoryB33aStore {
  constructor() {
    this.head = null;
    this.blobs = new Map();
    this.failNext = null;
    this.beforeCas = async () => {};
  }

  async readHead() { return this.head; }

  async readBlob(valueDigest) {
    const value = this.blobs.get(valueDigest);
    return value === undefined ? null : copyBytes(value);
  }

  async compareAndSwap(expectedDigest, nextHead, blobWrites) {
    await this.beforeCas({ expectedDigest, nextHead, blobWrites });
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
        failB33a(B33A_ERROR.CORRUPT, 'content-addressed blob collision');
      }
      nextBlobs.set(valueDigest, copyBytes(bytes));
    }
    this.blobs = nextBlobs;
    this.head = nextHead;
    return true;
  }
}

export class B33aJournal {
  constructor(store) {
    if (!store || typeof store.readHead !== 'function' || typeof store.readBlob !== 'function'
      || typeof store.compareAndSwap !== 'function') {
      failB33a(B33A_ERROR.INVALID, 'journal store does not implement the closed CAS interface');
    }
    this.store = store;
  }

  async #cas(expectedHead, nextHead, blobs, initialization = false) {
    try {
      const changed = await this.store.compareAndSwap(
        expectedHead?.headDigestHex ?? null, nextHead, blobs,
      );
      if (!changed) failB33a(
        initialization ? B33A_ERROR.DUPLICATE_INITIALIZATION : B33A_ERROR.CAS_CONFLICT,
        initialization ? 'the B3.2a JOINED head already activated a journal'
          : 'journal head changed before authoritative CAS',
      );
      return nextHead;
    } catch (error) {
      if (error instanceof B33aError) throw error;
      failB33a(B33A_ERROR.PERSISTENCE_FAILED, 'journal persistence failed closed', {}, error);
    }
  }

  async initializeFromB32a(joinedHeadValue, canonicalState) {
    const sourceHead = parseB32aHead(joinedHeadValue);
    assertBytes('B3.2a canonical state', canonicalState,
      { min: 1, max: B33A_LIMITS.maxProviderBytes });
    if (sourceHead.state !== B32A_STATE.JOINED
      || sourceHead.candidateBlobSha256Hex !== sha256Hex(canonicalState)) {
      failB33a(B33A_ERROR.STATE_CONFLICT, 'activation requires its exact B3.2a JOINED state');
    }
    let current;
    try { current = await this.store.readHead(); } catch (error) {
      failB33a(B33A_ERROR.PERSISTENCE_FAILED, 'journal activation read failed', {}, error);
    }
    if (current !== null) {
      failB33a(B33A_ERROR.DUPLICATE_INITIALIZATION,
        'the B3.2a JOINED head already activated a journal');
    }
    const journalIdHex = sha256Hex(canonicalJsonBytes({
      domain: 'STYX-B33A-JOURNAL-ID-v1',
      sourceB32aHeadDigestHex: sourceHead.headDigestHex,
    }));
    const head = buildHead({
      journalIdHex,
      sourceB32aHeadDigestHex: sourceHead.headDigestHex,
      sequence: 1,
      state: B33A_STATE.ACTIVE,
      previousHeadDigestHex: null,
      accountIdentityHex: sourceHead.accountIdentityHex,
      leafSignatureKeyHex: sourceHead.leafSignatureKeyHex,
      groupIdHex: sourceHead.groupIdHex,
      epochDec: sourceHead.projection.epochDec,
      stateBlobSha256Hex: sourceHead.candidateBlobSha256Hex,
      sourceB32aHead: { value: sourceHead },
      outboundRecords: [],
      inboundRecords: [],
    });
    return this.#cas(null, head, [copyBytes(canonicalState)], true);
  }

  async #readHead() {
    try {
      const value = await this.store.readHead();
      if (value === null) failB33a(B33A_ERROR.STATE_CONFLICT, 'B3.3a journal is not active');
      return parseB33aHead(value);
    } catch (error) {
      if (error instanceof B33aError) throw error;
      failB33a(B33A_ERROR.PERSISTENCE_FAILED, 'journal head read failed', {}, error);
    }
  }

  async #readBlob(valueDigest, label, maximumBytes) {
    let bytes;
    try { bytes = await this.store.readBlob(valueDigest); } catch (error) {
      if (error instanceof B33aError) throw error;
      failB33a(B33A_ERROR.PERSISTENCE_FAILED, `${label} read failed`, {}, error);
    }
    if (bytes === null || bytes.byteLength > maximumBytes || sha256Hex(bytes) !== valueDigest) {
      clearBytes(bytes);
      failB33a(B33A_ERROR.CORRUPT, `${label} is absent, oversized or corrupt`);
    }
    return bytes;
  }

  async readCurrent() {
    const head = await this.#readHead();
    const stateBytes = await this.#readBlob(
      head.stateBlobSha256Hex, 'current canonical state', B33A_LIMITS.maxProviderBytes,
    );
    return Object.freeze({ head, stateBytes });
  }

  async duplicateInbound(ciphertextBlobSha256Hex) {
    assertDigest('ciphertext digest', ciphertextBlobSha256Hex);
    const head = await this.#readHead();
    const record = head.inboundRecords.find(
      (candidate) => candidate.ciphertextBlobSha256Hex === ciphertextBlobSha256Hex,
    );
    if (!record) return null;
    return Object.freeze({ status: B33A_OUTCOME.DUPLICATE,
      ciphertextBlobSha256Hex, eventIdHex: record.eventIdHex });
  }

  async commitOutbound(expectedHeadDigestHex, fields) {
    const current = await this.readCurrent();
    try {
      if (current.head.headDigestHex !== expectedHeadDigestHex) {
        failB33a(B33A_ERROR.CAS_CONFLICT, 'outbound operation started from a stale head');
      }
      if (current.head.outboundRecords.some((record) => record.requestId === fields.requestId)) {
        failB33a(B33A_ERROR.STATE_CONFLICT, 'outbound request id already exists');
      }
      if (current.head.sequence >= B33A_LIMITS.maxJournalRecords + 1) {
        failB33a(B33A_ERROR.RESOURCE_LIMIT, 'journal record envelope is full');
      }
      assertBytes('candidate state', fields.candidateState,
        { min: 1, max: B33A_LIMITS.maxProviderBytes });
      assertBytes('ciphertext', fields.ciphertext,
        { min: 1, max: B33A_LIMITS.maxCiphertextBytes });
      const record = parseOutbound({
        ordinal: current.head.outboundRecords.length + 1,
        requestId: fields.requestId,
        eventIdHex: fields.eventIdHex,
        stateBlobSha256Hex: sha256Hex(fields.candidateState),
        ciphertextBlobSha256Hex: sha256Hex(fields.ciphertext),
        senderIdentityHex: fields.senderIdentityHex,
        senderSignatureKeyHex: fields.senderSignatureKeyHex,
      }, current.head.outboundRecords.length + 1);
      const nextHead = buildHead({
        ...headPayload(current.head),
        sequence: current.head.sequence + 1,
        previousHeadDigestHex: current.head.headDigestHex,
        stateBlobSha256Hex: record.stateBlobSha256Hex,
        outboundRecords: [...current.head.outboundRecords, record],
      });
      await this.#cas(current.head, nextHead,
        [copyBytes(fields.candidateState), copyBytes(fields.ciphertext)]);
      const durable = await this.readCurrent();
      const ciphertext = await this.#readBlob(
        record.ciphertextBlobSha256Hex, 'durable outbound ciphertext',
        B33A_LIMITS.maxCiphertextBytes,
      );
      return Object.freeze({ status: B33A_OUTCOME.COMMITTED, head: durable.head,
        record, stateBytes: durable.stateBytes, ciphertext });
    } finally {
      clearBytes(current.stateBytes);
    }
  }

  async commitInbound(expectedHeadDigestHex, fields) {
    const current = await this.readCurrent();
    try {
      if (current.head.headDigestHex !== expectedHeadDigestHex) {
        failB33a(B33A_ERROR.CAS_CONFLICT, 'inbound operation started from a stale head');
      }
      if (current.head.inboundRecords.some((record) =>
        record.ciphertextBlobSha256Hex === sha256Hex(fields.ciphertext))) {
        failB33a(B33A_ERROR.STATE_CONFLICT, 'inbound ciphertext already exists');
      }
      if (current.head.sequence >= B33A_LIMITS.maxJournalRecords + 1) {
        failB33a(B33A_ERROR.RESOURCE_LIMIT, 'journal record envelope is full');
      }
      assertBytes('candidate state', fields.candidateState,
        { min: 1, max: B33A_LIMITS.maxProviderBytes });
      assertBytes('ciphertext', fields.ciphertext,
        { min: 1, max: B33A_LIMITS.maxCiphertextBytes });
      assertBytes('plaintext', fields.plaintext,
        { min: 1, max: B33A_LIMITS.maxEventBytes });
      const record = parseInbound({
        ordinal: current.head.inboundRecords.length + 1,
        eventIdHex: fields.eventIdHex,
        stateBlobSha256Hex: sha256Hex(fields.candidateState),
        ciphertextBlobSha256Hex: sha256Hex(fields.ciphertext),
        plaintextBlobSha256Hex: sha256Hex(fields.plaintext),
        senderLeafIndex: fields.senderLeafIndex,
        senderIdentityHex: fields.senderIdentityHex,
        senderSignatureKeyHex: fields.senderSignatureKeyHex,
        verifiedLeafDigestHex: fields.verifiedLeafDigestHex,
      }, current.head.inboundRecords.length + 1);
      const nextHead = buildHead({
        ...headPayload(current.head),
        sequence: current.head.sequence + 1,
        previousHeadDigestHex: current.head.headDigestHex,
        stateBlobSha256Hex: record.stateBlobSha256Hex,
        inboundRecords: [...current.head.inboundRecords, record],
      });
      await this.#cas(current.head, nextHead, [
        copyBytes(fields.candidateState), copyBytes(fields.ciphertext), copyBytes(fields.plaintext),
      ]);
      const durable = await this.readCurrent();
      const [ciphertext, plaintext] = await Promise.all([
        this.#readBlob(record.ciphertextBlobSha256Hex, 'durable inbound ciphertext',
          B33A_LIMITS.maxCiphertextBytes),
        this.#readBlob(record.plaintextBlobSha256Hex, 'durable inbound plaintext',
          B33A_LIMITS.maxEventBytes),
      ]);
      return Object.freeze({ status: B33A_OUTCOME.COMMITTED, head: durable.head,
        record, stateBytes: durable.stateBytes, ciphertext, plaintext });
    } finally {
      clearBytes(current.stateBytes);
    }
  }
}

function assertPrivateChild(directory, approvedRoot) {
  mkdirSync(approvedRoot, { recursive: true, mode: 0o700 });
  chmodSync(approvedRoot, 0o700);
  const root = realpathSync(approvedRoot);
  const target = resolve(directory);
  const pathFromRoot = relative(root, target);
  if (pathFromRoot === '' || pathFromRoot === '..' || pathFromRoot.startsWith(`..${sep}`)) {
    failB33a(B33A_ERROR.INVALID, 'journal directory is not a strict child of the private root');
  }
  mkdirSync(target, { recursive: true, mode: 0o700 });
  chmodSync(target, 0o700);
  const resolvedFromRoot = relative(root, realpathSync(target));
  if (resolvedFromRoot === '' || resolvedFromRoot === '..'
    || resolvedFromRoot.startsWith(`..${sep}`)) {
    failB33a(B33A_ERROR.INVALID, 'journal directory is not a resolved strict child');
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

function readBoundedFile(path, maximumBytes, label) {
  let descriptor;
  try { descriptor = openSync(path, 'r'); } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
  let scratch;
  try {
    scratch = Buffer.alloc(maximumBytes + 1);
    let offset = 0;
    let reachedEof = false;
    while (offset < scratch.length) {
      let count;
      try { count = readSync(descriptor, scratch, offset, scratch.length - offset, null); } catch (error) {
        if (error?.code === 'EINTR') continue;
        throw error;
      }
      if (count === 0) { reachedEof = true; break; }
      offset += count;
    }
    if (!reachedEof && offset > maximumBytes) {
      failB33a(B33A_ERROR.CORRUPT, `${label} exceeds its resource envelope`);
    }
    return Uint8Array.from(scratch.subarray(0, offset));
  } finally {
    scratch?.fill(0);
    closeSync(descriptor);
  }
}

function boundedFileEquals(path, expectedBytes, maximumBytes, label) {
  const actual = readBoundedFile(path, maximumBytes, label);
  if (actual === null) return null;
  try { return Buffer.from(actual).equals(Buffer.from(expectedBytes)); } finally { actual.fill(0); }
}

export class FileB33aStore {
  constructor(directory, approvedRoot = B33A_PRIVATE_ROOT) {
    this.directory = assertPrivateChild(directory, approvedRoot);
    this.blobDirectory = resolve(this.directory, 'blobs');
    mkdirSync(this.blobDirectory, { recursive: true, mode: 0o700 });
    chmodSync(this.blobDirectory, 0o700);
    this.headPath = resolve(this.directory, 'head.json');
    this.lockDirectory = resolve(this.directory, 'cas.lock');
  }

  async readHead() {
    const raw = readBoundedFile(
      this.headPath, B33A_LIMITS.maxJournalHeadBytes, 'durable head',
    );
    if (raw === null) return null;
    try {
      let parsed;
      try { parsed = JSON.parse(Buffer.from(raw).toString('utf8')); } catch (error) {
        failB33a(B33A_ERROR.CORRUPT, 'durable head is not strict JSON', {}, error);
      }
      if (!Buffer.from(raw).equals(Buffer.from(canonicalJsonBytes(parsed)))) {
        failB33a(B33A_ERROR.CORRUPT, 'durable head is not canonical JSON');
      }
      return parsed;
    } finally {
      raw.fill(0);
    }
  }

  async readBlob(valueDigest) {
    assertDigest('blob digest', valueDigest);
    return readBoundedFile(
      resolve(this.blobDirectory, valueDigest), B33A_LIMITS.maxProviderBytes, 'durable blob',
    );
  }

  #acquireLock() {
    const owner = `${process.pid}:${randomUUID()}\n`;
    let created = false;
    try {
      mkdirSync(this.lockDirectory, { mode: 0o700 });
      created = true;
      durableWrite(resolve(this.lockDirectory, 'owner'), owner);
      return owner;
    } catch (error) {
      if (created) {
        const ownerPath = resolve(this.lockDirectory, 'owner');
        if (existsSync(ownerPath)) unlinkSync(ownerPath);
        if (existsSync(this.lockDirectory)) rmdirSync(this.lockDirectory);
      }
      if (error?.code === 'EEXIST') {
        failB33a(B33A_ERROR.CAS_CONFLICT, 'CAS lock exists; stale-lock recovery is explicit');
      }
      throw error;
    }
  }

  #releaseLock(expectedOwner) {
    const ownerPath = resolve(this.lockDirectory, 'owner');
    const ownerBytes = readBoundedFile(ownerPath, 128, 'CAS lock owner');
    if (ownerBytes === null) {
      failB33a(B33A_ERROR.CAS_CONFLICT, 'CAS lock disappeared before release');
    }
    let owner;
    try { owner = Buffer.from(ownerBytes).toString('utf8'); } finally { ownerBytes.fill(0); }
    if (owner !== expectedOwner) {
      failB33a(B33A_ERROR.CAS_CONFLICT, 'CAS lock ownership changed before release');
    }
    unlinkSync(ownerPath);
    rmdirSync(this.lockDirectory);
  }

  #writeImmutableBlob(bytes) {
    const valueDigest = sha256Hex(bytes);
    const finalPath = resolve(this.blobDirectory, valueDigest);
    const existing = boundedFileEquals(
      finalPath, bytes, B33A_LIMITS.maxProviderBytes, 'immutable blob',
    );
    if (existing !== null) {
      if (!existing) failB33a(B33A_ERROR.CORRUPT, 'immutable blob content-address collision');
      return;
    }
    const temporary = resolve(
      this.blobDirectory, `.${valueDigest}.${process.pid}.${randomUUID()}.tmp`,
    );
    durableWrite(temporary, bytes);
    try {
      linkSync(temporary, finalPath);
      chmodSync(finalPath, 0o600);
      syncDirectory(this.blobDirectory);
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      if (boundedFileEquals(
        finalPath, bytes, B33A_LIMITS.maxProviderBytes, 'immutable blob',
      ) !== true) {
        failB33a(B33A_ERROR.CORRUPT, 'immutable blob race disagreed on bytes');
      }
    } finally {
      if (existsSync(temporary)) unlinkSync(temporary);
    }
  }

  async compareAndSwap(expectedDigest, nextHead, blobWrites) {
    const owner = this.#acquireLock();
    try {
      const current = await this.readHead();
      if ((current?.headDigestHex ?? null) !== expectedDigest) return false;
      for (const bytes of blobWrites) this.#writeImmutableBlob(bytes);
      const temporary = resolve(
        this.directory, `.head.${process.pid}.${randomUUID()}.tmp`,
      );
      durableWrite(temporary, canonicalJsonBytes(nextHead));
      renameSync(temporary, this.headPath);
      chmodSync(this.headPath, 0o600);
      syncDirectory(this.directory);
      return true;
    } finally {
      this.#releaseLock(owner);
    }
  }
}

export function openB33aFileJournal(directory, approvedRoot = B33A_PRIVATE_ROOT) {
  return new B33aJournal(new FileB33aStore(directory, approvedRoot));
}
