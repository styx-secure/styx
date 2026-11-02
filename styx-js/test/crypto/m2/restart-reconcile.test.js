// restart-reconcile.test.js — I-RESTART-API (contract Issue #532): the M2 restart re-exposure of a durable
// reconciliation hold (C-API CAPI-S030, CAPI-S031), the C-API §5 reference form and operation-identity rule,
// and the hermetic C-API §10 TABLES transcription.
//
// Every test runs through the public adapter surface composed with the merged I-TXN driver
// (`runMutation`, `reconcileIndeterminate`, `classifyAuthority`) and the merged I-RESTART loader
// (`loadBoundHold`) over an in-memory RS port. The in-memory port, the canonical store fixtures and the
// held-output digest staging are those of `test/storage/m2/session-transaction.test.js` (I-RESTART T-suite);
// a relaunch is a fresh adapter snapshot at EMPTY over the same port with the SS memory hold dropped.
//
// Ratified inputs: C-API docs/architecture/m2/adapter-contract.md sha256 0afd0f21…c3871 (#319 6114147886);
// C-MUT f37915f1…3059c, C-FMT 526fc4c3…3f3e2, C-REST bc3026e7…d5dc0 (#514 6433983465).

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, test } from '@jest/globals';
import { M2_KIND, decodePlaintext, encodePlaintext, encodeRecordKey } from '../../../src/storage/m2/session-codec.js';
import {
  ciphertextDigest, computeKeyedRoot, encodeManifest, encodeManifestKey, manifestEntry, manifestKeyDigest,
} from '../../../src/storage/m2/session-root.js';
import {
  M2_OUTCOME, M2_TXN, buildMutationEnvelope, classifyAuthority, heldOutputDigest, loadBoundHold, mutationRow,
  reconcileIndeterminate, runMutation,
} from '../../../src/storage/m2/session-transaction.js';
import { FRESH_WORKER_FIXTURES } from '../../../src/storage/m2/session-restore.js';
import { M2_ADAPTER, M2AdapterError, invokeAdapterTransition } from '../../../src/crypto/mls/m2/adapter.js';
import { createAdapterSnapshot } from '../../../src/crypto/mls/m2/state-machine.js';

// ---------------------------------------------------------------------------------------------------
// Hermetic C-API §10 fixture (contract #532, Allowed paths): exactly the ratified record bytes.
// ---------------------------------------------------------------------------------------------------
const FIXTURE_URL = new URL('./fixtures/c-api-0afd0f21-section10.json', import.meta.url);
const FIXTURE_SHA256 = 'cee4a7a39415a5988e3f8932a220006604df3b2d1912477993da83c6b09e552d';
const STATE_MACHINE_URL = new URL('../../../src/crypto/mls/m2/state-machine.js', import.meta.url);
const C_API = JSON.parse(readFileSync(FIXTURE_URL, 'utf8'));

// ---------------------------------------------------------------------------------------------------
// The in-memory RS port and the canonical store fixtures (I-RESTART T-suite).
// ---------------------------------------------------------------------------------------------------
const K6 = M2_KIND.BINDING_PROFILE;
const K8 = M2_KIND.COMMIT_RESULT;
const K9 = M2_KIND.OUTPUT_ESCROW;
const K13 = M2_KIND.MUTATION_HOLD;
const K14 = M2_KIND.COMPONENT_SET;
const K17 = M2_KIND.GENERATION_SELECTOR;
const LOCAL = new Uint8Array(32).fill(0x21);
const ROOT_KEY = new Uint8Array(32).fill(0x11);
const SESSION_ID = new Uint8Array(32).fill(0x41);
const OLD_GENERATION = 1n;
const NEW_GENERATION = 2n;
const DATA_KINDS = Array.from({ length: 15 }, (_, i) => i + 1);
const OPERATIONS = ['CREATE', 'RESTORE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION',
  'SELF_UPDATE', 'APPLY_PEER_UPDATE', 'RECONCILE_INDETERMINATE'];
const OUTPUT_KINDS = ['NONE', 'EMBEDDED_TREE_WELCOME', 'PROTECTED_APPLICATION_BYTES', 'APPLICATION_BYTES',
  'PROTECTED_COMMIT_BYTES', 'SELECTED_CANDIDATE_REF'];
const SUCCESS_CODES = ['CREATED', 'RESTORED', 'JOINED', 'APPLICATION_PROTECTED', 'APPLICATION_OPENED',
  'SELF_UPDATED', 'PEER_UPDATE_APPLIED', 'CANDIDATE_SELECTED', 'RECONCILED_COMMITTED', 'DUPLICATE_IGNORED'];
const BINDING = Uint8Array.from({ length: 389 }, (_, i) => (0x31 + i * 7) & 0xff);
const TE = new TextEncoder();

const bytesOf = (n, seed) => Uint8Array.from({ length: n }, (_, i) => (seed + i * 7) & 0xff);
const hex = (u8) => Buffer.from(u8).toString('hex');
const b64 = (u8) => Buffer.from(u8).toString('base64url');
const sha256 = (...parts) => new Uint8Array(parts.reduce((h, p) => h.update(p), createHash('sha256')).digest());
const be32 = (n) => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const bindingDigestOf = (binding) => sha256(TE.encode('STYX-M2-BINDING-DIGEST-V1'), be32(binding.length), binding);
/** The C-API §5 reference form, computed here independently of the module. */
const refOf = (reference) => `I-SM-HOLD:${b64(reference)}`;

function recordKeyFor(generation, kind) {
  const pre = generation === OLD_GENERATION;
  return encodeRecordKey({
    scope: pre ? 1 : 2, localContextId: LOCAL, secureSessionIdentity: pre ? null : SESSION_ID,
    writeGeneration: generation, recordKind: kind,
  });
}

function generationFixture(generation) {
  const pre = generation === OLD_GENERATION;
  const records = DATA_KINDS.map((kind) => ({
    recordKey: recordKeyFor(generation, kind), recordKind: kind,
    plaintext: bytesOf(9, kind), ciphertext: bytesOf(17, kind + 3), tag: bytesOf(16, kind + 11),
  }));
  const manifestBytes = encodeManifest(records.map((r) => manifestEntry({
    recordKey: r.recordKey, recordKind: r.recordKind,
    ciphertextDigest: ciphertextDigest({ recordKey: r.recordKey, recordKind: r.recordKind, ciphertext: r.ciphertext, tag: r.tag }),
  })));
  const manifestKey = encodeManifestKey({
    localContextId: LOCAL, scope: pre ? 1 : 2, secureSessionIdentity: pre ? null : SESSION_ID, writeGeneration: generation,
  });
  return {
    generation, records, manifestKey, manifestBytes,
    manifestCipherDigest: bytesOf(32, Number(generation) + 0x90),
    keyedRoot: computeKeyedRoot({ manifestRootKey: ROOT_KEY, manifestKey, generation, manifestBytes }),
    sessionBindingDigest: pre ? null : bindingDigestOf(BINDING),
  };
}

const OLD = generationFixture(OLD_GENERATION);
const NEW = generationFixture(NEW_GENERATION);

function sameTupleSelector(facts, state) {
  const digest = manifestKeyDigest(facts.manifestKey);
  return {
    presence: 1, generation: facts.generation, manifestKeyDigest: digest, manifestCipherDigest: facts.manifestCipherDigest,
    keyedRoot: facts.keyedRoot, state, candidateGeneration: facts.generation, candidateManifestKey: facts.manifestKey,
    candidateManifestKeyDigest: digest, candidateManifestCipherDigest: facts.manifestCipherDigest, candidateKeyedRoot: facts.keyedRoot,
  };
}
const selectorOf = (facts, state) => encodePlaintext(K17, sameTupleSelector(facts, state));
const HOLD_SELECTOR = encodePlaintext(K17, {
  presence: 1, generation: OLD.generation, manifestKeyDigest: manifestKeyDigest(OLD.manifestKey),
  manifestCipherDigest: OLD.manifestCipherDigest, keyedRoot: OLD.keyedRoot, state: 3,
  candidateGeneration: NEW.generation, candidateManifestKey: NEW.manifestKey,
  candidateManifestKeyDigest: manifestKeyDigest(NEW.manifestKey), candidateManifestCipherDigest: NEW.manifestCipherDigest,
  candidateKeyedRoot: NEW.keyedRoot,
});

let ENVELOPE_WRITES = 0;
function sealSelector(plaintext) {
  ENVELOPE_WRITES += 1;
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setUint32(8, ENVELOPE_WRITES);
  const out = new Uint8Array(12 + plaintext.length + 16);
  out.set(nonce, 0);
  out.set(plaintext, 12);
  out.fill(0xa5, 12 + plaintext.length);
  return out;
}

/** The deterministic in-memory RS port of the I-TXN suites, with an optional readback fault. */
function makeStore() {
  const store = {
    generations: new Map(), selector: null, selectorEnvelope: null, sealedFor: null, memoryHold: null,
    applied: [], readFault: null,
  };
  const pending = new Map();
  const currentEnvelope = () => {
    if (store.selector !== store.sealedFor) {
      store.sealedFor = store.selector;
      store.selectorEnvelope = store.selector === null ? null : sealSelector(store.selector);
    }
    return store.selectorEnvelope;
  };
  store.seed = (generations, selector) => {
    store.generations.clear();
    pending.clear();
    for (const g of generations) {
      store.generations.set(g.generation, { ...g, mutationHold: { presence: 0 }, escrow: null, resultEvidence: null });
    }
    store.selector = Uint8Array.prototype.slice.call(selector);
    return store;
  };
  store.apply = async (step) => {
    store.applied.push({ boundary: step.boundary, kind: step.kind });
    const { payload } = step;
    if (step.kind === 'STAGE_DATA') {
      if (!pending.has(payload.generation)) pending.set(payload.generation, new Map());
      pending.get(payload.generation).set(payload.recordKind, {
        recordKey: payload.recordKey, recordKind: payload.recordKind, plaintext: payload.plaintext,
        ciphertext: payload.ciphertext, tag: payload.tag,
      });
    } else if (step.kind === 'STAGE_MANIFEST') {
      const staged = pending.get(payload.generation);
      store.generations.set(payload.generation, {
        generation: payload.generation, records: staged === undefined ? [] : Array.from(staged.values()),
        manifestKey: payload.manifestKey, manifestBytes: payload.manifestBytes, manifestCipherDigest: payload.manifestCipherDigest,
        keyedRoot: payload.keyedRoot, sessionBindingDigest: payload.sessionBindingDigest,
        mutationHold: { presence: 0 }, escrow: null, resultEvidence: null,
      });
    } else if (step.kind === 'STAGE_EVIDENCE') {
      const g = store.generations.get(payload.generation);
      if (g !== undefined) g.resultEvidence = payload.evidence;
    } else if (step.kind === 'STAGE_ESCROW') {
      const g = store.generations.get(payload.generation);
      if (g !== undefined) g.escrow = payload.escrow;
    } else if (step.kind === 'WRITE_HOLD') {
      const g = store.generations.get(payload.generation);
      if (g !== undefined) g.mutationHold = { ...payload.hold };
      store.memoryHold = payload.hold === null || payload.holdRecordKey === undefined || payload.holdRecordKey === null
        ? payload.hold : { ...payload.hold, recordKey: payload.holdRecordKey };
    } else if (step.kind === 'CLEAR_CANDIDATE') {
      store.generations.delete(payload.generation);
      pending.delete(payload.generation);
      store.memoryHold = null;
    } else if (step.kind === 'REPLACE_SELECTOR') {
      const expected = payload.expectedSelectorBytes;
      const envelope = currentEnvelope();
      const same = expected === null ? envelope === null
        : envelope !== null && expected.length === envelope.length && expected.every((b, i) => b === envelope[i]);
      if (!same) throw Object.assign(new Error('selector precondition failed'), { code: 'SELECTOR_PRECONDITION_FAILED' });
      store.selector = Uint8Array.prototype.slice.call(payload.selectorBytes);
      currentEnvelope();
      if (payload.resolveHoldGeneration !== null && payload.resolveHoldGeneration !== undefined) {
        const resolved = store.generations.get(payload.resolveHoldGeneration);
        if (resolved !== undefined) resolved.mutationHold = { presence: 0 };
      }
    } else if (step.kind === 'RELEASE_ESCROW') {
      store.memoryHold = null;
    }
    return undefined;
  };
  const readFault = () => {
    if (store.readFault !== null) throw store.readFault;
  };
  store.readSelector = async () => {
    readFault();
    const envelope = currentEnvelope();
    return store.selector === null ? null : {
      plaintext: Uint8Array.prototype.slice.call(store.selector), envelope: Uint8Array.prototype.slice.call(envelope),
    };
  };
  store.readGeneration = async (generation) => {
    readFault();
    const g = store.generations.get(generation);
    if (g === undefined) return null;
    return {
      generation: g.generation, records: g.records, manifestKey: g.manifestKey, manifestBytes: g.manifestBytes,
      manifestCipherDigest: g.manifestCipherDigest, keyedRoot: g.keyedRoot, sessionBindingDigest: g.sessionBindingDigest,
      mutationHold: g.mutationHold, escrow: g.escrow, resultEvidence: g.resultEvidence,
    };
  };
  store.readMemoryHold = async () => store.memoryHold;
  store.readGenerationNumbers = async () => [...new Set([...store.generations.keys(), ...pending.keys()])];
  return store;
}

/** Everything durable in the port, byte for byte, plus the SS memory hold. */
function fingerprint(store) {
  const value = (v) => (v instanceof Uint8Array ? hex(v) : (typeof v === 'bigint' ? v.toString() : v));
  return JSON.stringify({
    selector: store.selector === null ? null : hex(store.selector),
    generations: [...store.generations.entries()].map(([g, v]) => [
      g.toString(), hex(v.manifestBytes), hex(v.keyedRoot), v.records.map((r) => hex(r.plaintext)).join(''),
      JSON.stringify(v.mutationHold, (_, x) => value(x)), v.escrow === null ? null : JSON.stringify(v.escrow, (_, x) => value(x)),
    ]),
    memoryHold: store.memoryHold === null ? null : 'present',
  });
}

// ---------------------------------------------------------------------------------------------------
// The SS/RS producer: one mutation envelope, its canonical candidate and its I-TXN run.
// ---------------------------------------------------------------------------------------------------

/** The 32-byte SS/RS operation identity and reconciliation reference of one mutation. */
const IDENTITY_BYTES = bytesOf(32, 0x01);
const REFERENCE_BYTES = bytesOf(32, 0x0c);

/**
 * The closed row-bound `MutationEnvelope`. Held-output digest rule (C-FMT outputEscrow.heldOutputDigestRule,
 * #514): the producer derives `heldOutput.digest` from the bytes it stages, with the merged `heldOutputDigest`.
 */
function envelopeFor(scenario, output, { identity = IDENTITY_BYTES, reference = REFERENCE_BYTES } = {}) {
  const row = mutationRow(scenario);
  return buildMutationEnvelope({
    operationIdentity: { value: identity, assignedBy: 'SS_RS', fresh: true, reusable: false, apRequestIdEqual: false },
    operation: row.operation,
    scenario,
    originalApiState: row.stateBefore,
    originalAuthority: { digest: bytesOf(32, 0x02), reference: bytesOf(32, 0x03) },
    bindingProfileIdentity: { bindingRef: bytesOf(32, 0x04), profile: bytesOf(32, 0x05) },
    candidate: { digest: bytesOf(32, 0x06), reference: bytesOf(32, 0x07) },
    componentSet: { digest: bytesOf(32, 0x08), reference: bytesOf(32, 0x09), entries: row.components.map((c) => ({ ...c })) },
    heldOutput: row.outputKind === 'NONE' ? { kind: 'NONE', digest: null, reference: null }
      : { kind: row.outputKind, digest: heldOutputDigest({ kind: row.outputKind, output }), reference: bytesOf(32, 0x0b) },
    expectedSuccess: { code: row.successCode, stateAfter: row.stateAfterCommitted },
    reconciliationIdentity: { reference, owner: 'SS_RS' },
  });
}

function evidenceFor(envelope, outcome, overrides = {}) {
  return {
    operationIdentity: envelope.operationIdentity.value,
    originalAuthorityDigest: envelope.originalAuthority.digest,
    originalAuthorityReference: envelope.originalAuthority.reference,
    candidateDigest: envelope.candidate.digest,
    candidateReference: envelope.candidate.reference,
    mutationSetDigest: envelope.componentSet.digest,
    mutationSetReference: envelope.componentSet.reference,
    expectedOriginalState: envelope.originalApiState === 'EMPTY' ? 1 : 2,
    bindingRef: envelope.bindingProfileIdentity.bindingRef,
    profile: envelope.bindingProfileIdentity.profile,
    outcome,
    authenticatedByRS: true,
    terminal: true,
    ...overrides,
  };
}

function holdRecordOf(envelope) {
  const row = mutationRow(envelope.scenario);
  return {
    presence: 1,
    operationIdentity: envelope.operationIdentity.value,
    operation: OPERATIONS.indexOf(row.operation) + 1,
    scenario: M2_TXN.SCENARIOS.indexOf(envelope.scenario) + 1,
    originalApiState: row.stateBefore === 'EMPTY' ? 1 : 2,
    originalAuthorityDigest: envelope.originalAuthority.digest,
    originalAuthorityReference: envelope.originalAuthority.reference,
    bindingRef: envelope.bindingProfileIdentity.bindingRef,
    profileDigest: envelope.bindingProfileIdentity.profile,
    candidateDigest: envelope.candidate.digest,
    candidateReference: envelope.candidate.reference,
    componentSetDigest: envelope.componentSet.digest,
    componentSetReference: envelope.componentSet.reference,
    heldOutputKind: OUTPUT_KINDS.indexOf(row.outputKind) + 1,
    heldOutputDigest: envelope.heldOutput.digest,
    heldOutputReference: envelope.heldOutput.reference,
    expectedSuccessCode: SUCCESS_CODES.indexOf(row.successCode) + 1,
    expectedStateAfter: row.stateAfterCommitted === 'EMPTY' ? 1 : 2,
    reconciliationReference: envelope.reconciliationIdentity.reference,
    resultStatus: M2_OUTCOME.INDETERMINATE,
    parentGeneration: OLD_GENERATION,
    parentKeyedRoot: OLD.keyedRoot,
  };
}

/** The candidate generation's canonical kind-6/8/9/13/14 plaintexts (filler for the other kinds). */
function canonicalRecords(envelope, outcome, output) {
  const row = mutationRow(envelope.scenario);
  const evidence = evidenceFor(envelope, outcome);
  const plain = {
    [K6]: encodePlaintext(K6, { presence: 1, canonicalBinding: BINDING, profileDigest: envelope.bindingProfileIdentity.profile }),
    [K8]: encodePlaintext(K8, {
      presence: 1, operationIdentity: evidence.operationIdentity, originalAuthorityDigest: evidence.originalAuthorityDigest,
      originalAuthorityReference: evidence.originalAuthorityReference, candidateDigest: evidence.candidateDigest,
      candidateReference: evidence.candidateReference, mutationSetDigest: evidence.mutationSetDigest,
      mutationSetReference: evidence.mutationSetReference, expectedOriginalState: evidence.expectedOriginalState,
      bindingRef: evidence.bindingRef, profileDigest: evidence.profile, outcome, authenticatedByRS: true, terminal: evidence.terminal,
    }),
    [K14]: encodePlaintext(K14, {
      presence: 1, mutationSetDigest: evidence.mutationSetDigest, mutationSetReference: evidence.mutationSetReference,
      entries: bytesOf(64, 0x61),
    }),
  };
  if (row.outputKind !== 'NONE') {
    plain[K13] = encodePlaintext(K13, holdRecordOf(envelope));
    plain[K9] = encodePlaintext(K9, {
      presence: 1, operationIdentity: evidence.operationIdentity, candidateDigest: evidence.candidateDigest,
      candidateReference: evidence.candidateReference, mutationSetDigest: evidence.mutationSetDigest,
      mutationSetReference: evidence.mutationSetReference, outputKind: OUTPUT_KINDS.indexOf(row.outputKind) + 1,
      output, resultDigest: bytesOf(32, 0x77),
    });
  }
  return NEW.records.map((r) => ({ ...r, plaintext: plain[r.recordKind] ?? r.plaintext }));
}

/** The selected generation of a bound hold: the canonical tombstone of its own kind-13 record. */
const selectedGeneration = () => ({
  ...OLD,
  records: OLD.records.map((r) => (r.recordKind === K13 ? { ...r, plaintext: encodePlaintext(K13, { presence: 0 }) } : r)),
});

/**
 * One I-TXN run of `scenario` with RS outcome `outcome` over `store` (a fresh store over the selected
 * generation by default). Returns the store, the envelope and the driver result.
 */
async function produce(scenario, outcome, output, { store = null, identity, reference } = {}) {
  const row = mutationRow(scenario);
  const envelope = envelopeFor(scenario, output, { identity, reference });
  const port = store ?? makeStore().seed([selectedGeneration()], selectorOf(OLD, 1));
  const candidate = {
    generation: NEW_GENERATION,
    records: canonicalRecords(envelope, outcome, output),
    manifestKey: NEW.manifestKey,
    manifestBytes: NEW.manifestBytes,
    manifestCipherDigest: NEW.manifestCipherDigest,
    keyedRoot: NEW.keyedRoot,
    sessionBindingDigest: NEW.sessionBindingDigest,
    escrow: row.outputKind === 'NONE' ? null : {
      kind: row.outputKind, digest: envelope.heldOutput.digest, reference: envelope.heldOutput.reference,
      output: Uint8Array.prototype.slice.call(output),
    },
    resultEvidence: evidenceFor(envelope, outcome),
    selectorBytes: selectorOf(NEW, 2),
    holdSelectorBytes: HOLD_SELECTOR,
    parentSelectorBytes: selectorOf(OLD, 1),
    parentGeneration: OLD_GENERATION,
    parentKeyedRoot: OLD.keyedRoot,
  };
  const result = await runMutation({ storage: port, manifestRootKey: ROOT_KEY, envelope, candidate, outcome });
  return { store: port, envelope, result };
}

const loadOf = (store) => loadBoundHold({ storage: store, manifestRootKey: ROOT_KEY });
const codeOf = (promise) => promise.then(() => 'OK', (e) => e.code ?? e.message);

// ---------------------------------------------------------------------------------------------------
// The adapter side: requests, live observations and the restore facts the SS/RS produce.
// ---------------------------------------------------------------------------------------------------
const SLOT = new Uint8Array(32).fill(0x5c);
const LOW = new Uint8Array(32).fill(0x02);
const HIGH = new Uint8Array(32).fill(0xfe);
const STAGED = bytesOf(24, 0xa3);

/** The live operation of each RS_TRI_STATE row: its C-API request input, origin and released member. */
const LIVE = {
  'CAPI-S001': { operation: 'CREATE', origin: 'EMPTY', input: { peerFramedKeyPackage: bytesOf(16, 0x31) }, member: 'embeddedTreeWelcome' },
  'CAPI-S006': { operation: 'JOIN_WELCOME', origin: 'EMPTY', input: { embeddedTreeWelcome: bytesOf(16, 0x32) }, member: null },
  'CAPI-S009': { operation: 'PROTECT_APPLICATION', origin: 'ACTIVE', input: { applicationBytes: bytesOf(16, 0x33) }, member: 'protectedApplicationBytes' },
  'CAPI-S010': { operation: 'OPEN_APPLICATION', origin: 'ACTIVE', input: { protectedApplicationMessage: bytesOf(16, 0x34) }, member: 'applicationBytes' },
  'CAPI-S014': { operation: 'SELF_UPDATE', origin: 'ACTIVE', input: {}, member: 'protectedCommitBytes' },
  'CAPI-S016': { operation: 'APPLY_PEER_UPDATE', origin: 'ACTIVE', input: { protectedCommitBytes: bytesOf(16, 0x35) }, member: null },
  'CAPI-S017': { operation: 'APPLY_PEER_UPDATE', origin: 'ACTIVE', input: { protectedCommitBytes: bytesOf(16, 0x36) }, member: 'selectedCandidateRef' },
};
const TRI_STATE_ROWS = Object.keys(LIVE);
/** The rows that can hold durably under the merged I-TXN (R3: CAPI-S006 and CAPI-S016 cannot). */
const HOLD_ROWS = ['CAPI-S001', 'CAPI-S009', 'CAPI-S010', 'CAPI-S014', 'CAPI-S017'];
const STAGED_ROWS = ['CAPI-S001', 'CAPI-S009', 'CAPI-S010', 'CAPI-S014'];

const request = (operation, input, overrides = {}) => ({
  api: M2_ADAPTER.API, operation, requestId: `req-${operation}`, profile: { ...M2_ADAPTER.PROFILE },
  bindingRef: SLOT.slice(), input, ...overrides,
});

/** The two-candidate classification whose winner (the lower committer) carries `winnerRef`. */
const eligiblePair = (winnerRef, winner = 'current', loserRef = 'loser:ref') => ({
  kind: 'ELIGIBLE_TWO_CANDIDATE',
  current: { committerId: (winner === 'current' ? LOW : HIGH).slice(), ref: winner === 'current' ? winnerRef : loserRef },
  incoming: { committerId: (winner === 'current' ? HIGH : LOW).slice(), ref: winner === 'current' ? loserRef : winnerRef },
});

/**
 * The live observation of `scenario` for RS outcome `commitOutcome`: the canonical 43-character identity of
 * the 32 SS/RS bytes, the SS/RS 32-byte reconciliation reference, and the staged handover.
 */
function liveObservation(scenario, commitOutcome, {
  identity = b64(IDENTITY_BYTES), reference = REFERENCE_BYTES, staged = STAGED, candidate = eligiblePair('cand:winner'),
} = {}) {
  const { operation, member } = LIVE[scenario];
  const stagedOutput = commitOutcome === 'COMMITTED' && member !== null && member !== 'selectedCandidateRef'
    ? { [member]: staged } : null;
  const tri = { commitOutcome, operationIdentity: identity, reconciliationReference: reference };
  switch (operation) {
    case 'CREATE': return { onboarding: 'SUPPORTED', ...tri, stagedOutput };
    case 'JOIN_WELCOME': return { keyPackage: 'MATCHED', ...tri };
    case 'PROTECT_APPLICATION': return { ...tri, stagedOutput };
    case 'OPEN_APPLICATION':
      return { currentEpoch: 9, framingEpoch: 8, authentication: 'AUTHENTICATED', replayIdentity: 'UNSEEN', ...tri, stagedOutput };
    case 'SELF_UPDATE': return { updateForm: 'SUPPORTED', ...tri, stagedOutput, slotContext: SLOT.slice() };
    default:
      return {
        authentication: 'AUTHENTICATED', candidate: scenario === 'CAPI-S016' ? { kind: 'CURRENT_PARENT' } : candidate,
        ...tri, slotContext: SLOT.slice(),
      };
  }
}

const live = (scenario, commitOutcome, options = {}) => invokeAdapterTransition({
  request: request(LIVE[scenario].operation, LIVE[scenario].input),
  snapshot: createAdapterSnapshot(LIVE[scenario].origin),
  observation: liveObservation(scenario, commitOutcome, options),
});

/** The C-REST observation of a stored selector state, as the fresh-worker fixture of that state carries it. */
const VECTOR_STATE = { 'FMT-KAT-EMPTY': 'EMPTY', 'FMT-KAT-ACTIVE': 'ACTIVE', 'FMT-KAT-HOLD': 'RECONCILIATION_REQUIRED' };
function restoreObservationOf(store, faults = []) {
  const state = store.selector === null ? null : decodePlaintext(K17, store.selector).state;
  const id = { 1: 'POS-EMPTY', 2: 'POS-ACTIVE', 3: 'POS-HOLD' }[state] ?? 'POS-NO-M2';
  const row = FRESH_WORKER_FIXTURES.positive.find((r) => r.id === id);
  return {
    faults: [...faults], inventory: row.inventory, legacy: row.legacy, vector: row.vector,
    selectorState: row.vector === null ? 'EMPTY' : VECTOR_STATE[row.vector],
  };
}

/**
 * The SS/RS restore facts of one relaunch: the C-REST observation and `restoreHold`, the I-RESTART loader's
 * `{ hold, facts }` for a RECONCILIATION_REQUIRED selector, `null` when the loader refuses the hold as an
 * authenticated contradiction, and `'READBACK_UNAVAILABLE'` when the readback could not be performed.
 */
async function restoreFacts(store, faults = []) {
  const restoreObservation = restoreObservationOf(store, faults);
  let restoreHold = null;
  if (restoreObservation.selectorState === 'RECONCILIATION_REQUIRED') {
    try {
      restoreHold = await loadOf(store);
    } catch (error) {
      if (error.code === 'READBACK_UNAVAILABLE') restoreHold = 'READBACK_UNAVAILABLE';
      else if (error.code === 'BOUND_HOLD_INVALID') restoreHold = null;
      else throw error;
    }
  }
  return { restoreObservation, restoreHold };
}

/** A relaunch: the SS memory hold is gone and a fresh adapter at EMPTY restores over the same port. */
async function relaunch(store, { faults = [], req = request('RESTORE', {}) } = {}) {
  store.memoryHold = null;
  return invokeAdapterTransition({ request: req, snapshot: createAdapterSnapshot('EMPTY'), observation: await restoreFacts(store, faults) });
}

const code = (result) => (result.kind === 'REJECTED' ? result.error.code : (result.successCode ?? result.kind));
const COMMON = ['api', 'requestId', 'operation', 'kind', 'stateBefore', 'stateAfter'];
const hasBytes = (value) => value instanceof Uint8Array
  || (value !== null && typeof value === 'object' && Object.values(value).some(hasBytes));

/** The escrow the SS hands to a reconciliation: the stored candidate escrow, as the C-API output member. */
async function heldOutputOf(store, scenario) {
  const member = LIVE[scenario].member;
  if (member === null) return null;
  const g = await store.readGeneration(NEW_GENERATION);
  const output = g === null || g.escrow === null ? null : g.escrow.output;
  if (output === null) return null;
  return member === 'selectedCandidateRef'
    ? { selectedCandidateRef: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(output) }
    : { [member]: Uint8Array.prototype.slice.call(output) };
}

const READBACK_OUTCOME = { RECONCILED_COMMITTED: 'COMMITTED', NOT_COMMITTED: 'NOT_COMMITTED', INDETERMINATE: 'INDETERMINATE' };

/**
 * RECONCILE_INDETERMINATE over a durable hold with the SS memory hold lost: the SS hands over the stored
 * escrow, I-TXN reconciles from the RS readback `rs`, and the adapter decides from what I-TXN established.
 */
async function reconcileDurable(store, envelope, scenario, snapshot, rs, echo) {
  const heldOutput = await heldOutputOf(store, scenario);
  const out = await reconcileIndeterminate({
    // The SS hands over its memory hold when it still has one, and nothing after an SS memory loss.
    storage: store, manifestRootKey: ROOT_KEY, hold: store.memoryHold,
    evidence: evidenceFor(envelope, rs, rs === M2_OUTCOME.INDETERMINATE ? { terminal: false } : {}),
    reference: envelope.reconciliationIdentity.reference,
  });
  const commitOutcome = READBACK_OUTCOME[out.reconciliation];
  return invokeAdapterTransition({
    request: request('RECONCILE_INDETERMINATE', { reconciliationRef: echo }),
    snapshot,
    observation: { slotContext: SLOT.slice(), commitOutcome, responseEmission: commitOutcome === 'COMMITTED' ? 'SUCCEEDED' : null, heldOutput },
  });
}

/** The staged bytes of a row: the S017 winner reference as UTF-8, or opaque bytes. */
const outputOf = (scenario, winnerRef = 'cand:winner') => (scenario === 'CAPI-S017' ? TE.encode(winnerRef) : Uint8Array.prototype.slice.call(STAGED));

// ---------------------------------------------------------------------------------------------------
// Tables (contract #532 Acceptance criteria, Tables).
// ---------------------------------------------------------------------------------------------------
describe('Tables: TABLES is the exact C-API 0afd0f21 §10 transcription (hermetic fixture)', () => {
  test('the fixture is exactly the ratified §10 record bytes', () => {
    const bytes = readFileSync(FIXTURE_URL);
    expect(bytes.length).toBe(89828);
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(FIXTURE_SHA256);
    expect(bytes[bytes.length - 1]).toBe(0x0a);
  });

  test('TABLES regenerated from the fixture equals the state-machine literal byte for byte', () => {
    const source = readFileSync(STATE_MACHINE_URL, 'utf8');
    const line = source.split('\n').find((l) => l.startsWith('const TABLES = '));
    const literal = JSON.parse(line.slice('const TABLES = '.length, -1));
    const regenerated = {
      states: C_API.stateEnum,
      operations: C_API.operationEnum,
      stateRows: Object.fromEntries(C_API.stateMatrix.map((r) => [`${r.state}|${r.operation}`, {
        scenario: r.scenario, disposition: r.disposition, resultKind: r.resultKind, stateAfter: r.stateAfter, persistence: r.persistence,
      }])),
      errorRows: Object.fromEntries(C_API.errorDefinitions.map((r) => [r.errorCode, {
        scenario: r.scenario, errorCode: r.errorCode, precedenceLevel: r.precedenceLevel,
      }])),
      decisionRows: Object.fromEntries(C_API.decisionRows.map((r) => [r.scenario, {
        scenario: r.scenario, operation: r.operation, stateBefore: r.stateBefore, precedenceLevel: r.precedenceLevel,
        persistence: r.persistence, stateAfter: r.stateAfterOnNamedDisposition, code: r.namedDisposition,
        kind: r.resultKindOnNamedDisposition,
      }])),
      errorOrder: C_API.precedenceLevels.flatMap((level) => C_API.withinLevelErrorOrder[level.id]),
      successCodes: C_API.successCodeEnum,
      // The C-MUT §4 plans are not part of the C-API record; they are carried over unchanged.
      mutationPlans: literal.mutationPlans,
    };
    expect(`const TABLES = ${JSON.stringify(regenerated)};`).toBe(line);
    expect(C_API.decisionRows).toHaveLength(31);
    expect(C_API.stateMatrix).toHaveLength(24);
    expect(C_API.errorDefinitions).toHaveLength(25);
    expect(C_API.successCodeEnum).toHaveLength(11);
    expect(C_API.successCodeEnum[10]).toBe('RESTORED_EMPTY_SESSION');
    expect(Object.keys(literal.decisionRows)).toEqual(expect.arrayContaining(['CAPI-S030', 'CAPI-S031']));
    expect([...M2_ADAPTER.SUCCESS_CODES]).toEqual(C_API.successCodeEnum);
    expect(literal.decisionRows['CAPI-S030']).toEqual({
      scenario: 'CAPI-S030', operation: 'RESTORE', stateBefore: 'EMPTY', precedenceLevel: 'P10', persistence: 'NONE',
      stateAfter: 'RECONCILIATION_REQUIRED', code: 'INDETERMINATE', kind: 'INDETERMINATE',
    });
    expect(literal.decisionRows['CAPI-S031']).toEqual({
      scenario: 'CAPI-S031', operation: 'RESTORE', stateBefore: 'EMPTY', precedenceLevel: 'P10', persistence: 'NONE',
      stateAfter: 'EMPTY', code: 'RESTORED_EMPTY_SESSION', kind: 'SUCCESS',
    });
  });
});

// ---------------------------------------------------------------------------------------------------
// T7: the INDETERMINATE response is re-exposed after a restart (CAPI-S030).
// ---------------------------------------------------------------------------------------------------
const STATE_GATES = Object.fromEntries(C_API.stateMatrix.map((r) => [`${r.state}|${r.operation}`, r]));

describe('T7: response never received — a fresh adapter re-exposes the durable hold (CAPI-S030)', () => {
  test.each(HOLD_ROWS)('%s: RESTORE → CAPI-S030, S028, the RR gates, NOT_COMMITTED reconciliation, then the repeat gate', async (scenario) => {
    const { origin } = LIVE[scenario];
    const { store, envelope, result } = await produce(scenario, M2_OUTCOME.INDETERMINATE, outputOf(scenario));
    expect(result.commitOutcome).toBe('INDETERMINATE');
    // The live INDETERMINATE response is dropped; the harness keeps the expected reference apart.
    const dropped = live(scenario, 'INDETERMINATE');
    expect(dropped.result.kind).toBe('INDETERMINATE');
    const liveSnapshot = dropped.snapshot;
    const expectedRef = refOf(envelope.reconciliationIdentity.reference);

    const restored = await relaunch(store);
    expect(restored.result).toEqual({
      api: M2_ADAPTER.API, requestId: 'req-RESTORE', operation: 'RESTORE', kind: 'INDETERMINATE',
      stateBefore: 'EMPTY', stateAfter: 'RECONCILIATION_REQUIRED', commitOutcome: 'INDETERMINATE',
      reconciliationRef: expectedRef, originalStateBefore: origin,
    });
    // C-API §6: the rebuilt snapshot equals, member by member, the one the original emission left.
    expect(restored.snapshot).toEqual(liveSnapshot);
    const before = fingerprint(store);

    // A wrong reference is CAPI-S028 at the adapter, before the SS asks RS anything: no mutation, the hold unchanged.
    const wrong = invokeAdapterTransition({
      request: request('RECONCILE_INDETERMINATE', { reconciliationRef: refOf(bytesOf(32, 0x44)) }),
      snapshot: restored.snapshot,
      observation: { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: await heldOutputOf(store, scenario) },
    });
    expect(code(wrong.result)).toBe('RECONCILIATION_REFERENCE_MISMATCH');
    expect(wrong.result.stateAfter).toBe('RECONCILIATION_REQUIRED');
    expect(wrong.snapshot).toBeNull();
    expect(fingerprint(store)).toBe(before);
    expect(envelope.scenario).toBe(scenario);

    // Every other operation is the RECONCILIATION_REQUIRED state gate (CAPI-G017 to CAPI-G023).
    const gateStore = (await produce(scenario, M2_OUTCOME.INDETERMINATE, outputOf(scenario))).store;
    const gateSnapshot = (await relaunch(gateStore)).snapshot;
    const gateBefore = fingerprint(gateStore);
    for (const operation of OPERATIONS.filter((op) => op !== 'RECONCILE_INDETERMINATE')) {
      const gate = STATE_GATES[`RECONCILIATION_REQUIRED|${operation}`];
      const scenarioOf = Object.keys(LIVE).find((s) => LIVE[s].operation === operation);
      const answer = invokeAdapterTransition({
        request: request(operation, operation === 'RESTORE' ? {} : LIVE[scenarioOf].input),
        snapshot: gateSnapshot,
        // A complete RS observation: the P05 state gate preempts it before any commit proof is read.
        observation: operation === 'RESTORE' ? await restoreFacts(gateStore) : liveObservation(scenarioOf, 'COMMITTED'),
      });
      expect(`${operation}:${code(answer.result)}`).toBe(`${operation}:${gate.disposition}`);
      expect(answer.result.stateAfter).toBe('RECONCILIATION_REQUIRED');
      expect(answer.snapshot).toBeNull();
    }
    expect(fingerprint(gateStore)).toBe(gateBefore);

    // RECONCILE_INDETERMINATE: a terminal NOT_COMMITTED readback is CAPI-S021 (EMPTY) or CAPI-S023 (ACTIVE).
    const fresh = await produce(scenario, M2_OUTCOME.INDETERMINATE, outputOf(scenario));
    const reopened = await relaunch(fresh.store);
    const resolved = await reconcileDurable(fresh.store, fresh.envelope, scenario, reopened.snapshot, M2_OUTCOME.NOT_COMMITTED, expectedRef);
    expect(resolved.result).toEqual({
      api: M2_ADAPTER.API, requestId: 'req-RECONCILE_INDETERMINATE', operation: 'RECONCILE_INDETERMINATE', kind: 'NOT_COMMITTED',
      stateBefore: 'RECONCILIATION_REQUIRED', stateAfter: origin, commitOutcome: 'NOT_COMMITTED',
    });
    expect(resolved.snapshot).toEqual({ state: origin, held: null });
    // A repeat is the NO_RECONCILIATION_PENDING gate of the original state (CAPI-G008 / CAPI-G016).
    const repeat = invokeAdapterTransition({
      request: request('RECONCILE_INDETERMINATE', { reconciliationRef: expectedRef }),
      snapshot: resolved.snapshot,
      observation: { slotContext: SLOT.slice(), commitOutcome: 'NOT_COMMITTED', responseEmission: null, heldOutput: null },
    });
    const repeatGate = STATE_GATES[`${origin}|RECONCILE_INDETERMINATE`];
    expect(repeatGate.scenario).toBe(origin === 'EMPTY' ? 'CAPI-G008' : 'CAPI-G016');
    expect(code(repeat.result)).toBe(repeatGate.disposition);
  });

  test.each(HOLD_ROWS)('%s: a COMMITTED readback after the re-exposure releases the stored escrow once (CAPI-S020/S022)', async (scenario) => {
    const output = outputOf(scenario);
    const { store, envelope } = await produce(scenario, M2_OUTCOME.INDETERMINATE, output);
    const restored = await relaunch(store);
    const resolved = await reconcileDurable(store, envelope, scenario, restored.snapshot, M2_OUTCOME.COMMITTED,
      restored.result.reconciliationRef);
    const member = LIVE[scenario].member;
    expect(resolved.result.kind).toBe('SUCCESS');
    expect(resolved.result.successCode).toBe('RECONCILED_COMMITTED');
    expect(resolved.result.stateAfter).toBe('ACTIVE');
    expect(resolved.result.output.originalSuccessCode).toBe(mutationRow(scenario).successCode);
    const released = resolved.result.output.originalOutput[member];
    if (member === 'selectedCandidateRef') expect(released).toBe('cand:winner');
    else expect(hex(released)).toBe(hex(output));
    expect((await classifyAuthority({ storage: store, manifestRootKey: ROOT_KEY, oldGeneration: OLD_GENERATION, newGeneration: NEW_GENERATION })).authority)
      .toBe('COMPLETE_NEW');
    // Released once: the repeat is the ACTIVE NO_RECONCILIATION_PENDING gate and releases nothing.
    const repeat = invokeAdapterTransition({
      request: request('RECONCILE_INDETERMINATE', { reconciliationRef: restored.result.reconciliationRef }),
      snapshot: resolved.snapshot,
      observation: { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: null },
    });
    expect(code(repeat.result)).toBe('NO_RECONCILIATION_PENDING');
    expect(Object.hasOwn(repeat.result, 'output')).toBe(false);
  });
});

describe('T7: response received — the reference AP holds is the one CAPI-S030 re-emits', () => {
  test.each(HOLD_ROWS)('%s: byte-equal 53-character references', async (scenario) => {
    const { store, envelope } = await produce(scenario, M2_OUTCOME.INDETERMINATE, outputOf(scenario));
    const received = live(scenario, 'INDETERMINATE').result.reconciliationRef;
    const restored = await relaunch(store);
    expect(restored.result.reconciliationRef).toBe(received);
    expect(Buffer.from(restored.result.reconciliationRef).equals(Buffer.from(received))).toBe(true);
    expect(received).toHaveLength(53);
    expect(received).toBe(refOf(envelope.reconciliationIdentity.reference));
  });
});

describe('T7: a COMMITTED outcome whose output cannot be handed over is retained with the COMMITTED proof', () => {
  test.each(STAGED_ROWS)('%s: retained hold, 53-character reference, one release of the durable escrow', async (scenario) => {
    const output = outputOf(scenario);
    const { store, envelope, result } = await produce(scenario, M2_OUTCOME.COMMITTED, output);
    expect(result.commitOutcome).toBe('COMMITTED');
    // The handover fails its bound (an empty staged output) while the durable escrow is HOD-bound bytes.
    const retained = live(scenario, 'COMMITTED', { staged: new Uint8Array(0) });
    expect(retained.result.kind).toBe('INDETERMINATE');
    expect(Object.hasOwn(retained.result, 'output')).toBe(false);
    expect(retained.snapshot.held.terminalEvidenceStatus).toBe('COMMITTED');
    expect(retained.result.reconciliationRef).toBe(refOf(envelope.reconciliationIdentity.reference));
    expect(retained.result.reconciliationRef).toHaveLength(53);
    const durable = (await store.readGeneration(NEW_GENERATION)).escrow;
    expect(hex(durable.digest)).toBe(hex(heldOutputDigest({ kind: mutationRow(scenario).outputKind, output: durable.output })));
    // RS proves COMMITTED (the selector names the new generation ACTIVE); the stored escrow is released once.
    const selected = decodePlaintext(K17, store.selector);
    expect(selected.state).toBe(2);
    expect(selected.generation).toBe(NEW_GENERATION);
    const resolved = invokeAdapterTransition({
      request: request('RECONCILE_INDETERMINATE', { reconciliationRef: retained.result.reconciliationRef }),
      snapshot: retained.snapshot,
      observation: { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: await heldOutputOf(store, scenario) },
    });
    expect(resolved.result.successCode).toBe('RECONCILED_COMMITTED');
    expect(hex(resolved.result.output.originalOutput[LIVE[scenario].member])).toBe(hex(output));
    const again = invokeAdapterTransition({
      request: request('RECONCILE_INDETERMINATE', { reconciliationRef: retained.result.reconciliationRef }),
      snapshot: resolved.snapshot,
      observation: { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: null },
    });
    expect(code(again.result)).toBe('NO_RECONCILIATION_PENDING');
  });

  test('CAPI-S014: a durable escrow over the adapter bound stays held and is never released', async () => {
    const scenario = 'CAPI-S014';
    const output = bytesOf(M2_ADAPTER.BOUNDS.MAX_OPAQUE_BYTES + 1, 0x19);
    const { store } = await produce(scenario, M2_OUTCOME.COMMITTED, output);
    const retained = live(scenario, 'COMMITTED', { staged: output });
    expect(retained.result.kind).toBe('INDETERMINATE');
    expect(retained.snapshot.held.terminalEvidenceStatus).toBe('COMMITTED');
    let snapshot = retained.snapshot;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const answer = invokeAdapterTransition({
        request: request('RECONCILE_INDETERMINATE', { reconciliationRef: retained.result.reconciliationRef }),
        snapshot,
        observation: { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: await heldOutputOf(store, scenario) },
      });
      expect(answer.result.kind).toBe('INDETERMINATE');
      expect(Object.hasOwn(answer.result, 'output')).toBe(false);
      expect(answer.snapshot.held.terminalEvidenceStatus).toBe('COMMITTED');
      snapshot = answer.snapshot;
    }
  });
});

describe('T7: repeat — a second relaunch re-exposes the same bytes and the store is unchanged', () => {
  test.each(HOLD_ROWS)('%s: identical CAPI-S030 twice; RESTORE again in the same worker is CAPI-G018', async (scenario) => {
    const { store } = await produce(scenario, M2_OUTCOME.INDETERMINATE, outputOf(scenario));
    store.memoryHold = null;
    const before = fingerprint(store);
    const appliedBefore = store.applied.length;
    const first = await relaunch(store);
    const second = await relaunch(store);
    expect(second.result).toEqual(first.result);
    expect(second.snapshot).toEqual(first.snapshot);
    expect(fingerprint(store)).toBe(before);
    expect(store.applied).toHaveLength(appliedBefore);
    const again = invokeAdapterTransition({ request: request('RESTORE', {}), snapshot: first.snapshot, observation: await restoreFacts(store) });
    expect(STATE_GATES['RECONCILIATION_REQUIRED|RESTORE'].scenario).toBe('CAPI-G018');
    expect(code(again.result)).toBe(STATE_GATES['RECONCILIATION_REQUIRED|RESTORE'].disposition);
    expect(again.snapshot).toBeNull();
  });
});

describe('T7: restored fields — the rebuilt snapshot equals the live one for every row that can hold', () => {
  const CASES = [
    ...HOLD_ROWS.filter((s) => s !== 'CAPI-S017').map((s) => [s, 'current']),
    ['CAPI-S017', 'current'], ['CAPI-S017', 'incoming'],
  ];
  test.each(CASES)('%s (winner %s): every member, originalStateBefore of its origin', async (scenario, winner) => {
    const winnerRef = `cand:${winner}`;
    const { store } = await produce(scenario, M2_OUTCOME.INDETERMINATE, outputOf(scenario, winnerRef));
    const liveHold = live(scenario, 'INDETERMINATE', { candidate: eligiblePair(winnerRef, winner) }).snapshot;
    const restored = await relaunch(store);
    expect(restored.snapshot).toEqual(liveHold);
    expect(restored.snapshot.held.originalStateBefore).toBe(LIVE[scenario].origin);
    expect(restored.result.originalStateBefore).toBe(LIVE[scenario].origin);
    expect(restored.snapshot.held.terminalEvidenceStatus).toBe('PENDING');
    if (scenario === 'CAPI-S017') expect(restored.snapshot.held.selectedCandidateRef).toBe(winnerRef);
  });

  // Decision D-A2: TextEncoder out, fatal TextDecoder with ignoreBOM in.
  const REFS = [
    ['ASCII', 'ref-0001:admitted-candidate'],
    ['non-ASCII', 'référence-候補-ü'],
    ['a leading U+FEFF', '\uFEFFref-with-bom'],
    ['128 non-BMP characters (256 units)', '\u{1F600}'.repeat(128)],
  ];
  test.each(REFS)('CAPI-S017 %s reference survives the escrow round trip', async (_label, ref) => {
    expect(ref.length).toBeLessThanOrEqual(256);
    const { store } = await produce('CAPI-S017', M2_OUTCOME.INDETERMINATE, TE.encode(ref));
    const liveHold = live('CAPI-S017', 'INDETERMINATE', { candidate: eligiblePair(ref) }).snapshot;
    const restored = await relaunch(store);
    expect(restored.snapshot.held.selectedCandidateRef).toBe(ref);
    expect(restored.snapshot).toEqual(liveHold);
  });

  const BAD = [
    ['malformed UTF-8', Uint8Array.of(0x72, 0xff, 0x66), /not well-formed UTF-8/],
    ['empty', new Uint8Array(0), /is empty/],
    ['over-bound (257 units)', TE.encode('r'.repeat(257)), /over the 256 bound/],
  ];
  test.each(BAD)('CAPI-S017 %s escrow bytes fail closed as CAPI-S004 at the loader decoding rule', async (_label, bytes, message) => {
    const { store } = await produce('CAPI-S017', M2_OUTCOME.INDETERMINATE, bytes);
    store.memoryHold = null;
    const failure = await loadOf(store).then(() => null, (e) => e);
    expect(failure.code).toBe('BOUND_HOLD_INVALID');
    expect(failure.message).toMatch(message);
    expect(failure.message).not.toMatch(/not the held output/);
    const before = fingerprint(store);
    const restored = await relaunch(store);
    expect(code(restored.result)).toBe('AUTHENTICATED_STATE_INCONSISTENT');
    expect(restored.result.stateAfter).toBe('EMPTY');
    expect(restored.snapshot).toBeNull();
    expect(fingerprint(store)).toBe(before);
  });

  test('a live CAPI-S017 candidate reference holding a lone surrogate is refused at P06, nothing held', () => {
    for (const commitOutcome of ['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']) {
      for (const winner of ['current', 'incoming']) {
        const answer = live('CAPI-S017', commitOutcome, { candidate: eligiblePair('cand:\uD800', winner) });
        expect(`${commitOutcome}:${winner}:${code(answer.result)}`).toBe(`${commitOutcome}:${winner}:FAIL_CLOSED_INTERNAL`);
        expect(answer.snapshot).toBeNull();
      }
      // A lone surrogate in the losing candidate is refused the same way.
      const loser = live('CAPI-S017', commitOutcome, { candidate: eligiblePair('cand:ok', 'current', 'lose:\uDC00') });
      expect(code(loser.result)).toBe('FAIL_CLOSED_INTERNAL');
    }
  });
});

describe('T7: no leaks — re-exposure, terminal and continued reconciliation carry no output and no escrow bytes', () => {
  test.each(HOLD_ROWS)('%s: CAPI-S030, CAPI-S024 and CAPI-S021/S023', async (scenario) => {
    const { store, envelope } = await produce(scenario, M2_OUTCOME.INDETERMINATE, outputOf(scenario));
    const restored = await relaunch(store);
    const continued = await reconcileDurable(store, envelope, scenario, restored.snapshot, M2_OUTCOME.INDETERMINATE,
      restored.result.reconciliationRef);
    expect(continued.result.kind).toBe('INDETERMINATE');
    expect(continued.result.reconciliationRef).toBe(restored.result.reconciliationRef);
    const terminal = await reconcileDurable(store, envelope, scenario, continued.snapshot, M2_OUTCOME.NOT_COMMITTED,
      restored.result.reconciliationRef);
    expect(terminal.result.kind).toBe('NOT_COMMITTED');
    for (const result of [restored.result, continued.result, terminal.result]) {
      expect(Object.hasOwn(result, 'output')).toBe(false);
      expect(hasBytes(result)).toBe(false);
      expect(Object.keys(result).filter((k) => !COMMON.includes(k)).sort())
        .toEqual(result.kind === 'NOT_COMMITTED' ? ['commitOutcome'] : ['commitOutcome', 'originalStateBefore', 'reconciliationRef']);
    }
  });
});

describe('T7: precedence of CAPI-S030 and CAPI-S028', () => {
  test('C-REST rejections of higher precedence preempt the re-exposure; the loaded hold changes nothing', async () => {
    const { store } = await produce('CAPI-S014', M2_OUTCOME.INDETERMINATE, outputOf('CAPI-S014'));
    const before = fingerprint(store);
    for (const [fault, expected] of [
      ['buildNotListed', 'STORED_SESSION_INCOMPATIBLE'],
      ['wrapperWrongOrInvalid', 'AUTHENTICATION_FAILED'],
      ['selectorAuthenticationFailed', 'AUTHENTICATION_FAILED'],
      ['recordAuthenticationFailed', 'AUTHENTICATION_FAILED'],
      ['manifestOrRootMismatch', 'AUTHENTICATION_FAILED'],
    ]) {
      const facts = await restoreFacts(store);
      expect(facts.restoreHold).not.toBeNull();
      const answer = invokeAdapterTransition({
        request: request('RESTORE', {}), snapshot: createAdapterSnapshot('EMPTY'),
        observation: { ...facts, restoreObservation: { ...facts.restoreObservation, faults: [fault] } },
      });
      expect(`${fault}:${code(answer.result)}`).toBe(`${fault}:${expected}`);
      expect(answer.snapshot).toBeNull();
    }
    expect(fingerprint(store)).toBe(before);
  });

  test('unknown and malformed requests preempt CAPI-S030 and CAPI-S028', async () => {
    const { store, envelope } = await produce('CAPI-S001', M2_OUTCOME.INDETERMINATE, outputOf('CAPI-S001'));
    const facts = await restoreFacts(store);
    const restoreWith = (req) => invokeAdapterTransition({ request: req, snapshot: createAdapterSnapshot('EMPTY'), observation: facts });
    expect(code(restoreWith({ ...request('RESTORE', {}), extra: 1 }).result)).toBe('UNKNOWN_FIELD');
    expect(code(restoreWith(request('RESTORE', { extra: 1 })).result)).toBe('UNKNOWN_FIELD');
    expect(code(restoreWith(request('RESTORE', {}, { api: 'styx-m2-session-adapter/v2' })).result)).toBe('UNSUPPORTED_API_VERSION');
    expect(code(restoreWith(request('RESTORE', {}, { profile: { ...M2_ADAPTER.PROFILE, stage: 'production' } })).result)).toBe('UNSUPPORTED_PROFILE');
    expect(code(restoreWith(request('RESTORE', {}, { requestId: 'r'.repeat(129) })).result)).toBe('VALUE_OUT_OF_RANGE');
    expect(() => restoreWith(request('RESTORE', {}, { requestId: '' }))).toThrow(M2AdapterError);
    expect(code(invokeAdapterTransition({
      request: request('RESTORE', {}), snapshot: createAdapterSnapshot('EMPTY'), observation: { ...facts, extra: 1 },
    }).result)).toBe('UNKNOWN_FIELD');
    const held = restoreWith(request('RESTORE', {})).snapshot;
    const wrong = refOf(bytesOf(32, 0x45));
    const heldOutput = await heldOutputOf(store, 'CAPI-S001');
    const reconcileWith = (req) => invokeAdapterTransition({
      request: req, snapshot: held,
      observation: { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput },
    });
    expect(code(reconcileWith(request('RECONCILE_INDETERMINATE', { reconciliationRef: wrong })).result)).toBe('RECONCILIATION_REFERENCE_MISMATCH');
    expect(code(reconcileWith({ ...request('RECONCILE_INDETERMINATE', { reconciliationRef: wrong }), extra: 1 }).result)).toBe('UNKNOWN_FIELD');
    expect(code(reconcileWith(request('RECONCILE_INDETERMINATE', { reconciliationRef: wrong, extra: 1 })).result)).toBe('UNKNOWN_FIELD');
    expect(code(reconcileWith(request('RECONCILE_INDETERMINATE', { reconciliationRef: '' })).result)).toBe('INVALID_REQUEST');
    expect(code(reconcileWith(request('RECONCILE_INDETERMINATE', { reconciliationRef: wrong }, { api: 'x' })).result)).toBe('UNSUPPORTED_API_VERSION');
    expect(code(reconcileWith(request('RECONCILE_INDETERMINATE', { reconciliationRef: wrong }, { bindingRef: new Uint8Array(32).fill(9) })).result))
      .toBe('BINDING_MISMATCH');
    expect(envelope.scenario).toBe('CAPI-S001');
  });
});

// ---------------------------------------------------------------------------------------------------
// Held-output digest and loader failures.
// ---------------------------------------------------------------------------------------------------
describe('T7: loader failure — CAPI-S004 for a contradiction, FAIL_CLOSED_INTERNAL otherwise', () => {
  const flip = (value) => {
    const out = Uint8Array.prototype.slice.call(value);
    out[0] ^= 0x5a;
    return out;
  };
  const reencode = (store, kind, plaintext) => {
    const g = store.generations.get(NEW_GENERATION);
    g.records = g.records.map((r) => (r.recordKind === kind ? { ...r, plaintext } : r));
  };
  const CONTRADICTIONS = [
    ['the candidate generation is not stored', (store) => { store.generations.delete(NEW_GENERATION); }],
    ['the candidate binding profile does not hash to its binding digest', (store) => {
      store.generations.get(NEW_GENERATION).sessionBindingDigest = bytesOf(32, 0x5b);
    }],
    ['the kind-13 hold names another scenario', (store, envelope) => {
      const hold = { ...holdRecordOf(envelope), scenario: M2_TXN.SCENARIOS.indexOf('CAPI-S009') + 1 };
      reencode(store, K13, encodePlaintext(K13, hold));
      store.generations.get(NEW_GENERATION).mutationHold = { ...hold };
    }],
    ['the component set digest is not the held one', (store) => {
      const g = store.generations.get(NEW_GENERATION);
      const record = { ...decodePlaintext(K14, g.records.find((r) => r.recordKind === K14).plaintext) };
      reencode(store, K14, encodePlaintext(K14, { ...record, mutationSetDigest: flip(record.mutationSetDigest) }));
    }],
    ['the escrow record operation identity is not the held one', (store) => {
      const g = store.generations.get(NEW_GENERATION);
      const record = { ...decodePlaintext(K9, g.records.find((r) => r.recordKind === K9).plaintext) };
      reencode(store, K9, encodePlaintext(K9, { ...record, operationIdentity: flip(record.operationIdentity) }));
    }],
    ['the kind-8 result evidence names another candidate', (store) => {
      const g = store.generations.get(NEW_GENERATION);
      const record = { ...decodePlaintext(K8, g.records.find((r) => r.recordKind === K8).plaintext) };
      reencode(store, K8, encodePlaintext(K8, { ...record, candidateDigest: flip(record.candidateDigest) }));
    }],
    ['the held-output digest does not bind the stored escrow bytes', (store) => {
      // HOD-bound bytes were staged; the stored escrow bytes then change while their recorded digest stays.
      const g = store.generations.get(NEW_GENERATION);
      g.escrow = { ...g.escrow, output: flip(g.escrow.output) };
    }],
    ['a port verification refusal of the readback', (store) => {
      store.readFault = Object.assign(new Error('authentication failed'), { code: 'AUTHENTICATION_FAILED' });
    }],
  ];
  test.each(CONTRADICTIONS)('%s: BOUND_HOLD_INVALID → CAPI-S004, nothing written', async (_label, corrupt) => {
    const { store, envelope } = await produce('CAPI-S014', M2_OUTCOME.INDETERMINATE, outputOf('CAPI-S014'));
    corrupt(store, envelope);
    store.memoryHold = null;
    const appliedBefore = store.applied.length;
    const before = fingerprint(store);
    expect(await codeOf(loadOf(store))).toBe('BOUND_HOLD_INVALID');
    const restored = await relaunch(store);
    expect(restored.result).toEqual({
      api: M2_ADAPTER.API, requestId: 'req-RESTORE', operation: 'RESTORE', kind: 'REJECTED', stateBefore: 'EMPTY',
      stateAfter: 'EMPTY', error: { code: 'AUTHENTICATED_STATE_INCONSISTENT' },
    });
    expect(restored.snapshot).toBeNull();
    expect(store.applied).toHaveLength(appliedBefore);
    expect(fingerprint(store)).toBe(before);
  });

  test('the held-output digest refusal is the loader digest rule, not the D-A2 decoding rule', async () => {
    const { store } = await produce('CAPI-S017', M2_OUTCOME.INDETERMINATE, TE.encode('cand:winner'));
    const g = store.generations.get(NEW_GENERATION);
    g.escrow = { ...g.escrow, output: TE.encode('cand:winnes') };
    const failure = await loadOf(store).then(() => null, (e) => e);
    expect(failure.code).toBe('BOUND_HOLD_INVALID');
    expect(failure.message).toMatch(/not the held output/);
    expect(failure.message).not.toMatch(/well-formed|is empty|bound/);
  });

  test('a restoreHold beside another C-REST result, or whose facts disagree with its hold, is FAIL_CLOSED_INTERNAL', async () => {
    const { store } = await produce('CAPI-S014', M2_OUTCOME.INDETERMINATE, outputOf('CAPI-S014'));
    const loaded = await loadOf(store);
    const restoreWith = (restoreObservation, restoreHold) => invokeAdapterTransition({
      request: request('RESTORE', {}), snapshot: createAdapterSnapshot('EMPTY'), observation: { restoreObservation, restoreHold },
    });
    const positive = (id) => {
      const row = FRESH_WORKER_FIXTURES.positive.find((r) => r.id === id);
      return { faults: [], inventory: row.inventory, legacy: row.legacy, vector: row.vector, selectorState: VECTOR_STATE[row.vector] };
    };
    expect(code(restoreWith(positive('POS-ACTIVE'), loaded).result)).toBe('FAIL_CLOSED_INTERNAL');
    expect(code(restoreWith(positive('POS-EMPTY'), loaded).result)).toBe('FAIL_CLOSED_INTERNAL');
    expect(code(restoreWith(positive('POS-ACTIVE'), 'READBACK_UNAVAILABLE').result)).toBe('FAIL_CLOSED_INTERNAL');
    const hold = positive('POS-HOLD');
    const disagreeing = [
      ['scenario', { ...loaded.facts, scenario: 'CAPI-S009' }],
      ['operation', { ...loaded.facts, operation: 'CREATE' }],
      ['originalStateBefore', { ...loaded.facts, originalStateBefore: 'EMPTY' }],
      ['expectedSuccessCode', { ...loaded.facts, expectedSuccessCode: 'CREATED' }],
      ['outputKind', { ...loaded.facts, outputKind: 'PROTECTED_APPLICATION_BYTES' }],
      ['operationIdentity', { ...loaded.facts, operationIdentity: flip(loaded.facts.operationIdentity) }],
      ['reconciliationReference', { ...loaded.facts, reconciliationReference: flip(loaded.facts.reconciliationReference) }],
      ['selectedCandidateRef', { ...loaded.facts, selectedCandidateRef: 'not-null' }],
    ];
    for (const [label, facts] of disagreeing) {
      const answer = restoreWith(hold, { hold: loaded.hold, facts });
      expect(`${label}:${code(answer.result)}`).toBe(`${label}:FAIL_CLOSED_INTERNAL`);
      expect(answer.snapshot).toBeNull();
    }
    for (const [label, value] of [
      ['another string', 'BOUND_HOLD_INVALID'], ['undefined', undefined], ['a number', 0], ['an array', []],
      ['an extra member', { ...loaded, extra: 1 }], ['a missing member', { hold: loaded.hold }],
      ['a hold of 21 members', { hold: { ...loaded.hold, presence: undefined }, facts: loaded.facts }],
    ]) {
      expect(`${label}:${code(restoreWith(hold, value).result)}`).toBe(`${label}:FAIL_CLOSED_INTERNAL`);
    }
    // The well-formed loader output beside its own C-REST result is the re-exposure.
    expect(restoreWith(hold, loaded).result.kind).toBe('INDETERMINATE');
  });

  test('an unavailable readback (D-A4) is FAIL_CLOSED_INTERNAL, never CAPI-S004 or CAPI-S030; a later fresh RESTORE reaches CAPI-S030', async () => {
    const { store } = await produce('CAPI-S009', M2_OUTCOME.INDETERMINATE, outputOf('CAPI-S009'));
    store.readFault = new Error('the storage engine is gone');
    expect(await codeOf(loadOf(store))).toBe('READBACK_UNAVAILABLE');
    const appliedBefore = store.applied.length;
    const unavailable = await relaunch(store);
    expect(unavailable.result).toEqual({
      api: M2_ADAPTER.API, requestId: 'req-RESTORE', operation: 'RESTORE', kind: 'REJECTED', stateBefore: 'EMPTY',
      stateAfter: 'EMPTY', error: { code: 'FAIL_CLOSED_INTERNAL' },
    });
    expect(unavailable.snapshot).toBeNull();
    expect(store.applied).toHaveLength(appliedBefore);
    store.readFault = null;
    const recovered = await relaunch(store);
    expect(recovered.result.kind).toBe('INDETERMINATE');
    expect(recovered.result.reconciliationRef).toBe(refOf(REFERENCE_BYTES));
  });
});

describe('T7: R3 rows — CAPI-S006 and CAPI-S016 reach no durable hold and restore fail-closed (CAPI-S004)', () => {
  test.each(['CAPI-S006', 'CAPI-S016'])(
    '%s: restore fails closed; its C-API INDETERMINATE restart obligation remains outstanding (R3, K13-NONE-CODE)',
    async (scenario) => {
      const { store } = await produce(scenario, M2_OUTCOME.INDETERMINATE, null);
      store.memoryHold = null;
      expect(decodePlaintext(K17, store.selector).state).toBe(3);
      expect(await codeOf(loadOf(store))).toBe('BOUND_HOLD_INVALID');
      const before = fingerprint(store);
      const restored = await relaunch(store);
      expect(code(restored.result)).toBe('AUTHENTICATED_STATE_INCONSISTENT');
      expect(restored.snapshot).toBeNull();
      expect(fingerprint(store)).toBe(before);
    },
  );
});

// ---------------------------------------------------------------------------------------------------
// T8: the EMPTY authority after a terminal reconciliation (CAPI-S031).
// ---------------------------------------------------------------------------------------------------
describe('T8: RESTORED_EMPTY_SESSION after an EMPTY-origin reconciliation', () => {
  test('CAPI-S001 reconciled NOT_COMMITTED ends EMPTY; RESTORE → CAPI-S031; then a CREATE commits', async () => {
    const { store, envelope } = await produce('CAPI-S001', M2_OUTCOME.INDETERMINATE, outputOf('CAPI-S001'));
    const held = live('CAPI-S001', 'INDETERMINATE');
    const resolved = await reconcileDurable(store, envelope, 'CAPI-S001', held.snapshot, M2_OUTCOME.NOT_COMMITTED,
      held.result.reconciliationRef);
    expect(resolved.result.kind).toBe('NOT_COMMITTED');
    expect(resolved.snapshot).toEqual({ state: 'EMPTY', held: null });
    const restored = await relaunch(store);
    expect(restored.result).toEqual({
      api: M2_ADAPTER.API, requestId: 'req-RESTORE', operation: 'RESTORE', kind: 'SUCCESS', stateBefore: 'EMPTY',
      stateAfter: 'EMPTY', successCode: 'RESTORED_EMPTY_SESSION',
    });
    expect(restored.snapshot).toEqual({ state: 'EMPTY', held: null });
    // A fresh CREATE with a fresh SS/RS identity commits from the restored EMPTY authority.
    const identity = bytesOf(32, 0x21);
    const reference = bytesOf(32, 0x2c);
    const welcome = bytesOf(20, 0x6b);
    const created = await produce('CAPI-S001', M2_OUTCOME.COMMITTED, welcome, { store, identity, reference });
    expect(created.result.commitOutcome).toBe('COMMITTED');
    const answer = invokeAdapterTransition({
      request: request('CREATE', LIVE['CAPI-S001'].input), snapshot: restored.snapshot,
      observation: liveObservation('CAPI-S001', 'COMMITTED', { identity: b64(identity), reference, staged: created.result.output }),
    });
    expect(answer.result.successCode).toBe('CREATED');
    expect(hex(answer.result.output.embeddedTreeWelcome)).toBe(hex(welcome));
    expect(answer.snapshot).toEqual({ state: 'ACTIVE', held: null });
    expect(code((await relaunch(store)).result)).toBe('RESTORED');
  });

  test('CAPI-S014 (ACTIVE origin) reconciled NOT_COMMITTED: the final RESTORE gives RESTORED', async () => {
    const { store, envelope } = await produce('CAPI-S014', M2_OUTCOME.INDETERMINATE, outputOf('CAPI-S014'));
    const held = live('CAPI-S014', 'INDETERMINATE');
    const resolved = await reconcileDurable(store, envelope, 'CAPI-S014', held.snapshot, M2_OUTCOME.NOT_COMMITTED,
      held.result.reconciliationRef);
    expect(resolved.snapshot).toEqual({ state: 'ACTIVE', held: null });
    const restored = await relaunch(store);
    expect(code(restored.result)).toBe('RESTORED');
    expect(restored.snapshot).toEqual({ state: 'ACTIVE', held: null });
  });
});

// ---------------------------------------------------------------------------------------------------
// The C-API §5 operation-identity rule and decision D-A1.
// ---------------------------------------------------------------------------------------------------
describe('Identity bound: exactly 43 canonical characters for the seven RS_TRI_STATE rows (C-API §5)', () => {
  const canonical = b64(IDENTITY_BYTES);
  const lastIndex = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.indexOf(canonical[42]);
  const nonCanonical = `${canonical.slice(0, 42)}${'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'[lastIndex + 1]}`;
  const IDENTITIES = [
    ['44 characters', `${canonical}A`, 'VALUE_OUT_OF_RANGE'],
    ['42 characters', canonical.slice(0, 42), 'FAIL_CLOSED_INTERNAL'],
    ['a non-alphabet character', `+${canonical.slice(1)}`, 'FAIL_CLOSED_INTERNAL'],
    ['a non-canonical last character', nonCanonical, 'FAIL_CLOSED_INTERNAL'],
    ['an all-zero identity', b64(new Uint8Array(32)), 'FAIL_CLOSED_INTERNAL'],
  ];
  const CASES = TRI_STATE_ROWS.flatMap((scenario) => ['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']
    .flatMap((outcome) => IDENTITIES.map(([label, identity, expected]) => [scenario, outcome, label, identity, expected])));
  test.each(CASES)('%s %s with %s is refused before any request, nothing held', (scenario, outcome, _label, identity, expected) => {
    expect(nonCanonical).not.toBe(canonical);
    expect(Buffer.from(nonCanonical, 'base64url').toString('base64url')).not.toBe(nonCanonical);
    const answer = live(scenario, outcome, { identity });
    expect(code(answer.result)).toBe(expected);
    expect(answer.result.kind).toBe('REJECTED');
    expect(answer.result.stateAfter).toBe(LIVE[scenario].origin);
    expect(answer.snapshot).toBeNull();
  });

  test.each(TRI_STATE_ROWS)('%s with the canonical 43-character identity keeps its tri-state behaviour', (scenario) => {
    const { origin } = LIVE[scenario];
    const committed = live(scenario, 'COMMITTED');
    expect(committed.result.kind).toBe('SUCCESS');
    expect(committed.result.successCode).toBe(mutationRow(scenario).successCode);
    const notCommitted = live(scenario, 'NOT_COMMITTED');
    expect(notCommitted.result.kind).toBe('NOT_COMMITTED');
    expect(notCommitted.snapshot).toEqual({ state: origin, held: null });
    const held = live(scenario, 'INDETERMINATE');
    expect(held.result.kind).toBe('INDETERMINATE');
    expect(held.result.reconciliationRef).toBe(refOf(REFERENCE_BYTES));
    expect(held.snapshot.held.operationIdentity).toBe(canonical);
  });
});

describe('D-A1: a defective reconciliationReference is a producer contradiction (FAIL_CLOSED_INTERNAL at P06)', () => {
  const DEFECTS = [
    ['missing', undefined],
    ['null beside an outcome', null],
    ['short (31 bytes)', bytesOf(31, 0x0c)],
    ['long (33 bytes)', bytesOf(33, 0x0c)],
    ['zero', new Uint8Array(32)],
    ['not a Uint8Array (Uint16Array)', new Uint16Array(32).fill(7)],
    ['not a Uint8Array (array)', Array.from(REFERENCE_BYTES)],
    ['not a Uint8Array (string)', b64(REFERENCE_BYTES)],
  ];
  const withReference = (observation, reference) => {
    const out = { ...observation };
    if (reference === undefined) delete out.reconciliationReference;
    else out.reconciliationReference = reference;
    return out;
  };
  const CASES = TRI_STATE_ROWS.flatMap((scenario) => ['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']
    .flatMap((outcome) => DEFECTS.map(([label, reference]) => [scenario, outcome, label, reference])));
  test.each(CASES)('%s %s with a %s reference: refused, nothing held, nothing released', (scenario, outcome, _label, reference) => {
    const answer = invokeAdapterTransition({
      request: request(LIVE[scenario].operation, LIVE[scenario].input),
      snapshot: createAdapterSnapshot(LIVE[scenario].origin),
      observation: withReference(liveObservation(scenario, outcome), reference),
    });
    expect(code(answer.result)).toBe('FAIL_CLOSED_INTERNAL');
    expect(Object.hasOwn(answer.result, 'output')).toBe(false);
    expect(answer.snapshot).toBeNull();
  });

  test('a non-null reference beside a null outcome is FAIL_CLOSED_INTERNAL', () => {
    // CAPI-S011 (an authenticated in-window duplicate) is the honest null-outcome row that would succeed.
    const duplicate = {
      currentEpoch: 9, framingEpoch: 8, authentication: 'AUTHENTICATED', replayIdentity: 'DUPLICATE',
      commitOutcome: null, operationIdentity: null, stagedOutput: null,
    };
    const opened = (observation) => invokeAdapterTransition({
      request: request('OPEN_APPLICATION', LIVE['CAPI-S010'].input), snapshot: createAdapterSnapshot('ACTIVE'), observation,
    });
    expect(code(opened(duplicate).result)).toBe('DUPLICATE_IGNORED');
    expect(code(opened({ ...duplicate, reconciliationReference: null }).result)).toBe('DUPLICATE_IGNORED');
    const refused = opened({ ...duplicate, reconciliationReference: REFERENCE_BYTES });
    expect(code(refused.result)).toBe('FAIL_CLOSED_INTERNAL');
    expect(refused.snapshot).toBeNull();
    // An ACTIVE PROTECT_APPLICATION that reports no request at all, with a reference beside it.
    const protect = invokeAdapterTransition({
      request: request('PROTECT_APPLICATION', LIVE['CAPI-S009'].input), snapshot: createAdapterSnapshot('ACTIVE'),
      observation: { commitOutcome: null, operationIdentity: null, stagedOutput: null, reconciliationReference: REFERENCE_BYTES },
    });
    expect(code(protect.result)).toBe('FAIL_CLOSED_INTERNAL');
  });

  test.each(HOLD_ROWS.flatMap((s) => [[s, 'COMMITTED'], [s, 'INDETERMINATE']]))(
    '%s %s: after the refusal a fresh RESTORE classifies what the driver wrote',
    async (scenario, outcome) => {
      const { store } = await produce(scenario, M2_OUTCOME[outcome], outputOf(scenario));
      const refused = invokeAdapterTransition({
        request: request(LIVE[scenario].operation, LIVE[scenario].input),
        snapshot: createAdapterSnapshot(LIVE[scenario].origin),
        observation: withReference(liveObservation(scenario, outcome), new Uint8Array(32)),
      });
      expect(code(refused.result)).toBe('FAIL_CLOSED_INTERNAL');
      const restored = await relaunch(store);
      if (outcome === 'COMMITTED') {
        expect(code(restored.result)).toBe('RESTORED');
        expect(restored.snapshot).toEqual({ state: 'ACTIVE', held: null });
      } else {
        expect(restored.result.kind).toBe('INDETERMINATE');
        expect(restored.result.reconciliationRef).toBe(refOf(REFERENCE_BYTES));
        expect(restored.snapshot.held.scenario).toBe(scenario);
      }
    },
  );
});

describe('Reference form: 53 characters on every entry into RECONCILIATION_REQUIRED; any other echo is CAPI-S028', () => {
  test('the original INDETERMINATE, the retained COMMITTED hold and CAPI-S030 all emit the §5 form', async () => {
    const form = /^I-SM-HOLD:[A-Za-z0-9_-]{43}$/;
    for (const scenario of TRI_STATE_ROWS) {
      const ref = live(scenario, 'INDETERMINATE').result.reconciliationRef;
      expect(ref).toMatch(form);
      expect(ref).toBe(refOf(REFERENCE_BYTES));
    }
    for (const scenario of STAGED_ROWS) {
      const retained = live(scenario, 'COMMITTED', { staged: new Uint8Array(0) }).result.reconciliationRef;
      expect(retained).toMatch(form);
      expect(retained).toBe(refOf(REFERENCE_BYTES));
    }
    for (const scenario of HOLD_ROWS) {
      const { store } = await produce(scenario, M2_OUTCOME.INDETERMINATE, outputOf(scenario));
      const restored = (await relaunch(store)).result.reconciliationRef;
      expect(restored).toMatch(form);
      expect(restored).toBe(refOf(REFERENCE_BYTES));
    }
  });

  test('an echo with a different prefix, padding, length or decoded bytes is CAPI-S028; store and snapshot unchanged', async () => {
    const { store } = await produce('CAPI-S010', M2_OUTCOME.INDETERMINATE, outputOf('CAPI-S010'));
    const restored = await relaunch(store);
    const ref = restored.result.reconciliationRef;
    const encoded = ref.slice('I-SM-HOLD:'.length);
    const otherBytes = Uint8Array.prototype.slice.call(REFERENCE_BYTES);
    otherBytes[31] ^= 0x01;
    const echoes = [
      ['another prefix', `I-SM-HOLE:${encoded}`],
      ['a lower-case prefix', `i-sm-hold:${encoded}`],
      ['the bare reference', encoded],
      ['padding', `${ref}=`],
      ['one character short', ref.slice(0, -1)],
      ['one character long', `${ref}A`],
      ['standard base64', `I-SM-HOLD:${Buffer.from(REFERENCE_BYTES).toString('base64')}`],
      ['other decoded bytes', refOf(otherBytes)],
      ['the operation identity instead of the reference', `I-SM-HOLD:${b64(IDENTITY_BYTES)}`],
    ];
    const before = fingerprint(store);
    for (const [label, echo] of echoes) {
      expect(echo).not.toBe(ref);
      const answer = invokeAdapterTransition({
        request: request('RECONCILE_INDETERMINATE', { reconciliationRef: echo }), snapshot: restored.snapshot,
        observation: { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: await heldOutputOf(store, 'CAPI-S010') },
      });
      expect(`${label}:${code(answer.result)}`).toBe(`${label}:RECONCILIATION_REFERENCE_MISMATCH`);
      expect(answer.result.stateAfter).toBe('RECONCILIATION_REQUIRED');
      expect(answer.snapshot).toBeNull();
    }
    expect(fingerprint(store)).toBe(before);
    expect(restored.snapshot.state).toBe('RECONCILIATION_REQUIRED');
  });
});
