import { describe, expect, jest, test } from '@jest/globals';
import {
  M2_KIND, encodePlaintext, encodeRecordKey, decodePlaintext,
} from '../../../src/storage/m2/session-codec.js';
import {
  computeKeyedRoot, ciphertextDigest, encodeManifest, encodeManifestKey, manifestEntry,
  manifestKeyDigest,
} from '../../../src/storage/m2/session-root.js';
import {
  M2TxnError, M2_OUTCOME, M2_TXN, buildMutationEnvelope, classifyAuthority, mutationRow,
  mutationSteps, reconcileIndeterminate, runMutation, validateCommitResultEvidence,
} from '../../../src/storage/m2/session-transaction.js';

// ---------------------------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------------------------

const LOCAL = new Uint8Array(32).fill(0x21);
const PROFILE = new Uint8Array(32).fill(0x31);
const ROOT_KEY = new Uint8Array(32).fill(0x11);
const SESSION_ID = new Uint8Array(32).fill(0x41);
const BINDING_DIGEST = new Uint8Array(32).fill(0x51);
const OLD_GENERATION = 1n;
const NEW_GENERATION = 2n;
const DATA_KINDS = Array.from({ length: 15 }, (_, i) => i + 1);
const MEMORY_ONLY_KINDS = new Set([
  'VALIDATE_ENVELOPE', 'COMPUTE_CANDIDATE', 'STAGE_LOCAL', 'OPEN_RS_REQUEST', 'CONFIRM_AUTHORITY',
  'REPORT_RESULT',
]);

const bytesOf = (n, seed) => Uint8Array.from({ length: n }, (_, i) => (seed + i * 7) & 0xff);
const hex = (u8) => Buffer.from(u8).toString('hex');

function recordKeyFor(generation, kind) {
  const pre = generation === OLD_GENERATION;
  return encodeRecordKey({
    scope: pre ? 1 : 2,
    localContextId: LOCAL,
    secureSessionIdentity: pre ? null : SESSION_ID,
    writeGeneration: generation,
    recordKind: kind,
  });
}

function generationFixture(generation) {
  const pre = generation === OLD_GENERATION;
  const records = DATA_KINDS.map((kind) => ({
    recordKey: recordKeyFor(generation, kind),
    recordKind: kind,
    plaintext: bytesOf(9, kind),
    ciphertext: bytesOf(17, kind + 3),
    tag: bytesOf(16, kind + 11),
  }));
  const manifestBytes = encodeManifest(records.map((r) => manifestEntry({
    recordKey: r.recordKey,
    recordKind: r.recordKind,
    ciphertextDigest: ciphertextDigest({
      recordKey: r.recordKey, recordKind: r.recordKind, ciphertext: r.ciphertext, tag: r.tag,
    }),
  })));
  const manifestKey = encodeManifestKey({
    localContextId: LOCAL,
    scope: pre ? 1 : 2,
    secureSessionIdentity: pre ? null : SESSION_ID,
    writeGeneration: generation,
  });
  return {
    generation,
    records,
    manifestKey,
    manifestBytes,
    manifestCipherDigest: bytesOf(32, Number(generation) + 0x90),
    keyedRoot: computeKeyedRoot({ manifestRootKey: ROOT_KEY, manifestKey, generation, manifestBytes }),
    sessionBindingDigest: pre ? null : BINDING_DIGEST,
  };
}

const OLD = generationFixture(OLD_GENERATION);
const NEW = generationFixture(NEW_GENERATION);

function sameTupleSelector(facts, state) {
  const digest = manifestKeyDigest(facts.manifestKey);
  return {
    presence: 1,
    generation: facts.generation,
    manifestKeyDigest: digest,
    manifestCipherDigest: facts.manifestCipherDigest,
    keyedRoot: facts.keyedRoot,
    state,
    candidateGeneration: facts.generation,
    candidateManifestKey: facts.manifestKey,
    candidateManifestKeyDigest: digest,
    candidateManifestCipherDigest: facts.manifestCipherDigest,
    candidateKeyedRoot: facts.keyedRoot,
  };
}

const PARENT_SELECTOR = encodePlaintext(M2_KIND.GENERATION_SELECTOR, sameTupleSelector(OLD, 1));
const COMMIT_SELECTOR = encodePlaintext(M2_KIND.GENERATION_SELECTOR, sameTupleSelector(NEW, 2));
const HOLD_SELECTOR = encodePlaintext(M2_KIND.GENERATION_SELECTOR, {
  presence: 1,
  generation: OLD.generation,
  manifestKeyDigest: manifestKeyDigest(OLD.manifestKey),
  manifestCipherDigest: OLD.manifestCipherDigest,
  keyedRoot: OLD.keyedRoot,
  state: 3,
  candidateGeneration: NEW.generation,
  candidateManifestKey: NEW.manifestKey,
  candidateManifestKeyDigest: manifestKeyDigest(NEW.manifestKey),
  candidateManifestCipherDigest: NEW.manifestCipherDigest,
  candidateKeyedRoot: NEW.keyedRoot,
});

const ESCROW = {
  kind: 'PROTECTED_COMMIT_BYTES',
  digest: bytesOf(32, 0xa1),
  reference: bytesOf(32, 0xa2),
  output: bytesOf(24, 0xa3),
};

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

// mutationSteps takes the plan view of a candidate: the same facts without the two generation-meta
// fields the step plan does not carry, plus the hold it is told to write.
function planInput(scenario, outcome) {
  const c = candidateInput(scenario, outcome);
  return {
    generation: c.generation,
    parentGeneration: c.parentGeneration,
    records: c.records,
    manifestKey: c.manifestKey,
    manifestBytes: c.manifestBytes,
    manifestCipherDigest: c.manifestCipherDigest,
    keyedRoot: c.keyedRoot,
    sessionBindingDigest: c.sessionBindingDigest,
    selectorBytes: c.selectorBytes,
    holdSelectorBytes: c.holdSelectorBytes,
    parentSelectorBytes: c.parentSelectorBytes,
    resultEvidence: c.resultEvidence,
    escrow: c.escrow,
    mutationHold: null,
  };
}

function envelopeInput(scenario, overrides = {}) {
  const row = mutationRow(scenario);
  const base = {
    operationIdentity: {
      value: bytesOf(32, 0x01), assignedBy: 'SS_RS', fresh: true, reusable: false, apRequestIdEqual: false,
    },
    operation: row.operation,
    scenario,
    originalApiState: row.stateBefore,
    originalAuthority: { digest: bytesOf(32, 0x02), reference: bytesOf(32, 0x03) },
    bindingProfileIdentity: { bindingRef: bytesOf(32, 0x04), profile: bytesOf(32, 0x05) },
    candidate: { digest: bytesOf(32, 0x06), reference: bytesOf(32, 0x07) },
    componentSet: {
      digest: bytesOf(32, 0x08), reference: bytesOf(32, 0x09),
      entries: row.components.map((c) => ({ ...c })),
    },
    heldOutput: row.outputKind === 'NONE'
      ? { kind: 'NONE', digest: null, reference: null }
      : { kind: row.outputKind, digest: bytesOf(32, 0x0a), reference: bytesOf(32, 0x0b) },
    expectedSuccess: { code: row.successCode, stateAfter: row.stateAfterCommitted },
    reconciliationIdentity: { reference: bytesOf(32, 0x0c), owner: 'SS_RS' },
  };
  const merged = { ...base, ...overrides };
  if (overrides.heldOutput !== undefined) merged.heldOutput = overrides.heldOutput;
  return merged;
}

function candidateInput(scenario, outcome, overrides = {}) {
  const envelope = buildMutationEnvelope(envelopeInput(scenario));
  const row = mutationRow(scenario);
  const base = {
    generation: NEW_GENERATION,
    records: NEW.records.map((r) => ({
      recordKey: r.recordKey,
      recordKind: r.recordKind,
      plaintext: r.plaintext,
      ciphertext: r.ciphertext,
      tag: r.tag,
    })),
    manifestKey: NEW.manifestKey,
    manifestBytes: NEW.manifestBytes,
    manifestCipherDigest: NEW.manifestCipherDigest,
    keyedRoot: NEW.keyedRoot,
    sessionBindingDigest: NEW.sessionBindingDigest,
    // The escrow is the row's held output: its kind, digest and reference are the envelope's heldOutput.
    escrow: row.outputKind === 'NONE' ? null : {
      ...ESCROW, kind: row.outputKind, digest: envelope.heldOutput.digest, reference: envelope.heldOutput.reference,
      output: Uint8Array.prototype.slice.call(ESCROW.output),
    },
    resultEvidence: evidenceFor(envelope, outcome),
    selectorBytes: COMMIT_SELECTOR,
    holdSelectorBytes: HOLD_SELECTOR,
    parentSelectorBytes: PARENT_SELECTOR,
    parentGeneration: OLD_GENERATION,
    parentKeyedRoot: OLD.keyedRoot,
  };
  return { ...base, ...overrides };
}

function holdRecordFor(scenario) {
  const envelope = buildMutationEnvelope(envelopeInput(scenario));
  const row = mutationRow(scenario);
  const OPERATIONS = ['CREATE', 'RESTORE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION',
    'SELF_UPDATE', 'APPLY_PEER_UPDATE', 'RECONCILE_INDETERMINATE'];
  const OUTPUT_KINDS = ['NONE', 'EMBEDDED_TREE_WELCOME', 'PROTECTED_APPLICATION_BYTES',
    'APPLICATION_BYTES', 'PROTECTED_COMMIT_BYTES', 'SELECTED_CANDIDATE_REF'];
  const SUCCESS_CODES = ['CREATED', 'RESTORED', 'JOINED', 'APPLICATION_PROTECTED', 'APPLICATION_OPENED',
    'SELF_UPDATED', 'PEER_UPDATE_APPLIED', 'CANDIDATE_SELECTED', 'RECONCILED_COMMITTED',
    'DUPLICATE_IGNORED'];
  return {
    presence: 1,
    operationIdentity: envelope.operationIdentity.value,
    operation: OPERATIONS.indexOf(row.operation) + 1,
    scenario: M2_TXN.SCENARIOS.indexOf(scenario) + 1,
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

/**
 * A deterministic in-memory RS port with fault injection at every durable step. `faults` is a list of
 * `{ boundary, kind, mode, remaining, id }`; a fault matches the first time a step with the same
 * boundary, kind and mode is applied, `BEFORE` raising before the durable effect and `AFTER` after it.
 */
// F2: the stored selector is an opaque C-FMT envelope. A fresh nonce per write is modelled by a
// write counter, so re-writing the same plaintext yields different envelope bytes.
let ENVELOPE_WRITES = 0;
function sealSelector(plaintext) {
  ENVELOPE_WRITES += 1;
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setUint32(8, ENVELOPE_WRITES);
  const out = new Uint8Array(12 + plaintext.length + 16);
  out.set(nonce, 0);
  out.set(plaintext, 12);
  out.fill(0xa5, 12 + plaintext.length); // stand-in tag: the port never interprets the envelope
  return out;
}
const selectorPreconditionFailed = () => Object.assign(
  new Error('the stored selector envelope differs from expectedSelectorBytes'),
  { code: 'SELECTOR_PRECONDITION_FAILED' },
);
// Every REPLACE_SELECTOR this module executes carries the CAS member; the port compares bytes only.
function checkSelectorPrecondition(payload, envelope) {
  if (!Object.hasOwn(payload, 'expectedSelectorBytes')) throw new Error('REPLACE_SELECTOR without expectedSelectorBytes');
  const expected = payload.expectedSelectorBytes;
  const same = expected === null ? envelope === null
    : envelope !== null && expected.length === envelope.length && expected.every((b, i) => b === envelope[i]);
  if (!same) throw selectorPreconditionFailed();
}

function makeStore() {
  const store = {
    generations: new Map(),
    selector: null,
    selectorEnvelope: null,
    sealedFor: null, // the stored plaintext object the current envelope seals
    memoryHold: null,
    applied: [],
    faults: [],
    readFault: null,
    applyCalls: 0,
  };
  const pendingRecords = new Map();
  const takeFault = (boundary, kind, mode) => {
    for (const f of store.faults) {
      if (f.remaining > 0 && f.boundary === boundary && f.kind === kind && f.mode === mode) {
        f.remaining -= 1;
        return f;
      }
    }
    return null;
  };
  const boom = (step, mode) => new Error(`injected crash ${mode} ${step.boundary}/${step.kind}`);
  // A direct test assignment of store.selector is a new durable write: it gets a new envelope.
  const currentEnvelope = () => {
    if (store.selector !== store.sealedFor) {
      store.sealedFor = store.selector;
      store.selectorEnvelope = store.selector === null ? null : sealSelector(store.selector);
    }
    return store.selectorEnvelope;
  };

  store.seed = (generations = [OLD], selector = PARENT_SELECTOR) => {
    store.generations.clear();
    pendingRecords.clear();
    for (const g of generations) {
      store.generations.set(g.generation, {
        generation: g.generation,
        records: g.records,
        manifestKey: g.manifestKey,
        manifestBytes: g.manifestBytes,
        manifestCipherDigest: g.manifestCipherDigest,
        keyedRoot: g.keyedRoot,
        sessionBindingDigest: g.sessionBindingDigest,
        mutationHold: { presence: 0 },
        escrow: null,
        resultEvidence: null,
      });
    }
    store.selector = selector === null ? null : Uint8Array.prototype.slice.call(selector);
    store.memoryHold = null;
    store.applied = [];
    store.applyCalls = 0;
    return store;
  };

  store.apply = async (step) => {
    store.applyCalls += 1;
    store.applied.push({ boundary: step.boundary, kind: step.kind });
    if (takeFault(step.boundary, step.kind, 'BEFORE')) throw boom(step, 'BEFORE');
    const { payload } = step;
    if (step.kind === 'STAGE_DATA') {
      if (!pendingRecords.has(payload.generation)) pendingRecords.set(payload.generation, new Map());
      pendingRecords.get(payload.generation).set(payload.recordKind, {
        recordKey: payload.recordKey,
        recordKind: payload.recordKind,
        plaintext: payload.plaintext,
        ciphertext: payload.ciphertext,
        tag: payload.tag,
      });
    } else if (step.kind === 'STAGE_MANIFEST') {
      const staged = pendingRecords.get(payload.generation);
      const records = staged === undefined ? [] : Array.from(staged.values());
      store.generations.set(payload.generation, {
        generation: payload.generation,
        records,
        manifestKey: payload.manifestKey,
        manifestBytes: payload.manifestBytes,
        manifestCipherDigest: payload.manifestCipherDigest,
        keyedRoot: payload.keyedRoot,
        sessionBindingDigest: payload.sessionBindingDigest,
        mutationHold: { presence: 0 },
        escrow: null,
        resultEvidence: null,
      });
    } else if (step.kind === 'STAGE_EVIDENCE') {
      const g = store.generations.get(payload.generation);
      if (g !== undefined) g.resultEvidence = payload.evidence;
    } else if (step.kind === 'STAGE_ESCROW') {
      const g = store.generations.get(payload.generation);
      if (g !== undefined) g.escrow = payload.escrow;
    } else if (step.kind === 'WRITE_HOLD') {
      const g = store.generations.get(payload.generation);
      // A conformant port stores the complete C-FMT kind-13 record in the candidate generation.
      if (g !== undefined) g.mutationHold = { ...payload.hold };
      store.memoryHold = payload.hold === null || payload.holdRecordKey === undefined || payload.holdRecordKey === null
        ? payload.hold : { ...payload.hold, recordKey: payload.holdRecordKey };
    } else if (step.kind === 'CLEAR_CANDIDATE') {
      store.generations.delete(payload.generation);
      pendingRecords.delete(payload.generation);
      store.memoryHold = null;
    } else if (step.kind === 'REPLACE_SELECTOR') {
      checkSelectorPrecondition(payload, currentEnvelope());
      store.selector = Uint8Array.prototype.slice.call(payload.selectorBytes);
      currentEnvelope();
      // The authority change is atomic with the resolution of the candidate's retained hold: the
      // selector that names a generation as authority and the tombstone of that generation's
      // unresolved hold are one durable write, so no reader ever sees a mixture.
      if (payload.resolveHoldGeneration !== null && payload.resolveHoldGeneration !== undefined) {
        const resolved = store.generations.get(payload.resolveHoldGeneration);
        if (resolved !== undefined) resolved.mutationHold = { presence: 0 };
      }
    } else if (step.kind === 'RELEASE_ESCROW') {
      store.memoryHold = null;
    }
    if (takeFault(step.boundary, step.kind, 'AFTER')) throw boom(step, 'AFTER');
    return undefined;
  };

  store.readSelector = async () => {
    if (store.readFault !== null && store.readFault.remaining > 0) {
      store.readFault.remaining -= 1;
      throw new Error('injected crash before the RS request');
    }
    const envelope = currentEnvelope();
    return store.selector === null ? null : {
      plaintext: Uint8Array.prototype.slice.call(store.selector),
      envelope: Uint8Array.prototype.slice.call(envelope),
    };
  };
  store.readGeneration = async (generation) => {
    const g = store.generations.get(generation);
    if (g === undefined) return null;
    return {
      generation: g.generation,
      records: g.records,
      manifestKey: g.manifestKey,
      manifestBytes: g.manifestBytes,
      manifestCipherDigest: g.manifestCipherDigest,
      keyedRoot: g.keyedRoot,
      sessionBindingDigest: g.sessionBindingDigest,
      mutationHold: g.mutationHold,
      escrow: g.escrow,
      resultEvidence: g.resultEvidence,
    };
  };
  store.readMemoryHold = async () => store.memoryHold;
  // Number-only inventory: every generation number with any stored artifact, complete or staged.
  store.readGenerationNumbers = async () => [...new Set([...store.generations.keys(), ...pendingRecords.keys()])];
  return store;
}

function classify(store, overrides = {}) {
  return classifyAuthority({
    storage: store,
    manifestRootKey: ROOT_KEY,
    oldGeneration: OLD_GENERATION,
    newGeneration: NEW_GENERATION,
    ...overrides,
  });
}

async function runCase(scenario, outcome, overrides = {}, storeOverrides = {}) {
  const envelope = buildMutationEnvelope(envelopeInput(scenario));
  const store = makeStore();
  store.seed(storeOverrides.generations ?? [OLD], storeOverrides.selector ?? PARENT_SELECTOR);
  if (storeOverrides.faults !== undefined) store.faults = storeOverrides.faults;
  if (storeOverrides.readFault !== undefined) store.readFault = storeOverrides.readFault;
  let result = null;
  let error = null;
  try {
    result = await runMutation({
      storage: store,
      manifestRootKey: ROOT_KEY,
      envelope,
      candidate: candidateInput(scenario, outcome, overrides.candidate),
      outcome,
      ...overrides.run,
    });
  } catch (e) {
    error = e;
  }
  return { store, result, error, envelope };
}

const ROWS_EXPECTED = [
  {
    scenario: 'CAPI-S001', operation: 'CREATE', stateBefore: 'EMPTY', stateAfterCommitted: 'ACTIVE',
    successCode: 'CREATED', outputKind: 'EMBEDDED_TREE_WELCOME', selectionEffect: 'NOT_APPLICABLE', retainedParentEffect: 'NOT_APPLICABLE',
    components: [
      { id: 'SESSION_TRANSITION', disposition: 'CHANGED', fact: 'FOUNDER_STATE' },
      { id: 'BINDING_METADATA', disposition: 'CHANGED', fact: 'INITIAL_EXACT_BINDING_AND_PROFILE' },
      { id: 'REPLAY_RETENTION_STATE', disposition: 'CHANGED', fact: 'INITIAL_BASELINE' },
      { id: 'AUTHENTICATED_MANIFEST_UPDATE', disposition: 'CHANGED', fact: 'FOUNDER_MANIFEST' },
      { id: 'COMMIT_RESULT_EVIDENCE', disposition: 'CREATED', fact: 'BOUND_TO_OPERATION_IDENTITY' },
      { id: 'OUTPUT_ESCROW', disposition: 'HELD', fact: 'EMBEDDED_TREE_WELCOME' },
    ],
  },
  {
    scenario: 'CAPI-S006', operation: 'JOIN_WELCOME', stateBefore: 'EMPTY', stateAfterCommitted: 'ACTIVE',
    successCode: 'JOINED', outputKind: 'NONE', selectionEffect: 'NOT_APPLICABLE', retainedParentEffect: 'NOT_APPLICABLE',
    components: [
      { id: 'SESSION_TRANSITION', disposition: 'CHANGED', fact: 'JOINED_STATE' },
      { id: 'BINDING_METADATA', disposition: 'CHANGED', fact: 'JOINED_EXACT_BINDING_AND_PROFILE' },
      { id: 'REPLAY_RETENTION_STATE', disposition: 'CHANGED', fact: 'JOINED_BASELINE' },
      { id: 'AUTHENTICATED_MANIFEST_UPDATE', disposition: 'CHANGED', fact: 'JOINED_MANIFEST' },
      { id: 'COMMIT_RESULT_EVIDENCE', disposition: 'CREATED', fact: 'BOUND_TO_OPERATION_IDENTITY' },
      { id: 'KEY_PACKAGE_CONSUMPTION', disposition: 'CONSUMED', fact: 'MATCHING_LOCAL_ONE_SHOT_REFERENCE' },
    ],
  },
  {
    scenario: 'CAPI-S009', operation: 'PROTECT_APPLICATION', stateBefore: 'ACTIVE', stateAfterCommitted: 'ACTIVE',
    successCode: 'APPLICATION_PROTECTED', outputKind: 'PROTECTED_APPLICATION_BYTES', selectionEffect: 'PRESERVE', retainedParentEffect: 'PRESERVE',
    components: [
      { id: 'SESSION_TRANSITION', disposition: 'CHANGED', fact: 'SENDER_RATCHET_ADVANCEMENT' },
      { id: 'BINDING_METADATA', disposition: 'UNCHANGED', fact: 'EXACT_BINDING_AND_PROFILE' },
      { id: 'REPLAY_RETENTION_STATE', disposition: 'CHANGED', fact: 'SENDER_RATCHET_RETENTION' },
      { id: 'AUTHENTICATED_MANIFEST_UPDATE', disposition: 'CHANGED', fact: 'RATCHET_STATE_MANIFEST' },
      { id: 'COMMIT_RESULT_EVIDENCE', disposition: 'CREATED', fact: 'BOUND_TO_OPERATION_IDENTITY' },
      { id: 'OUTPUT_ESCROW', disposition: 'HELD', fact: 'PROTECTED_APPLICATION_BYTES' },
      { id: 'SELECTION_METADATA', disposition: 'UNCHANGED', fact: 'EPOCH_PRESERVING_ELIGIBILITY' },
      { id: 'RETAINED_PARENT_REFERENCE', disposition: 'UNCHANGED', fact: 'PRESERVED_IF_PRESENT' },
    ],
  },
  {
    scenario: 'CAPI-S010', operation: 'OPEN_APPLICATION', stateBefore: 'ACTIVE', stateAfterCommitted: 'ACTIVE',
    successCode: 'APPLICATION_OPENED', outputKind: 'APPLICATION_BYTES', selectionEffect: 'PRESERVE', retainedParentEffect: 'PRESERVE',
    components: [
      { id: 'SESSION_TRANSITION', disposition: 'CHANGED', fact: 'RECEIVER_RATCHET_ADVANCEMENT' },
      { id: 'BINDING_METADATA', disposition: 'UNCHANGED', fact: 'EXACT_BINDING_AND_PROFILE' },
      { id: 'REPLAY_RETENTION_STATE', disposition: 'CHANGED', fact: 'REPLAY_ACCEPTANCE_AND_RECEIVER_RETENTION' },
      { id: 'AUTHENTICATED_MANIFEST_UPDATE', disposition: 'CHANGED', fact: 'RATCHET_AND_REPLAY_MANIFEST' },
      { id: 'COMMIT_RESULT_EVIDENCE', disposition: 'CREATED', fact: 'BOUND_TO_OPERATION_IDENTITY' },
      { id: 'OUTPUT_ESCROW', disposition: 'HELD', fact: 'APPLICATION_BYTES' },
      { id: 'SELECTION_METADATA', disposition: 'UNCHANGED', fact: 'EPOCH_PRESERVING_ELIGIBILITY' },
      { id: 'RETAINED_PARENT_REFERENCE', disposition: 'UNCHANGED', fact: 'PRESERVED_IF_PRESENT' },
    ],
  },
  {
    scenario: 'CAPI-S014', operation: 'SELF_UPDATE', stateBefore: 'ACTIVE', stateAfterCommitted: 'ACTIVE',
    successCode: 'SELF_UPDATED', outputKind: 'PROTECTED_COMMIT_BYTES', selectionEffect: 'ESTABLISH', retainedParentEffect: 'ESTABLISH_FOR_CAPI_S017_ONLY',
    components: [
      { id: 'SESSION_TRANSITION', disposition: 'CHANGED', fact: 'LOCAL_UPDATE_STATE' },
      { id: 'BINDING_METADATA', disposition: 'UNCHANGED', fact: 'EXACT_BINDING_AND_PROFILE' },
      { id: 'REPLAY_RETENTION_STATE', disposition: 'CHANGED', fact: 'EPOCH_WINDOW_ADVANCEMENT' },
      { id: 'AUTHENTICATED_MANIFEST_UPDATE', disposition: 'CHANGED', fact: 'LOCAL_UPDATE_MANIFEST' },
      { id: 'COMMIT_RESULT_EVIDENCE', disposition: 'CREATED', fact: 'BOUND_TO_OPERATION_IDENTITY' },
      { id: 'OUTPUT_ESCROW', disposition: 'HELD', fact: 'PROTECTED_COMMIT_BYTES' },
      { id: 'SELECTION_METADATA', disposition: 'ESTABLISHED', fact: 'IMMEDIATELY_PRECEDING_LOCAL_UPDATE_ELIGIBILITY' },
      { id: 'RETAINED_PARENT_REFERENCE', disposition: 'ESTABLISHED', fact: 'PARENT_REQUIRED_BY_CAPI_S017' },
    ],
  },
  {
    scenario: 'CAPI-S016', operation: 'APPLY_PEER_UPDATE', stateBefore: 'ACTIVE', stateAfterCommitted: 'ACTIVE',
    successCode: 'PEER_UPDATE_APPLIED', outputKind: 'NONE', selectionEffect: 'INVALIDATE', retainedParentEffect: 'INVALIDATE_SELECTION_ROLE',
    components: [
      { id: 'SESSION_TRANSITION', disposition: 'CHANGED', fact: 'PEER_UPDATE_STATE' },
      { id: 'BINDING_METADATA', disposition: 'UNCHANGED', fact: 'EXACT_BINDING_AND_PROFILE' },
      { id: 'REPLAY_RETENTION_STATE', disposition: 'CHANGED', fact: 'EPOCH_WINDOW_ADVANCEMENT' },
      { id: 'AUTHENTICATED_MANIFEST_UPDATE', disposition: 'CHANGED', fact: 'PEER_UPDATE_MANIFEST' },
      { id: 'COMMIT_RESULT_EVIDENCE', disposition: 'CREATED', fact: 'BOUND_TO_OPERATION_IDENTITY' },
      { id: 'SELECTION_METADATA', disposition: 'INVALIDATED', fact: 'ANY_CAPI_S014_ELIGIBILITY' },
      { id: 'RETAINED_PARENT_REFERENCE', disposition: 'INVALIDATED', fact: 'NO_LONGER_SELECTION_AUTHORIZING' },
      { id: 'LOSING_CANDIDATE_EVIDENCE', disposition: 'INVALIDATED', fact: 'ANY_RETAINED_LOSER_EVIDENCE' },
    ],
  },
  {
    scenario: 'CAPI-S017', operation: 'APPLY_PEER_UPDATE', stateBefore: 'ACTIVE', stateAfterCommitted: 'ACTIVE',
    successCode: 'CANDIDATE_SELECTED', outputKind: 'SELECTED_CANDIDATE_REF', selectionEffect: 'TERMINATE', retainedParentEffect: 'TERMINATE_SELECTION_ROLE',
    components: [
      { id: 'SESSION_TRANSITION', disposition: 'CHANGED_OR_UNCHANGED_BY_SELECTED_CANDIDATE', fact: 'CURRENT_WINNER_UNCHANGED_INCOMING_WINNER_CHANGED' },
      { id: 'BINDING_METADATA', disposition: 'UNCHANGED', fact: 'EXACT_BINDING_AND_PROFILE' },
      { id: 'REPLAY_RETENTION_STATE', disposition: 'CHANGED', fact: 'SELECTED_EPOCH_WINDOW' },
      { id: 'AUTHENTICATED_MANIFEST_UPDATE', disposition: 'CHANGED', fact: 'SELECTED_STATE_MANIFEST' },
      { id: 'COMMIT_RESULT_EVIDENCE', disposition: 'CREATED', fact: 'BOUND_TO_OPERATION_IDENTITY' },
      { id: 'OUTPUT_ESCROW', disposition: 'HELD', fact: 'SELECTED_CANDIDATE_REF' },
      { id: 'SELECTION_METADATA', disposition: 'TERMINATED', fact: 'NO_FURTHER_SELECTION_FROM_OLD_PARENT' },
      { id: 'RETAINED_PARENT_REFERENCE', disposition: 'TERMINATED', fact: 'NO_LONGER_SELECTION_AUTHORIZING' },
      { id: 'LOSING_CANDIDATE_EVIDENCE', disposition: 'RETAINED_NON_AUTHORITATIVE', fact: 'BOUNDED_VALID_LOSER' },
    ],
  },
];

const MAPPING = [
  { item: 'row:CAPI-S001', disposition: 'MAPPED', scenarios: ['OSC-0a9c6c696e07f086', 'OSC-0b36b4fc93c1f086', 'OSC-1de4ab26b30ee850', 'OSC-1e32d0b92bb14d1f', 'OSC-1e8cd00a29f00515', 'OSC-3025f5a196952d16', 'OSC-3400f06e4194ae2e', 'OSC-40af086284d924ed', 'OSC-597179b4ddcc6479', 'OSC-6b235583a6e17f65', 'OSC-84c65c3c3f5de73f', 'OSC-875d73f651f443a5', 'OSC-8d548f6a9ecd92fb', 'OSC-930d17946bf6c967', 'OSC-a852e6a8cda419e2', 'OSC-b4160d2a3287d977', 'OSC-b48a57c8ebff37ff', 'OSC-c359ad98204af835', 'OSC-cd7a3683e503b398', 'OSC-d3f2a15efb3e68bc', 'OSC-f11b21a14c7b04f3', 'OSC-fd726cb8d4099ec5'] },
  { item: 'row:CAPI-S001:COMMITTED', disposition: 'UNMAPPED', reason: 'the ratified O-SCEN blind set names no C-MUT commit outcome as a bound clause value: it carries the outcome only inside the three-row enum registry, which binds no observation' },
  { item: 'row:CAPI-S001:NOT_COMMITTED', disposition: 'MAPPED', scenarios: ['OSC-c99986582316e23c'] },
  { item: 'row:CAPI-S001:INDETERMINATE', disposition: 'MAPPED', scenarios: ['OSC-51567df24eb069da', 'OSC-c99986582316e23c'] },
  { item: 'hold:CAPI-S001', disposition: 'MAPPED', scenarios: ['OSC-112920325b357a7e', 'OSC-250f10c2a2c543e6', 'OSC-3ed8449397b3ffbe', 'OSC-4ef8014c76cd3087', 'OSC-51ed1457d19a4a24', 'OSC-5f9478e07be50a17'] },
  { item: 'reconciliation:CAPI-S001', disposition: 'MAPPED', scenarios: ['OSC-0cee31b5a784a715', 'OSC-10460c2c4a6b46ab', 'OSC-c99986582316e23c', 'OSC-527ea0d7ec05ac1e', 'OSC-ee1310a7fcd443b8'] },
  { item: 'row:CAPI-S006', disposition: 'MAPPED', scenarios: ['OSC-0d238b5685352693', 'OSC-11e5567a07066948', 'OSC-182925a16715ecf7', 'OSC-25242934bdd6ada6', 'OSC-3400f06e4194ae2e', 'OSC-345d9f9fb61f4c7a', 'OSC-8c7f1cf1a1c11050', 'OSC-9fc8875eeccb297a', 'OSC-c359ad98204af835', 'OSC-c99986582316e23c', 'OSC-d6ecf1bdc183c085'] },
  { item: 'row:CAPI-S006:COMMITTED', disposition: 'UNMAPPED', reason: 'the ratified O-SCEN blind set names no C-MUT commit outcome as a bound clause value: it carries the outcome only inside the three-row enum registry, which binds no observation' },
  { item: 'row:CAPI-S006:NOT_COMMITTED', disposition: 'MAPPED', scenarios: ['OSC-c99986582316e23c'] },
  { item: 'row:CAPI-S006:INDETERMINATE', disposition: 'MAPPED', scenarios: ['OSC-51567df24eb069da', 'OSC-c99986582316e23c'] },
  { item: 'hold:CAPI-S006', disposition: 'MAPPED', scenarios: ['OSC-112920325b357a7e', 'OSC-250f10c2a2c543e6', 'OSC-3ed8449397b3ffbe', 'OSC-4ef8014c76cd3087', 'OSC-51ed1457d19a4a24', 'OSC-5f9478e07be50a17'] },
  { item: 'reconciliation:CAPI-S006', disposition: 'MAPPED', scenarios: ['OSC-0cee31b5a784a715', 'OSC-10460c2c4a6b46ab', 'OSC-c99986582316e23c', 'OSC-527ea0d7ec05ac1e', 'OSC-ee1310a7fcd443b8'] },
  { item: 'row:CAPI-S009', disposition: 'MAPPED', scenarios: ['OSC-04cc306cd9846794', 'OSC-050c82981f89d599', 'OSC-1029ab9325459674', 'OSC-17716576addeb3f1', 'OSC-1aa23e70f40184bc', 'OSC-1cc072dba10a2854', 'OSC-3400f06e4194ae2e', 'OSC-3401e254e9f15e28', 'OSC-4c997dc0bf6eb84b', 'OSC-685f7964be69bbe4', 'OSC-695490a460e82efa', 'OSC-71ee405a29339504', 'OSC-7db34b0c712afc85', 'OSC-7e717b5f91a3ca2b', 'OSC-8d548f6a9ecd92fb', 'OSC-a852e6a8cda419e2', 'OSC-b5c4ed22e9e24e8d', 'OSC-bb242d983717f6c5', 'OSC-bbdaaec35cce1524', 'OSC-c359ad98204af835', 'OSC-d427cba99a720ea3', 'OSC-e275c339da596e6f'] },
  { item: 'row:CAPI-S009:COMMITTED', disposition: 'UNMAPPED', reason: 'the ratified O-SCEN blind set names no C-MUT commit outcome as a bound clause value: it carries the outcome only inside the three-row enum registry, which binds no observation' },
  { item: 'row:CAPI-S009:NOT_COMMITTED', disposition: 'MAPPED', scenarios: ['OSC-c99986582316e23c'] },
  { item: 'row:CAPI-S009:INDETERMINATE', disposition: 'MAPPED', scenarios: ['OSC-51567df24eb069da', 'OSC-c99986582316e23c'] },
  { item: 'hold:CAPI-S009', disposition: 'MAPPED', scenarios: ['OSC-112920325b357a7e', 'OSC-250f10c2a2c543e6', 'OSC-3ed8449397b3ffbe', 'OSC-4ef8014c76cd3087', 'OSC-51ed1457d19a4a24', 'OSC-5f9478e07be50a17'] },
  { item: 'reconciliation:CAPI-S009', disposition: 'MAPPED', scenarios: ['OSC-0cee31b5a784a715', 'OSC-10460c2c4a6b46ab', 'OSC-c99986582316e23c', 'OSC-527ea0d7ec05ac1e', 'OSC-ee1310a7fcd443b8'] },
  { item: 'row:CAPI-S010', disposition: 'MAPPED', scenarios: ['OSC-04cc306cd9846794', 'OSC-050c82981f89d599', 'OSC-1029ab9325459674', 'OSC-17716576addeb3f1', 'OSC-1a08e0ffd8d5ea96', 'OSC-1aa23e70f40184bc', 'OSC-1cc072dba10a2854', 'OSC-31fcaf5066f6ef17', 'OSC-3400f06e4194ae2e', 'OSC-3401e254e9f15e28', 'OSC-3ab959d8e50a26a2', 'OSC-4675f6391aa57171', 'OSC-4c997dc0bf6eb84b', 'OSC-541bd9326aef4530', 'OSC-5ed707585970798d', 'OSC-685f7964be69bbe4', 'OSC-695490a460e82efa', 'OSC-6f7a3ab9e58f6159', 'OSC-71ee405a29339504', 'OSC-78d1a8f340cad648', 'OSC-7db34b0c712afc85', 'OSC-7e717b5f91a3ca2b', 'OSC-8281eefda6850e2f', 'OSC-831f2bf06490baf4', 'OSC-8d548f6a9ecd92fb', 'OSC-99576027eb6292b2', 'OSC-a852e6a8cda419e2', 'OSC-b3f71bbe3a7db50a', 'OSC-b5c4ed22e9e24e8d', 'OSC-bb242d983717f6c5', 'OSC-bbdaaec35cce1524', 'OSC-c0241ae770e62cd6', 'OSC-c359ad98204af835', 'OSC-d40d9b6c2170f7b3', 'OSC-d427cba99a720ea3', 'OSC-d45b03d2149e9214', 'OSC-e275c339da596e6f', 'OSC-e2871dc4bd750ba4', 'OSC-eafd401729822193', 'OSC-f3196edee41e7f5e'] },
  { item: 'row:CAPI-S010:COMMITTED', disposition: 'UNMAPPED', reason: 'the ratified O-SCEN blind set names no C-MUT commit outcome as a bound clause value: it carries the outcome only inside the three-row enum registry, which binds no observation' },
  { item: 'row:CAPI-S010:NOT_COMMITTED', disposition: 'MAPPED', scenarios: ['OSC-c99986582316e23c'] },
  { item: 'row:CAPI-S010:INDETERMINATE', disposition: 'MAPPED', scenarios: ['OSC-51567df24eb069da', 'OSC-c99986582316e23c'] },
  { item: 'hold:CAPI-S010', disposition: 'MAPPED', scenarios: ['OSC-112920325b357a7e', 'OSC-250f10c2a2c543e6', 'OSC-3ed8449397b3ffbe', 'OSC-4ef8014c76cd3087', 'OSC-51ed1457d19a4a24', 'OSC-5f9478e07be50a17'] },
  { item: 'reconciliation:CAPI-S010', disposition: 'MAPPED', scenarios: ['OSC-0cee31b5a784a715', 'OSC-10460c2c4a6b46ab', 'OSC-c99986582316e23c', 'OSC-527ea0d7ec05ac1e', 'OSC-ee1310a7fcd443b8'] },
  { item: 'row:CAPI-S014', disposition: 'MAPPED', scenarios: ['OSC-04738fa7ac2291cd', 'OSC-128bf4a039055481', 'OSC-24ca2258e98b5e59', 'OSC-31f0021b23bf7538', 'OSC-3400f06e4194ae2e', 'OSC-55b81d35adc0364c', 'OSC-55e536517e005ce7', 'OSC-6a70b695d4208a1f', 'OSC-700c1ae9277784ba', 'OSC-81f17aae8cb70ff5', 'OSC-8d548f6a9ecd92fb', 'OSC-a0ced4d7fa79adad', 'OSC-a64784c52329ee2c', 'OSC-a852e6a8cda419e2', 'OSC-be27ec8a776e557e', 'OSC-c359ad98204af835', 'OSC-dfd3d9a47d9b0152', 'OSC-e44bc308ffade4f8', 'OSC-e61f0562a8141183', 'OSC-f0cb026186adfe24', 'OSC-f5d08a775c94816a', 'OSC-f8e42479496626f8'] },
  { item: 'row:CAPI-S014:COMMITTED', disposition: 'UNMAPPED', reason: 'the ratified O-SCEN blind set names no C-MUT commit outcome as a bound clause value: it carries the outcome only inside the three-row enum registry, which binds no observation' },
  { item: 'row:CAPI-S014:NOT_COMMITTED', disposition: 'MAPPED', scenarios: ['OSC-c99986582316e23c'] },
  { item: 'row:CAPI-S014:INDETERMINATE', disposition: 'MAPPED', scenarios: ['OSC-51567df24eb069da', 'OSC-c99986582316e23c'] },
  { item: 'hold:CAPI-S014', disposition: 'MAPPED', scenarios: ['OSC-112920325b357a7e', 'OSC-250f10c2a2c543e6', 'OSC-3ed8449397b3ffbe', 'OSC-4ef8014c76cd3087', 'OSC-51ed1457d19a4a24', 'OSC-5f9478e07be50a17'] },
  { item: 'reconciliation:CAPI-S014', disposition: 'MAPPED', scenarios: ['OSC-0cee31b5a784a715', 'OSC-10460c2c4a6b46ab', 'OSC-c99986582316e23c', 'OSC-527ea0d7ec05ac1e', 'OSC-ee1310a7fcd443b8'] },
  { item: 'row:CAPI-S016', disposition: 'MAPPED', scenarios: ['OSC-3400f06e4194ae2e', 'OSC-345d9f9fb61f4c7a', 'OSC-43bc2f410abce99b', 'OSC-4a35f605fe18b4a1', 'OSC-66ad56eda1ee122d', 'OSC-9fc8875eeccb297a', 'OSC-c99986582316e23c'] },
  { item: 'row:CAPI-S016:COMMITTED', disposition: 'UNMAPPED', reason: 'the ratified O-SCEN blind set names no C-MUT commit outcome as a bound clause value: it carries the outcome only inside the three-row enum registry, which binds no observation' },
  { item: 'row:CAPI-S016:NOT_COMMITTED', disposition: 'MAPPED', scenarios: ['OSC-c99986582316e23c'] },
  { item: 'row:CAPI-S016:INDETERMINATE', disposition: 'MAPPED', scenarios: ['OSC-51567df24eb069da', 'OSC-c99986582316e23c'] },
  { item: 'hold:CAPI-S016', disposition: 'MAPPED', scenarios: ['OSC-112920325b357a7e', 'OSC-250f10c2a2c543e6', 'OSC-3ed8449397b3ffbe', 'OSC-4ef8014c76cd3087', 'OSC-51ed1457d19a4a24', 'OSC-5f9478e07be50a17'] },
  { item: 'reconciliation:CAPI-S016', disposition: 'MAPPED', scenarios: ['OSC-0cee31b5a784a715', 'OSC-10460c2c4a6b46ab', 'OSC-c99986582316e23c', 'OSC-527ea0d7ec05ac1e', 'OSC-ee1310a7fcd443b8'] },
  { item: 'row:CAPI-S017', disposition: 'MAPPED', scenarios: ['OSC-12b7a5ba00f42584', 'OSC-1378eefba98c3bd6', 'OSC-15ab3ed907be546d', 'OSC-1fe113241f2c9918', 'OSC-3400f06e4194ae2e', 'OSC-3437bea23599b7a8', 'OSC-3d72f930d4889668', 'OSC-5f3965bf73f28403', 'OSC-78cb88bff97774de', 'OSC-8d548f6a9ecd92fb', 'OSC-91a80dfc04637543', 'OSC-a4649178d11d8442', 'OSC-a49834cd1e212b4b', 'OSC-a852e6a8cda419e2', 'OSC-b5d4b1bb18b6c450', 'OSC-bb5dd5c0a6aeb984', 'OSC-c359ad98204af835', 'OSC-c9063ada2ad882b2', 'OSC-d534e533becc26b6', 'OSC-de916ead32d92304', 'OSC-ecfeb9e6b5e0ce4e', 'OSC-ee25153e1020e020'] },
  { item: 'row:CAPI-S017:COMMITTED', disposition: 'UNMAPPED', reason: 'the ratified O-SCEN blind set names no C-MUT commit outcome as a bound clause value: it carries the outcome only inside the three-row enum registry, which binds no observation' },
  { item: 'row:CAPI-S017:NOT_COMMITTED', disposition: 'MAPPED', scenarios: ['OSC-c99986582316e23c'] },
  { item: 'row:CAPI-S017:INDETERMINATE', disposition: 'MAPPED', scenarios: ['OSC-51567df24eb069da', 'OSC-c99986582316e23c'] },
  { item: 'hold:CAPI-S017', disposition: 'MAPPED', scenarios: ['OSC-112920325b357a7e', 'OSC-250f10c2a2c543e6', 'OSC-3ed8449397b3ffbe', 'OSC-4ef8014c76cd3087', 'OSC-51ed1457d19a4a24', 'OSC-5f9478e07be50a17'] },
  { item: 'reconciliation:CAPI-S017', disposition: 'MAPPED', scenarios: ['OSC-0cee31b5a784a715', 'OSC-10460c2c4a6b46ab', 'OSC-c99986582316e23c', 'OSC-527ea0d7ec05ac1e', 'OSC-ee1310a7fcd443b8'] },
  { item: 'boundary:BEFORE_STAGING', disposition: 'MAPPED', scenarios: ['OSC-2710110ec6e695f2', 'OSC-4818f75fc23c5086', 'OSC-c40f165d4c9d88eb'] },
  { item: 'boundary:AFTER_CANDIDATE_COMPUTATION', disposition: 'MAPPED', scenarios: ['OSC-716a648405acf45a', 'OSC-c40f165d4c9d88eb', 'OSC-cf85a9910593f32a'] },
  { item: 'boundary:AFTER_LOCAL_STAGING', disposition: 'MAPPED', scenarios: ['OSC-17a6efef854703e6', 'OSC-3514faaba88506e0', 'OSC-c40f165d4c9d88eb'] },
  { item: 'boundary:BEFORE_RS_REQUEST', disposition: 'MAPPED', scenarios: ['OSC-5838d127ddc39f84', 'OSC-824783bb7f44ea9e', 'OSC-c40f165d4c9d88eb'] },
  { item: 'boundary:DURING_RS_WORK', disposition: 'MAPPED', scenarios: ['OSC-24d8eed2fef4e042', 'OSC-c40f165d4c9d88eb', 'OSC-e6ac4808436fd6c3'] },
  { item: 'boundary:AFTER_DURABLE_COMMIT_BEFORE_RESPONSE', disposition: 'MAPPED', scenarios: ['OSC-8c6968efb4972ccf', 'OSC-acab7219eeca9917', 'OSC-c40f165d4c9d88eb'] },
  { item: 'boundary:AFTER_NOT_COMMITTED', disposition: 'MAPPED', scenarios: ['OSC-04daae56d1686d3c', 'OSC-ba753d4e25faf8fe', 'OSC-c40f165d4c9d88eb'] },
  { item: 'boundary:AFTER_INDETERMINATE', disposition: 'MAPPED', scenarios: ['OSC-197803331ac04575', 'OSC-383576cc06aa6682', 'OSC-c40f165d4c9d88eb'] },
  { item: 'boundary:DURING_RECONCILIATION', disposition: 'MAPPED', scenarios: ['OSC-bf4855c2df040ada', 'OSC-c40f165d4c9d88eb', 'OSC-fec29af8fbaaa48a'] },
  { item: 'boundary:AFTER_AUTHORITY_SELECTION_BEFORE_OUTPUT_RESPONSE', disposition: 'MAPPED', scenarios: ['OSC-bc0dd0fb1ca69f07', 'OSC-be1ddafca3e7c023', 'OSC-c40f165d4c9d88eb'] },
  { item: 'boundary:DURING_ESCROW_OUTPUT_RESPONSE', disposition: 'MAPPED', scenarios: ['OSC-6086dd97b6ef94b0', 'OSC-9074aa99f04bd4fd', 'OSC-c40f165d4c9d88eb'] },
  { item: 'boundary:AFTER_OUTPUT_RESPONSE_LOSS', disposition: 'MAPPED', scenarios: ['OSC-015e75cc45c2e13a', 'OSC-41e96513fc49f21a', 'OSC-c40f165d4c9d88eb'] },
];

// ---------------------------------------------------------------------------------------------
// Constants and row fidelity.
// ---------------------------------------------------------------------------------------------

describe('M2_TXN constants', () => {
  test('the closed constant surface is frozen and complete', () => {
    expect(Object.isFrozen(M2_TXN)).toBe(true);
    expect(M2_TXN.ROW_COUNT).toBe(7);
    expect(M2_TXN.BOUNDARY_COUNT).toBe(12);
    expect(M2_TXN.COMPONENT_COUNT).toBe(10);
    expect(M2_TXN.SCENARIOS).toHaveLength(7);
    expect(M2_TXN.BOUNDARIES).toHaveLength(12);
    expect(Object.isFrozen(M2_TXN.STORAGE_METHODS)).toBe(true);
    expect(M2_TXN.STORAGE_METHODS).toEqual(['apply', 'readSelector', 'readGeneration', 'readMemoryHold', 'readGenerationNumbers']);
    expect(M2_TXN.AUTOMATIC_ROWS).toEqual(['CAPI-S006']);
    expect(M2_OUTCOME).toEqual({ COMMITTED: 1, NOT_COMMITTED: 2, INDETERMINATE: 3 });
  });

  test('every C-MUT mutation row is reproduced exactly', () => {
    expect(ROWS_EXPECTED).toHaveLength(7);
    for (const expected of ROWS_EXPECTED) {
      expect(mutationRow(expected.scenario)).toEqual(expected);
    }
  });

  test('the row surface rejects anything that is not a C-MUT row', () => {
    for (const bad of ['CAPI-S002', 'capi-s001', '', null, 1, {}, ['CAPI-S001']]) {
      expect(() => mutationRow(bad)).toThrow(M2TxnError);
      expect(() => mutationRow(bad)).toThrow(/unknown C-MUT mutation row/);
    }
  });

  test('a returned row is deeply frozen', () => {
    const row = mutationRow('CAPI-S001');
    expect(Object.isFrozen(row)).toBe(true);
    expect(Object.isFrozen(row.components)).toBe(true);
    expect(Object.isFrozen(row.components[0])).toBe(true);
  });
});


// ---------------------------------------------------------------------------------------------
// Step plans.
// ---------------------------------------------------------------------------------------------

describe('mutationSteps', () => {
  const planFor = (scenario, outcome, phase, overrides = {}) => mutationSteps({
    envelope: buildMutationEnvelope(envelopeInput(scenario)),
    candidate: planInput(scenario, outcome, overrides),
    outcome,
    phase,
  });

  test('the plan is frozen, indexed and carries only the closed boundary and step-kind sets', () => {
    const plan = planFor('CAPI-S001', M2_OUTCOME.COMMITTED, 'ORIGINAL');
    expect(Object.isFrozen(plan)).toBe(true);
    plan.forEach((step, i) => {
      expect(Object.isFrozen(step)).toBe(true);
      expect(step.index).toBe(i);
      expect(M2_TXN.BOUNDARIES).toContain(step.boundary);
      expect(Object.isFrozen(step.payload)).toBe(true);
    });
  });

  test('the plan is deterministic: identical inputs produce an identical plan', () => {
    const a = planFor('CAPI-S009', M2_OUTCOME.COMMITTED, 'ORIGINAL');
    const b = planFor('CAPI-S009', M2_OUTCOME.COMMITTED, 'ORIGINAL');
    expect(JSON.stringify(a.map((s) => [s.boundary, s.kind]))).toBe(JSON.stringify(b.map((s) => [s.boundary, s.kind])));
  });

  test('exactly one authority-changing selector replacement exists in the whole step surface', () => {
    for (const scenario of M2_TXN.SCENARIOS) {
      for (const outcome of [1, 2, 3]) {
        for (const phase of ['ORIGINAL', 'RECONCILIATION']) {
          const plan = planFor(scenario, outcome, phase);
          const replacements = plan.filter((s) => s.kind === 'REPLACE_SELECTOR');
          const authority = replacements.filter((s) => s.boundary === 'AFTER_DURABLE_COMMIT_BEFORE_RESPONSE');
          expect(authority.length).toBe(outcome === 1 && phase === 'ORIGINAL' ? 1 : 0);
          expect(replacements.length).toBeLessThanOrEqual(2);
        }
      }
    }
  });

  test('every one of the twelve C-MUT crash boundaries is carried by some plan step', () => {
    const seen = new Set();
    for (const scenario of M2_TXN.SCENARIOS) {
      for (const outcome of [1, 2, 3]) {
        for (const phase of ['ORIGINAL', 'RECONCILIATION']) {
          for (const step of planFor(scenario, outcome, phase)) seen.add(step.boundary);
        }
      }
    }
    expect(Array.from(seen).sort()).toEqual([...M2_TXN.BOUNDARIES].sort());
  });

  test('every row stages exactly the fifteen data kinds once and the manifest before any selector write', () => {
    for (const scenario of M2_TXN.SCENARIOS) {
      const plan = planFor(scenario, M2_OUTCOME.COMMITTED, 'ORIGINAL');
      const kinds = plan.filter((s) => s.kind === 'STAGE_DATA').map((s) => s.payload.recordKind);
      expect(kinds).toEqual(DATA_KINDS);
      const manifestIndex = plan.findIndex((s) => s.kind === 'STAGE_MANIFEST');
      const manifestStep = plan.find((s) => s.kind === 'STAGE_MANIFEST');
      const selectorIndex = plan.findIndex((s) => s.kind === 'REPLACE_SELECTOR');
      expect(manifestStep.boundary).toBe('DURING_RS_WORK');
      expect(manifestIndex).toBeLessThan(selectorIndex);
    }
  });

  test('the escrow step exists exactly for the rows whose C-MUT output kind is not NONE', () => {
    for (const scenario of M2_TXN.SCENARIOS) {
      const row = mutationRow(scenario);
      const plan = planFor(scenario, M2_OUTCOME.COMMITTED, 'ORIGINAL');
      const escrows = plan.filter((s) => ['STAGE_ESCROW', 'RELEASE_ESCROW'].includes(s.kind));
      expect(escrows.length).toBe(row.outputKind === 'NONE' ? 0 : 2);
    }
  });

  test('a NOT_COMMITTED plan never replaces the selector in the original phase', () => {
    for (const scenario of M2_TXN.SCENARIOS) {
      const plan = planFor(scenario, M2_OUTCOME.NOT_COMMITTED, 'ORIGINAL');
      expect(plan.filter((s) => s.kind === 'REPLACE_SELECTOR')).toHaveLength(0);
      expect(plan.map((s) => s.kind)).toContain('CLEAR_CANDIDATE');
    }
  });

  test('an INDETERMINATE plan binds the retained candidate through one selector replacement', () => {
    for (const scenario of M2_TXN.SCENARIOS) {
      const plan = mutationSteps({
        envelope: buildMutationEnvelope(envelopeInput(scenario)),
        candidate: { ...planInput(scenario, M2_OUTCOME.INDETERMINATE), mutationHold: holdRecordFor(scenario) },
        outcome: M2_OUTCOME.INDETERMINATE,
        phase: 'ORIGINAL',
      });
      const holds = plan.filter((s) => s.kind === 'WRITE_HOLD');
      const replacements = plan.filter((s) => s.kind === 'REPLACE_SELECTOR');
      expect(holds).toHaveLength(1);
      expect(holds[0].boundary).toBe('DURING_RS_WORK');
      expect(holds[0].payload.hold.presence).toBe(1);
      expect(holds[0].payload.hold.resultStatus).toBe(M2_OUTCOME.INDETERMINATE);
      expect(replacements).toHaveLength(1);
      expect(replacements[0].boundary).toBe('AFTER_INDETERMINATE');
      const held = decodePlaintext(M2_KIND.GENERATION_SELECTOR, replacements[0].payload.selectorBytes);
      expect(held.state).toBe(3);
      expect(held.generation).toBe(OLD_GENERATION);
      expect(held.generation).not.toBe(held.candidateGeneration);
    }
  });

  test('a reconciliation plan never re-stages a transition or a security-sensitive candidate byte', () => {
    for (const scenario of M2_TXN.SCENARIOS) {
      for (const outcome of [1, 2, 3]) {
        const plan = planFor(scenario, outcome, 'RECONCILIATION');
        for (const step of plan) {
          expect(['STAGE_DATA', 'STAGE_MANIFEST', 'STAGE_EVIDENCE', 'STAGE_ESCROW', 'WRITE_HOLD'])
            .not.toContain(step.kind);
          expect(step.boundary).not.toBe('BEFORE_STAGING');
        }
      }
    }
  });

  test('the plan builder rejects an unknown phase and an unbound row', () => {
    expect(() => mutationSteps({
      envelope: buildMutationEnvelope(envelopeInput('CAPI-S001')),
      candidate: planInput('CAPI-S001', 1),
      outcome: 1,
      phase: 'MAYBE',
    })).toThrow(/phase is not ORIGINAL or RECONCILIATION/);
    expect(() => mutationSteps({
      envelope: buildMutationEnvelope(envelopeInput('CAPI-S001')),
      candidate: planInput('CAPI-S001', 1),
      outcome: 9,
      phase: 'ORIGINAL',
    })).toThrow(/not a defined C-MUT commit outcome/);
  });
});

// ---------------------------------------------------------------------------------------------
// Envelope formation.
// ---------------------------------------------------------------------------------------------

describe('buildMutationEnvelope', () => {
  test('a complete row-bound envelope is accepted, frozen and identity-normalised', () => {
    for (const scenario of M2_TXN.SCENARIOS) {
      const envelope = buildMutationEnvelope(envelopeInput(scenario));
      expect(Object.isFrozen(envelope)).toBe(true);
      expect(envelope.scenario).toBe(scenario);
      expect(envelope.operationIdentity).toEqual({
        value: expect.any(Uint8Array), assignedBy: 'SS_RS', fresh: true, reusable: false, apRequestIdEqual: false,
      });
      expect(envelope.componentSet.entries).toEqual(mutationRow(scenario).components);
    }
  });

  const badIdentities = [
    ['an application-originated identity', { assignedBy: 'AP' }],
    ['a non-fresh identity', { fresh: false }],
    ['a reusable identity', { reusable: true }],
    ['an identity equal to the C-API request id', { apRequestIdEqual: true }],
    ['an all-zero identity', { value: new Uint8Array(32) }],
    ['a short identity', { value: new Uint8Array(31) }],
  ];
  test.each(badIdentities)('%s is rejected before any RS request', (_name, patch) => {
    const input = envelopeInput('CAPI-S001');
    input.operationIdentity = { ...input.operationIdentity, ...patch };
    expect(() => buildMutationEnvelope(input)).toThrow(M2TxnError);
  });

  test('a held output with no verifiable bytes must be exactly NONE/null/null', () => {
    const input = envelopeInput('CAPI-S001');
    input.heldOutput = { kind: 'NONE', digest: bytesOf(32, 1), reference: null };
    expect(() => buildMutationEnvelope(input)).toThrow(/NONE held output requires a null digest/);
  });

  test('a non-NONE held output must carry both digest and reference', () => {
    const input = envelopeInput('CAPI-S001');
    input.heldOutput = { kind: 'EMBEDDED_TREE_WELCOME', digest: null, reference: bytesOf(32, 1) };
    expect(() => buildMutationEnvelope(input)).toThrow(M2TxnError);
  });

  test('the envelope must be bound to its own selected row', () => {
    const wrongOperation = envelopeInput('CAPI-S001');
    wrongOperation.operation = 'RESTORE';
    expect(() => buildMutationEnvelope(wrongOperation)).toThrow(/not bound to its selected C-MUT row/);

    const wrongState = envelopeInput('CAPI-S001');
    wrongState.originalApiState = 'ACTIVE';
    expect(() => buildMutationEnvelope(wrongState)).toThrow(/not bound to its selected C-MUT row/);

    const wrongComponents = envelopeInput('CAPI-S001');
    wrongComponents.componentSet.entries = wrongComponents.componentSet.entries.slice(0, 5);
    expect(() => buildMutationEnvelope(wrongComponents)).toThrow(/not bound to its selected C-MUT row/);

    const reordered = envelopeInput('CAPI-S009');
    reordered.componentSet.entries = [...reordered.componentSet.entries].reverse();
    expect(() => buildMutationEnvelope(reordered)).toThrow(/not bound to its selected C-MUT row/);
  });

  test('the envelope is closed: unknown, missing and symbol keys are rejected', () => {
    const extra = { ...envelopeInput('CAPI-S001'), extra: 1 };
    expect(() => buildMutationEnvelope(extra)).toThrow(/unknown, missing, or symbol property/);
    const missing = envelopeInput('CAPI-S001');
    delete missing.reconciliationIdentity;
    expect(() => buildMutationEnvelope(missing)).toThrow(/unknown, missing, or symbol property/);
    const symbol = envelopeInput('CAPI-S001');
    symbol[Symbol('x')] = 1;
    expect(() => buildMutationEnvelope(symbol)).toThrow(/unknown, missing, or symbol property/);
  });

  test('an unknown operation, scenario, output kind or success code is rejected', () => {
    const cases = [
      ['operation', 'LAUNCH'],
      ['scenario', 'CAPI-S999'],
    ];
    for (const [field, value] of cases) {
      expect(() => buildMutationEnvelope(envelopeInput('CAPI-S001', { [field]: value })))
        .toThrow(/not a defined value/);
    }
  });

  test('an application-owned reconciliation identity is rejected', () => {
    const input = envelopeInput('CAPI-S001');
    input.reconciliationIdentity = { reference: bytesOf(32, 1), owner: 'AP' };
    expect(() => buildMutationEnvelope(input)).toThrow(/owned by SS_RS/);
  });
});

// ---------------------------------------------------------------------------------------------
// Commit-result evidence.
// ---------------------------------------------------------------------------------------------

describe('validateCommitResultEvidence', () => {
  const envelope = buildMutationEnvelope(envelopeInput('CAPI-S001'));

  test('evidence whose every identity field matches the envelope is accepted', () => {
    for (const outcome of [1, 2, 3]) {
      const evidence = validateCommitResultEvidence({ evidence: evidenceFor(envelope, outcome), envelope });
      expect(evidence.outcome).toBe(outcome);
      expect(Object.isFrozen(evidence)).toBe(true);
    }
  });

  const mutations = [
    ['operationIdentity', bytesOf(32, 0xf1)],
    ['originalAuthorityDigest', bytesOf(32, 0xf2)],
    ['originalAuthorityReference', bytesOf(32, 0xf3)],
    ['candidateDigest', bytesOf(32, 0xf4)],
    ['candidateReference', bytesOf(32, 0xf5)],
    ['mutationSetDigest', bytesOf(32, 0xf6)],
    ['mutationSetReference', bytesOf(32, 0xf7)],
    ['bindingRef', bytesOf(32, 0xf8)],
    ['profile', bytesOf(32, 0xf9)],
  ];
  test.each(mutations)('evidence with a foreign %s is rejected and selects nothing', (field, value) => {
    expect(() => validateCommitResultEvidence({
      evidence: evidenceFor(envelope, 1, { [field]: value }), envelope,
    })).toThrow(/does not match the envelope/);
  });

  test('evidence with a foreign expected original state is rejected', () => {
    expect(() => validateCommitResultEvidence({
      evidence: evidenceFor(envelope, 1, { expectedOriginalState: 2 }), envelope,
    })).toThrow(/expected original state does not match the envelope/);
  });

  test('evidence not authenticated by RS is rejected', () => {
    expect(() => validateCommitResultEvidence({
      evidence: evidenceFor(envelope, 1, { authenticatedByRS: false }), envelope,
    })).toThrow(/must be authenticated by RS/);
  });

  test('a NOT_COMMITTED result is accepted only from terminal evidence', () => {
    expect(() => validateCommitResultEvidence({
      evidence: evidenceFor(envelope, 2, { terminal: false }), envelope,
    })).toThrow(M2TxnError);
    expect(() => validateCommitResultEvidence({
      evidence: evidenceFor(envelope, 2, { terminal: false }), envelope,
    })).toThrow(/only from terminal evidence/);
  });

  test('evidence is closed and cannot smuggle an extra application-supplied outcome', () => {
    const evidence = { ...evidenceFor(envelope, 1), apOutcome: 1 };
    expect(() => validateCommitResultEvidence({ evidence, envelope })).toThrow(/unknown, missing, or symbol property/);
  });
});


// ---------------------------------------------------------------------------------------------
// The acceptance sweep. Every step of every row's plan of every outcome is faulted in both modes.
//
// The C-MUT crash boundaries are logical points in a transaction, not all durable writes, so the
// sweep realises each boundary at the step that follows it in the plan:
//   * a durable step is faulted through the injected port before and after its durable effect;
//   * a memory-only step before the first RS request is faulted through the port's read path, the
//     only port interaction available at that point, so nothing durable is attempted;
//   * a memory-only step after a durable step is realised by the after-effect fault of the durable
//     step immediately before it, which leaves exactly the same stored bytes;
//   * the INDETERMINATE plan replaces the selector at AFTER_INDETERMINATE while the named authority
//     stays the old generation, so a fault there must still read back as the complete old generation.
// After every fault the stored state must be exactly the complete old generation or exactly the
// complete new generation, never a mixture, and no result may be reported.
// ---------------------------------------------------------------------------------------------

const PRE_REQUEST_BOUNDARIES = new Set([
  'BEFORE_STAGING', 'AFTER_CANDIDATE_COMPUTATION', 'AFTER_LOCAL_STAGING', 'BEFORE_RS_REQUEST',
]);

const selectorGeneration = (store) => {
  if (store.selector === null) return null;
  const selector = decodePlaintext(M2_KIND.GENERATION_SELECTOR, store.selector);
  return selector.generation;
};

const SWEEP = {
  cases: 0, durableFaults: 0, readAborts: 0, reconciliationFaults: 0, byBoundary: {},
};

const record = (boundary) => { SWEEP.byBoundary[boundary] = (SWEEP.byBoundary[boundary] ?? 0) + 1; };

function realisedBoundaries(step, durable, outcome) {
  const realised = [];
  if (step.kind === 'REPLACE_SELECTOR' && outcome === M2_OUTCOME.COMMITTED) {
    realised.push('AFTER_AUTHORITY_SELECTION_BEFORE_OUTPUT_RESPONSE');
  }
  if (step.kind === 'CLEAR_CANDIDATE') realised.push('AFTER_NOT_COMMITTED');
  if (step === durable[durable.length - 1]) realised.push('AFTER_OUTPUT_RESPONSE_LOSS');
  return realised;
}

describe('acceptance sweep over every plan step', () => {
  for (const scenario of M2_TXN.SCENARIOS) {
    for (const outcome of [1, 2, 3]) {
      test(`${scenario} / outcome ${outcome}: every step boundary leaves exactly one complete generation`, async () => {
        const plan = mutationSteps({
          envelope: buildMutationEnvelope(envelopeInput(scenario)),
          candidate: planInput(scenario, outcome),
          outcome,
          phase: 'ORIGINAL',
        });
        const durable = plan.filter((s) => !MEMORY_ONLY_KINDS.has(s.kind));
        expect(durable.length).toBeGreaterThan(0);
        for (const step of durable) {
          for (const mode of ['BEFORE', 'AFTER']) {
            const { store, result, error, envelope } = await runCase(scenario, outcome, {}, {
              faults: [{ boundary: step.boundary, kind: step.kind, mode, remaining: 1 }],
            });
            SWEEP.cases += 1;
            SWEEP.durableFaults += 1;
            record(step.boundary);
            if (mode === 'AFTER') for (const b of realisedBoundaries(step, durable, outcome)) record(b);

            // The fault must be reported, and no result may be returned on a fault.
            expect(error).not.toBeNull();
            expect(result).toBeNull();

            const named = selectorGeneration(store);
            const classification = await classify(store);
            expect(['COMPLETE_OLD', 'COMPLETE_NEW']).toContain(classification.authority);
            // The readback must agree with the authority the storage actually names, never with a guess.
            expect(classification.authority).toBe(named === NEW_GENERATION ? 'COMPLETE_NEW' : 'COMPLETE_OLD');
            expect(classification.generation).toBe(named);

            if (classification.authority === 'COMPLETE_OLD') {
              // C-MUT /crashBoundaries: exactly COMPLETE_OLD with no hold, or OLD_PLUS_ONE_IMMUTABLE_HOLD
              // bound durably by a RECONCILIATION_REQUIRED selector. Never an unbound memory-only hold.
              if (classification.held) {
                expect(hex(store.selector)).toBe(hex(HOLD_SELECTOR));
                expect(store.memoryHold).not.toBeNull();
                expect(store.memoryHold.resultStatus).toBe(M2_OUTCOME.INDETERMINATE);
                // After an SS restart (memory lost) the durable hold alone is reconcilable.
                store.memoryHold = null;
                const evidence = evidenceFor(envelope, M2_OUTCOME.NOT_COMMITTED, { terminal: true });
                const r = await reconcileIndeterminate({
                  storage: store, manifestRootKey: ROOT_KEY, hold: null, evidence,
                  reference: holdRecordFor(scenario).reconciliationReference,
                });
                expect(r.reconciliation).toBe('NOT_COMMITTED');
                expect(store.memoryHold).toBeNull();
                const after = await classify(store);
                expect(after.authority).toBe('COMPLETE_OLD');
                expect(after.held).toBe(false);
              } else {
                expect(hex(store.selector)).toBe(hex(PARENT_SELECTOR));
                expect(store.memoryHold).toBeNull();
              }
            } else {
              // A complete new authority is selected: the committed evidence is present.
              const generation = await store.readGeneration(NEW_GENERATION);
              expect(generation).not.toBeNull();
              expect(generation.resultEvidence).not.toBeNull();
            }
          }
        }

        // A crash inside a memory-only step before the first RS request: nothing durable is attempted,
        // the complete old authority is untouched and no hold exists.
        for (const step of plan.filter((s) => MEMORY_ONLY_KINDS.has(s.kind) && PRE_REQUEST_BOUNDARIES.has(s.boundary))) {
          const { store, result, error } = await runCase(scenario, outcome, {}, { readFault: { remaining: 1 } });
          SWEEP.cases += 1;
          SWEEP.readAborts += 1;
          record(step.boundary);
          expect(error).not.toBeNull();
          expect(result).toBeNull();
          expect(store.applyCalls).toBe(0);
          expect(hex(store.selector)).toBe(hex(PARENT_SELECTOR));
          expect(store.memoryHold).toBeNull();
          expect((await classify(store)).authority).toBe('COMPLETE_OLD');
        }
      });
    }
  }

  for (const scenario of M2_TXN.SCENARIOS) {
    for (const outcome of [1, 2, 3]) {
      const reconciliation = mutationSteps({
        envelope: buildMutationEnvelope(envelopeInput(scenario)),
        candidate: planInput(scenario, outcome),
        outcome,
        phase: 'RECONCILIATION',
      });
      const durable = reconciliation.filter((s) => !MEMORY_ONLY_KINDS.has(s.kind));
      if (durable.length === 0) continue;
      test(`${scenario} / outcome ${outcome}: every reconciliation step boundary leaves one complete generation`, async () => {
        for (const step of durable) {
          for (const mode of ['BEFORE', 'AFTER']) {
            const { store, envelope, hold } = await pendingHold(scenario);
            const evidence = outcome === M2_OUTCOME.NOT_COMMITTED
              ? evidenceFor(envelope, M2_OUTCOME.NOT_COMMITTED, { terminal: true })
              : evidenceFor(envelope, M2_OUTCOME.COMMITTED, { terminal: true });
            store.faults = [{ boundary: step.boundary, kind: step.kind, mode, remaining: 1 }];
            let error = null;
            try {
              await reconcileIndeterminate({
                storage: store, manifestRootKey: ROOT_KEY, hold, evidence,
                reference: hold.reconciliationReference,
              });
            } catch (e) {
              error = e;
            }
            SWEEP.cases += 1;
            SWEEP.reconciliationFaults += 1;
            record(step.boundary);
            expect(error).not.toBeNull();
            const named = selectorGeneration(store);
            const classification = await classify(store);
            expect(classification.authority).toBe(named === NEW_GENERATION ? 'COMPLETE_NEW' : 'COMPLETE_OLD');
          }
        }
      });
    }
  }

  test('the sweep actually covered every plan step of every row and outcome', () => {
    let expected = 0;
    for (const scenario of M2_TXN.SCENARIOS) {
      for (const outcome of [1, 2, 3]) {
        const plan = mutationSteps({
          envelope: buildMutationEnvelope(envelopeInput(scenario)),
          candidate: planInput(scenario, outcome),
          outcome,
          phase: 'ORIGINAL',
        });
        expected += plan.filter((s) => !MEMORY_ONLY_KINDS.has(s.kind)).length * 2;
        expected += plan.filter((s) => MEMORY_ONLY_KINDS.has(s.kind) && PRE_REQUEST_BOUNDARIES.has(s.boundary)).length;
        const reconciliation = mutationSteps({
          envelope: buildMutationEnvelope(envelopeInput(scenario)),
          candidate: planInput(scenario, outcome),
          outcome,
          phase: 'RECONCILIATION',
        });
        expected += reconciliation.filter((s) => !MEMORY_ONLY_KINDS.has(s.kind)).length * 2;
      }
    }
    expect(SWEEP.cases).toBe(expected);
    expect(SWEEP.cases).toBeGreaterThan(500);
    for (const boundary of M2_TXN.BOUNDARIES) {
      expect(SWEEP.byBoundary[boundary]).toBeGreaterThan(0);
    }
    expect(SWEEP.durableFaults).toBeGreaterThan(0);
    expect(SWEEP.readAborts).toBe(7 * 3 * 4);
    expect(SWEEP.reconciliationFaults).toBeGreaterThan(0);
    const byBoundary = Object.keys(SWEEP.byBoundary).sort().map((b) => `${b}=${SWEEP.byBoundary[b]}`).join(' ');
    console.log(`acceptance sweep size: ${SWEEP.cases} faulted cases `
      + `(durable before/after ${SWEEP.durableFaults}, pre-request read aborts ${SWEEP.readAborts}, `
      + `reconciliation ${SWEEP.reconciliationFaults}): ${byBoundary}`);
  });
});

// ---------------------------------------------------------------------------------------------
// The happy paths: a result is reported only after the commit landed.
// ---------------------------------------------------------------------------------------------

describe('runMutation outcomes', () => {
  test('a COMMITTED run selects the new authority, releases the escrow and reports the result', async () => {
    for (const scenario of M2_TXN.SCENARIOS) {
      const row = mutationRow(scenario);
      const { store, result, error } = await runCase(scenario, M2_OUTCOME.COMMITTED);
      expect(error).toBeNull();
      expect(result).toEqual({
        commitOutcome: 'COMMITTED',
        resultKind: 'SUCCESS',
        state: row.stateAfterCommitted,
        originalStateBefore: row.stateBefore,
        generation: NEW_GENERATION,
        keyedRoot: expect.any(Uint8Array),
        reconciliationRef: null,
        output: row.outputKind === 'NONE' ? null : expect.any(Uint8Array),
        holds: 0,
      });
      expect((await classify(store)).authority).toBe('COMPLETE_NEW');
      expect(store.memoryHold).toBeNull();
      expect(store.applyCalls).toBeGreaterThan(0);
      const keys = store.applied.filter((a) => a.kind === 'REPLACE_SELECTOR');
      expect(keys).toHaveLength(1);
      expect(keys[0].boundary).toBe('AFTER_DURABLE_COMMIT_BEFORE_RESPONSE');
    }
  });

  test('a NOT_COMMITTED run keeps the old authority, discards candidate and escrow and reports no output', async () => {
    for (const scenario of M2_TXN.SCENARIOS) {
      const row = mutationRow(scenario);
      const { store, result, error } = await runCase(scenario, M2_OUTCOME.NOT_COMMITTED);
      expect(error).toBeNull();
      expect(result.commitOutcome).toBe('NOT_COMMITTED');
      expect(result.output).toBeNull();
      expect(result.holds).toBe(0);
      expect(result.generation).toBe(OLD_GENERATION);
      expect(result.state).toBe(row.stateBefore);
      expect((await classify(store)).authority).toBe('COMPLETE_OLD');
      expect(await store.readGeneration(NEW_GENERATION)).toBeNull();
      expect(store.applied.map((a) => a.kind)).not.toContain('REPLACE_SELECTOR');
    }
  });

  test('an INDETERMINATE run keeps the old authority, binds the candidate and reports a reference', async () => {
    for (const scenario of M2_TXN.SCENARIOS) {
      const { store, result, error, envelope } = await runCase(scenario, M2_OUTCOME.INDETERMINATE);
      expect(error).toBeNull();
      expect(result.commitOutcome).toBe('INDETERMINATE');
      expect(result.state).toBe('RECONCILIATION_REQUIRED');
      expect(result.output).toBeNull();
      expect(result.holds).toBe(1);
      expect(hex(result.reconciliationRef)).toBe(hex(envelope.reconciliationIdentity.reference));
      const classification = await classify(store);
      expect(classification.authority).toBe('COMPLETE_OLD');
      expect(classification.held).toBe(true);
      const held = decodePlaintext(M2_KIND.GENERATION_SELECTOR, store.selector);
      expect(held.state).toBe(3);
      expect(held.candidateGeneration).toBe(NEW_GENERATION);
      expect(store.memoryHold).not.toBeNull();
    }
  });

  test('the result is reported only after the commit: a fault at the authority write yields no result', async () => {
    const { store, result, error } = await runCase('CAPI-S001', M2_OUTCOME.COMMITTED, {}, {
      faults: [{ boundary: 'AFTER_DURABLE_COMMIT_BEFORE_RESPONSE', kind: 'REPLACE_SELECTOR', mode: 'BEFORE', remaining: 1 }],
    });
    expect(result).toBeNull();
    expect(error).not.toBeNull();
    expect((await classify(store)).authority).toBe('COMPLETE_OLD');
  });

  test('a lost commit response leaves the new authority and no reported result', async () => {
    const { store, result, error } = await runCase('CAPI-S001', M2_OUTCOME.COMMITTED, {}, {
      faults: [{ boundary: 'AFTER_DURABLE_COMMIT_BEFORE_RESPONSE', kind: 'REPLACE_SELECTOR', mode: 'AFTER', remaining: 1 }],
    });
    expect(result).toBeNull();
    expect(error).not.toBeNull();
    expect((await classify(store)).authority).toBe('COMPLETE_NEW');
  });

  test('the same mutation does not enlarge its hold: a repeated request is refused', async () => {
    const envelope = buildMutationEnvelope(envelopeInput('CAPI-S001'));
    const store = makeStore();
    store.seed([OLD], PARENT_SELECTOR);
    const first = await runMutation({
      storage: store, manifestRootKey: ROOT_KEY, envelope,
      candidate: candidateInput('CAPI-S001', M2_OUTCOME.INDETERMINATE), outcome: M2_OUTCOME.INDETERMINATE,
    });
    const second = makeStore();
    second.seed([OLD], PARENT_SELECTOR);
    const secondResult = await runMutation({
      storage: second, manifestRootKey: ROOT_KEY, envelope,
      candidate: candidateInput('CAPI-S001', M2_OUTCOME.INDETERMINATE), outcome: M2_OUTCOME.INDETERMINATE,
    });
    const plain = (v) => JSON.stringify(v, (k, x) => (typeof x === 'bigint' ? `${x}n` : x));
    expect(plain(first)).toBe(plain(secondResult));
    await expect(runMutation({
      storage: store, manifestRootKey: ROOT_KEY, envelope,
      candidate: candidateInput('CAPI-S001', M2_OUTCOME.INDETERMINATE), outcome: M2_OUTCOME.INDETERMINATE,
    })).rejects.toThrow(/blind retry is forbidden/);
    expect(store.memoryHold.presence).toBe(1);
  });

  test('a candidate generation number is refused when any generation number is present at or above it', async () => {
    // C-FMT unboundCandidate: generation numbers are never reused, and the number-only inventory
    // covers a generation whose bytes exist but whose complete generation read returns nothing.
    const store = makeStore();
    store.seed([OLD], PARENT_SELECTOR);
    store.generations.set(5n, { ...NEW, generation: 5n });
    const error = await runMutation({
      storage: store, manifestRootKey: ROOT_KEY, envelope: buildMutationEnvelope(envelopeInput('CAPI-S001')),
      candidate: candidateInput('CAPI-S001', M2_OUTCOME.INDETERMINATE), outcome: M2_OUTCOME.INDETERMINATE,
    }).then(() => null, (e) => e);
    expect(error.code).toBe('STALE_PARENT');
    expect(store.applyCalls).toBe(0);
  });

  test('a bound selector that names a candidate the retained record key does not derive is refused', async () => {
    // holdLocatorRule: the bound selector and the locator derived from the retained key must coincide.
    const { store, envelope } = await runCase('CAPI-S001', M2_OUTCOME.INDETERMINATE, {}, {
      faults: [{ boundary: 'AFTER_INDETERMINATE', kind: 'REPLACE_SELECTOR', mode: 'AFTER', remaining: 1 }],
    });
    expect(store.memoryHold).not.toBeNull();
    // A bound selector that names a candidate the retained record key does not derive.
    const decoyKey = Uint8Array.prototype.slice.call(NEW.manifestKey);
    decoyKey[24] ^= 0x01;
    store.selector = encodePlaintext(M2_KIND.GENERATION_SELECTOR, {
      presence: 1, generation: OLD.generation, manifestKeyDigest: manifestKeyDigest(OLD.manifestKey),
      manifestCipherDigest: OLD.manifestCipherDigest, keyedRoot: OLD.keyedRoot, state: 3,
      candidateGeneration: NEW.generation, candidateManifestKey: decoyKey,
      candidateManifestKeyDigest: manifestKeyDigest(decoyKey),
      candidateManifestCipherDigest: NEW.manifestCipherDigest, candidateKeyedRoot: NEW.keyedRoot,
    });
    await expect(reconcileIndeterminate({
      storage: store, manifestRootKey: ROOT_KEY, hold: null,
      evidence: evidenceFor(envelope, M2_OUTCOME.COMMITTED, { terminal: true }),
      reference: holdRecordFor('CAPI-S001').reconciliationReference,
    })).rejects.toThrow(/does not derive the candidate|must be present/);
  });

  test('a stored result whose expected original state is not the held original state is an evidence mismatch', async () => {
    const { store, envelope } = await runCase('CAPI-S001', M2_OUTCOME.INDETERMINATE, {}, {
      faults: [{ boundary: 'AFTER_INDETERMINATE', kind: 'REPLACE_SELECTOR', mode: 'AFTER', remaining: 1 }],
    });
    expect(store.memoryHold).not.toBeNull();
    store.memoryHold = { ...store.memoryHold, originalApiState: { marker: 'tampered' } };
    await expect(reconcileIndeterminate({
      storage: store, manifestRootKey: ROOT_KEY, hold: null,
      evidence: evidenceFor(envelope, M2_OUTCOME.COMMITTED, { terminal: true }),
      reference: holdRecordFor('CAPI-S001').reconciliationReference,
    })).rejects.toThrow(/original/i);
  });

  test('a stale parent is refused strictly before the RS request, leaving nothing durable', async () => {
    const { store, result, error } = await runCase('CAPI-S001', M2_OUTCOME.COMMITTED, {}, {
      selector: COMMIT_SELECTOR,
      generations: [OLD, NEW],
    });
    expect(result).toBeNull();
    expect(error.code).toBe('STALE_PARENT');
    expect(store.applyCalls).toBe(0);
    expect(hex(store.selector)).toBe(hex(COMMIT_SELECTOR));
  });

  test('a stored selector that names another physical generation is a stale parent on every row', async () => {
    // This row used to be exempt. It is not: a selector that names a generation the candidate does not
    // replace is a stale parent, and acting on it deletes or re-selects the live authority.
    for (const scenario of M2_TXN.SCENARIOS) {
      const { result, error } = await runCase(scenario, M2_OUTCOME.COMMITTED, {}, {
        selector: COMMIT_SELECTOR,
        generations: [OLD, NEW],
      });
      expect(result).toBeNull();
      expect(error.code).toBe('STALE_PARENT');
    }
  });

  test('an already-complete new authority is not re-selected by a duplicate request', async () => {
    const first = await runCase('CAPI-S001', M2_OUTCOME.COMMITTED);
    await expect(runMutation({
      storage: first.store,
      manifestRootKey: ROOT_KEY,
      envelope: first.envelope,
      candidate: candidateInput('CAPI-S001', M2_OUTCOME.COMMITTED),
      outcome: M2_OUTCOME.COMMITTED,
    })).rejects.toThrow(/is not the candidate parent/);
  });
});

// ---------------------------------------------------------------------------------------------
// Reconciliation.
// ---------------------------------------------------------------------------------------------

async function pendingHold(scenario) {
  const envelope = buildMutationEnvelope(envelopeInput(scenario));
  const store = makeStore();
  store.seed([OLD], PARENT_SELECTOR);
  const result = await runMutation({
    storage: store,
    manifestRootKey: ROOT_KEY,
    envelope,
    candidate: candidateInput(scenario, M2_OUTCOME.INDETERMINATE),
    outcome: M2_OUTCOME.INDETERMINATE,
  });
  return { store, envelope, result, hold: holdRecordFor(scenario) };
}

describe('reconcileIndeterminate', () => {
  test('matching proven COMMITTED selects the already-staged candidate once and releases the escrow', async () => {
    for (const scenario of M2_TXN.SCENARIOS) {
      const row = mutationRow(scenario);
      const { store, envelope, hold } = await pendingHold(scenario);
      const stepsBefore = store.applied.length;
      const outcome = await reconcileIndeterminate({
        storage: store,
        manifestRootKey: ROOT_KEY,
        hold,
        evidence: evidenceFor(envelope, M2_OUTCOME.COMMITTED, { terminal: true }),
        reference: hold.reconciliationReference,
      });
      expect(outcome.reconciliation).toBe('RECONCILED_COMMITTED');
      expect(outcome.authority).toBe('COMPLETE_NEW');
      expect(outcome.state).toBe(row.stateAfterCommitted);
      expect(outcome.holds).toBe(0);
      if (row.outputKind === 'NONE') {
        expect(outcome.output).toBeNull();
      } else {
        expect(hex(outcome.output)).toBe(hex(ESCROW.output));
      }
      // One selector replacement, no re-staged transition byte.
      const added = store.applied.slice(stepsBefore);
      expect(added.filter((a) => a.kind === 'REPLACE_SELECTOR')).toHaveLength(1);
      for (const kind of ['STAGE_DATA', 'STAGE_MANIFEST', 'STAGE_EVIDENCE', 'STAGE_ESCROW', 'WRITE_HOLD']) {
        expect(added.map((a) => a.kind)).not.toContain(kind);
      }
      expect((await classify(store)).authority).toBe('COMPLETE_NEW');
      // The atomic selector replacement tombstones the candidate's retained hold on every row.
      expect(store.generations.get(NEW_GENERATION).mutationHold.presence).toBe(0);
      // Every row ends the reconciliation with the local emission call, which releases the retained
      // response hold. A row with no escrow releases nothing but still resolves the hold.
      expect(added.filter((a) => a.kind === 'RELEASE_ESCROW')).toHaveLength(1);
      expect(store.memoryHold).toBeNull();
      if (row.outputKind === 'NONE') expect(row.heldOutputKind ?? 'NONE').toBe('NONE');
    }
  });

  test('after the hold is cleared a repeat is NO_RECONCILIATION_PENDING', async () => {
    const { store, envelope, hold } = await pendingHold('CAPI-S001');
    await reconcileIndeterminate({
      storage: store, manifestRootKey: ROOT_KEY, hold,
      evidence: evidenceFor(envelope, M2_OUTCOME.COMMITTED, { terminal: true }),
      reference: hold.reconciliationReference,
    });
    await expect(reconcileIndeterminate({
      storage: store, manifestRootKey: ROOT_KEY, hold,
      evidence: evidenceFor(envelope, M2_OUTCOME.COMMITTED, { terminal: true }),
      reference: hold.reconciliationReference,
    })).rejects.toThrow(/no reconciliation is pending/);
  });

  test('matching terminal NOT_COMMITTED clears the candidate and restores the old authority', async () => {
    const { store, envelope, hold } = await pendingHold('CAPI-S009');
    const outcome = await reconcileIndeterminate({
      storage: store,
      manifestRootKey: ROOT_KEY,
      hold,
      evidence: evidenceFor(envelope, M2_OUTCOME.NOT_COMMITTED, { terminal: true }),
      reference: hold.reconciliationReference,
    });
    expect(outcome.reconciliation).toBe('NOT_COMMITTED');
    expect(outcome.authority).toBe('COMPLETE_OLD');
    expect(outcome.output).toBeNull();
    expect(outcome.holds).toBe(0);
    expect(await store.readGeneration(NEW_GENERATION)).toBeNull();
    const classification = await classify(store);
    expect(classification.authority).toBe('COMPLETE_OLD');
    expect(classification.held).toBe(false);
    expect(store.memoryHold).toBeNull();
  });

  test('continued INDETERMINATE leaves the hold logically unchanged and returns no output', async () => {
    const { store, envelope, hold } = await pendingHold('CAPI-S001');
    const before = hex(store.selector);
    const outcome = await reconcileIndeterminate({
      storage: store,
      manifestRootKey: ROOT_KEY,
      hold,
      evidence: evidenceFor(envelope, M2_OUTCOME.INDETERMINATE, { terminal: false }),
      reference: hold.reconciliationReference,
    });
    expect(outcome.reconciliation).toBe('INDETERMINATE');
    expect(outcome.holds).toBe(1);
    expect(outcome.output).toBeNull();
    expect(hex(store.selector)).toBe(before);
    expect(store.memoryHold.presence).toBe(1);
  });

  test('a foreign reference rejects with no mutation and no hold change', async () => {
    const { store, envelope, hold } = await pendingHold('CAPI-S001');
    const before = hex(store.selector);
    await expect(reconcileIndeterminate({
      storage: store,
      manifestRootKey: ROOT_KEY,
      hold,
      evidence: evidenceFor(envelope, M2_OUTCOME.COMMITTED, { terminal: true }),
      reference: bytesOf(32, 0xff),
    })).rejects.toThrow(/not the held reference/);
    expect(hex(store.selector)).toBe(before);
    expect(store.memoryHold.presence).toBe(1);
  });

  test('cross-binding evidence rejects with no mutation and no hold change', async () => {
    const { store, envelope, hold } = await pendingHold('CAPI-S001');
    const before = hex(store.selector);
    await expect(reconcileIndeterminate({
      storage: store,
      manifestRootKey: ROOT_KEY,
      hold,
      evidence: evidenceFor(envelope, M2_OUTCOME.COMMITTED, { candidateDigest: bytesOf(32, 0xee) }),
      reference: hold.reconciliationReference,
    })).rejects.toThrow(/does not match the held envelope/);
    expect(hex(store.selector)).toBe(before);
    expect(store.memoryHold.presence).toBe(1);
  });

  test('a supplied hold that is not the held envelope rejects with no mutation', async () => {
    const { store, envelope, hold } = await pendingHold('CAPI-S001');
    const forged = { ...hold, candidateReference: bytesOf(32, 0xdd) };
    await expect(reconcileIndeterminate({
      storage: store,
      manifestRootKey: ROOT_KEY,
      hold: forged,
      evidence: evidenceFor(envelope, M2_OUTCOME.COMMITTED, { terminal: true }),
      reference: hold.reconciliationReference,
    })).rejects.toThrow(/does not match the held envelope/);
  });

  test('reconciliation with no hold pending is refused', async () => {
    const store = makeStore();
    store.seed([OLD], PARENT_SELECTOR);
    const envelope = buildMutationEnvelope(envelopeInput('CAPI-S001'));
    await expect(reconcileIndeterminate({
      storage: store,
      manifestRootKey: ROOT_KEY,
      hold: holdRecordFor('CAPI-S001'),
      evidence: evidenceFor(envelope, M2_OUTCOME.COMMITTED, { terminal: true }),
      reference: buildMutationEnvelope(envelopeInput('CAPI-S001')).reconciliationIdentity.reference,
    })).rejects.toThrow(/no reconciliation is pending/);
  });

  // A durable hold, or an interrupted local emission, is reconciled only for the mutation the bound
  // generation's own stored COMMIT_RESULT and escrow identify (C-FMT /generationCommit/
  // originalAuthorityMatch, §9; C-MUT /escrow sameMutationAsCandidate).
  const SUBSTITUTE = Object.freeze({
    operationIdentity: bytesOf(32, 0xde), originalAuthorityReference: bytesOf(32, 0xdf),
    candidateDigest: bytesOf(32, 0xe0), candidateReference: bytesOf(32, 0xe1),
  });

  test('a substituted durable hold with matching substituted evidence selects nothing', async () => {
    const { store, envelope } = await pendingHold('CAPI-S014');
    const { recordKey: _memoryOnlyKey, ...v2 } = store.memoryHold; // the stored kind-13 record is v2: no key field
    const held = { ...v2, ...SUBSTITUTE };
    store.generations.get(NEW_GENERATION).mutationHold = held;
    store.memoryHold = null;
    const selector = hex(store.selector);
    const applied = store.applied.length;
    await expect(reconcileIndeterminate({
      storage: store, manifestRootKey: ROOT_KEY, hold: null,
      evidence: { ...evidenceFor(envelope, M2_OUTCOME.COMMITTED), ...SUBSTITUTE },
      reference: held.reconciliationReference,
    })).rejects.toMatchObject({ code: 'EVIDENCE_MISMATCH' });
    expect(store.applied.length).toBe(applied);
    expect(hex(store.selector)).toBe(selector);
    expect((await classify(store)).held).toBe(true);
    // The same substitution answered by terminal NOT_COMMITTED discards nothing either.
    await expect(reconcileIndeterminate({
      storage: store, manifestRootKey: ROOT_KEY, hold: null,
      evidence: { ...evidenceFor(envelope, M2_OUTCOME.NOT_COMMITTED), ...SUBSTITUTE },
      reference: held.reconciliationReference,
    })).rejects.toMatchObject({ code: 'EVIDENCE_MISMATCH' });
    expect(store.applied.length).toBe(applied);
    expect(await store.readGeneration(NEW_GENERATION)).not.toBeNull();
  });

  async function interruptedEmission(scenario = 'CAPI-S014') {
    const pending = await pendingHold(scenario);
    const input = {
      storage: pending.store, manifestRootKey: ROOT_KEY, hold: pending.store.memoryHold,
      evidence: evidenceFor(pending.envelope, M2_OUTCOME.COMMITTED),
      reference: pending.store.memoryHold.reconciliationReference,
    };
    pending.store.faults = [{ boundary: 'DURING_ESCROW_OUTPUT_RESPONSE', kind: 'RELEASE_ESCROW', mode: 'BEFORE', remaining: 1 }];
    await expect(reconcileIndeterminate(input)).rejects.toThrow();
    expect((await classify(pending.store)).authority).toBe('COMPLETE_NEW');
    expect(pending.store.memoryHold).not.toBeNull();
    return { ...pending, input };
  }

  test('an interrupted emission repeats once with the same escrow and clears the hold', async () => {
    const { store, input } = await interruptedEmission();
    const applied = store.applied.length;
    const outcome = await reconcileIndeterminate(input);
    expect(outcome).toMatchObject({ reconciliation: 'RECONCILED_COMMITTED', authority: 'COMPLETE_NEW', holds: 0 });
    expect(hex(outcome.output)).toBe(hex(ESCROW.output));
    expect(store.applied.slice(applied).map((a) => a.kind)).toEqual(['RELEASE_ESCROW']);
    expect(store.memoryHold).toBeNull();
  });

  test('an interrupted emission never releases a substituted escrow', async () => {
    const { store, input } = await interruptedEmission();
    store.generations.get(NEW_GENERATION).escrow = {
      kind: 'APPLICATION_BYTES', digest: bytesOf(32, 0x58), reference: bytesOf(32, 0x59), output: new Uint8Array([99, 100]),
    };
    const applied = store.applied.length;
    await expect(reconcileIndeterminate(input)).rejects.toMatchObject({ code: 'EVIDENCE_MISMATCH' });
    expect(store.applied.length).toBe(applied);
    expect(store.memoryHold).not.toBeNull();
  });

  test('a COMMITTED selection never releases a substituted escrow', async () => {
    const { store, envelope } = await pendingHold('CAPI-S014');
    store.generations.get(NEW_GENERATION).escrow = { ...store.generations.get(NEW_GENERATION).escrow, digest: bytesOf(32, 0x58) };
    const selector = hex(store.selector);
    const applied = store.applied.length;
    await expect(reconcileIndeterminate({
      storage: store, manifestRootKey: ROOT_KEY, hold: store.memoryHold,
      evidence: evidenceFor(envelope, M2_OUTCOME.COMMITTED), reference: store.memoryHold.reconciliationReference,
    })).rejects.toMatchObject({ code: 'EVIDENCE_MISMATCH' });
    expect(store.applied.length).toBe(applied);
    expect(hex(store.selector)).toBe(selector);
    expect(store.memoryHold).not.toBeNull();
  });

  test('non-COMMITTED evidence, INDETERMINATE included, contradicts an interrupted emission', async () => {
    const { store, envelope, input } = await interruptedEmission();
    const applied = store.applied.length;
    for (const [outcome, overrides] of [[M2_OUTCOME.INDETERMINATE, { terminal: false }], [M2_OUTCOME.NOT_COMMITTED, {}]]) {
      await expect(reconcileIndeterminate({ ...input, evidence: evidenceFor(envelope, outcome, overrides) }))
        .rejects.toMatchObject({ code: 'EVIDENCE_MISMATCH' });
    }
    expect(store.applied.length).toBe(applied);
    expect(store.memoryHold).not.toBeNull();
  });
});


// ---------------------------------------------------------------------------------------------
// The readback oracle must bite: a mixture, a partial generation or an inconsistent selector is
// never reported as a complete authority.
// ---------------------------------------------------------------------------------------------

describe('classifyAuthority fails closed on anything but a complete generation', () => {
  async function committedStore(scenario = 'CAPI-S001') {
    const { store, error } = await runCase(scenario, M2_OUTCOME.COMMITTED);
    expect(error).toBeNull();
    expect((await classify(store)).authority).toBe('COMPLETE_NEW');
    return store;
  }

  test('an empty storage names no authority', async () => {
    const store = makeStore();
    store.seed([], null);
    const classification = await classifyAuthority({
      storage: store, manifestRootKey: ROOT_KEY, oldGeneration: null, newGeneration: NEW_GENERATION,
    });
    expect(classification.authority).toBe('EMPTY');
    expect(classification.generation).toBeNull();
  });

  test('a vanished old authority is not reported as EMPTY', async () => {
    const store = makeStore();
    store.seed([], null);
    await expect(classify(store)).rejects.toThrow(/no stored selector exists although an old authority was expected/);
  });

  test('a selector naming a stored generation with one missing data record is a partial generation', async () => {
    const store = await committedStore();
    store.generations.get(NEW_GENERATION).records = store.generations.get(NEW_GENERATION).records.slice(0, 14);
    await expect(classify(store)).rejects.toThrow(M2TxnError);
    await expect(classify(store)).rejects.toThrow(/does not store exactly 15 complete data records/);
  });

  test('a selector naming a generation whose manifest bytes were replaced is a partial generation', async () => {
    const store = await committedStore();
    const records = store.generations.get(NEW_GENERATION).records;
    const swapped = records.map((r, i) => (i === 4 ? { ...r, ciphertext: bytesOf(17, 0xaa) } : r));
    store.generations.get(NEW_GENERATION).records = swapped;
    await expect(classify(store)).rejects.toThrow(/do not reproduce its stored manifest bytes/);
  });

  test('a declared keyed root that its own manifest does not produce is rejected', async () => {
    const store = await committedStore();
    store.generations.get(NEW_GENERATION).keyedRoot = bytesOf(32, 0xbb);
    await expect(classify(store)).rejects.toThrow(/keyed root that its own manifest does not produce/);
  });

  test('a selector naming a generation that is not stored at all is rejected', async () => {
    const store = await committedStore();
    store.generations.delete(NEW_GENERATION);
    await expect(classify(store)).rejects.toThrow(/which is not stored/);
  });

  test('a selector whose state and candidate tuple disagree is rejected', async () => {
    const store = await committedStore();
    store.selector = HOLD_SELECTOR;
    await expect(classify(store)).rejects.toThrow(/selector state\/candidate inconsistency|not consistent with the generation/);
  });

  test('a selector naming neither the expected old nor the expected new authority is rejected', async () => {
    const store = await committedStore();
    await expect(classifyAuthority({
      storage: store, manifestRootKey: ROOT_KEY, oldGeneration: OLD_GENERATION, newGeneration: 9n,
    })).rejects.toThrow(/neither the expected old nor the expected new authority/);
  });

  test('the old authority after a NOT_COMMITTED run is still reported as complete', async () => {
    const { store } = await runCase('CAPI-S010', M2_OUTCOME.NOT_COMMITTED);
    const classification = await classify(store);
    expect(classification.authority).toBe('COMPLETE_OLD');
    expect(classification.generation).toBe(OLD_GENERATION);
    expect(hex(classification.keyedRoot)).toBe(hex(OLD.keyedRoot));
  });

  test('readback is deterministic for a repeated call on unchanged bytes', async () => {
    const store = await committedStore();
    const a = await classify(store);
    const b = await classify(store);
    const plain = (v) => JSON.stringify(v, (k, x) => (typeof x === 'bigint' ? `${x}n` : x));
    expect(plain(a)).toBe(plain(b));
  });
});

// ---------------------------------------------------------------------------------------------
// The rejected set: malformed port, candidate, outcome and storage inputs.
// ---------------------------------------------------------------------------------------------

describe('runMutation rejects malformed inputs', () => {
  const base = () => ({
    storage: makeStore().seed([OLD], PARENT_SELECTOR),
    manifestRootKey: ROOT_KEY,
    envelope: buildMutationEnvelope(envelopeInput('CAPI-S001')),
    candidate: candidateInput('CAPI-S001', 1),
    outcome: M2_OUTCOME.COMMITTED,
  });

  const portCases = [
    ['a null port', null],
    ['an array port', []],
    ['a port missing apply', { readSelector: async () => null, readGeneration: async () => null, readMemoryHold: async () => null, readGenerationNumbers: async () => [] }],
    ['a port with a non-function apply', { apply: 1, readSelector: async () => null, readGeneration: async () => null, readMemoryHold: async () => null, readGenerationNumbers: async () => [] }],
  ];
  test.each(portCases)('%s is rejected', async (_name, storage) => {
    await expect(runMutation({ ...base(), storage })).rejects.toThrow(/storage port/);
  });

  const candidateCases = [
    ['a short manifest root key', { manifestRootKey: new Uint8Array(31) }, /wrong byte width/],
    ['fourteen staged records', { candidate: { ...candidateInput('CAPI-S001', 1), records: NEW.records.slice(0, 14).map((r) => ({ ...r, ciphertext: r.ciphertext, tag: r.tag })) } }, /exactly 15 data records/],
    ['a duplicated data kind', { candidate: { ...candidateInput('CAPI-S001', 1), records: NEW.records.map((r, i) => ({ ...r, recordKind: i === 3 ? 1 : r.recordKind, ciphertext: r.ciphertext, tag: r.tag })) } }, /duplicate data record kind|records do not form a complete manifest/],
    ['a zero generation', { candidate: { ...candidateInput('CAPI-S001', 1), generation: 0n } }, /generation is zero/],
    ['a manifest that its own records do not reproduce', { candidate: { ...candidateInput('CAPI-S001', 1), manifestBytes: bytesOf(64, 0xc1) } }, /do not reproduce the candidate manifest bytes/],
    ['a keyed root that its own manifest does not produce', { candidate: { ...candidateInput('CAPI-S001', 1), keyedRoot: bytesOf(32, 0xc2) } }, /keyed root does not reproduce/],
    ['a NONE escrow', { candidate: { ...candidateInput('CAPI-S001', 1), escrow: { kind: 'NONE', digest: bytesOf(32, 1), reference: bytesOf(32, 2), output: null } } }, /NONE escrow is expressed as a null escrow/],
    ['a stage tag that is not sixteen bytes', { candidate: { ...candidateInput('CAPI-S001', 1), records: NEW.records.map((r, i) => ({ ...r, ciphertext: r.ciphertext, tag: i === 0 ? bytesOf(15, 1) : r.tag })) } }, /wrong byte width/],
  ];
  test.each(candidateCases)('%s is rejected', async (_name, patch, pattern) => {
    await expect(runMutation({ ...base(), ...patch })).rejects.toThrow(pattern);
  });

  test('evidence that does not carry the requested outcome is rejected', async () => {
    const input = base();
    await expect(runMutation({
      ...input,
      candidate: candidateInput('CAPI-S001', 1, {
        resultEvidence: evidenceFor(input.envelope, M2_OUTCOME.NOT_COMMITTED, { terminal: true }),
      }),
    })).rejects.toThrow(/does not carry the requested outcome/);
  });

  test('an outcome outside the closed enum is rejected', async () => {
    for (const bad of [0, 4, 'COMMITTED', null, 1.5]) {
      await expect(runMutation({ ...base(), outcome: bad })).rejects.toThrow(/not a defined C-MUT commit outcome/);
    }
  });

  test('runMutation input is closed', async () => {
    await expect(runMutation({ ...base(), extra: 1 })).rejects.toThrow(/unknown, missing, or symbol property/);
  });

  test('a memory-only step is never handed to the port', async () => {
    const store = makeStore().seed([OLD], PARENT_SELECTOR);
    await runMutation({
      storage: store, manifestRootKey: ROOT_KEY,
      envelope: buildMutationEnvelope(envelopeInput('CAPI-S001')),
      candidate: candidateInput('CAPI-S001', 1), outcome: M2_OUTCOME.COMMITTED,
    });
    for (const applied of store.applied) expect(MEMORY_ONLY_KINDS.has(applied.kind)).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
// Property sweep with reproducible seeds, and determinism across a fresh module registry.
// ---------------------------------------------------------------------------------------------

function lcg(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

describe('property sweep', () => {
  test('200 reproducible random fault schedules never leave a mixture and never report a result', async () => {
    const rand = lcg(20261001);
    let executed = 0;
    for (let trial = 0; trial < 200; trial += 1) {
      const scenario = M2_TXN.SCENARIOS[Math.floor(rand() * M2_TXN.SCENARIOS.length)];
      const outcome = [1, 2, 3][Math.floor(rand() * 3)];
      const plan = mutationSteps({
        envelope: buildMutationEnvelope(envelopeInput(scenario)),
        candidate: planInput(scenario, outcome),
        outcome,
        phase: 'ORIGINAL',
      });
      const durable = plan.filter((s) => !MEMORY_ONLY_KINDS.has(s.kind));
      const step = durable[Math.floor(rand() * durable.length)];
      const mode = rand() < 0.5 ? 'BEFORE' : 'AFTER';
      const { store, result, error } = await runCase(scenario, outcome, {}, {
        faults: [{ boundary: step.boundary, kind: step.kind, mode, remaining: 1 }],
      });
      executed += 1;
      expect(error).not.toBeNull();
      expect(result).toBeNull();
      const named = selectorGeneration(store);
      const classification = await classify(store);
      expect(classification.authority).toBe(named === NEW_GENERATION ? 'COMPLETE_NEW' : 'COMPLETE_OLD');
    }
    expect(executed).toBe(200);
  });

  test('a double fault schedule still leaves exactly one complete generation', async () => {
    const { store, error } = await runCase('CAPI-S014', M2_OUTCOME.COMMITTED, {}, {
      faults: [
        { boundary: 'DURING_RS_WORK', kind: 'STAGE_DATA', mode: 'AFTER', remaining: 1 },
        { boundary: 'DURING_RS_WORK', kind: 'STAGE_MANIFEST', mode: 'AFTER', remaining: 1 },
      ],
    });
    expect(error).not.toBeNull();
    const classification = await classify(store);
    expect(['COMPLETE_OLD', 'COMPLETE_NEW']).toContain(classification.authority);
    expect(classification.authority).toBe('COMPLETE_OLD');
  });
});

describe('determinism', () => {
  const digestOf = async () => {
    const { store, result } = await runCase('CAPI-S001', M2_OUTCOME.COMMITTED);
    const classification = await classify(store);
    return JSON.stringify({
      result: { ...result, keyedRoot: hex(result.keyedRoot), output: result.output === null ? null : hex(result.output) },
      classification: { ...classification, keyedRoot: hex(classification.keyedRoot) },
      applied: store.applied,
    }, (key, value) => (typeof value === 'bigint' ? `${value}n` : value));
  };

  test('re-importing the module in a fresh registry reproduces identical results byte for byte', async () => {
    const inProcess = await digestOf();
    const first = await digestOf();
    expect(first).toBe(inProcess);
    jest.resetModules();
    const fresh = await import('../../../src/storage/m2/session-transaction.js');
    expect(typeof fresh.runMutation).toBe('function');
    expect(typeof fresh.mutationRow).toBe('function');
    expect(fresh.M2_TXN).not.toBe(M2_TXN);
    const planA = mutationSteps({
      envelope: buildMutationEnvelope(envelopeInput('CAPI-S001')),
      candidate: planInput('CAPI-S001', 1), outcome: 1, phase: 'ORIGINAL',
    }).map((s) => [s.boundary, s.kind]);
    const planB = fresh.mutationSteps({
      envelope: fresh.buildMutationEnvelope(envelopeInput('CAPI-S001')),
      candidate: planInput('CAPI-S001', 1), outcome: 1, phase: 'ORIGINAL',
    }).map((s) => [s.boundary, s.kind]);
    expect(JSON.stringify(planA)).toBe(JSON.stringify(planB));
  });

  test('the same inputs produce the same JS serialisation of the result and the plan', async () => {
    const a = await digestOf();
    const b = await digestOf();
    expect(a).toBe(b);
  });
});

// ---------------------------------------------------------------------------------------------
// The scenario mapping this card owns, cross-checked against the ratified O-SCEN set.
// ---------------------------------------------------------------------------------------------

describe('scenario mapping against O-SCEN', () => {
  test('every owned item appears exactly once and every disposition is closed', () => {
    const ids = MAPPING.map((m) => m.item);
    expect(new Set(ids).size).toBe(ids.length);
    for (const entry of MAPPING) {
      expect(['MAPPED', 'UNMAPPED']).toContain(entry.disposition);
      if (entry.disposition === 'MAPPED') {
        expect(entry.scenarios.length).toBeGreaterThan(0);
        for (const id of entry.scenarios) expect(id).toMatch(/^OSC-[0-9a-f]{16}$/);
      } else {
        expect(typeof entry.reason).toBe('string');
        expect(entry.reason.length).toBeGreaterThan(0);
      }
    }
  });

  test('the owned item set is exactly the C-MUT surface this card implements', () => {
    const expected = [];
    for (const scenario of M2_TXN.SCENARIOS) {
      expected.push(`row:${scenario}`);
      for (const outcome of ['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']) {
        expected.push(`row:${scenario}:${outcome}`);
      }
      expected.push(`hold:${scenario}`);
      expected.push(`reconciliation:${scenario}`);
    }
    for (const boundary of M2_TXN.BOUNDARIES) expected.push(`boundary:${boundary}`);
    expected.sort();
    expect(MAPPING.map((m) => m.item).sort()).toEqual(expected);
  });

  test('every C-MUT mutation row, crash boundary, outcome, hold and reconciliation case is either mapped or explained', () => {
    const counts = MAPPING.reduce((acc, m) => {
      acc[m.disposition] += 1;
      return acc;
    }, { MAPPED: 0, UNMAPPED: 0 });
    expect(counts.MAPPED + counts.UNMAPPED).toBe(MAPPING.length);
    expect(MAPPING.length).toBe(54);
    expect(counts.MAPPED).toBe(47);
    expect(counts.UNMAPPED).toBe(7);
  });
});
