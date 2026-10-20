// B-CHR frozen conformance suite: fixtures. Port-neutral; identical for every factory.
// Canonical C-FMT kind records (B-CHR-CANON): every data record of every generation (kinds 1-15) is a
// canonical C-FMT plaintext of its kind under its canonical record key, and the records carry the
// relations the ratified documents define between them:
// - kind 6 BINDING_PROFILE: its 389-byte canonicalBinding gives the generation's sessionBindingDigest
//   (C-FMT sessionDomain, computed by session-codec.js encodeAad);
// - kind 8 COMMIT_RESULT: the request's commit-result evidence (C-FMT /recordKinds[8], C-MUT §5);
// - kind 9 OUTPUT_ESCROW: present for a row with an output, bound to the operation, candidate,
//   mutation set and output kind (C-FMT outputEscrow.binding); a canonical tombstone otherwise;
// - kind 13 MUTATION_HOLD: the complete v2 hold of this mutation, staged before the outcome is known
//   (resultStatus INDETERMINATE), field for field the hold I-TXN writes (buildHold);
// - kind 14 COMPONENT_SET: the envelope's component-set digest and reference.
// R3 (#468 6123056674, carried by #468 6171085366 §3a): for CAPI-S006/S016 (output kind NONE) the
// ratified kind-13 v2 layout cannot encode the null held-output fields C-MUT requires. While the served
// codec refuses such a hold, those rows stage a canonical kind-13 tombstone, and I-TXN must refuse their
// INDETERMINATE requests before any write. NONE_HOLD_ENCODABLE switches the rows to the present hold as
// soon as the served codec encodes it (K13-NONE-FORMAT); nothing else changes.
// Ciphertext and tag are opaque bytes committed by the manifest digests: the I-TXN STAGE_DATA payload
// carries no nonce or AAD, so no port can rebuild a C-FMT record envelope from it (contract residual).
import {
  M2_KIND, decodeAad, encodeAad, encodePlaintext, encodeRecordKey, deriveNamespaceKey,
} from '/src/storage/m2/session-codec.js';
import {
  computeKeyedRoot, ciphertextDigest, deriveManifestRootKey, encodeManifest, encodeManifestKey, manifestEntry,
  manifestKeyDigest,
} from '/src/storage/m2/session-root.js';
import { buildMutationEnvelope, mutationRow } from '/src/storage/m2/session-transaction.js';

export const ROWS = Object.freeze(['CAPI-S001', 'CAPI-S006', 'CAPI-S009', 'CAPI-S010', 'CAPI-S014', 'CAPI-S016', 'CAPI-S017']);
export const LOCAL = new Uint8Array(32).fill(0x21);
export const STORAGE_ROOT_KEY = new Uint8Array(32).fill(0x12);
export const PROFILE_DIGEST = new Uint8Array(32).fill(0x31);
const SESSION_ID = new Uint8Array(32).fill(0x41);
const CANONICAL_BINDING = Uint8Array.from({ length: 389 }, (_, i) => (0x61 + i * 3) & 0xff);
const DATA_KINDS = Array.from({ length: 15 }, (_, i) => i + 1);
export const bytesOf = (n, seed) => Uint8Array.from({ length: n }, (_, i) => (seed + i * 7) & 0xff);
const K = M2_KIND;

/** The context a factory receives. A port derives its own keys from it; nothing else is shared. */
export const PORT_CONTEXT = Object.freeze({
  rootStorageKey: STORAGE_ROOT_KEY, localContextId: LOCAL, productProfileDigest: PROFILE_DIGEST,
});

// C-MUT registries in I-TXN order (session-transaction.js OPERATIONS, SCENARIOS, SUCCESS_CODES, OUTPUT_KINDS).
const OPERATIONS = ['CREATE', 'RESTORE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION', 'SELF_UPDATE',
  'APPLY_PEER_UPDATE', 'RECONCILE_INDETERMINATE'];
const OUTPUT_KINDS = ['NONE', 'EMBEDDED_TREE_WELCOME', 'PROTECTED_APPLICATION_BYTES', 'APPLICATION_BYTES',
  'PROTECTED_COMMIT_BYTES', 'SELECTED_CANDIDATE_REF'];
const SUCCESS_CODES = ['CREATED', 'RESTORED', 'JOINED', 'APPLICATION_PROTECTED', 'APPLICATION_OPENED', 'SELF_UPDATED',
  'PEER_UPDATE_APPLIED', 'CANDIDATE_SELECTED', 'RECONCILED_COMMITTED', 'DUPLICATE_IGNORED'];
const API = { EMPTY: 1, ACTIVE: 2 };
const INDETERMINATE = 3;

/**
 * The escrowed output of a row (C-MUT outputKind). CAPI-S017 escrows its selected-candidate reference as
 * the UTF-8 of a well-formed string of 1 to 256 UTF-16 units (the shared rule of the I-RESTART and
 * I-RESTART-API drafts); the other output rows escrow opaque bytes. A NONE row escrows nothing.
 */
export const SELECTED_CANDIDATE_REF = 'bchr-selected-candidate-ref-01';
export function escrowOutput(row) {
  const kind = mutationRow(row).outputKind;
  if (kind === 'NONE') return null;
  return kind === 'SELECTED_CANDIDATE_REF' ? new TextEncoder().encode(SELECTED_CANDIDATE_REF) : bytesOf(24, 0xa3);
}

let MANIFEST_ROOT = null;
let BINDING_DIGEST = null;
/** The C-FMT manifest-root key of the suite context (session-root.js deriveManifestRootKey). */
export const manifestRootKey = () => MANIFEST_ROOT;
/** Async key derivations, once per worker, before any fixture is built. */
export async function prepareFixtures() {
  const namespaceKey = await deriveNamespaceKey(PORT_CONTEXT);
  MANIFEST_ROOT = await deriveManifestRootKey({ namespaceKey, localContextId: LOCAL, productProfileDigest: PROFILE_DIGEST });
  const aad = await encodeAad({
    recordKey: encodeRecordKey({ scope: 2, localContextId: LOCAL, secureSessionIdentity: SESSION_ID, writeGeneration: 1n, recordKind: K.BINDING_PROFILE }),
    localContextId: LOCAL, productProfileDigest: PROFILE_DIGEST, scope: 2, secureSessionIdentity: SESSION_ID,
    canonicalBinding: CANONICAL_BINDING, writeGeneration: 1n, mutationIdentity: new Uint8Array(32), plaintextLength: 1,
    recordKind: K.BINDING_PROFILE,
  });
  BINDING_DIGEST = decodeAad(aad).bindingDigest;
  return true;
}

const tomb = (kind) => encodePlaintext(kind, { presence: 0 });

/** The complete kind-13 v2 hold of a mutation (session-transaction.js buildHold, field for field). */
export function holdOf(envelope, parent) {
  return {
    presence: 1,
    operationIdentity: envelope.operationIdentity.value,
    operation: OPERATIONS.indexOf(envelope.operation) + 1,
    scenario: ROWS.indexOf(envelope.scenario) + 1,
    originalApiState: API[envelope.originalApiState],
    originalAuthorityDigest: envelope.originalAuthority.digest,
    originalAuthorityReference: envelope.originalAuthority.reference,
    bindingRef: envelope.bindingProfileIdentity.bindingRef,
    profileDigest: envelope.bindingProfileIdentity.profile,
    candidateDigest: envelope.candidate.digest,
    candidateReference: envelope.candidate.reference,
    componentSetDigest: envelope.componentSet.digest,
    componentSetReference: envelope.componentSet.reference,
    heldOutputKind: OUTPUT_KINDS.indexOf(envelope.heldOutput.kind) + 1,
    heldOutputDigest: envelope.heldOutput.digest,
    heldOutputReference: envelope.heldOutput.reference,
    expectedSuccessCode: SUCCESS_CODES.indexOf(envelope.expectedSuccess.code) + 1,
    expectedStateAfter: API[envelope.expectedSuccess.stateAfter],
    reconciliationReference: envelope.reconciliationIdentity.reference,
    resultStatus: INDETERMINATE,
    parentGeneration: parent.generation,
    parentKeyedRoot: parent.keyedRoot,
  };
}

// R3 switch: true iff the served codec encodes a present kind-13 hold with null held-output fields.
function probeNoneHold() {
  try {
    const env = buildMutationEnvelope(envelopeInput('CAPI-S006', 0x01, new Uint8Array(32).fill(0x07)));
    encodePlaintext(K.MUTATION_HOLD, holdOf(env, { generation: 1n, keyedRoot: new Uint8Array(32).fill(0x07) }));
    return true;
  } catch { return false; }
}

/** The C-FMT kind-8 plaintext of commit-result evidence (evidence `profile` is the record's `profileDigest`). */
function commitResultPlaintext(e) {
  return encodePlaintext(K.COMMIT_RESULT, {
    presence: 1, operationIdentity: e.operationIdentity, originalAuthorityDigest: e.originalAuthorityDigest,
    originalAuthorityReference: e.originalAuthorityReference, candidateDigest: e.candidateDigest,
    candidateReference: e.candidateReference, mutationSetDigest: e.mutationSetDigest,
    mutationSetReference: e.mutationSetReference, expectedOriginalState: e.expectedOriginalState, bindingRef: e.bindingRef,
    profileDigest: e.profile, outcome: e.outcome, authenticatedByRS: e.authenticatedByRS, terminal: e.terminal,
  });
}

/**
 * One complete canonical generation. `content` maps a kind to its present plaintext; every other kind
 * is a canonical tombstone. Records are in ascending canonical-key order (C-FMT manifest order).
 */
function buildGeneration(generation, scope, content) {
  const g = BigInt(generation);
  const session = scope === 2 ? SESSION_ID : null;
  const records = DATA_KINDS.map((kind) => {
    const recordKey = encodeRecordKey({ scope, localContextId: LOCAL, secureSessionIdentity: session, writeGeneration: g, recordKind: kind });
    const plaintext = content[kind] ?? tomb(kind);
    // Opaque ciphertext of the plaintext's length and an opaque tag, both committed by the manifest.
    const ciphertext = Uint8Array.from(plaintext, (b, i) => b ^ ((0x5a + i * 13 + kind + Number(g)) & 0xff));
    return { recordKey, recordKind: kind, plaintext, ciphertext, tag: bytesOf(16, kind * 5 + Number(g)) };
  }).sort((a, b) => {
    for (let i = 0; i < Math.min(a.recordKey.length, b.recordKey.length); i += 1) if (a.recordKey[i] !== b.recordKey[i]) return a.recordKey[i] - b.recordKey[i];
    return a.recordKey.length - b.recordKey.length;
  });
  const manifestBytes = encodeManifest(records.map((r) => manifestEntry({
    recordKey: r.recordKey, recordKind: r.recordKind,
    ciphertextDigest: ciphertextDigest({ recordKey: r.recordKey, recordKind: r.recordKind, ciphertext: r.ciphertext, tag: r.tag }),
  })));
  const manifestKey = encodeManifestKey({ localContextId: LOCAL, scope, secureSessionIdentity: session, writeGeneration: g });
  return {
    generation: g, scope, records, manifestKey, manifestBytes,
    manifestCipherDigest: bytesOf(32, (Number(g) * 11 + (content.seed ?? 0) + 0x90) & 0xff),
    keyedRoot: computeKeyedRoot({ manifestRootKey: MANIFEST_ROOT, manifestKey, generation: g, manifestBytes }),
    sessionBindingDigest: scope === 2 ? BINDING_DIGEST : null,
  };
}

const slotPlaintext = () => encodePlaintext(K.SLOT_REGISTRATION, { presence: 1, slotState: 2, registeredBindingRef: bytesOf(32, 0x04), profileDigest: bytesOf(32, 0x05) });
const sessionContent = (seed) => ({
  [K.SLOT_REGISTRATION]: slotPlaintext(),
  [K.SESSION_STATE]: encodePlaintext(K.SESSION_STATE, { presence: 1, providerState: bytesOf(48, seed) }),
  [K.BINDING_PROFILE]: encodePlaintext(K.BINDING_PROFILE, { presence: 1, canonicalBinding: CANONICAL_BINDING, profileDigest: bytesOf(32, 0x05) }),
  [K.REPLAY_RETENTION]: encodePlaintext(K.REPLAY_RETENTION, { presence: 1, replayState: bytesOf(20, seed + 1), retentionState: bytesOf(12, seed + 2) }),
});

const parents = new Map();
/**
 * Generation 1, the parent authority a row starts from, in the row's origin state: EMPTY is a
 * pre-session generation with one UNCONSUMED KeyPackage and tombstoned session facts; ACTIVE is a
 * SESSION generation with its session state, binding profile and replay state (C-FMT §12 shapes).
 */
export function parentFixture(row) {
  if (parents.has(row)) return parents.get(row);
  const empty = mutationRow(row).stateBefore === 'EMPTY';
  const content = empty ? {
    [K.SLOT_REGISTRATION]: slotPlaintext(),
    [K.KEY_PACKAGE]: encodePlaintext(K.KEY_PACKAGE, {
      presence: 1, publicKeyPackage: bytesOf(40, 0x71), privateBundle: bytesOf(40, 0x72), localKeyPackageRef: bytesOf(32, 0x73),
      mlsKeyPackageRef: bytesOf(32, 0x74), registeredBindingRef: bytesOf(32, 0x04), profileDigest: bytesOf(32, 0x05),
      lifecycle: 1, invalidPending: false,
    }),
  } : sessionContent(0x30);
  const out = Object.freeze(buildGeneration(1n, empty ? 1 : 2, content));
  parents.set(row, out);
  return out;
}

export function envelopeInput(scenario, op = 0x01, parentRoot = null) {
  const row = mutationRow(scenario);
  return {
    operationIdentity: { value: bytesOf(32, op), assignedBy: 'SS_RS', fresh: true, reusable: false, apRequestIdEqual: false },
    operation: row.operation, scenario, originalApiState: row.stateBefore,
    originalAuthority: { digest: parentRoot ?? bytesOf(32, 0x02), reference: bytesOf(32, op + 0x03) },
    bindingProfileIdentity: { bindingRef: bytesOf(32, 0x04), profile: bytesOf(32, 0x05) },
    candidate: { digest: bytesOf(32, op + 0x06), reference: bytesOf(32, op + 0x07) },
    componentSet: { digest: bytesOf(32, op + 0x08), reference: bytesOf(32, op + 0x09), entries: row.components.map((c) => ({ ...c })) },
    heldOutput: row.outputKind === 'NONE' ? { kind: 'NONE', digest: null, reference: null }
      : { kind: row.outputKind, digest: bytesOf(32, op + 0x0a), reference: bytesOf(32, op + 0x0b) },
    expectedSuccess: { code: row.successCode, stateAfter: row.stateAfterCommitted },
    reconciliationIdentity: { reference: bytesOf(32, op + 0x0c), owner: 'SS_RS' },
  };
}

export function evidenceFor(envelope, outcome) {
  return {
    operationIdentity: envelope.operationIdentity.value,
    originalAuthorityDigest: envelope.originalAuthority.digest, originalAuthorityReference: envelope.originalAuthority.reference,
    candidateDigest: envelope.candidate.digest, candidateReference: envelope.candidate.reference,
    mutationSetDigest: envelope.componentSet.digest, mutationSetReference: envelope.componentSet.reference,
    expectedOriginalState: envelope.originalApiState === 'EMPTY' ? 1 : 2,
    bindingRef: envelope.bindingProfileIdentity.bindingRef, profile: envelope.bindingProfileIdentity.profile,
    outcome, authenticatedByRS: true, terminal: true,
  };
}

let noneHold = null;
/** R3 switch (see the header): does the served codec encode a present NONE-output hold? */
export function noneHoldEncodable() {
  if (noneHold === null) noneHold = probeNoneHold();
  return noneHold;
}

const SELECTOR_KIND = K.GENERATION_SELECTOR;
function tuple(facts, state, candidate = facts) {
  return {
    presence: 1, generation: facts.generation, manifestKeyDigest: manifestKeyDigest(facts.manifestKey),
    manifestCipherDigest: facts.manifestCipherDigest, keyedRoot: facts.keyedRoot, state,
    candidateGeneration: candidate.generation, candidateManifestKey: candidate.manifestKey,
    candidateManifestKeyDigest: manifestKeyDigest(candidate.manifestKey),
    candidateManifestCipherDigest: candidate.manifestCipherDigest, candidateKeyedRoot: candidate.keyedRoot,
  };
}
/** The selector naming `facts` alone (state 1 EMPTY, 2 ACTIVE). */
export const selfSelector = (facts, state) => encodePlaintext(SELECTOR_KIND, tuple(facts, state));
/** The RECONCILIATION_REQUIRED selector keeping `parent` and binding `candidate`. */
export const boundSelector = (parent, candidate) => encodePlaintext(SELECTOR_KIND, tuple(parent, 3, candidate));

/**
 * One I-TXN mutation request of `scenario` with `outcome`, staging generation `generation` over the
 * stored `parent` fixture. Returns the envelope, the runMutation candidate, the staged generation and
 * the exact kind-13 plaintext it stages (null for a tombstone).
 */
export function mutationInput(scenario, outcome, { parent, generation = 2n, parentState = null, op = 0x01 } = {}) {
  const row = mutationRow(scenario);
  const P = parent ?? parentFixture(scenario);
  const envelope = buildMutationEnvelope(envelopeInput(scenario, op, P.keyedRoot));
  const evidence = evidenceFor(envelope, outcome);
  const output = escrowOutput(scenario);
  const hasOutput = row.outputKind !== 'NONE';
  const holdPlaintext = hasOutput || noneHoldEncodable() ? encodePlaintext(K.MUTATION_HOLD, holdOf(envelope, P)) : null;
  const content = {
    ...sessionContent(0x40 + op),
    seed: op,
    [K.COMMIT_RESULT]: commitResultPlaintext(evidence),
    [K.COMPONENT_SET]: encodePlaintext(K.COMPONENT_SET, {
      presence: 1, mutationSetDigest: envelope.componentSet.digest, mutationSetReference: envelope.componentSet.reference,
      // The ratified documents define no byte rule for `entries`; the row's components, one per line.
      entries: new TextEncoder().encode(row.components.map((c) => `${c.id}:${c.disposition}`).join('\n')),
    }),
  };
  if (holdPlaintext !== null) content[K.MUTATION_HOLD] = holdPlaintext;
  if (hasOutput) {
    content[K.OUTPUT_ESCROW] = encodePlaintext(K.OUTPUT_ESCROW, {
      presence: 1, operationIdentity: envelope.operationIdentity.value, candidateDigest: envelope.candidate.digest,
      candidateReference: envelope.candidate.reference, mutationSetDigest: envelope.componentSet.digest,
      mutationSetReference: envelope.componentSet.reference, outputKind: OUTPUT_KINDS.indexOf(row.outputKind) + 1,
      output, resultDigest: bytesOf(32, op + 0x0d),
    });
  }
  const C = buildGeneration(generation, 2, content);
  return {
    envelope,
    staged: C,
    holdPlaintext,
    candidate: {
      generation: C.generation, records: C.records.map((r) => ({ ...r })),
      manifestKey: C.manifestKey, manifestBytes: C.manifestBytes, manifestCipherDigest: C.manifestCipherDigest,
      keyedRoot: C.keyedRoot, sessionBindingDigest: C.sessionBindingDigest,
      escrow: hasOutput ? { kind: row.outputKind, digest: envelope.heldOutput.digest, reference: envelope.heldOutput.reference, output } : null,
      resultEvidence: evidence,
      selectorBytes: selfSelector(C, 2), holdSelectorBytes: boundSelector(P, C),
      parentSelectorBytes: selfSelector(P, parentState ?? API[row.stateBefore]),
      parentGeneration: P.generation, parentKeyedRoot: P.keyedRoot,
    },
  };
}
