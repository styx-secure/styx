// B-CHR frozen conformance suite: fixtures. Port-neutral; identical for every factory.
// The fixture shapes are those of test/storage/m2/session-transaction.test.js (I-TXN unit fixtures),
// made generation-parametric so a second mutation can stage over any surviving generation.
import { M2_KIND, encodePlaintext, encodeRecordKey } from '/src/storage/m2/session-codec.js';
import {
  computeKeyedRoot, ciphertextDigest, encodeManifest, encodeManifestKey, manifestEntry, manifestKeyDigest,
} from '/src/storage/m2/session-root.js';
import { buildMutationEnvelope, mutationRow } from '/src/storage/m2/session-transaction.js';

export const ROWS = Object.freeze(['CAPI-S001', 'CAPI-S006', 'CAPI-S009', 'CAPI-S010', 'CAPI-S014', 'CAPI-S016', 'CAPI-S017']);
export const LOCAL = new Uint8Array(32).fill(0x21);
export const ROOT_KEY = new Uint8Array(32).fill(0x11);
export const STORAGE_ROOT_KEY = new Uint8Array(32).fill(0x12);
export const PROFILE_DIGEST = new Uint8Array(32).fill(0x31);
const SESSION_ID = new Uint8Array(32).fill(0x41);
const BINDING_DIGEST = new Uint8Array(32).fill(0x51);
const DATA_KINDS = Array.from({ length: 15 }, (_, i) => i + 1);
export const bytesOf = (n, seed) => Uint8Array.from({ length: n }, (_, i) => (seed + i * 7) & 0xff);

/** The context a factory receives. A port derives its own keys from it; nothing else is shared. */
export const PORT_CONTEXT = Object.freeze({
  rootStorageKey: STORAGE_ROOT_KEY, localContextId: LOCAL, productProfileDigest: PROFILE_DIGEST,
});

const cache = new Map();
export function generationFixture(generation) {
  const g = BigInt(generation);
  if (cache.has(g)) return cache.get(g);
  const pre = g === 1n;
  const recordKey = (kind) => encodeRecordKey({
    scope: pre ? 1 : 2, localContextId: LOCAL, secureSessionIdentity: pre ? null : SESSION_ID, writeGeneration: g, recordKind: kind,
  });
  const records = DATA_KINDS.map((kind) => ({
    recordKey: recordKey(kind), recordKind: kind,
    plaintext: bytesOf(9, kind + Number(g)), ciphertext: bytesOf(17, kind + 3 + Number(g)), tag: bytesOf(16, kind + 11),
  }));
  const manifestBytes = encodeManifest(records.map((r) => manifestEntry({
    recordKey: r.recordKey, recordKind: r.recordKind,
    ciphertextDigest: ciphertextDigest({ recordKey: r.recordKey, recordKind: r.recordKind, ciphertext: r.ciphertext, tag: r.tag }),
  })));
  const manifestKey = encodeManifestKey({
    localContextId: LOCAL, scope: pre ? 1 : 2, secureSessionIdentity: pre ? null : SESSION_ID, writeGeneration: g,
  });
  const out = Object.freeze({
    generation: g, records, manifestKey, manifestBytes,
    manifestCipherDigest: bytesOf(32, Number(g) + 0x90),
    keyedRoot: computeKeyedRoot({ manifestRootKey: ROOT_KEY, manifestKey, generation: g, manifestBytes }),
    sessionBindingDigest: pre ? null : BINDING_DIGEST,
  });
  cache.set(g, out);
  return out;
}

function tuple(facts, state, candidate = facts) {
  return {
    presence: 1, generation: facts.generation, manifestKeyDigest: manifestKeyDigest(facts.manifestKey),
    manifestCipherDigest: facts.manifestCipherDigest, keyedRoot: facts.keyedRoot, state,
    candidateGeneration: candidate.generation, candidateManifestKey: candidate.manifestKey,
    candidateManifestKeyDigest: manifestKeyDigest(candidate.manifestKey),
    candidateManifestCipherDigest: candidate.manifestCipherDigest, candidateKeyedRoot: candidate.keyedRoot,
  };
}
export const selectorBytes = (generation, state) => encodePlaintext(M2_KIND.GENERATION_SELECTOR, tuple(generationFixture(generation), state));
const holdSelectorBytes = (parent, cand) => encodePlaintext(M2_KIND.GENERATION_SELECTOR,
  tuple(generationFixture(parent), 3, generationFixture(cand)));

export function envelopeInput(scenario, op = 0x01) {
  const row = mutationRow(scenario);
  return {
    operationIdentity: { value: bytesOf(32, op), assignedBy: 'SS_RS', fresh: true, reusable: false, apRequestIdEqual: false },
    operation: row.operation, scenario, originalApiState: row.stateBefore,
    originalAuthority: { digest: bytesOf(32, 0x02), reference: bytesOf(32, 0x03) },
    bindingProfileIdentity: { bindingRef: bytesOf(32, 0x04), profile: bytesOf(32, 0x05) },
    candidate: { digest: bytesOf(32, op + 0x06), reference: bytesOf(32, op + 0x07) },
    componentSet: { digest: bytesOf(32, 0x08), reference: bytesOf(32, 0x09), entries: row.components.map((c) => ({ ...c })) },
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

/** One I-TXN mutation request: envelope + candidate staging `generation` over `parent`. */
export function mutationInput(scenario, outcome, { parent = 1n, generation = 2n, parentState = 1, op = 0x01 } = {}) {
  const envelope = buildMutationEnvelope(envelopeInput(scenario, op));
  const row = mutationRow(scenario);
  const C = generationFixture(generation);
  const P = generationFixture(parent);
  return {
    envelope,
    candidate: {
      generation: C.generation, records: C.records.map((r) => ({ ...r })),
      manifestKey: C.manifestKey, manifestBytes: C.manifestBytes, manifestCipherDigest: C.manifestCipherDigest,
      keyedRoot: C.keyedRoot, sessionBindingDigest: C.sessionBindingDigest,
      escrow: row.outputKind === 'NONE' ? null : {
        kind: row.outputKind, digest: envelope.heldOutput.digest, reference: envelope.heldOutput.reference, output: bytesOf(24, 0xa3),
      },
      resultEvidence: evidenceFor(envelope, outcome),
      selectorBytes: selectorBytes(generation, 2), holdSelectorBytes: holdSelectorBytes(parent, generation),
      parentSelectorBytes: selectorBytes(parent, parentState),
      parentGeneration: P.generation, parentKeyedRoot: P.keyedRoot,
    },
  };
}
