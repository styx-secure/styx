// B-CHR reference port (test-owned; act #317 6091950328 §1 "Reference port"; B-CHR-CANON).
// - Delegates only to VaultDb.transaction and the public VaultDb reads (get, list) on the `mls` store.
// - Implements only the public port interface: the I-TXN storage methods apply, readSelector,
//   readGeneration, readMemoryHold, readGenerationNumbers, and the B-CHR obligation v2 item-13 producer
//   readbackEvidence. No test hook, no fallback, no knowledge of the suite.
// - Layout: one sealed value per generation (`gen:<n>`, n the write generation of the generation's own
//   canonical manifest key) and the fixed selector (`sel`).
//   - The selector is a C-FMT envelope sealed with a fresh 96-bit CSPRNG nonce on every write (C-FMT §4;
//     obligation item 10).
//   - A generation value holds exactly the staged data records (record key, kind, plaintext, ciphertext,
//     tag) and the staged manifest facts. It is sealed at rest (AES-256-GCM under a key derived from the
//     C-FMT namespace key, the IndexedDB key as AAD, a fresh nonce per write). No projection is stored.
// - Trusted authenticating reader (obligation item 12, as amended by #468 B1 and B4): a read returns
//   only authenticated values whose record keys and plaintexts are canonical C-FMT encodings of their
//   kind (re-encoded); every projection (mutationHold, resultEvidence, escrow, sessionBindingDigest) is
//   derived from the authenticated record of its kind; a present kind-13 record must meet the
//   record-derived conjuncts of C-FMT historicalHoldRule/holdLocatorRule. A failed verification throws
//   an own string `code` in AUTHENTICATION_FAILED, CONTEXT_MISMATCH, MALFORMED_INPUT, UNSUPPORTED_VALUE,
//   unwrapped; any other throw means the read was not performed.
// - Writes: everything is computed before VaultDb.transaction is called; inside it only IndexedDB
//   requests are awaited (obligation item 3, best effort over VaultDb). WRITE_HOLD writes nothing durable
//   (#468 B1) and must agree with the staged kind-13 record; STAGE_EVIDENCE, STAGE_ESCROW and the staged
//   sessionBindingDigest must agree with the records they project.
// Non-claims (act §1): B-CHR obligation items 3, 4 and 7 (the transaction object is not exposed by
// VaultDb) are not claimed for this port.
import {
  M2_KIND, decodeAad, decodeEnvelope, decodePlaintext, decodeRecordKey, deriveNamespaceKey, deriveSelectorAeadKey,
  encodeAad, encodePlaintext, encodeSelectorKey, openRecord, sealRecord,
} from '/src/storage/m2/session-codec.js';
import {
  ciphertextDigest, computeKeyedRoot, deriveManifestRootKey, encodeManifest, encodeManifestKey, manifestEntry,
  manifestKeyDigest,
} from '/src/storage/m2/session-root.js';
import { decodeBindingV0 } from '/src/crypto/m2-binding-v0.js';

const NS = 'mls';
const SEL = 'sel';
const genKey = (g) => `gen:${BigInt(g).toString()}`;
const ZERO32 = new Uint8Array(32);
const OUTCOME = Object.freeze({ COMMITTED: 1, NOT_COMMITTED: 2, INDETERMINATE: 3 });
const RECONCILIATION_REQUIRED = 3;
const K = M2_KIND;
const OUTPUT_KINDS = ['NONE', 'EMBEDDED_TREE_WELCOME', 'PROTECTED_APPLICATION_BYTES', 'APPLICATION_BYTES',
  'PROTECTED_COMMIT_BYTES', 'SELECTED_CANDIDATE_REF'];
const VERIFY_CODES = new Set(['AUTHENTICATION_FAILED', 'CONTEXT_MISMATCH', 'MALFORMED_INPUT', 'UNSUPPORTED_VALUE']);
// C-FMT historicalHoldRule association (C-MUT originalAuthorityMatch): COMMIT_RESULT field, hold field.
const RESULT_HOLD = [['operationIdentity', 'operationIdentity'], ['originalAuthorityDigest', 'originalAuthorityDigest'],
  ['originalAuthorityReference', 'originalAuthorityReference'], ['candidateDigest', 'candidateDigest'],
  ['candidateReference', 'candidateReference'], ['mutationSetDigest', 'componentSetDigest'],
  ['mutationSetReference', 'componentSetReference'], ['bindingRef', 'bindingRef'], ['profileDigest', 'profileDigest']];
const HOLD_FIELDS = ['operationIdentity', 'operation', 'scenario', 'originalApiState', 'originalAuthorityDigest',
  'originalAuthorityReference', 'bindingRef', 'profileDigest', 'candidateDigest', 'candidateReference', 'componentSetDigest',
  'componentSetReference', 'heldOutputKind', 'heldOutputDigest', 'heldOutputReference', 'expectedSuccessCode',
  'expectedStateAfter', 'reconciliationReference', 'resultStatus', 'parentGeneration', 'parentKeyedRoot'];
const EVIDENCE_FIELDS = ['operationIdentity', 'originalAuthorityDigest', 'originalAuthorityReference', 'candidateDigest',
  'candidateReference', 'mutationSetDigest', 'mutationSetReference', 'expectedOriginalState', 'bindingRef', 'profile',
  'outcome', 'authenticatedByRS', 'terminal'];

export class SelectorPreconditionFailed extends Error {
  constructor() { super('the stored selector envelope differs from expectedSelectorBytes'); this.code = 'SELECTOR_PRECONDITION_FAILED'; }
}
const sameBytes = (a, b) => (a === null || b === null || a === undefined || b === undefined ? (a ?? null) === (b ?? null)
  : a.length === b.length && a.every((x, i) => x === b[i]));
const same = (a, b) => ((a instanceof Uint8Array || b instanceof Uint8Array) ? sameBytes(a, b) : a === b);
const copy = (u8) => Uint8Array.prototype.slice.call(u8);
const failed = (code, message) => Object.assign(new Error(message), { code });
const inconsistent = (message) => failed('CONTEXT_MISMATCH', message);
const hex = (u8) => Array.from(u8, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const utf8 = (t) => new TextEncoder().encode(t);
const compareBytes = (a, b) => {
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};
// A verification failure keeps its own code when it is one of the four; any other validation failure
// (for example a session-root code) is an authenticated-consistency failure.
const asVerification = (e) => (VERIFY_CODES.has(e?.code) ? e : inconsistent(String(e?.message ?? e)));

// Canonical, lossless encoding of a generation value (sorted keys; bytes and u64 tagged).
function encodeValue(v) {
  if (v instanceof Uint8Array) return { $b: hex(v) };
  if (typeof v === 'bigint') return { $n: v.toString() };
  if (Array.isArray(v)) return v.map(encodeValue);
  if (v !== null && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, encodeValue(v[k])]));
  return v;
}
function decodeValue(v) {
  if (Array.isArray(v)) return v.map(decodeValue);
  if (v !== null && typeof v === 'object') {
    const keys = Object.keys(v);
    if (keys.length === 1 && typeof v.$b === 'string') return unhex(v.$b);
    if (keys.length === 1 && typeof v.$n === 'string') return BigInt(v.$n);
    return Object.fromEntries(keys.map((k) => [k, decodeValue(v[k])]));
  }
  return v;
}

// The commit-result evidence projection of an authenticated kind-8 record (record `profileDigest` is
// evidence `profile`), or null for a tombstone.
function evidenceOfRecord(k8) {
  if (k8.presence !== 1) return null;
  const out = {};
  for (const f of EVIDENCE_FIELDS) {
    const v = k8[f === 'profile' ? 'profileDigest' : f];
    out[f] = v instanceof Uint8Array ? copy(v) : v;
  }
  return out;
}
// Item 13: evidence whose identity fields are copied from an authenticated source, never invented.
function evidenceFrom(src, outcome, terminal) {
  return {
    operationIdentity: copy(src.operationIdentity),
    originalAuthorityDigest: copy(src.originalAuthorityDigest), originalAuthorityReference: copy(src.originalAuthorityReference),
    candidateDigest: copy(src.candidateDigest), candidateReference: copy(src.candidateReference),
    mutationSetDigest: copy(src.mutationSetDigest ?? src.componentSetDigest),
    mutationSetReference: copy(src.mutationSetReference ?? src.componentSetReference),
    expectedOriginalState: src.expectedOriginalState ?? src.originalApiState, bindingRef: copy(src.bindingRef),
    profile: copy(src.profile ?? src.profileDigest), outcome, authenticatedByRS: true, terminal,
  };
}
const holdMatches = (a, b) => a !== null && b !== null && a.presence === 1 && b.presence === 1
  && HOLD_FIELDS.every((f) => (typeof a[f] === 'bigint' || typeof b[f] === 'bigint' ? BigInt(a[f]) === BigInt(b[f]) : same(a[f], b[f])));
const resultMatchesHold = (k8, hold) => k8.presence === 1 && RESULT_HOLD.every(([r, h]) => sameBytes(k8[r], hold[h]))
  && k8.expectedOriginalState === hold.originalApiState;

export async function createPort({ db, context }) {
  const selectorKey = encodeSelectorKey({ localContextId: context.localContextId });
  const namespaceKey = await deriveNamespaceKey(context);
  const aeadKey = await deriveSelectorAeadKey({ namespaceKey, selectorKey });
  const manifestRootKey = await deriveManifestRootKey({
    namespaceKey, localContextId: context.localContextId, productProfileDigest: context.productProfileDigest,
  });
  const genBase = await crypto.subtle.importKey('raw', copy(namespaceKey), 'HKDF', false, ['deriveKey']);
  const genAead = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: utf8('styx-bchr-reference-port/generation-aead/v1') },
    genBase, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
  let buffer = new Map(); // generation -> staged value (not durable)
  let pendingMemoryHold;   // set at WRITE_HOLD, becomes the memory hold only after the binding complete
  let memoryHold = null;

  const staged = (g) => {
    const k = BigInt(g);
    if (!buffer.has(k)) buffer.set(k, { generation: k, records: [], manifest: null, evidence: undefined, escrow: undefined });
    return buffer.get(k);
  };
  const resetBuffer = () => { buffer = new Map(); pendingMemoryHold = undefined; };

  // ---- the sealed generation value ------------------------------------------------------------------
  async function sealGeneration(v) {
    const value = {
      generation: v.generation, records: v.records, manifestKey: v.manifest.manifestKey, manifestBytes: v.manifest.manifestBytes,
      manifestCipherDigest: v.manifest.manifestCipherDigest, keyedRoot: v.manifest.keyedRoot,
    };
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: utf8(genKey(v.generation)) }, genAead, utf8(JSON.stringify(encodeValue(value))),
    ));
    return { nonce, ct };
  }

  // One canonical data record of generation `g`: canonical key of its kind and generation under this
  // context, canonical plaintext of its kind (returned re-encoded).
  function canonicalRecord(r, g, name) {
    if (r === null || typeof r !== 'object') throw failed('MALFORMED_INPUT', `${name} is not a record`);
    const key = decodeRecordKey(r.recordKey);
    if (key.recordKind !== r.recordKind || key.writeGeneration !== BigInt(g)) throw inconsistent(`${name} key does not name its kind and generation`);
    if (!sameBytes(key.localContextId, context.localContextId)) throw inconsistent(`${name} key names another context`);
    const decoded = decodePlaintext(r.recordKind, r.plaintext);
    return {
      record: { recordKey: copy(r.recordKey), recordKind: r.recordKind, plaintext: encodePlaintext(r.recordKind, decoded), ciphertext: copy(r.ciphertext), tag: copy(r.tag) },
      key, decoded,
    };
  }

  /**
   * Authenticate and canonically decode a stored generation value; derive every projection from the
   * authenticated records. `strict` adds the producer's completeness checks (exactly the fifteen data
   * kinds, the manifest reproduced from the records, the keyed root reproduced from the manifest).
   */
  async function openGeneration(generation, stored, { strict = false } = {}) {
    if (stored === null || typeof stored !== 'object' || !(stored.nonce instanceof Uint8Array) || stored.nonce.length !== 12
      || !(stored.ct instanceof Uint8Array)) {
      throw failed('AUTHENTICATION_FAILED', `generation ${generation} is not a sealed value`);
    }
    let plain;
    try {
      plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: stored.nonce, additionalData: utf8(genKey(generation)) }, genAead, stored.ct);
    } catch {
      throw failed('AUTHENTICATION_FAILED', `generation ${generation} does not authenticate`);
    }
    try {
      const v = decodeValue(JSON.parse(new TextDecoder().decode(plain)));
      const g = BigInt(generation);
      if (v.generation !== g) throw failed('AUTHENTICATION_FAILED', 'generation number mismatch');
      const mk = decodeRecordKey(v.manifestKey);
      if (mk.recordKind !== 16 || mk.objectId.length !== 0 || mk.writeGeneration !== g || !sameBytes(mk.localContextId, context.localContextId)) {
        throw inconsistent(`generation ${generation} manifest key is not its canonical kind-16 key`);
      }
      const byKind = new Map();
      const records = (Array.isArray(v.records) ? v.records : []).map((r, i) => {
        const c = canonicalRecord(r, g, `generation ${generation} record ${i}`);
        if (c.key.scope !== mk.scope || !sameBytes(c.key.secureSessionIdentity, mk.secureSessionIdentity)) {
          throw inconsistent(`generation ${generation} record ${i} has another scope or session than its manifest key`);
        }
        if (byKind.has(c.record.recordKind)) throw inconsistent(`generation ${generation} stores kind ${c.record.recordKind} twice`);
        byKind.set(c.record.recordKind, c);
        return c.record;
      });
      if (strict) {
        if (byKind.size !== 15) throw inconsistent(`generation ${generation} does not store the fifteen data kinds`);
        const sorted = [...records].sort((a, b) => compareBytes(a.recordKey, b.recordKey));
        const rebuilt = encodeManifest(sorted.map((r) => manifestEntry({
          recordKey: r.recordKey, recordKind: r.recordKind,
          ciphertextDigest: ciphertextDigest({ recordKey: r.recordKey, recordKind: r.recordKind, ciphertext: r.ciphertext, tag: r.tag }),
        })));
        if (!sameBytes(rebuilt, v.manifestBytes)) throw inconsistent(`generation ${generation} records do not reproduce its manifest`);
        const root = computeKeyedRoot({ manifestRootKey, manifestKey: v.manifestKey, generation: g, manifestBytes: v.manifestBytes });
        if (!sameBytes(root, v.keyedRoot)) throw inconsistent(`generation ${generation} manifest does not reproduce its keyed root`);
      }
      const k13 = byKind.get(K.MUTATION_HOLD);
      const k8 = byKind.get(K.COMMIT_RESULT);
      const k9 = byKind.get(K.OUTPUT_ESCROW);
      const k6 = byKind.get(K.BINDING_PROFILE);
      // mutationHold: the authenticated kind-13 record itself (presence plus the 21 v2 fields).
      let mutationHold = null;
      if (k13 !== undefined) {
        mutationHold = k13.decoded.presence === 1 ? { ...k13.decoded } : { presence: 0 };
        if (k13.decoded.presence === 1) {
          // C-FMT holdLocatorRule / historicalHoldRule record-derived conjuncts (#468 B4): the record key
          // derives this generation and its manifest key, the parent is earlier, and the hold is the one
          // of this generation's own COMMIT_RESULT.
          const derived = encodeManifestKey({
            localContextId: k13.key.localContextId, scope: k13.key.scope,
            secureSessionIdentity: k13.key.secureSessionIdentity, writeGeneration: k13.key.writeGeneration,
          });
          if (!sameBytes(derived, v.manifestKey)) throw inconsistent(`generation ${generation} hold key does not derive its manifest key`);
          if (!(BigInt(k13.decoded.parentGeneration) < g)) throw inconsistent(`generation ${generation} hold does not name an earlier parent`);
          if (k8 === undefined || !resultMatchesHold(k8.decoded, k13.decoded)) throw inconsistent(`generation ${generation} hold is not its own COMMIT_RESULT's`);
        }
      }
      const resultEvidence = k8 === undefined ? null : evidenceOfRecord(k8.decoded);
      // A present COMMIT_RESULT must be usable commit-result evidence (I-TXN evidenceFacts; C-MUT §5):
      // authenticated by the RS, and terminal when NOT_COMMITTED (B-CHR-CANON r1 C2).
      if (resultEvidence !== null && (resultEvidence.authenticatedByRS !== true
        || (resultEvidence.outcome === OUTCOME.NOT_COMMITTED && resultEvidence.terminal !== true))) {
        throw inconsistent(`generation ${generation} COMMIT_RESULT is not usable commit-result evidence`);
      }
      // escrow: the authenticated kind-9 record, bound to the generation's own hold (C-FMT outputEscrow.binding).
      let escrow = null;
      if (k9 !== undefined && k9.decoded.presence === 1) {
        const e = k9.decoded;
        const h = k13?.decoded;
        if (h === undefined || h.presence !== 1 || e.outputKind !== h.heldOutputKind || !sameBytes(e.operationIdentity, h.operationIdentity)
          || !sameBytes(e.candidateDigest, h.candidateDigest) || !sameBytes(e.candidateReference, h.candidateReference)
          || !sameBytes(e.mutationSetDigest, h.componentSetDigest) || !sameBytes(e.mutationSetReference, h.componentSetReference)) {
          throw inconsistent(`generation ${generation} OUTPUT_ESCROW is not bound to its hold`);
        }
        escrow = { kind: OUTPUT_KINDS[e.outputKind - 1], digest: copy(h.heldOutputDigest), reference: copy(h.heldOutputReference), output: copy(e.output) };
      }
      // sessionBindingDigest: from the authenticated kind-6 BINDING_PROFILE (C-FMT sessionDomain), whose
      // binding is a canonical C-BIND v0 binding of this context and this generation's session.
      let sessionBindingDigest = null;
      if (mk.scope === 2) {
        if (k6 === undefined || k6.decoded.presence !== 1) throw inconsistent(`SESSION generation ${generation} carries no BINDING_PROFILE`);
        const b = decodeBindingV0(k6.decoded.canonicalBinding);
        if (!sameBytes(b.localContextId, context.localContextId) || !sameBytes(b.secureSessionIdentity, mk.secureSessionIdentity)) {
          throw inconsistent(`generation ${generation} BINDING_PROFILE binds another context or session`);
        }
        const aad = await encodeAad({
          recordKey: k6.record.recordKey, localContextId: context.localContextId, productProfileDigest: context.productProfileDigest,
          scope: 2, secureSessionIdentity: mk.secureSessionIdentity, canonicalBinding: k6.decoded.canonicalBinding, writeGeneration: g,
          mutationIdentity: ZERO32, plaintextLength: 1, recordKind: K.BINDING_PROFILE,
        });
        sessionBindingDigest = decodeAad(aad).bindingDigest;
      } else if (k6 !== undefined && k6.decoded.presence === 1) {
        throw inconsistent(`pre-session generation ${generation} carries a BINDING_PROFILE`);
      }
      return {
        value: {
          generation: g, records, manifestKey: copy(v.manifestKey), manifestBytes: copy(v.manifestBytes),
          manifestCipherDigest: copy(v.manifestCipherDigest), keyedRoot: copy(v.keyedRoot),
          mutationHold, sessionBindingDigest, escrow, resultEvidence,
        },
        byKind,
      };
    } catch (e) {
      throw asVerification(e);
    }
  }
  async function readDurableGeneration(generation, options) {
    const v = await db.get(NS, genKey(generation));
    return v === undefined ? null : (await openGeneration(generation, v, options));
  }

  // ---- the selector -------------------------------------------------------------------------------------
  async function seal(plaintext) {
    const v = decodePlaintext(K.GENERATION_SELECTOR, plaintext);
    const aad = await encodeAad({
      recordKey: selectorKey, localContextId: context.localContextId, productProfileDigest: context.productProfileDigest,
      scope: 1, secureSessionIdentity: null, canonicalBinding: null, writeGeneration: v.generation,
      mutationIdentity: ZERO32, plaintextLength: plaintext.length, recordKind: K.GENERATION_SELECTOR,
    });
    return sealRecord({
      aeadKey, recordKind: K.GENERATION_SELECTOR, recordKey: selectorKey, aad, plaintext,
      nonce: crypto.getRandomValues(new Uint8Array(12)),
    });
  }
  async function open(envelope) {
    const env = decodeEnvelope(envelope);
    const ad = decodeAad(env.aad);
    if (ad.recordKind !== K.GENERATION_SELECTOR || !sameBytes(ad.localContextId, context.localContextId)
      || !sameBytes(ad.productProfileDigest, context.productProfileDigest)) {
      throw failed('AUTHENTICATION_FAILED', 'selector AAD context mismatch');
    }
    const opened = await openRecord({ aeadKey, envelope, expectedRecordKey: selectorKey, expectedAad: env.aad });
    // Canonical re-encoding of the authenticated plaintext (F3 / obligation item 12).
    return encodePlaintext(K.GENERATION_SELECTOR, decodePlaintext(K.GENERATION_SELECTOR, opened.plaintext));
  }

  // ---- the write path -------------------------------------------------------------------------------------
  // The projections of a staged (buffered) generation, derived exactly as a later read derives them.
  async function stagedProjection(v) {
    const fake = await sealGeneration(v);
    return (await openGeneration(v.generation, fake)).value;
  }
  const sameEvidence = (a, b) => a !== null && b !== null && EVIDENCE_FIELDS.every((f) => same(a[f], b[f]));
  const sameEscrow = (a, b) => (a === null || b === null ? a === b
    : a.kind === b.kind && sameBytes(a.digest, b.digest) && sameBytes(a.reference, b.reference) && sameBytes(a.output ?? null, b.output ?? null));

  async function replaceSelector(p) {
    // Everything is computed before transaction() (obligation item 3, best effort over VaultDb).
    let envelope; let after; let expected; let unbind = null;
    const puts = [];
    try {
      if (p.resolveHoldGeneration !== null && p.resolveHoldGeneration !== undefined) {
        throw failed('MALFORMED_INPUT', 'a selector replacement never resolves a hold (#468 B1: resolveHoldGeneration is null)');
      }
      envelope = await seal(copy(p.selectorBytes));
      after = decodePlaintext(K.GENERATION_SELECTOR, p.selectorBytes);
      expected = p.expectedSelectorBytes === null || p.expectedSelectorBytes === undefined ? null : copy(p.expectedSelectorBytes);
      // The selector this write replaces is the one whose envelope the request planned from; the CAS
      // below admits the write only if the stored envelope is byte-identical, so its plaintext is known.
      if (expected !== null) {
        const before = decodePlaintext(K.GENERATION_SELECTOR, await open(expected));
        const c = before.candidateGeneration;
        if (c !== before.generation && after.generation !== c && after.candidateGeneration !== c) unbind = c;
      }
      for (const v of buffer.values()) {
        if (v.manifest === null) throw failed('MALFORMED_INPUT', `generation ${v.generation} has no staged manifest`);
        // No sidecar: whatever the plan stages beside the records must be what the records project.
        const proj = await stagedProjection(v);
        if (!sameBytes(proj.sessionBindingDigest, v.manifest.sessionBindingDigest)) {
          throw inconsistent(`generation ${v.generation} staged sessionBindingDigest is not its BINDING_PROFILE's`);
        }
        if (v.evidence !== undefined && !sameEvidence(proj.resultEvidence, v.evidence)) {
          throw inconsistent(`generation ${v.generation} staged evidence is not its COMMIT_RESULT record`);
        }
        if (v.escrow !== undefined && !sameEscrow(proj.escrow, v.escrow)) {
          throw inconsistent(`generation ${v.generation} staged escrow is not its OUTPUT_ESCROW record`);
        }
        puts.push([genKey(v.generation), await sealGeneration(v)]);
      }
    } catch (e) {
      resetBuffer();
      throw e;
    }
    // Inside the transaction only IndexedDB requests are awaited (obligation item 3).
    try {
      await db.transaction([NS], async (ops) => {
        const cur = await ops.get(NS, SEL); // the F2 read, first request of the transaction
        const stored = cur === undefined ? null : copy(cur);
        if (!sameBytes(stored, expected)) throw new SelectorPreconditionFailed();
        const pending = puts.map(([k, v]) => ops.put(NS, k, v));
        if (unbind !== null) pending.push(ops.delete(NS, genKey(unbind))); // obligation item 2 / B3-1 item 3
        pending.push(ops.put(NS, SEL, envelope)); // the selector put last
        await Promise.all(pending);
      });
    } catch (e) {
      pendingMemoryHold = undefined; // nothing was written, so no hold is retained (B3-1 item 5)
      throw e;
    } finally {
      // Resolved: committed. Rejected: a reported abort, terminal evidence that nothing was written
      // (B3-1 item 4). Either way this write's buffer is spent.
      buffer = new Map();
    }
    // Success means complete (item 5); only now is the memory hold retained (item 6, B3-1 item 5).
    if (pendingMemoryHold !== undefined) { memoryHold = pendingMemoryHold; pendingMemoryHold = undefined; }
    if (unbind !== null) memoryHold = null; // the unbound candidate's hold went with it (B3-1 item 3)
  }

  async function writeHold(p) {
    // #468 B1: WRITE_HOLD creates no durable byte; it must agree with the generation's staged kind-13
    // record (buffered in this write, or already durable), field for field.
    const g = BigInt(p.generation);
    let k13;
    if (buffer.has(g)) {
      const r = buffer.get(g).records.find((x) => x.recordKind === K.MUTATION_HOLD);
      k13 = r === undefined ? null : decodePlaintext(K.MUTATION_HOLD, r.plaintext);
    } else {
      let d;
      try { d = await readDurableGeneration(g); } catch (e) { resetBuffer(); throw e; }
      k13 = d === null ? null : d.value.mutationHold;
    }
    if (k13 === null || !holdMatches(k13, p.hold)) {
      resetBuffer();
      throw inconsistent(`WRITE_HOLD does not agree with the kind-13 record of generation ${g}`);
    }
    pendingMemoryHold = p.holdRecordKey === null || p.holdRecordKey === undefined ? p.hold : { ...p.hold, recordKey: copy(p.holdRecordKey) };
  }

  // ---- the terminal readback producer (obligation item 13) -------------------------------------------------
  /**
   * The caller holds the writer lock and the original writer is quiescent (A(2), A(3)); the selector and
   * every generation live in the one `mls` store (A(4)). Only a failed IndexedDB read makes the readback
   * unavailable; every authenticated contradiction or failed verification fails closed (never S024).
   */
  async function readbackEvidence({ hold: memory = null } = {}) {
    const unavailable = () => {
      if (memory === null) throw failed('HOLD_UNAVAILABLE', 'the readback cannot be performed and no hold is in memory');
      return evidenceFrom(memory, OUTCOME.INDETERMINATE, false); // item 13: INDETERMINATE, S024
    };
    const read = async (key) => {
      try { const v = await db.get(NS, key); return { v: v === undefined ? null : v }; } catch { return null; }
    };
    const sel = await read(SEL);
    if (sel === null) return unavailable();
    if (sel.v === null) throw failed('NO_RECONCILIATION_PENDING', 'no selector to read back');
    const s = decodePlaintext(K.GENERATION_SELECTOR, await open(copy(sel.v))); // AEAD failure fails closed
    if (s.state === RECONCILIATION_REQUIRED) {
      // The bound candidate: a point lookup by the exact candidateManifestKey (item 12).
      const ck = decodeRecordKey(s.candidateManifestKey);
      if (ck.recordKind !== 16 || ck.writeGeneration !== s.candidateGeneration || !sameBytes(manifestKeyDigest(s.candidateManifestKey), s.candidateManifestKeyDigest)) {
        throw inconsistent('the RR selector candidate locator is not canonical');
      }
      const bound = await read(genKey(ck.writeGeneration));
      if (bound === null) return unavailable();
      if (bound.v === null) throw inconsistent('the bound candidate is missing');
      const cand = (await openGeneration(ck.writeGeneration, bound.v, { strict: true })).value;
      if (!sameBytes(cand.manifestKey, s.candidateManifestKey) || !sameBytes(cand.keyedRoot, s.candidateKeyedRoot)
        || !sameBytes(cand.manifestCipherDigest, s.candidateManifestCipherDigest)) {
        throw failed('EVIDENCE_MISMATCH', 'the RR selector does not bind exactly the stored candidate');
      }
      const hold = cand.mutationHold;
      if (hold?.presence !== 1 || hold.resultStatus !== OUTCOME.INDETERMINATE) throw inconsistent('the bound candidate carries no unresolved hold');
      if (s.generation !== BigInt(hold.parentGeneration) || !sameBytes(s.keyedRoot, hold.parentKeyedRoot)) {
        throw failed('EVIDENCE_MISMATCH', 'the RR selector does not keep the exact parent tuple of the hold');
      }
      if (memory !== null && !holdMatches(memory, hold)) throw failed('EVIDENCE_MISMATCH', 'the memory hold is not the durable hold');
      // The parent the RR selector keeps: complete and exactly the selected tuple.
      const parentRead = await read(genKey(s.generation));
      if (parentRead === null) return unavailable();
      if (parentRead.v === null) throw inconsistent('the selected parent is missing');
      const parent = (await openGeneration(s.generation, parentRead.v, { strict: true })).value;
      if (!sameBytes(manifestKeyDigest(parent.manifestKey), s.manifestKeyDigest) || !sameBytes(parent.keyedRoot, s.keyedRoot)
        || !sameBytes(parent.manifestCipherDigest, s.manifestCipherDigest)) {
        throw failed('EVIDENCE_MISMATCH', 'the RR selector does not keep exactly the stored parent');
      }
      return evidenceFrom(cand.resultEvidence, OUTCOME.NOT_COMMITTED, true);
    }
    if (memory === null) throw failed('NO_RECONCILIATION_PENDING', 'no reconciliation is pending');
    if (memory.recordKey === undefined || memory.recordKey === null) throw failed('EVIDENCE_MISMATCH', 'the memory hold carries no record key');
    // holdLocatorRule: the held candidate is the write generation of the hold's own record key.
    const hk = decodeRecordKey(memory.recordKey);
    const heldGeneration = hk.writeGeneration;
    if (s.generation !== heldGeneration) throw failed('EVIDENCE_MISMATCH', 'the readback contradicts the hold');
    const heldManifestKey = encodeManifestKey({
      localContextId: hk.localContextId, scope: hk.scope, secureSessionIdentity: hk.secureSessionIdentity, writeGeneration: hk.writeGeneration,
    });
    if (!sameBytes(s.candidateManifestKey, heldManifestKey)) throw failed('EVIDENCE_MISMATCH', 'the selected generation is not the held candidate');
    const r = await read(genKey(heldGeneration));
    if (r === null) return unavailable();
    if (r.v === null) throw inconsistent('the selected generation is missing');
    const sel2 = await openGeneration(heldGeneration, r.v, { strict: true });
    const cand = sel2.value;
    if (!sameBytes(cand.manifestKey, heldManifestKey) || !sameBytes(cand.keyedRoot, s.keyedRoot)
      || !sameBytes(cand.manifestCipherDigest, s.manifestCipherDigest)) {
      throw failed('EVIDENCE_MISMATCH', 'the selector does not name exactly the stored candidate');
    }
    // The complete new generation validates as this mutation's: its own hold is the held hold (kept as
    // historical evidence, #468 B2), its COMMIT_RESULT identifies it, its escrow and component set are
    // the hold's (C-FMT generationCommit, outputEscrow.binding; C-MUT originalAuthorityMatch).
    if (!holdMatches(cand.mutationHold, memory)) throw failed('EVIDENCE_MISMATCH', 'the selected generation does not carry the held hold');
    const k8 = sel2.byKind.get(K.COMMIT_RESULT).decoded;
    if (!resultMatchesHold(k8, memory)) throw failed('EVIDENCE_MISMATCH', 'the selected COMMIT_RESULT does not identify the held mutation');
    const k14 = sel2.byKind.get(K.COMPONENT_SET).decoded;
    if (k14.presence !== 1 || !sameBytes(k14.mutationSetDigest, memory.componentSetDigest) || !sameBytes(k14.mutationSetReference, memory.componentSetReference)) {
      throw failed('EVIDENCE_MISMATCH', 'the selected COMPONENT_SET is not the held mutation set');
    }
    const none = OUTPUT_KINDS[memory.heldOutputKind - 1] === 'NONE';
    if (none ? cand.escrow !== null : (cand.escrow === null || !sameBytes(cand.escrow.digest, memory.heldOutputDigest)
      || !sameBytes(cand.escrow.reference, memory.heldOutputReference))) {
      throw failed('EVIDENCE_MISMATCH', 'the selected escrow is not the held output');
    }
    return evidenceFrom(evidenceOfRecord(k8), OUTCOME.COMMITTED, true);
  }

  return {
    async apply(step) {
      const p = step.payload;
      switch (step.kind) {
        case 'STAGE_DATA': {
          const c = canonicalRecord(p, p.generation, `staged record of generation ${p.generation}`);
          staged(p.generation).records.push(c.record);
          return;
        }
        case 'STAGE_MANIFEST':
          staged(p.generation).manifest = {
            manifestKey: copy(p.manifestKey), manifestBytes: copy(p.manifestBytes), manifestCipherDigest: copy(p.manifestCipherDigest),
            keyedRoot: copy(p.keyedRoot), sessionBindingDigest: p.sessionBindingDigest === null ? null : copy(p.sessionBindingDigest),
          };
          return;
        case 'STAGE_EVIDENCE': staged(p.generation).evidence = p.evidence; return;
        case 'STAGE_ESCROW': staged(p.generation).escrow = p.escrow; return;
        case 'WRITE_HOLD': await writeHold(p); return;
        case 'REPLACE_SELECTOR': await replaceSelector(p); return;
        case 'CLEAR_CANDIDATE':
          // A buffered candidate was never durable; a durable bound candidate was removed together with the
          // unbind (item 2). Durable unbound bytes are debris and are never removed here (B3-1 item 2).
          buffer.delete(BigInt(p.generation));
          pendingMemoryHold = undefined;
          memoryHold = null;
          return;
        case 'RELEASE_ESCROW': memoryHold = null; return; // escrow bytes stay with their generation (item 14)
        default:
          throw new Error(`unexpected step ${step.kind}`);
      }
    },
    async readSelector() {
      const v = await db.get(NS, SEL);
      if (v === undefined) return null;
      const envelope = copy(v);
      return { plaintext: await open(envelope), envelope };
    },
    async readGeneration(generation) {
      const r = await readDurableGeneration(generation);
      return r === null ? null : r.value;
    },
    async readMemoryHold() { return memoryHold; },
    async readGenerationNumbers() {
      const keys = await db.list(NS);
      const out = new Set([...buffer.keys()]);
      for (const k of keys) if (typeof k === 'string' && k.startsWith('gen:')) out.add(BigInt(k.slice(4)));
      return [...out];
    },
    readbackEvidence,
  };
}
