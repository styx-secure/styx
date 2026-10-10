// B-CHR reference port (test-owned; act #317 6091950328 §1 "Reference port").
// - Delegates only to VaultDb.transaction and the public VaultDb reads (get, list) on the `mls` store.
// - Implements only the public port interface: the I-TXN storage methods apply, readSelector,
//   readGeneration, readMemoryHold, readGenerationNumbers, and the B-CHR obligation v2 item-13 producer
//   readbackEvidence. No test hook, no fallback, no knowledge of the suite.
// - Layout: one value per generation (`gen:<n>`) and the fixed selector (`sel`).
//   - The selector is a C-FMT envelope sealed with a fresh 96-bit CSPRNG nonce on every write (C-FMT §4
//     nonce rule; obligation item 10).
//   - Every generation value is sealed at rest (AES-256-GCM, key derived from the C-FMT namespace key,
//     the generation key as AAD, a fresh nonce per write); a read returns only authenticated values and
//     a value that does not authenticate fails closed (obligation item 12, as far as the fixtures allow;
//     the contract records the residual).
// - Everything is computed before VaultDb.transaction is called; inside it only IndexedDB requests are
//   awaited (obligation item 3, best effort over VaultDb).
// Non-claims (act §1): B-CHR obligation items 3, 4 and 7 (the transaction object is not exposed by
// VaultDb) are not claimed for this port.
import {
  M2_KIND, decodeAad, decodeEnvelope, decodePlaintext, deriveNamespaceKey, deriveSelectorAeadKey, encodeAad,
  encodePlaintext, encodeSelectorKey, openRecord, sealRecord,
} from '/src/storage/m2/session-codec.js';

const NS = 'mls';
const SEL = 'sel';
const genKey = (g) => `gen:${BigInt(g).toString()}`;
const ZERO32 = new Uint8Array(32);
const OUTCOME = Object.freeze({ COMMITTED: 1, NOT_COMMITTED: 2, INDETERMINATE: 3 });
const RECONCILIATION_REQUIRED = 3;

export class SelectorPreconditionFailed extends Error {
  constructor() { super('the stored selector envelope differs from expectedSelectorBytes'); this.code = 'SELECTOR_PRECONDITION_FAILED'; }
}
const sameBytes = (a, b) => (a === null || b === null ? a === b : a.length === b.length && a.every((x, i) => x === b[i]));
const copy = (u8) => Uint8Array.prototype.slice.call(u8);
const failed = (code, message) => Object.assign(new Error(message), { code });
const hex = (u8) => Array.from(u8, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const utf8 = (t) => new TextEncoder().encode(t);

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

// Item 13: identity fields are copied from the hold, never invented.
function evidenceOf(hold, outcome, terminal) {
  return {
    operationIdentity: copy(hold.operationIdentity),
    originalAuthorityDigest: copy(hold.originalAuthorityDigest), originalAuthorityReference: copy(hold.originalAuthorityReference),
    candidateDigest: copy(hold.candidateDigest), candidateReference: copy(hold.candidateReference),
    mutationSetDigest: copy(hold.componentSetDigest), mutationSetReference: copy(hold.componentSetReference),
    expectedOriginalState: hold.originalApiState, bindingRef: copy(hold.bindingRef), profile: copy(hold.profileDigest),
    outcome, authenticatedByRS: true, terminal,
  };
}

export async function createPort({ db, context }) {
  const selectorKey = encodeSelectorKey({ localContextId: context.localContextId });
  const namespaceKey = await deriveNamespaceKey(context);
  const aeadKey = await deriveSelectorAeadKey({ namespaceKey, selectorKey });
  const genBase = await crypto.subtle.importKey('raw', copy(namespaceKey), 'HKDF', false, ['deriveKey']);
  const genAead = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: utf8('styx-bchr-reference-port/generation-aead/v1') },
    genBase, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
  let buffer = new Map(); // generation -> staged value (not durable)
  let holds = new Map();  // durable generation -> hold to write with the next selector replacement
  let pendingMemoryHold;   // set at WRITE_HOLD, becomes the memory hold only after the binding complete
  let memoryHold = null;

  const staged = (g) => {
    const k = BigInt(g);
    if (!buffer.has(k)) {
      buffer.set(k, {
        generation: k, records: [], manifestKey: null, manifestBytes: null, manifestCipherDigest: null, keyedRoot: null,
        sessionBindingDigest: null, mutationHold: { presence: 0 }, escrow: null, resultEvidence: null,
      });
    }
    return buffer.get(k);
  };

  async function sealGeneration(value) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: utf8(genKey(value.generation)) }, genAead, utf8(JSON.stringify(encodeValue(value))),
    ));
    return { nonce, ct };
  }
  async function openGeneration(generation, stored) {
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
    const value = decodeValue(JSON.parse(new TextDecoder().decode(plain)));
    if (value.generation !== BigInt(generation)) throw failed('AUTHENTICATION_FAILED', 'generation number mismatch');
    return value;
  }
  async function readDurableGeneration(generation) {
    const v = await db.get(NS, genKey(generation));
    return v === undefined ? null : openGeneration(generation, v);
  }

  async function seal(plaintext) {
    const v = decodePlaintext(M2_KIND.GENERATION_SELECTOR, plaintext);
    const aad = await encodeAad({
      recordKey: selectorKey, localContextId: context.localContextId, productProfileDigest: context.productProfileDigest,
      scope: 1, secureSessionIdentity: null, canonicalBinding: null, writeGeneration: v.generation,
      mutationIdentity: ZERO32, plaintextLength: plaintext.length, recordKind: M2_KIND.GENERATION_SELECTOR,
    });
    return sealRecord({
      aeadKey, recordKind: M2_KIND.GENERATION_SELECTOR, recordKey: selectorKey, aad, plaintext,
      nonce: crypto.getRandomValues(new Uint8Array(12)),
    });
  }

  async function open(envelope) {
    const env = decodeEnvelope(envelope);
    const ad = decodeAad(env.aad);
    if (ad.recordKind !== M2_KIND.GENERATION_SELECTOR || !sameBytes(ad.localContextId, context.localContextId)
      || !sameBytes(ad.productProfileDigest, context.productProfileDigest)) {
      throw failed('AUTHENTICATION_FAILED', 'selector AAD context mismatch');
    }
    const opened = await openRecord({ aeadKey, envelope, expectedRecordKey: selectorKey, expectedAad: env.aad });
    // Canonical re-encoding of the authenticated plaintext (F3 / obligation item 12).
    return encodePlaintext(M2_KIND.GENERATION_SELECTOR, decodePlaintext(M2_KIND.GENERATION_SELECTOR, opened.plaintext));
  }

  async function replaceSelector(p) {
    // Everything is computed before transaction() (obligation item 3, best effort over VaultDb).
    const envelope = await seal(copy(p.selectorBytes));
    const after = decodePlaintext(M2_KIND.GENERATION_SELECTOR, p.selectorBytes);
    const expected = p.expectedSelectorBytes === null || p.expectedSelectorBytes === undefined ? null : copy(p.expectedSelectorBytes);
    const resolve = p.resolveHoldGeneration === null || p.resolveHoldGeneration === undefined ? null : BigInt(p.resolveHoldGeneration);
    let unbind = null;
    const puts = [];
    try {
      // The selector this write replaces is the one whose envelope the request planned from; the CAS
      // below admits the write only if the stored envelope is byte-identical, so its plaintext is known.
      if (expected !== null) {
        const before = decodePlaintext(M2_KIND.GENERATION_SELECTOR, await open(expected));
        const c = before.candidateGeneration;
        if (c !== before.generation && after.generation !== c && after.candidateGeneration !== c) unbind = c;
      }
      for (const v of buffer.values()) {
        const value = resolve !== null && v.generation === resolve ? { ...v, mutationHold: { presence: 0 } } : v;
        puts.push([genKey(v.generation), await sealGeneration(value)]);
      }
      // Hold changes on already durable generations are read and re-sealed here; the selector CAS inside
      // the transaction admits the write only if the authority the plan read is still current (item 10).
      const durable = new Map([...holds.entries()].filter(([g]) => g !== unbind));
      if (resolve !== null && !buffer.has(resolve)) durable.set(resolve, { presence: 0 });
      for (const [g, hold] of durable) {
        const v = await readDurableGeneration(g);
        if (v !== null) puts.push([genKey(g), await sealGeneration({ ...v, mutationHold: hold })]);
      }
    } catch (e) {
      buffer = new Map();
      holds = new Map();
      pendingMemoryHold = undefined;
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
      holds = new Map();
    }
    // Success means complete (item 5); only now is the memory hold retained (item 6, B3-1 item 5).
    if (pendingMemoryHold !== undefined) { memoryHold = pendingMemoryHold; pendingMemoryHold = undefined; }
    if (unbind !== null) memoryHold = null; // the unbound candidate's hold went with it (B3-1 item 3)
  }

  return {
    async apply(step) {
      const p = step.payload;
      switch (step.kind) {
        case 'STAGE_DATA':
          staged(p.generation).records.push({
            recordKey: copy(p.recordKey), recordKind: p.recordKind, plaintext: copy(p.plaintext), ciphertext: copy(p.ciphertext), tag: copy(p.tag),
          });
          return;
        case 'STAGE_MANIFEST': {
          const s = staged(p.generation);
          Object.assign(s, {
            manifestKey: copy(p.manifestKey), manifestBytes: copy(p.manifestBytes), manifestCipherDigest: copy(p.manifestCipherDigest),
            keyedRoot: copy(p.keyedRoot), sessionBindingDigest: p.sessionBindingDigest === null ? null : copy(p.sessionBindingDigest),
          });
          return;
        }
        case 'STAGE_EVIDENCE': staged(p.generation).resultEvidence = p.evidence; return;
        case 'STAGE_ESCROW': staged(p.generation).escrow = p.escrow; return;
        case 'WRITE_HOLD':
          // A hold for a generation staged in this write travels with it; a hold for an already durable
          // generation is written in the same atomic write as the next selector replacement (B3-1 item 1).
          if (buffer.has(BigInt(p.generation))) staged(p.generation).mutationHold = p.hold;
          else holds.set(BigInt(p.generation), p.hold);
          pendingMemoryHold = p.holdRecordKey === null || p.holdRecordKey === undefined ? p.hold : { ...p.hold, recordKey: copy(p.holdRecordKey) };
          return;
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
      return readDurableGeneration(generation);
    },
    async readMemoryHold() { return memoryHold; },
    async readGenerationNumbers() {
      const keys = await db.list(NS);
      const out = new Set([...buffer.keys()]);
      for (const k of keys) if (typeof k === 'string' && k.startsWith('gen:')) out.add(BigInt(k.slice(4)));
      return [...out];
    },
    // Terminal readback producer (B-CHR obligation v2 item 13; restart design §2.2, Q1 = A). The caller
    // holds the writer lock and the original writer is quiescent (A(2), A(3)); the selector and every
    // generation live in the one `mls` store (A(4)). The hold is the supplied memory hold or, after a
    // memory loss, the authenticated kind-13 hold of the candidate the RR selector binds.
    async readbackEvidence({ hold: memory = null } = {}) {
      const unavailable = () => {
        if (memory === null) throw failed('HOLD_UNAVAILABLE', 'the readback cannot be performed and no hold is in memory');
        return evidenceOf(memory, OUTCOME.INDETERMINATE, false); // item 13: INDETERMINATE, S024
      };
      let stored;
      try {
        const v = await db.get(NS, SEL);
        stored = v === undefined ? null : copy(v);
      } catch {
        return unavailable();
      }
      if (stored === null) throw failed('NO_RECONCILIATION_PENDING', 'no selector to read back');
      const s = decodePlaintext(M2_KIND.GENERATION_SELECTOR, await open(stored)); // AEAD failure fails closed
      if (s.state === RECONCILIATION_REQUIRED) {
        let bound;
        try { bound = await db.get(NS, genKey(s.candidateGeneration)); } catch { return unavailable(); }
        if (bound === undefined) throw failed('AUTHENTICATION_FAILED', 'the bound candidate is missing');
        const cand = await openGeneration(s.candidateGeneration, bound);
        const hold = cand.mutationHold;
        if (hold?.presence !== 1) throw failed('AUTHENTICATION_FAILED', 'the bound candidate carries no hold');
        // The RR selector must bind exactly this candidate: its candidate tuple is the stored one.
        if (!sameBytes(s.candidateKeyedRoot, cand.keyedRoot) || !sameBytes(s.candidateManifestCipherDigest, cand.manifestCipherDigest)) {
          throw failed('EVIDENCE_MISMATCH', 'the RR selector does not bind exactly the stored candidate');
        }
        if (memory !== null && !sameBytes(memory.operationIdentity, hold.operationIdentity)) {
          throw failed('EVIDENCE_MISMATCH', 'the memory hold is not the durable hold');
        }
        if (s.generation !== BigInt(hold.parentGeneration) || !sameBytes(s.keyedRoot, hold.parentKeyedRoot)) {
          throw failed('EVIDENCE_MISMATCH', 'the RR selector does not keep the exact parent tuple of the hold');
        }
        return evidenceOf(hold, OUTCOME.NOT_COMMITTED, true);
      }
      if (memory === null) throw failed('NO_RECONCILIATION_PENDING', 'no reconciliation is pending');
      if (s.generation !== BigInt(memory.parentGeneration)) {
        let cand;
        try {
          const v = await db.get(NS, genKey(s.generation));
          cand = v === undefined ? null : await openGeneration(s.generation, v);
        } catch (e) {
          if (e.code === 'AUTHENTICATION_FAILED') throw e;
          return unavailable();
        }
        if (cand !== null && cand.resultEvidence !== null && BigInt(cand.generation) === s.generation
          && sameBytes(cand.keyedRoot, s.keyedRoot) && sameBytes(cand.manifestCipherDigest, s.manifestCipherDigest)
          && sameBytes(cand.resultEvidence.operationIdentity, memory.operationIdentity)) {
          return evidenceOf(memory, OUTCOME.COMMITTED, true);
        }
      }
      throw failed('EVIDENCE_MISMATCH', 'the readback contradicts the hold');
    },
  };
}
