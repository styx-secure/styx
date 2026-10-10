// B-CHR reference port (test-owned; act #317 6091950328 §1 "Reference port").
// - Delegates only to VaultDb.transaction and the public VaultDb reads (get, list) on the `mls` store.
// - Implements only the public I-TXN/C-FMT port interface: apply, readSelector, readGeneration,
//   readMemoryHold, readGenerationNumbers. No test hook, no fallback, no knowledge of the suite.
// - Layout: one value per generation (`gen:<n>`) and the fixed selector (`sel`), whose value is a
//   C-FMT envelope sealed with a fresh 96-bit CSPRNG nonce on every write (C-FMT §4 nonce rule; F2).
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

export class SelectorPreconditionFailed extends Error {
  constructor() { super('the stored selector envelope differs from expectedSelectorBytes'); this.code = 'SELECTOR_PRECONDITION_FAILED'; }
}
const sameBytes = (a, b) => (a === null || b === null ? a === b : a.length === b.length && a.every((x, i) => x === b[i]));
const copy = (u8) => Uint8Array.prototype.slice.call(u8);

export async function createPort({ db, context }) {
  const selectorKey = encodeSelectorKey({ localContextId: context.localContextId });
  const namespaceKey = await deriveNamespaceKey(context);
  const aeadKey = await deriveSelectorAeadKey({ namespaceKey, selectorKey });
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
      throw Object.assign(new Error('selector AAD context mismatch'), { code: 'AUTHENTICATION_FAILED' });
    }
    const opened = await openRecord({ aeadKey, envelope, expectedRecordKey: selectorKey, expectedAad: env.aad });
    // Canonical re-encoding of the authenticated plaintext (F3 / obligation item 12).
    return encodePlaintext(M2_KIND.GENERATION_SELECTOR, decodePlaintext(M2_KIND.GENERATION_SELECTOR, opened.plaintext));
  }

  async function replaceSelector(p) {
    // Everything computed before transaction() (obligation item 3, best effort over VaultDb).
    const envelope = await seal(copy(p.selectorBytes));
    const after = decodePlaintext(M2_KIND.GENERATION_SELECTOR, p.selectorBytes);
    const writes = [...buffer.values()];
    const heldWrites = [...holds.entries()];
    const expected = p.expectedSelectorBytes === null || p.expectedSelectorBytes === undefined ? null : copy(p.expectedSelectorBytes);
    const resolve = p.resolveHoldGeneration === null || p.resolveHoldGeneration === undefined ? null : BigInt(p.resolveHoldGeneration);
    if (resolve !== null && buffer.has(resolve)) buffer.get(resolve).mutationHold = { presence: 0 };
    const resolveDurable = resolve !== null && !buffer.has(resolve) ? resolve : null;
    // The selector this write replaces is the one whose envelope the request planned from; the CAS below
    // admits the write only if the stored envelope is byte-identical, so its plaintext is known here.
    let unbind = null;
    if (expected !== null) {
      const before = decodePlaintext(M2_KIND.GENERATION_SELECTOR, await open(expected));
      const c = before.candidateGeneration;
      if (c !== before.generation && after.generation !== c && after.candidateGeneration !== c) unbind = c;
    }
    // Inside the transaction only IndexedDB requests are awaited (obligation item 3).
    try {
      await db.transaction([NS], async (ops) => {
        const cur = await ops.get(NS, SEL); // the F2 read, first request of the transaction
        const stored = cur === undefined ? null : copy(cur);
        if (!sameBytes(stored, expected)) throw new SelectorPreconditionFailed();
        const pending = [];
        for (const v of writes) pending.push(ops.put(NS, genKey(v.generation), v));
        for (const [g, hold] of heldWrites) {
          const v = await ops.get(NS, genKey(g));
          if (v !== undefined && g !== unbind) pending.push(ops.put(NS, genKey(g), { ...v, mutationHold: hold }));
        }
        if (resolveDurable !== null) {
          const g = await ops.get(NS, genKey(resolveDurable));
          if (g !== undefined) pending.push(ops.put(NS, genKey(resolveDurable), { ...g, mutationHold: { presence: 0 } }));
        }
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
      const v = await db.get(NS, genKey(generation));
      return v === undefined ? null : v;
    },
    async readMemoryHold() { return memoryHold; },
    async readGenerationNumbers() {
      const keys = await db.list(NS);
      const out = new Set([...buffer.keys()]);
      for (const k of keys) if (typeof k === 'string' && k.startsWith('gen:')) out.add(BigInt(k.slice(4)));
      return [...out];
    },
  };
}
