// B-CHR dedicated worker (act #317 6091950328 §1 "Harness"): the I-TXN driver and the port run here,
// in one dedicated worker that the harness creates and that dies with its page. Port-neutral: it uses
// only the port's public C-FMT/I-TXN interface and the public VaultDb reads.
import { openVaultDb } from '/src/storage/vault-db.js';
import { M2_KIND, decodeEnvelope, decodePlaintext, encodePlaintext } from '/src/storage/m2/session-codec.js';
import {
  M2_OUTCOME, classifyAuthority, mutationRow, reconcileIndeterminate, runMutation, validateCommitResultEvidence,
} from '/src/storage/m2/session-transaction.js';
import { instrument } from './instrument.mjs';
import {
  PORT_CONTEXT, evidenceFor, manifestRootKey, mutationInput, noneHoldEncodable, parentFixture, prepareFixtures, restage, selfSelector,
} from './fixtures.mjs';

/**
 * The port the worker drives, wrapped so the harness sees every selector envelope the port reads or
 * writes (obligation item 10: a fresh 96-bit nonce per selector write, never a reused one), whatever
 * the factory does internally. The wrapper owns no behaviour: it forwards everything unchanged. An
 * envelope is identified by its own bytes; the nonce is read from the port's C-FMT selector envelope.
 */
function tracked(target) {
  const noteRead = (envelope, plaintext) => {
    if (!(envelope instanceof Uint8Array) || envelope.length === 0) return;
    const h = hex(envelope);
    const existing = state.selectors.find((sel) => sel.envelope === h);
    const pt = plaintext instanceof Uint8Array ? hex(plaintext) : null;
    if (existing === undefined) state.selectors.push({ envelope: h, nonce: hex(decodeEnvelope(envelope).nonce), plaintext: pt, read: true });
    else if (existing.plaintext === null) existing.plaintext = pt;
  };
  return {
    apply: (step) => {
      // The port's own resolution timing is preserved: nothing is awaited on its completion path
      // (review impl2 R2-5). A write's envelope is observed after the operation, never inside it.
      const r = target.apply(step);
      if (step.kind === 'REPLACE_SELECTOR') {
        Promise.resolve(r).then(() => target.readSelector()).then((stored) => {
          if (stored === null) return;
          const h = hex(stored.envelope);
          if (!state.selectors.some((sel) => sel.envelope === h)) {
            state.selectors.push({ envelope: h, nonce: hex(decodeEnvelope(stored.envelope).nonce), plaintext: hex(step.payload.selectorBytes), read: false, written: true });
          }
        }, () => {});
      }
      return r;
    },
    readSelector: async () => {
      const r = await target.readSelector();
      if (r !== null) noteRead(r.envelope, r.plaintext);
      return r;
    },
    readGeneration: (g) => target.readGeneration(g),
    readMemoryHold: () => target.readMemoryHold(),
    readGenerationNumbers: () => target.readGenerationNumbers(),
    readbackEvidence: (a) => target.readbackEvidence(a),
  };
}

const params = new URL(self.location.href).searchParams;
// The one line that selects the factory (act §1: no other line of the suite branches on it).
const FACTORY = { reference: './reference-port.mjs', product: '/src/storage/m2/session-idb-port.js' }[params.get('factory')];

const NS = 'mls';
const LOCK_NAME = 'styx-m2-bchr-suite-writer';
const API = { EMPTY: 1, ACTIVE: 2 };
const K = M2_KIND;
const hex = (b) => (b === null || b === undefined ? null : Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join(''));
const state = { armed: false, fault: null, tamperAt: null, plan: {}, trace: [], probes: [], selectors: [], next: 0, reads: 0, faulted: false, onOpen: null };
const hook = (point, data = null) => {
  const x = new XMLHttpRequest();
  x.open('GET', `/hook?p=${encodeURIComponent(point)}${data === null ? '' : `&d=${encodeURIComponent(JSON.stringify(data))}`}`, false);
  x.send();
};
instrument({ hook: (p, d) => { if (state.armed) hook(p, d); }, state });

let db = null;
let port = null;
let lock = null;

async function init({ dbName }) {
  // Harness-owned Web Lock (no product lock claim, act §1 non-claims): it shows that the lock of a dead
  // context is released and re-acquired before readback (act §1 item 4). A bounded wait, not
  // ifAvailable: the release by a dead context is asynchronous.
  lock = await new Promise((resolve) => {
    navigator.locks.request(LOCK_NAME, { signal: AbortSignal.timeout(10000) }, () => {
      resolve(true);
      return new Promise(() => {});
    }).catch(() => resolve(false));
  });
  await prepareFixtures();
  db = await openVaultDb({ name: dbName });
  const { createPort } = await import(FACTORY);
  port = tracked(await createPort({ db, context: PORT_CONTEXT }));
  return { lock, noneHoldEncodable: noneHoldEncodable() };
}

/** Write a generation and a selector through the public port interface only (I-TXN step shapes). */
async function writeGeneration(g, records, selector, expected, extra = []) {
  const steps = [
    ...records.map((r) => ({ kind: 'STAGE_DATA', payload: { generation: g.generation, ...r } })),
    { kind: 'STAGE_MANIFEST', payload: {
      generation: g.generation, manifestKey: g.manifestKey, manifestBytes: g.manifestBytes,
      manifestCipherDigest: g.manifestCipherDigest, keyedRoot: g.keyedRoot, sessionBindingDigest: g.sessionBindingDigest,
    } },
    ...extra,
    { kind: 'REPLACE_SELECTOR', payload: { selectorBytes: selector, resolveHoldGeneration: null, expectedSelectorBytes: expected } },
  ];
  let index = 0;
  for (const s of steps) await port.apply(Object.freeze({ index: index++, boundary: 'BEFORE_STAGING', ...s }));
}

/** The parent authority: generation 1 selected in the row's origin state. */
async function seed({ scenario }) {
  const P = parentFixture(scenario);
  await writeGeneration(P, P.records, selfSelector(P, API[mutationRow(scenario).stateBefore]), null);
  return 'seeded';
}

// A parent spec names the stored generation a request stages over: absent, the row's generation 1;
// { row, outcome, op }, the generation 2 that request of `row` staged over that row's generation 1.
const parentOf = (scenario, spec) => (spec ? mutationInput(spec.row, M2_OUTCOME[spec.outcome], { generation: 2n, op: spec.op }).staged
  : parentFixture(scenario));
const requestOf = (scenario, outcome, { parent, generation = '2', op = 1 } = {}) => mutationInput(scenario, outcome, {
  parent: parentOf(scenario, parent), generation: BigInt(generation), op,
  parentState: parent ? API.ACTIVE : API[mutationRow(scenario).stateBefore],
});

/**
 * Debris fixture (C-FMT generationCommit.unboundCandidate): a complete candidate generation 2 with its
 * result evidence and escrow made durable while the selector keeps naming the parent, byte for byte the
 * same plaintext, as a crash of a per-call writer leaves it. Written through the public interface only.
 */
async function seedDebris({ scenario, outcome }) {
  const { candidate, staged } = mutationInput(scenario, M2_OUTCOME[outcome], { generation: 2n, op: 0x40 });
  const stored = await port.readSelector();
  const extra = [{ kind: 'STAGE_EVIDENCE', payload: { generation: 2n, evidence: candidate.resultEvidence } }];
  if (candidate.escrow !== null) extra.push({ kind: 'STAGE_ESCROW', payload: { generation: 2n, escrow: candidate.escrow } });
  await writeGeneration(staged, staged.records, stored.plaintext, stored.envelope, extra);
  return 'debris';
}

/** The stored selector envelope, kept by the harness outside the context it will kill. */
async function snapshot() {
  const s = await port.readSelector();
  return s === null ? null : { envelope: hex(s.envelope), plaintext: hex(s.plaintext), nonce: hex(decodeEnvelope(s.envelope).nonce) };
}

/**
 * A delayed writer (T6b CAS): a REPLACE_SELECTOR carrying the envelope bytes its plan read before the
 * operation, sent through the public port interface after the authority changed.
 */
async function delayedReplace({ snap }) {
  const bytes = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
  const r = await guarded(() => port.apply(Object.freeze({
    index: 0, boundary: 'BEFORE_STAGING', kind: 'REPLACE_SELECTOR',
    payload: { selectorBytes: bytes(snap.plaintext), resolveHoldGeneration: null, expectedSelectorBytes: bytes(snap.envelope) },
  })));
  return { error: r.error ?? null };
}

/**
 * T9 PRODUCE_COMMITTED / TAMPER_COMMITTED (obligation item 13, COMMITTED branch): the commit lands while
 * its response is lost and the SS still holds its hold. The landed commit is driven through the I-TXN
 * driver with injected RS evidence; the producer is then given the hold the SS kept and must read back
 * COMMITTED, terminal, with identity fields that validate against the operation's envelope (or, with
 * `tamper`, every read after the first returns flipped bytes and the producer must fail closed). It
 * writes nothing.
 */
async function produceAfterCommit({ scenario, tamper = false }) {
  const hold = await port.readMemoryHold();
  const { envelope } = requestOf(scenario, M2_OUTCOME.INDETERMINATE);
  const landed = await guarded(async () => reconcileIndeterminate({
    storage: port, manifestRootKey: manifestRootKey(), hold, evidence: evidenceFor(envelope, M2_OUTCOME.COMMITTED),
    reference: envelope.reconciliationIdentity.reference,
  }));
  const before = (await readback({})).dbDigest;
  arm(tamper ? { fault: 'TAMPER', tamperAt: 'REST' } : {});
  const p = await guarded(() => port.readbackEvidence({ hold }));
  state.armed = false;
  const valid = p.ok ? await guarded(async () => validateCommitResultEvidence({ evidence: p.ok, envelope })) : null;
  const after = await readback({});
  return {
    setup: landed.error ?? null, hadHold: hold !== null,
    produced: p.ok ? { outcome: p.ok.outcome, terminal: p.ok.terminal } : null, error: p.error ?? null,
    identity: valid === null ? null : (valid.error ?? 'VALID'), before, after: after.dbDigest, trace: state.trace,
  };
}

const flip = (b) => { const c = Uint8Array.from(b); c[0] ^= 0xff; return c; };
function reencode(kind, plaintext, change) {
  const v = { ...decodePlaintext(kind, plaintext) };
  change(v);
  return encodePlaintext(kind, v);
}

/**
 * T9 CONTRADICT_* (obligation item 13, last bullet): an authenticated contradiction. With the SS hold
 * kept after an ORIGINAL INDETERMINATE, the harness writes through the public port interface (sealed by
 * the port, CAS on the stored envelope):
 * - CONTRADICT_RR_PARENT / CONTRADICT_RR_CANDIDATE: an RR selector whose parent / candidate keyed root
 *   is not the hold's / the stored candidate's;
 * - CONTRADICT_COMMITTED: a selector naming the candidate generation with roots it does not have;
 * - CONTRADICT_RESULT / CONTRADICT_RESULT_NONTERMINAL / CONTRADICT_ESCROW / CONTRADICT_PARTIAL: a selector
 *   naming a complete canonical generation 2 whose COMMIT_RESULT keeps the held identity but is not
 *   authenticated by the RS / is a non-terminal NOT_COMMITTED, whose OUTPUT_ESCROW has another output
 *   kind, or that lacks one data record (B-CHR PR-r1 F1; B-CHR-CANON r1 C2).
 * The port may refuse the write (nothing written); otherwise the producer must fail closed (never
 * NOT_COMMITTED, COMMITTED or S024) and write nothing.
 */
async function contradict({ scenario, kind }) {
  const hold = await port.readMemoryHold();
  const { candidate, staged } = requestOf(scenario, M2_OUTCOME.INDETERMINATE);
  const current = await port.readSelector();
  const start = (await readback({})).dbDigest;
  let setup;
  if (kind.startsWith('CONTRADICT_RR_') || kind === 'CONTRADICT_COMMITTED') {
    const committed = kind === 'CONTRADICT_COMMITTED';
    const v = decodePlaintext(K.GENERATION_SELECTOR, committed ? candidate.selectorBytes : candidate.holdSelectorBytes);
    const fields = { CONTRADICT_RR_PARENT: ['keyedRoot'], CONTRADICT_RR_CANDIDATE: ['candidateKeyedRoot'], CONTRADICT_COMMITTED: ['keyedRoot', 'candidateKeyedRoot'] }[kind];
    const bad = { ...v };
    for (const f of fields) bad[f] = flip(v[f]);
    setup = await guarded(() => port.apply(Object.freeze({
      index: 0, boundary: 'BEFORE_STAGING', kind: 'REPLACE_SELECTOR',
      payload: { selectorBytes: encodePlaintext(K.GENERATION_SELECTOR, bad), resolveHoldGeneration: null, expectedSelectorBytes: current.envelope },
    })));
  } else {
    let forged;
    const k8 = (change) => ({ [K.COMMIT_RESULT]: reencode(K.COMMIT_RESULT, staged.content[K.COMMIT_RESULT], change) });
    if (kind === 'CONTRADICT_RESULT') {
      // Identity unchanged, but not authenticated by the RS (Sol B-CHR-CANON r1 C2).
      forged = restage(staged, k8((x) => { x.authenticatedByRS = false; }));
    } else if (kind === 'CONTRADICT_RESULT_NONTERMINAL') {
      forged = restage(staged, k8((x) => { x.outcome = 2; x.terminal = false; }));
    } else if (kind === 'CONTRADICT_ESCROW') {
      const e = staged.content[K.OUTPUT_ESCROW];
      forged = restage(staged, { [K.OUTPUT_ESCROW]: reencode(K.OUTPUT_ESCROW, e, (x) => { x.outputKind = x.outputKind === 6 ? 2 : x.outputKind + 1; }) });
    } else {
      forged = restage(staged, {}, { drop: K.ABSENCE_COMMITMENTS });
    }
    setup = await guarded(() => writeGeneration(forged, forged.records, selfSelector(forged, API.ACTIVE), current.envelope));
  }
  const before = (await readback({})).dbDigest;
  arm({});
  const p = await guarded(() => port.readbackEvidence({ hold }));
  state.armed = false;
  const after = await readback({});
  return {
    setup: setup.error ?? null, wrote: before !== start, hadHold: hold !== null,
    produced: p.ok ? { outcome: p.ok.outcome, terminal: p.ok.terminal } : null, error: p.error ?? null,
    before, after: after.dbDigest, trace: state.trace,
  };
}

/**
 * #468 B4 (trusted reader, C-FMT historicalHoldRule): over the seeded generation 1, the harness writes
 * through the public port interface a complete canonical generation 2 whose present kind-13 record is
 * not historical evidence (its parent is not earlier; for a row without an output it is also another
 * mutation's hold), and a selector naming it as ACTIVE authority. The port may refuse the write
 * (nothing written); otherwise no reader may classify it as authority.
 */
async function forgeHistorical({ scenario }) {
  const own = requestOf(scenario, M2_OUTCOME.COMMITTED);
  const donor = own.holdPlaintext ?? requestOf('CAPI-S014', M2_OUTCOME.COMMITTED).holdPlaintext;
  const forgedHold = reencode(K.MUTATION_HOLD, donor, (x) => { x.parentGeneration = 2n; });
  const g = restage(own.staged, { [K.MUTATION_HOLD]: forgedHold });
  const current = await port.readSelector();
  const start = (await readback({})).dbDigest;
  const setup = await guarded(() => writeGeneration(g, g.records, selfSelector(g, API.ACTIVE), current.envelope));
  const rb = await readback({});
  return { setup: setup.error ?? null, wrote: rb.dbDigest !== start, classify: rb.classify, start, after: rb.dbDigest };
}

function arm({ plan = {}, fault = null, tamperAt = null } = {}) {
  Object.assign(state, { armed: true, fault, tamperAt, plan, trace: [], probes: [], selectors: [], next: 0, reads: 0, faulted: false });
}

const errorCode = (e) => (typeof e?.code === 'string' ? e.code : (e?.name ?? 'Error'));
async function guarded(fn) {
  try { return { ok: await fn() }; } catch (e) { return { error: { code: errorCode(e), message: String(e?.message ?? e) } }; }
}

function plain(r) {
  if (r === undefined || r === null) return null;
  const out = {};
  for (const [k, v] of Object.entries(r)) out[k] = v instanceof Uint8Array ? hex(v) : (typeof v === 'bigint' ? v.toString() : v);
  return out;
}

/** Let the microtask queue and any pending harness probe settle before the answer is returned, so an
 * answer that belongs to the operation is never lost to a snapshot taken too early (review impl1 F3). */
const settle = () => new Promise((r) => setTimeout(r, 0));

function finish(r) {
  if (state.armed) hook('RETURNED');
  state.armed = false;
  return { result: plain(r.ok), error: r.error ?? null, trace: state.trace, reads: state.reads, probes: state.probes, selectors: state.selectors };
}

// The memory-hold probe (B-CHR obligation v2 item 6): at the open of every armed readwrite transaction
// the harness asks the port for its memory hold; an answer that arrives before that transaction's
// `complete` is recorded, and a later answer is recorded as `late` so that "could not observe" is never
// mistaken for "observed no hold" (review impl1 F3). The probe is outside the port, identical for every port.
function holdProbe(id, tx) {
  let done = false;
  tx.addEventListener('complete', () => { done = true; });
  tx.addEventListener('abort', () => { done = true; });
  Promise.resolve()
    .then(() => port.readMemoryHold())
    .then((h) => {
      state.probes.push({ tx: id, late: done, held: h !== null });
      state.trace.push(done ? { ev: 'HOLD_AFTER_COMPLETE', tx: id, held: h !== null } : { ev: 'HOLD_BEFORE_COMPLETE', tx: id, held: h !== null });
    }, (e) => {
      state.probes.push({ tx: id, late: true, error: String(e?.code ?? e?.message ?? e) });
      state.trace.push({ ev: 'HOLD_PROBE_FAILED', tx: id, error: String(e?.code ?? e?.message ?? e) });
    });
}

async function original({ scenario, outcome, parent = null, generation = '2', op = 1 }) {
  const { envelope, candidate } = requestOf(scenario, M2_OUTCOME[outcome], { parent, generation, op });
  state.onOpen = holdProbe;
  const r = finish(await guarded(() => runMutation({
    storage: port, manifestRootKey: manifestRootKey(), envelope, candidate, outcome: M2_OUTCOME[outcome],
  })));
  state.onOpen = null;
  await settle();
  // The exact kind-13 record the candidate stages: a present hold or, under R3, a canonical tombstone.
  return { ...r, stagedHold: hex(candidate.records.find((x) => x.recordKind === K.MUTATION_HOLD).plaintext) };
}

/**
 * Reconciliation. `outcome` injects the RS evidence the I-TXN driver consumes (the C-MUT outcome
 * matrix). `produce: true` instead takes the evidence from the port's own terminal readback producer
 * (obligation item 13); `produceFault` arms a T9 fault for the producer's reads only. `emissionFault`
 * makes the harness's storage boundary refuse the first RELEASE_ESCROW (an interrupted local emission:
 * the selection landed, the emission did not), outside the port.
 */
async function reconcile({ scenario, outcome, parent = null, generation = '2', op = 1, produce = false, produceFault = null, tamperAt = null, emissionFault = false }) {
  state.onOpen = holdProbe;
  const { envelope } = requestOf(scenario, M2_OUTCOME.INDETERMINATE, { parent, generation, op });
  // The SS hold when SS memory survived; null after a restart, where I-TXN reads the durable kind-13 hold.
  const hold = await port.readMemoryHold();
  let produced = null;
  let producer = null;
  if (produce) {
    // The producer runs in its own armed section, so its trace, its write requests and the store
    // fingerprint around it are observed on their own (obligation item 13; review impl1 F2).
    const before = (await readback({})).dbDigest;
    arm({ fault: produceFault, tamperAt });
    const p = await guarded(() => port.readbackEvidence({ hold }));
    await settle();
    producer = { ...finish(p), before, after: (await readback({})).dbDigest };
    produced = p.ok ?? null; // a failed producer is judged by the reconciliation it then feeds
  }
  const evidence = produced ?? evidenceFor(envelope, M2_OUTCOME[outcome]);
  const storage = !emissionFault ? port : {
    apply: (step) => (step.kind === 'RELEASE_ESCROW'
      ? Promise.reject(Object.assign(new Error('injected emission interruption'), { code: 'BCHR_EMISSION_INTERRUPTED' }))
      : port.apply(step)),
    readSelector: () => port.readSelector(),
    readGeneration: (g) => port.readGeneration(g),
    readMemoryHold: () => port.readMemoryHold(),
    readGenerationNumbers: () => port.readGenerationNumbers(),
  };
  // The reconciliation is its own armed section: the producer's faults are off and its observations are
  // kept in `producer` (review impl2 R2-3). No evidence is fabricated when the producer failed.
  arm({});
  const r = finish(await guarded(async () => reconcileIndeterminate({
    storage, manifestRootKey: manifestRootKey(), hold, evidence, reference: envelope.reconciliationIdentity.reference,
  })));
  state.onOpen = null;
  await settle();
  return { ...r, producer, produced: produced === null ? null : { outcome: produced.outcome, terminal: produced.terminal } };
}

// Canonical logical-value digest: byte preservation by logical value, not by database files.
function canon(v) {
  if (v instanceof Uint8Array || v instanceof ArrayBuffer) return { b: hex(v) };
  if (typeof v === 'bigint') return { n: v.toString() };
  if (Array.isArray(v)) return v.map(canon);
  if (v !== null && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])]));
  return v;
}
async function digest(v) {
  return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(canon(v)))));
}
// A deterministic, type-tagged encoding of an IndexedDB key, for ordering and hashing only; lookups
// use the original key (B-CHR PR-r1 F8).
function keyCode(k) {
  if (typeof k === 'string') return `s:${k}`;
  if (typeof k === 'number') return `n:${k}`;
  if (k instanceof Date) return `d:${k.getTime()}`;
  if (k instanceof ArrayBuffer || ArrayBuffer.isView(k)) return `b:${hex(k instanceof ArrayBuffer ? k : new Uint8Array(k.buffer, k.byteOffset, k.byteLength))}`;
  if (Array.isArray(k)) return `a:[${k.map(keyCode).join(',')}]`;
  return `?:${String(k)}`;
}

async function readback({ parent = '1', candidate = '2' }) {
  const out = { lock };
  const stored = await guarded(() => port.readSelector());
  if (stored.error) out.selectorError = stored.error;
  else if (stored.ok === null) out.selector = null;
  else {
    const s = decodePlaintext(K.GENERATION_SELECTOR, stored.ok.plaintext);
    out.selector = {
      envelope: hex(stored.ok.envelope), nonce: hex(decodeEnvelope(stored.ok.envelope).nonce),
      plaintext: hex(stored.ok.plaintext), generation: s.generation.toString(),
      candidateGeneration: s.candidateGeneration.toString(), state: s.state,
    };
  }
  const c = await guarded(() => classifyAuthority({
    storage: port, manifestRootKey: manifestRootKey(), oldGeneration: BigInt(parent), newGeneration: BigInt(candidate),
  }));
  out.classify = c.error ? { error: c.error } : { authority: c.ok.authority, generation: c.ok.generation?.toString() ?? null, held: c.ok.held };
  const cand = await guarded(() => port.readGeneration(BigInt(candidate)));
  out.candidatePresent = cand.error ? { error: cand.error } : cand.ok !== null;
  out.candidateDigest = cand.ok ? await digest(cand.ok) : null;
  out.escrowOutput = cand.ok?.escrow?.output ? hex(cand.ok.escrow.output) : null;
  const k13 = cand.ok ? (cand.ok.records ?? []).find((r) => r.recordKind === K.MUTATION_HOLD) : undefined;
  out.candidateHold = k13 === undefined ? null : hex(k13.plaintext);
  const nums = await guarded(() => port.readGenerationNumbers());
  out.numbers = nums.error ? { error: nums.error } : Array.from(nums.ok, (n) => BigInt(n).toString()).sort();
  const mh = await guarded(() => port.readMemoryHold());
  out.memoryHold = mh.error ? { error: mh.error } : mh.ok !== null;
  // The whole `mls` store, read through the public VaultDb reads, original keys (F8).
  const keys = [...await db.list(NS)].sort((a, b) => (keyCode(a) < keyCode(b) ? -1 : (keyCode(a) > keyCode(b) ? 1 : 0)));
  const values = [];
  for (const k of keys) values.push([keyCode(k), await db.get(NS, k)]);
  out.dbDigest = await digest(values);
  out.entries = keys.length;
  return out;
}

const OPS = { init, seed, seedDebris, snapshot, delayedReplace, arm, original, reconcile, produceAfterCommit, contradict, forgeHistorical, readback };
self.onmessage = async (ev) => {
  // A dedicated worker only receives messages from the page that created it (same origin; the event
  // origin is empty or ours). Anything else is ignored; an unknown op is answered with an error.
  if (ev.origin !== '' && ev.origin !== self.location.origin) return;
  const { id, op, args } = ev.data ?? {};
  if (!Object.hasOwn(OPS, op)) { self.postMessage({ id, error: { code: 'UNKNOWN_OP', message: String(op) } }); return; }
  try {
    self.postMessage({ id, value: await OPS[op](args ?? {}) });
  } catch (e) {
    self.postMessage({ id, error: { code: errorCode(e), message: String(e?.message ?? e) } });
  }
};
self.postMessage({ ready: true });
