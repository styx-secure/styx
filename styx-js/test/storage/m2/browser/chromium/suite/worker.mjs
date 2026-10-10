// B-CHR dedicated worker (act #317 6091950328 §1 "Harness"): the I-TXN driver and the port run here,
// in one dedicated worker that the harness creates and that dies with its page. Port-neutral: it uses
// only the port's public C-FMT/I-TXN interface and the public VaultDb reads.
import { openVaultDb } from '/src/storage/vault-db.js';
import { M2_KIND, decodePlaintext } from '/src/storage/m2/session-codec.js';
import {
  M2_OUTCOME, classifyAuthority, mutationRow, reconcileIndeterminate, runMutation,
} from '/src/storage/m2/session-transaction.js';
import { instrument } from './instrument.mjs';
import {
  PORT_CONTEXT, ROOT_KEY, envelopeInput, evidenceFor, generationFixture, mutationInput, selectorBytes,
} from './fixtures.mjs';

const params = new URL(self.location.href).searchParams;
// The one line that selects the factory (act §1: no other line of the suite branches on it).
const FACTORY = { reference: './reference-port.mjs', product: '/src/storage/m2/session-idb-port.js' }[params.get('factory')];

const NS = 'mls';
const LOCK_NAME = 'styx-m2-bchr-suite-writer';
const API = { EMPTY: 1, ACTIVE: 2 };
const hex = (b) => (b === null || b === undefined ? null : Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join(''));
const state = { armed: false, fault: null, tamperAt: null, plan: {}, trace: [], next: 0, reads: 0, faulted: false };
const hook = (point) => {
  const x = new XMLHttpRequest();
  x.open('GET', `/hook?p=${encodeURIComponent(point)}`, false);
  x.send();
};
instrument({ hook: (p) => { if (state.armed) hook(p); }, state });

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
  db = await openVaultDb({ name: dbName });
  const { createPort } = await import(FACTORY);
  port = await createPort({ db, context: PORT_CONTEXT });
  return { lock };
}

/** Write a generation and a selector through the public port interface only (I-TXN step shapes). */
async function writeGeneration(g, selector, expected, extra = []) {
  const steps = [
    ...g.records.map((r) => ({ kind: 'STAGE_DATA', payload: { generation: g.generation, ...r } })),
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
  await writeGeneration(generationFixture(1n), selectorBytes(1n, API[mutationRow(scenario).stateBefore]), null);
  return 'seeded';
}

/**
 * Debris fixture (C-FMT generationCommit.unboundCandidate): a complete candidate generation 2 with its
 * result evidence and escrow made durable while the selector keeps naming the parent, byte for byte the
 * same plaintext, as a crash of a per-call writer leaves it. Written through the public interface only.
 */
async function seedDebris({ scenario, outcome }) {
  const { candidate } = mutationInput(scenario, M2_OUTCOME[outcome], { parent: 1n, generation: 2n, op: 0x40 });
  const stored = await port.readSelector();
  const extra = [{ kind: 'STAGE_EVIDENCE', payload: { generation: 2n, evidence: candidate.resultEvidence } }];
  if (candidate.escrow !== null) extra.push({ kind: 'STAGE_ESCROW', payload: { generation: 2n, escrow: candidate.escrow } });
  await writeGeneration(generationFixture(2n), stored.plaintext, stored.envelope, extra);
  return 'debris';
}

/** The stored selector envelope, kept by the harness outside the context it will kill. */
async function snapshot() {
  const s = await port.readSelector();
  return s === null ? null : { envelope: hex(s.envelope), plaintext: hex(s.plaintext) };
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

function arm({ plan = {}, fault = null, tamperAt = null } = {}) {
  Object.assign(state, { armed: true, fault, tamperAt, plan, trace: [], next: 0, reads: 0, faulted: false });
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

function finish(r) {
  if (state.armed) hook('RETURNED');
  state.armed = false;
  return { result: plain(r.ok), error: r.error ?? null, trace: state.trace, reads: state.reads };
}

async function original({ scenario, outcome, parent = '1', generation = '2', op = 1 }) {
  const { envelope, candidate } = mutationInput(scenario, M2_OUTCOME[outcome], {
    parent: BigInt(parent), generation: BigInt(generation), parentState: API[mutationRow(scenario).stateBefore], op,
  });
  return finish(await guarded(() => runMutation({
    storage: port, manifestRootKey: ROOT_KEY, envelope, candidate, outcome: M2_OUTCOME[outcome],
  })));
}

/**
 * Reconciliation. `outcome` injects the RS evidence the I-TXN driver consumes (the C-MUT outcome
 * matrix). `produce: true` instead takes the evidence from the port's own terminal readback producer
 * (obligation item 13); `produceFault` arms a T9 fault for the producer's reads only.
 */
async function reconcile({ scenario, outcome, op = 1, produce = false, produceFault = null, tamperAt = null }) {
  const envelope = envelopeInput(scenario, op);
  // The SS hold when SS memory survived; null after a restart, where I-TXN reads the durable kind-13 hold.
  const hold = await port.readMemoryHold();
  let produced = null;
  if (produce) {
    const saved = { fault: state.fault, tamperAt: state.tamperAt };
    Object.assign(state, { fault: produceFault, tamperAt });
    const p = await guarded(() => port.readbackEvidence({ hold }));
    Object.assign(state, saved);
    if (p.error) return { ...finish(p), produced: null };
    produced = p.ok;
  }
  const evidence = produced ?? evidenceFor(envelope, M2_OUTCOME[outcome]);
  const r = finish(await guarded(async () => reconcileIndeterminate({
    storage: port, manifestRootKey: ROOT_KEY, hold, evidence, reference: envelope.reconciliationIdentity.reference,
  })));
  return { ...r, produced: produced === null ? null : { outcome: produced.outcome, terminal: produced.terminal } };
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

async function readback({ parent = '1', candidate = '2' }) {
  const out = { lock };
  const stored = await guarded(() => port.readSelector());
  if (stored.error) out.selectorError = stored.error;
  else if (stored.ok === null) out.selector = null;
  else {
    const s = decodePlaintext(M2_KIND.GENERATION_SELECTOR, stored.ok.plaintext);
    out.selector = {
      envelope: hex(stored.ok.envelope), generation: s.generation.toString(),
      candidateGeneration: s.candidateGeneration.toString(), state: s.state,
    };
  }
  const c = await guarded(() => classifyAuthority({
    storage: port, manifestRootKey: ROOT_KEY, oldGeneration: BigInt(parent), newGeneration: BigInt(candidate),
  }));
  out.classify = c.error ? { error: c.error } : { authority: c.ok.authority, generation: c.ok.generation?.toString() ?? null, held: c.ok.held };
  const cand = await guarded(() => port.readGeneration(BigInt(candidate)));
  out.candidatePresent = cand.error ? { error: cand.error } : cand.ok !== null;
  out.candidateDigest = cand.ok ? await digest(cand.ok) : null;
  const nums = await guarded(() => port.readGenerationNumbers());
  out.numbers = nums.error ? { error: nums.error } : Array.from(nums.ok, (n) => BigInt(n).toString()).sort();
  const mh = await guarded(() => port.readMemoryHold());
  out.memoryHold = mh.error ? { error: mh.error } : mh.ok !== null;
  // The whole `mls` store, read through the public VaultDb reads.
  const keys = (await db.list(NS)).map(String).sort();
  const values = [];
  for (const k of keys) values.push([k, await db.get(NS, k)]);
  out.dbDigest = await digest(values);
  return out;
}

const OPS = { init, seed, seedDebris, snapshot, delayedReplace, arm, original, reconcile, readback };
self.onmessage = async (ev) => {
  const { id, op, args } = ev.data;
  try {
    self.postMessage({ id, value: await OPS[op](args ?? {}) });
  } catch (e) {
    self.postMessage({ id, error: { code: errorCode(e), message: String(e?.message ?? e) } });
  }
};
self.postMessage({ ready: true });
