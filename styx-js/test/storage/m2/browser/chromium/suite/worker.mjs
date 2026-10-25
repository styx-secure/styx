// B-CHR dedicated worker (act #317 6091950328 §1 "Harness"): the I-TXN driver and the port run here,
// in one dedicated worker that the harness creates and that dies with its page. Port-neutral: it uses
// only the port's public C-FMT/I-TXN interface and the public VaultDb reads.
// instrument.mjs is imported FIRST: it captures every intrinsic the observer uses at its top-level
// evaluation, before any other module of the worker (owner act v2 §3), and installs the observer there
// (K19 continuous collection, owner decision on #317 6384613341 §1), before the port module is imported.
import { append, WORKER_OBSERVER, keyEnc, digestValue } from './instrument.mjs';
import { openVaultDb } from '/src/storage/vault-db.js';
import { M2_KIND, decodeEnvelope, decodePlaintext, encodePlaintext } from '/src/storage/m2/session-codec.js';
import {
  M2_OUTCOME, classifyAuthority, mutationRow, reconcileIndeterminate, runMutation, validateCommitResultEvidence,
} from '/src/storage/m2/session-transaction.js';
import { checkCorrespondence, checkReemission, CITE } from './expectations.mjs';
import {
  PORT_CONTEXT, evidenceFor, manifestRootKey, mutationInput, noneHoldEncodable, parentFixture, prepareFixtures, restage, selfSelector,
} from './fixtures.mjs';

/**
 * The port the worker drives, wrapped so the harness sees every selector envelope the port reads or
 * writes (obligation item 10: a fresh 96-bit nonce per selector write, never a reused one), whatever
 * the factory does internally. The wrapper owns no behaviour: it forwards every call unchanged and returns
 * the port's own promise, never awaiting anything on the port's path (review impl2 R2-5).
 *
 * Write events (cycle 3, review impl3 R3-6/R3-7): every REPLACE_SELECTOR call is one write event, with
 * its own identity, the section it originates in, and the envelope it was asked to replace. The wrapper
 * issues no read of its own while an operation runs. The envelope a write produced is derived afterwards,
 * at a harness boundary (`observe`), from what the port itself shows: the envelope the next completed
 * write of the same port replaced (its compare-and-swap precondition), or, for the last write, the stored
 * selector read after the operation returned. Reads are recorded in the section that issued them.
 */
function tracked(target) {
  const worker = hex(crypto.getRandomValues(new Uint8Array(8)));
  const writes = [];
  const reads = [];
  // K19: the write records and selector reads are the observer's continuous collection of this worker
  // life (instrument.mjs), not lists attached when the port is installed: a request of `createPort`, or of
  // any interval between operations, is in them (D14, D15).
  const puts = lifeWrites;
  let seq = 0;
  const known = []; // envelopes known to the port, with the observer sequence number since when (item 10)
  const physical = (section) => puts.filter((r) => r.section === section).map((r) => structuredClone(r));
  const envelopeOf = (e) => (e instanceof Uint8Array && e.length > 0 ? { envelope: hex(e), nonce: hex(decodeEnvelope(e).nonce) } : null);
  // Every port call is counted while it runs (act §5: requests issued during a port call), and every
  // REPLACE_SELECTOR event carries the observer sequence numbers of its start and of its settlement.
  const call = (fn, settle = () => {}) => {
    state.portCalls += 1;
    let r;
    try { r = fn(); } catch (e) { state.portCalls -= 1; settle(false); throw e; }
    Promise.resolve(r).then(() => { state.portCalls -= 1; settle(true); }, () => { state.portCalls -= 1; settle(false); });
    return r;
  };
  const wrapper = {
    apply: (step) => {
      if (step.kind !== 'REPLACE_SELECTOR') return call(() => target.apply(step));
      const ev = {
        token: `${worker}:${seq++}`, section: state.section, status: 'pending', envelope: null, nonce: null,
        expected: step.payload.expectedSelectorBytes instanceof Uint8Array ? hex(step.payload.expectedSelectorBytes) : null,
        startSeq: tick(), endSeq: null,
      };
      append(writes, ev);
      if (ev.expected !== null) append(known, { envelope: ev.expected, nonce: nonceOfHex(ev.expected), seq: ev.startSeq, via: 'the expected envelope of a REPLACE_SELECTOR' });
      return call(() => target.apply(step), (ok) => { ev.status = ok ? 'written' : 'refused'; ev.endSeq = tick(); });
    },
    readSelector: () => {
      const section = state.section;
      return call(async () => {
        const r = await target.readSelector();
        const seen = r === null ? null : envelopeOf(r.envelope);
        if (seen !== null) append(reads, { section, ...seen });
        return r;
      });
    },
    readGeneration: (g) => call(() => target.readGeneration(g)),
    readMemoryHold: () => call(() => target.readMemoryHold()),
    readGenerationNumbers: () => call(() => target.readGenerationNumbers()),
    readbackEvidence: (a) => call(() => target.readbackEvidence(a)),
  };
  /**
   * The act §5 correspondence over every settled REPLACE_SELECTOR event and every terminal transaction
   * not yet audited, and the wrapper check of act §3. Runs unarmed, after an operation returned; what is
   * still pending is kept for the next audit. Returns failures.
   */
  const auditedEvents = new Set(); const auditedTx = new Set(); let lastStored; let carried = null;
  // CP2: the §5 read-back of an audit that judged events or transactions is an obligation: while the read
  // was not settled it stays due, every later audit reads again, and the final audit fails if it is due.
  let readbackDue = false;
  async function audit() {
    const failures = judgeWrites(known);
    // D21: a snapshot of the transactions BEFORE the audit's own read of the selector. The read opens a
    // readonly transaction of its own, which must neither defer the §5 read-back rule nor be judged here.
    const all = [...transactions()];
    const pending = writes.filter((e) => !auditedEvents.has(e.token));
    // An event is judged once it settled and every transaction opened in its window is terminal; a
    // transaction is judged once it is terminal and lies in no window still open or deferred.
    const inWindow = (t, e) => t.openSeq > e.startSeq && (e.endSeq === null || t.openSeq < e.endSeq);
    const ready = pending.filter((e) => e.endSeq !== null && all.every((t) => !inWindow(t, e) || t.terminal !== null));
    const deferred = pending.filter((e) => !ready.includes(e));
    const txs = all.filter((t) => !auditedTx.has(t.gid) && t.terminal !== null && !deferred.some((e) => inWindow(t, e)));
    if (ready.length === 0 && txs.length === 0 && !readbackDue) return failures;
    let stored = null;
    try { const s = await target.readSelector(); stored = s === null ? null : hex(s.envelope); } catch (e) {
      failures.push({ harnessError: true, what: `audit: the stored selector could not be read (${e?.code ?? e?.name})`, cite: 'owner act v2 §5' });
      return failures;
    }
    // Settled: every transaction of the snapshot is terminal, and every transaction opened while the
    // selector was read is readonly, or already terminal with no write or schema record (it changed
    // nothing); otherwise the read-back stays due for the next audit.
    const openedDuringRead = transactions().slice(all.length);
    // Requests the port issued while the audit read the selector are judged now (Argon C2).
    failures.push(...judgeWrites(known));
    const settledAll = deferred.length === 0 && all.every((t) => t.terminal !== null || auditedTx.has(t.gid) || txs.includes(t))
      && openedDuringRead.every((t) => t.mode === 'readonly' || (t.terminal !== null && t.writes.length === 0 && t.schema.length === 0));
    readbackDue = !settledAll;
    // A transaction opened during the read that changed nothing (readonly, or terminal without a write or
    // schema record) is accounted here (Argon, giro 2).
    for (const t of openedDuringRead) if ((t.mode === 'readonly' || t.terminal !== null) && t.writes.length === 0 && t.schema.length === 0) auditedTx.add(t.gid);
    const out = { last: null };
    failures.push(...checkCorrespondence({ events: ready, txs: txs.map(txView), stored: settledAll ? stored : undefined, lastStored: settledAll ? lastStored : undefined, carried, out }));
    carried = settledAll ? null : out.last;
    for (const e of ready) auditedEvents.add(e.token);
    for (const t of txs) auditedTx.add(t.gid);
    if (settledAll) lastStored = stored;
    return failures;
  }
  /**
   * The selector observations of `section`, taken at a harness boundary after the operation returned
   * and its promises settled: the reads it issued and its write events, each with the envelope it
   * produced when that can be derived (`null` otherwise).
   */
  async function observe(section) {
    let stored = null;
    try { const s = await target.readSelector(); stored = s === null ? null : envelopeOf(s.envelope); } catch { stored = null; }
    for (let i = 0; i < writes.length; i++) {
      const w = writes[i];
      if (w.status !== 'written' || w.envelope !== null) continue;
      let produced;
      const later = writes.slice(i + 1).filter((x) => x.status !== 'refused');
      if (later.length === 0) produced = stored;
      else if (later[0].status === 'written' && later[0].expected !== null) produced = { envelope: later[0].expected, nonce: hex(decodeEnvelope(Uint8Array.from(later[0].expected.match(/../g), (x) => parseInt(x, 16))).nonce) };
      else produced = null;
      if (produced !== null) Object.assign(w, produced);
    }
    return {
      reads: reads.filter((x) => x.section === section).map(({ envelope, nonce }) => ({ envelope, nonce })),
      writes: writes.filter((x) => x.section === section).map(({ token, status, envelope, nonce, expected }) => ({ token, status, envelope, nonce, expected })),
      puts: physical(section),
    };
  }
  return { port: wrapper, observe, physical, audit, readbackDue: () => readbackDue, known: () => known };
}

/**
 * The port-independent part of every audit (act §3/§4, K19): the wrapper check, then every write record
 * of this worker life not judged yet, in any operation, interval, section or transaction mode, before any
 * filter on issuance. `known` adds the expected envelopes of REPLACE_SELECTOR events.
 */
const auditedPuts = new Set();
let auditedReads = 0;
function judgeWrites(known = []) {
  const failures = checkInstalled().map((what) => ({ harnessError: true, what, cite: 'owner act v2 §3 (an observer or harness error is never PASS)' }));
  for (; deliveryErrorsJudged < deliveryErrors.length; deliveryErrorsJudged++) failures.push({ harnessError: true, what: `K19: ${deliveryErrors[deliveryErrorsJudged]}`, cite: CITE.K19 });
  const fresh = lifeWrites.filter((w) => !auditedPuts.has(w.token));
  const seen = lifeReads.filter((r) => r.limit !== true).map((r) => ({ envelope: r.envelope, nonce: r.nonce, seq: r.seq, via: `a ${r.via} result` }));
  // D19 (read side): a read result beyond the object limit leaves its envelopes unknown: never PASS.
  for (let i = auditedReads; i < lifeReads.length; i++) if (lifeReads[i].limit === true) failures.push({ unobserved: true, what: `K19: a ${lifeReads[i].via} result exceeded the object limit; the selector envelopes it returned are unknown`, cite: CITE.FRESH_NONCE });
  auditedReads = lifeReads.length;
  const before = lifeWrites.filter((w) => w.issued === true).flatMap((w) => (w.envelopes ?? []).map((e) => ({ envelope: e.envelope, nonce: e.nonce, seq: w.seq, token: w.token, via: `request ${w.token}` })));
  // Item 10 on the continuous collection (D17, D18): every request of this life, in or out of a port call,
  // whatever its fate, against every envelope and nonce known before it.
  failures.push(...checkReemission(fresh, [...seen, ...known, ...before]));
  for (const w of fresh) {
    auditedPuts.add(w.token);
    if (w.nonCanonical) failures.push({ what: `NON_CANONICAL_WRITE: ${w.token} (${w.method}${w.store ? ` on ${w.store}` : ''}): ${w.reasons.join(', ')}`, cite: CITE.NON_CANONICAL });
    if (w.observerError) failures.push({ harnessError: true, what: `observer error on ${w.token}: ${w.observerError}`, cite: 'owner act v2 §3 (an observer or harness error is never PASS)' });
  }
  return failures;
}
/** The audit of this worker life after an operation: with the port's §5 correspondence once it is installed. */
async function auditLife() {
  if (tracker !== null) return tracker.audit();
  const f = judgeWrites();
  // Writes in a life whose port was never installed cannot be checked under §5: never PASS.
  for (const w of lifeWrites) if (!auditedSelectorless.has(w.token)) { auditedSelectorless.add(w.token); f.push({ harnessError: true, what: `K19: write ${w.token} in a worker life without an installed port (§5 cannot be checked)`, cite: CITE.K19 }); }
  return f;
}
const auditedSelectorless = new Set();

const params = new URL(self.location.href).searchParams;
// The one line that selects the factory (act §1: no other line of the suite branches on it).
const FACTORY = { reference: './reference-port.mjs', product: '/src/storage/m2/session-idb-port.js' }[params.get('factory')];

const NS = 'mls';
const LOCK_NAME = 'styx-m2-bchr-suite-writer';
const API = { EMPTY: 1, ACTIVE: 2 };
const K = M2_KIND;
const hex = (b) => (b === null || b === undefined ? null : Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join(''));
/** The nonce of a selector envelope given in hex (null if it does not decode). */
const nonceOfHex = (h) => { try { return hex(decodeEnvelope(Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16))).nonce); } catch { return null; } };
if (WORKER_OBSERVER === null) throw new Error('B-CHR: the observer was not installed at the evaluation of instrument.mjs');
// The worker state is the observer's (instrument.mjs creates it with the observer, K19).
const { state } = WORKER_OBSERVER;
const hook = (point, data = null) => {
  const x = new XMLHttpRequest();
  // The K19 records, reads and delivery errors of this life that no channel delivered yet (a record an RPC
  // reply already carried is not repeated, so the hook stays within the request size the host accepts): a
  // killed context leaves them with the host. The hook cursor advances only once the host accepted the
  // hook (status 200); a rejected hook keeps everything for the next delivery (consensus plan P6, CP6).
  const delta = lifeDelta(hookCursor, replyCursor);
  const evidence = { ...(data ?? {}), section: state.section, writes: tracker?.physical(state.section) ?? [], k19: delta.payload };
  const url = `/hook?p=${encodeURIComponent(point)}&d=${encodeURIComponent(JSON.stringify(evidence))}`;
  let status = 0;
  try { x.open('GET', url, false); x.send(); status = x.status; } catch { status = -1; }
  if (status === 200) delta.commit();
  // A hook the host did not accept loses a kill point: a delivery error of this life, carried by every later
  // hook and reply until the host has it, and judged by the next audit (never silent).
  else deliveryErrors.push(`hook ${point} of worker life ${LIFE} was not accepted by the host (status ${status}, URL of ${url.length} characters)`);
};
const deliveryErrors = []; let deliveryErrorsJudged = 0;
state.hook = hook;
const { watchTransaction, tick, transactions, checkInstalled, writes: lifeWrites, reads: lifeReads, schema: lifeSchema, session: LIFE, lateLog } = WORKER_OBSERVER.api;

/**
 * K19 delivery to the host (owner decision §1, existing channels only): every write and schema record of
 * this worker life, in a shape the host's durable model reads (expectations.mjs lifeChain), its selector
 * reads and the expected envelopes of its REPLACE_SELECTOR events (the run-wide nonce ledger), and its
 * delivery errors. Each channel (RPC replies, /hook) has its own cursor; a reply carries everything it did
 * not carry yet, a hook everything no channel carried yet. `commit()` records the delivery.
 */
const replyCursor = new Map(); const hookCursor = new Map();
const viewOf = (r) => (r.kind === 'schema'
  ? { token: r.token, kind: 'schema', method: r.method, db: r.db, store: r.store ?? null, from: r.from ?? null, oldVersion: r.oldVersion ?? null, newVersion: r.newVersion ?? null,
    txg: r.txg, status: r.status, terminal: r.terminal, terminalSeq: r.terminalSeq, seq: r.seq, settledSeq: r.settledSeq, opaque: r.opaque === true }
  : { token: r.token, kind: 'write', method: r.method, db: r.db, store: r.store, txg: r.txg, key: r.key, digest: r.digest, status: r.status,
    issued: r.issued, nonCanonical: r.nonCanonical, reasons: [...(r.reasons ?? [])], observerError: r.observerError ?? null, terminal: r.terminal,
    issuedSeq: r.issuedSeq ?? null, settledSeq: r.settledSeq ?? null, terminalSeq: r.terminalSeq, seq: r.seq, opaque: r.opaque === true,
    envelopes: (r.envelopes ?? []).map((e) => ({ envelope: e.envelope, nonce: e.nonce })) });
function lifeDelta(cursor, delivered = null) {
  const records = []; const marks = [];
  for (const r of [...lifeWrites, ...lifeSchema]) {
    const v = viewOf(r); const s = JSON.stringify(v);
    if (cursor.get(v.token) !== s && delivered?.get(v.token) !== s) { records.push(v); marks.push([v.token, s]); }
  }
  const from = (k) => Math.max(cursor.get(k) ?? 0, delivered?.get(k) ?? 0);
  const reads = [];
  for (let i = from('#reads'); i < lifeReads.length; i++) reads.push({ envelope: lifeReads[i].envelope, nonce: lifeReads[i].nonce, seq: lifeReads[i].seq, via: lifeReads[i].via, limit: lifeReads[i].limit === true });
  const known = tracker?.known() ?? [];
  for (let i = from('#known'); i < known.length; i++) reads.push({ envelope: known[i].envelope, nonce: known[i].nonce, seq: known[i].seq, via: 'expected envelope', limit: false });
  const errors = deliveryErrors.slice(from('#errors'));
  const ends = { '#reads': lifeReads.length, '#known': known.length, '#errors': deliveryErrors.length };
  return {
    payload: { life: LIFE, closed: state.closed === true, late: lateLog.length, records, reads, deliveryErrors: errors },
    commit() { for (const [t, s] of marks) cursor.set(t, s); for (const [k, n] of Object.entries(ends)) cursor.set(k, n); },
  };
}
/** An RPC reply: always delivered (the page relays it), so its delta is committed at once. */
const replyDelta = () => { const d = lifeDelta(replyCursor); d.commit(); return d.payload; };
/** A transaction lifetime as the act §5 checker sees it (write records copied). */
const txView = (t) => ({ gid: t.gid, openSeq: t.openSeq, mode: t.mode, terminal: t.terminal, terminalSeq: t.terminalSeq,
  writes: t.writes.map((w) => structuredClone(w)) });


let db = null;
let port = null;
let tracker = null;
let lock = null;
/** Install the port behind the observing wrapper. */
function install(p) { tracker = tracked(p); port = tracker.port; }

async function init({ dbName }) {
  if (state.initialized) throw new Error('B-CHR: one initialization per worker life');
  state.initialized = true; // K19: the trusted reader (durable) runs only before this point
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
  // `createPort` is a port call (act §5 "issued during a port call"); its requests are collected (K19).
  state.portCalls += 1;
  let p;
  try { p = await createPort({ db, context: PORT_CONTEXT }); } finally { state.portCalls -= 1; }
  install(p);
  return { lock, noneHoldEncodable: noneHoldEncodable() };
}

/**
 * K19 trusted reader (owner decision §1, "Durable reconciliation"): in a fresh worker life, after the
 * previous life was terminated and before any initialization, it reads the complete durable state of the
 * origin, every database (side databases included), store, key and value, without importing or
 * initializing the port and without modifying data. Keys and values are encoded with the observer's
 * keyEnc/digestValue, as the observer recorded the judged requests.
 */
async function durable() {
  if (state.initialized || port !== null) throw Object.assign(new Error('the durable reader runs before any initialization'), { code: 'K19_READER_AFTER_INIT' });
  const req = (r) => new Promise((resolve, reject) => { r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
  const list = [...await indexedDB.databases()].sort((a, b) => (a.name < b.name ? -1 : (a.name > b.name ? 1 : 0)));
  const dbs = [];
  for (const { name } of list) {
    const conn = await new Promise((resolve) => {
      const r = indexedDB.open(name);
      let upgrading = false;
      // A database listed but absent would be created by the open: the reader aborts that instead.
      r.onupgradeneeded = () => { upgrading = true; r.transaction.abort(); };
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => resolve(upgrading ? 'vanished' : `error:${r.error?.name}`);
      r.onblocked = () => resolve('blocked');
    });
    if (typeof conn === 'string') { dbs.push({ name, error: conn }); continue; }
    const stores = [];
    for (const s of [...conn.objectStoreNames].sort()) {
      const st = conn.transaction(s, 'readonly').objectStore(s);
      const [keys, values] = await Promise.all([req(st.getAllKeys()), req(st.getAll())]);
      stores.push({ name: s, entries: keys.map((k, i) => [keyEnc(k), digestValue(values[i])]) });
    }
    dbs.push({ name, version: conn.version, stores });
    conn.close();
  }
  return { life: LIFE, dbs };
}

/** Wait until no port call, transaction or write request of this life is pending, stable for `stable` checks. */
async function quiesce({ bound = 10000, stable = 5 } = {}) {
  const t0 = performance.now(); let quiet = 0;
  while (performance.now() - t0 < bound) {
    await new Promise((r) => setTimeout(r, 10));
    const busy = state.portCalls > 0 || transactions().some((t) => t.terminal === null)
      || lifeWrites.some((w) => w.status === 'pending' || (w.issued === true && w.terminal === null && w.txg !== null))
      || lifeSchema.some((s) => s.status === 'pending');
    quiet = busy ? 0 : quiet + 1;
    if (quiet >= stable) return true;
  }
  return false;
}

/**
 * K19 closure (owner decision §1, "Closure to termination"): the final audit of this worker life, after
 * quiescence. It judges everything collected (with the §5 correspondence once a port is installed), then
 * closes the life: from then on every IndexedDB request is an observer error reported to the host by the
 * observer (instrument.mjs `late`), and the worker answers no further operation. Quiescence alone proves
 * nothing: the host also requires the closed reply and reconciles the durable state in the next life.
 */
async function finalAudit() {
  state.armed = false; // between operations only: no kill point is reported from here on
  const quiet = await quiesce();
  const failures = await auditLife();
  if (!quiet) failures.push({ harnessError: true, what: `K19: worker life ${LIFE} did not reach quiescence before its final audit`, cite: CITE.K19 });
  if (tracker !== null && tracker.readbackDue()) failures.push({ harnessError: true, what: `K19: worker life ${LIFE} closes with the act v2 §5 read-back still due (the stored selector was never read settled)`, cite: 'owner act v2 §5' });
  for (const w of lifeWrites) if (!auditedPuts.has(w.token)) failures.push({ harnessError: true, what: `K19: write ${w.token} was not judged by the final audit`, cite: CITE.K19 });
  state.closed = true;
  return { closed: true, life: LIFE, quiet, failures };
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
  const p = await produce({ hold, fault: tamper ? 'TAMPER' : null, tamperAt: tamper ? 'REST' : null });
  const valid = p.ok ? await guarded(async () => validateCommitResultEvidence({ evidence: p.ok, envelope })) : null;
  return {
    setup: landed.error ?? null, hadHold: hold !== null, producer: p.section,
    produced: p.ok ? { outcome: p.ok.outcome, terminal: p.ok.terminal } : null,
    identity: valid === null ? null : (valid.error ?? 'VALID'),
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
  const p = await produce({ hold });
  return {
    setup: setup.error ?? null, wrote: p.section.before !== start, hadHold: hold !== null, producer: p.section,
    produced: p.ok ? { outcome: p.ok.outcome, terminal: p.ok.terminal } : null,
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

/** A new section: its own trace, probes and selector observations (cycle 3, R3-7). */
function beginSection() {
  Object.assign(state, { section: state.section + 1, trace: [], probes: [], next: 0, reads: 0, faulted: false });
}
function arm({ plan = {}, fault = null, tamperAt = null } = {}) {
  beginSection();
  Object.assign(state, { armed: true, fault, tamperAt, plan });
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

/**
 * Close the current section after its operation returned (`r`): the RETURNED kill point, then, unarmed,
 * the pending probe answers settle into this section's own arrays and its selector observations are
 * drained (cycle 3, R3-7). The returned arrays are copies taken at this boundary.
 */
async function close(r) {
  if (state.armed) hook('RETURNED');
  state.armed = false;
  const { section, trace, probes, reads } = state;
  await settle();
  const selectors = await tracker.observe(section);
  return { result: plain(r.ok), error: r.error ?? null, trace: [...trace], reads, probes: [...probes], selectors };
}

// The memory-hold probe (B-CHR obligation v2 item 6): at the open of every armed readwrite transaction
// the harness asks the port for its memory hold; an answer that arrives before that transaction's
// `complete` is recorded, and a later answer is recorded as `late` so that "could not observe" is never
// mistaken for "observed no hold" (review impl1 F3). The probe is outside the port, identical for every port.
// Each answer is recorded in the section that opened the transaction (cycle 3, R3-7). Only an answer that
// arrived before `complete` (late: false) says anything about the hold while the transaction ran; a late
// answer is coverage at most (review impl3 R3-4).
// Timing (cycle 4, review impl4 R4-1): a port may sample its hold at once and answer later. The harness
// keeps the probed transaction from auto-committing until the answer arrives (bounded by
// HOLD_PROBE_KEEPALIVE_MS, harness reads only: no request index, kill point, fault or write), so an answer
// to a port that does not call commit() itself always arrives before `complete`. Only such an answer can
// prove an early hold; an answer that still arrives after `complete` (the port committed, or the bound
// elapsed) is insufficient observation, which the run reports apart from port failures.
const HOLD_PROBE_KEEPALIVE_MS = 5000;
function holdProbe(id, tx) {
  const { probes, trace, pending } = state;
  const answer = watchTransaction(tx, () => port.readMemoryHold(), (a) => {
    const p = Object.assign(a, { tx: id }); probes.push(p);
    trace.push({ ev: 'HOLD_SAMPLE', ...p });
  }, HOLD_PROBE_KEEPALIVE_MS);
  pending.push(answer);
}

/**
 * The port's terminal readback producer (obligation item 13) in its own armed section, the same for every
 * caller (cycle 3, R3-2/R2-6): the store fingerprint around it is taken unarmed, its faults are armed for
 * its reads only, and every readwrite transaction it opens is probed. The returned section carries its
 * error, trace, probes, selector observations and fingerprint; `ok` is its evidence, or null.
 */
async function produce({ hold, fault = null, tamperAt = null }) {
  state.armed = false;
  const before = (await readback({})).dbDigest;
  arm({ fault, tamperAt });
  const onOpen = state.onOpen;
  state.onOpen = holdProbe;
  const p = await guarded(() => port.readbackEvidence({ hold }));
  const section = await close(p);
  state.onOpen = onOpen;
  const after = (await readback({})).dbDigest;
  return { ok: p.ok ?? null, section: { ...section, before, after } };
}

async function original({ scenario, outcome, parent = null, generation = '2', op = 1 }) {
  const { envelope, candidate } = requestOf(scenario, M2_OUTCOME[outcome], { parent, generation, op });
  state.onOpen = holdProbe;
  const r = await close(await guarded(() => runMutation({
    storage: port, manifestRootKey: manifestRootKey(), envelope, candidate, outcome: M2_OUTCOME[outcome],
  })));
  state.onOpen = null;
  // The exact kind-13 record the candidate stages: a present hold or, under R3, a canonical tombstone.
  return { ...r, stagedHold: hex(candidate.records.find((x) => x.recordKind === K.MUTATION_HOLD).plaintext) };
}

/**
 * Reconciliation. `outcome` injects the RS evidence the I-TXN driver consumes (the C-MUT outcome
 * matrix). `produce: true` instead takes the evidence from the port's own terminal readback producer
 * (obligation item 13); `produceFault` arms a T9 fault for the producer's reads only. `emissionFault`
 * makes the harness's storage boundary refuse the first RELEASE_ESCROW (an interrupted local emission:
 * the selection landed, the emission did not), outside the port.
 *
 * Arming (cycle 3, R3-5): a reconciliation the caller armed runs in the caller's section with the
 * caller's plan and fault, unchanged, so the kill points of its plan are reported; an unarmed one is
 * armed with nothing. With a producer, the producer has its own section and the reconciliation then a
 * fresh one, armed with the caller's plan and fault. A failed producer ends the operation: no evidence is
 * synthesized and the I-TXN reconciliation is not invoked (R3-3).
 */
async function reconcile({ scenario, outcome, parent = null, generation = '2', op = 1, produce: useProducer = false, produceFault = null, tamperAt = null, emissionFault = false }) {
  const caller = state.armed ? { plan: state.plan, fault: state.fault, tamperAt: state.tamperAt } : null;
  if (caller === null) arm({});
  state.onOpen = holdProbe;
  const { envelope } = requestOf(scenario, M2_OUTCOME.INDETERMINATE, { parent, generation, op });
  // The SS hold when SS memory survived; null after a restart, where I-TXN reads the durable kind-13 hold.
  const hold = await port.readMemoryHold();
  let produced = null;
  let producer = null;
  if (useProducer) {
    const p = await produce({ hold, fault: produceFault, tamperAt });
    producer = p.section;
    produced = p.ok;
    if (produced === null) {
      state.onOpen = null;
      return { result: null, error: null, trace: [], reads: 0, probes: [], selectors: { reads: [], writes: [], puts: [] }, producer, produced: null, reconciled: false };
    }
    arm(caller ?? {});
    state.onOpen = holdProbe;
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
  const r = await close(await guarded(async () => reconcileIndeterminate({
    storage, manifestRootKey: manifestRootKey(), hold, evidence, reference: envelope.reconciliationIdentity.reference,
  })));
  state.onOpen = null;
  return { ...r, producer, produced: produced === null ? null : { outcome: produced.outcome, terminal: produced.terminal }, reconciled: true };
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

const OPS = { init, durable, finalAudit, seed, seedDebris, snapshot, delayedReplace, arm, original, reconcile, produceAfterCommit, contradict, forgeHistorical, readback };
self.onmessage = async (ev) => {
  // A dedicated worker only receives messages from the page that created it (same origin; the event
  // origin is empty or ours). Anything else is ignored; an unknown op is answered with an error.
  if (ev.origin !== '' && ev.origin !== self.location.origin) return;
  const { id, op, args } = ev.data ?? {};
  if (!Object.hasOwn(OPS, op)) { self.postMessage({ id, error: { code: 'UNKNOWN_OP', message: String(op) }, k19: replyDelta() }); return; }
  // K19: a closed life answers no operation (the harness issues no request after the final audit).
  if (state.closed === true) { self.postMessage({ id, error: { code: 'K19_LIFE_CLOSED', message: String(op) }, k19: replyDelta() }); return; }
  // Every operation the harness did not arm runs in a section of its own (cycle 3, R3-7).
  if (!state.armed && op !== 'arm') beginSection();
  let reply;
  try { reply = { id, value: await OPS[op](args ?? {}) }; } catch (e) { reply = { id, error: { code: errorCode(e), message: String(e?.message ?? e) } }; }
  // Act §3/§5: after every operation that leaves the worker unarmed, the observer audits what settled
  // (K19: whether or not a port is installed). The final audit closed the life and carries its own.
  if (op === 'finalAudit' && reply.value !== undefined) reply.audit = reply.value.failures;
  else if (!state.armed && state.closed !== true) {
    try { reply.audit = await auditLife(); } catch (e) { reply.audit = [{ harnessError: true, what: `audit failed: ${e?.message ?? e}`, cite: 'owner act v2 §5' }]; }
  }
  reply.k19 = replyDelta();
  self.postMessage(reply);
};
self.postMessage({ ready: true });
