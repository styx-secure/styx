// T-SWEEP harness: one SS process over one durable in-memory disk, driving the merged M2 stack
// through its public surface. Not a test file (no `.test.js` suffix); imported by the sweep tests.
//
// Every operation goes through the adapter's `invokeAdapterTransition`, every request and result
// crosses the I-WORK wire codec (`toWireBytes` / `fromWireBytes`), and every durable effect is an
// I-TXN transaction (`runMutation`, `reconcileIndeterminate`, `classifyAuthority`) over a storage
// port that mirrors the I-TXN test fake. A restart drops every module instance (`jest.resetModules()`
// and a fresh dynamic import of every module) and every in-process object; only the disk survives,
// re-read through an in-realm deep copy. The SS memory hold (`readMemoryHold`) is process memory: a
// restart drops it.
//
// The test-local SS glue only supplies what the integrated modules leave to their caller (the session
// state bytes, which RS outcome is observed, when the adapter snapshot is persisted). It never decides
// an outcome an integrated module decides.
//
// Derived from the T-COMPOSE harness (card T-COMPOSE, base 8c03d86); copied, not imported, so this
// card stays inside its allowlist.

import { createHash } from 'node:crypto';
import { jest } from '@jest/globals';

const SRC = '../../../../src';
const MODULE_PATHS = {
  adapter: `${SRC}/crypto/mls/m2/adapter.js`,
  sm: `${SRC}/crypto/mls/m2/state-machine.js`,
  wire: `${SRC}/crypto/mls/m2/worker-protocol.js`,
  txn: `${SRC}/storage/m2/session-transaction.js`,
  codec: `${SRC}/storage/m2/session-codec.js`,
  root: `${SRC}/storage/m2/session-root.js`,
  marker: `${SRC}/storage/m2/legacy-session-invalidation.js`,
};

/** One process: a fresh module registry, so no module-level state survives a restart. */
export async function loadProcess() {
  jest.resetModules();
  const out = {};
  for (const [name, path] of Object.entries(MODULE_PATHS)) out[name] = await import(path);
  return Object.freeze(out);
}

// ---------------------------------------------------------------------------------------------
// Deterministic randomness and clock. No Math.random, no Date.now.
// ---------------------------------------------------------------------------------------------

export function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const nonzeroBytes = (rand, n) => Uint8Array.from({ length: n }, () => 1 + Math.floor(rand() * 255));
function manualClock(start = 1_700_000_000_000) {
  let now = start;
  return { now: () => now, tick: (ms = 1) => { now += ms; return now; } };
}
export const hex = (u8) => Buffer.from(u8).toString('hex');
export const sha256 = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(typeof p === 'string' ? Buffer.from(p) : Buffer.from(p));
  return new Uint8Array(h.digest());
};
export const utf8 = (s) => new Uint8Array(Buffer.from(s, 'utf8'));
const fromUtf8 = (u8) => Buffer.from(u8).toString('utf8');

/**
 * In-realm deep copy of durable data (plain objects, arrays, Map, Uint8Array, bigint, primitives).
 * `structuredClone` is not used: under Jest it returns host-realm objects, whose prototypes the
 * integrated closed-record readers rightly refuse.
 */
export function deepCopy(v) {
  if (v === null || typeof v !== 'object') return v;
  if (v instanceof Uint8Array || ArrayBuffer.isView(v)) return Uint8Array.from(v);
  if (v instanceof Map) return new Map([...v].map(([k, x]) => [k, deepCopy(x)]));
  if (Array.isArray(v)) return v.map(deepCopy);
  const out = {};
  for (const k of Object.keys(v)) out[k] = deepCopy(v[k]);
  return out;
}

// ---------------------------------------------------------------------------------------------
// Fixed context.
// ---------------------------------------------------------------------------------------------

export const ROOT_KEY = new Uint8Array(32).fill(0x11);
export const SLOT = new Uint8Array(32).fill(0xa1);
const SESSION_ID = new Uint8Array(32).fill(0x41);
const BINDING_DIGEST = new Uint8Array(32).fill(0x51);
const PROFILE_DIGEST = new Uint8Array(32).fill(0x31);
const DATA_KINDS = Array.from({ length: 15 }, (_, i) => i + 1);
const STATE_KIND = 1; // the data record whose plaintext carries the test SS session state

export const SCENARIO_BY_OPERATION = Object.freeze({
  CREATE: 'CAPI-S001',
  JOIN_WELCOME: 'CAPI-S006',
  PROTECT_APPLICATION: 'CAPI-S009',
  OPEN_APPLICATION: 'CAPI-S010',
  SELF_UPDATE: 'CAPI-S014',
});
export const OUTPUT_MEMBER = Object.freeze({
  EMBEDDED_TREE_WELCOME: 'embeddedTreeWelcome',
  PROTECTED_APPLICATION_BYTES: 'protectedApplicationBytes',
  APPLICATION_BYTES: 'applicationBytes',
  PROTECTED_COMMIT_BYTES: 'protectedCommitBytes',
});
export const SEL = Object.freeze({ EMPTY: 1, ACTIVE: 2, RECONCILIATION_REQUIRED: 3 });

// ---------------------------------------------------------------------------------------------
// The durable disk: the only thing that survives a restart (plus `hold`, which is SS memory and is
// dropped by a restart).
// ---------------------------------------------------------------------------------------------

export function makeDisk() {
  return {
    generations: new Map(), // bigint -> stored generation
    selector: null, // the stored kind-14 selector bytes
    hold: null, // the SS in-memory hold (`readMemoryHold`); NOT durable, a restart drops it
    snapshot: null, // the persisted adapter snapshot
    pending: null, // the in-flight request the SS fixed before the RS call (durable SS fact)
    marker: null, // the L-MARK marker bytes (test-local durable cell; L-MARK owns encoding only)
    nextGeneration: 1n,
  };
}

/**
 * The I-TXN storage port over the disk, with one optional crash.
 *
 * `crash` is `null` or `{ target, mode, fault }`:
 * - `target` `{ index, when }`: `when` is `'BEFORE'` or `'AFTER'` the durable effect of the plan step
 *   with that `index`, or `'FIRST_READ'` (the first port call of the transaction throws).
 * - `fault` `'EXCEPTION'`: one throw; the module's own failure handling then runs normally.
 *   `fault` `'KILL'`: the process dies at that point: every later port call throws too, so nothing
 *   the module attempts afterwards lands.
 */
export function makePort(disk, crash = null) {
  const port = { applied: [], crashed: false, dead: false };
  let firstCall = true;
  const die = (where) => {
    port.crashed = true;
    if (crash.fault === 'KILL') port.dead = true;
    throw new Error(`crash ${where}`);
  };
  const guard = () => {
    if (port.dead) throw new Error('process is dead');
    if (firstCall) {
      firstCall = false;
      if (crash !== null && !port.crashed && crash.target.when === 'FIRST_READ') die('FIRST_READ');
    }
  };
  const hits = (step, when) => crash !== null && !port.crashed && step.index >= 0
    && crash.target.when === when && crash.target.index === step.index;
  port.apply = async (step) => {
    guard();
    port.applied.push(`${step.index}:${step.boundary}/${step.kind}`);
    if (hits(step, 'BEFORE')) die(`BEFORE ${step.index}:${step.boundary}/${step.kind}`);
    const p = step.payload;
    if (step.kind === 'STAGE_DATA') {
      if (!disk.staged) disk.staged = new Map();
      if (!disk.staged.has(p.generation)) disk.staged.set(p.generation, new Map());
      disk.staged.get(p.generation).set(p.recordKind, deepCopy({
        recordKey: p.recordKey, recordKind: p.recordKind, plaintext: p.plaintext, ciphertext: p.ciphertext, tag: p.tag,
      }));
    } else if (step.kind === 'STAGE_MANIFEST') {
      const s = disk.staged ? disk.staged.get(p.generation) : undefined;
      disk.generations.set(p.generation, deepCopy({
        generation: p.generation,
        records: s === undefined ? [] : [...s.values()],
        manifestKey: p.manifestKey,
        manifestBytes: p.manifestBytes,
        manifestCipherDigest: p.manifestCipherDigest,
        keyedRoot: p.keyedRoot,
        sessionBindingDigest: p.sessionBindingDigest,
        mutationHold: { presence: 0 },
        escrow: null,
        resultEvidence: null,
      }));
    } else if (step.kind === 'STAGE_EVIDENCE') {
      const g = disk.generations.get(p.generation);
      if (g !== undefined) g.resultEvidence = deepCopy(p.evidence);
    } else if (step.kind === 'STAGE_ESCROW') {
      const g = disk.generations.get(p.generation);
      if (g !== undefined) g.escrow = deepCopy(p.escrow);
    } else if (step.kind === 'WRITE_HOLD') {
      const g = disk.generations.get(p.generation);
      if (g !== undefined) {
        g.mutationHold = deepCopy({
          presence: 1, resultStatus: p.hold.resultStatus,
          parentGeneration: p.hold.parentGeneration, parentKeyedRoot: p.hold.parentKeyedRoot,
        });
      }
      disk.hold = deepCopy(p.hold);
    } else if (step.kind === 'CLEAR_CANDIDATE') {
      disk.generations.delete(p.generation);
      if (disk.staged) disk.staged.delete(p.generation);
      disk.hold = null;
    } else if (step.kind === 'REPLACE_SELECTOR') {
      disk.selector = Uint8Array.prototype.slice.call(p.selectorBytes);
      if (p.resolveHoldGeneration !== null && p.resolveHoldGeneration !== undefined) {
        const g = disk.generations.get(p.resolveHoldGeneration);
        if (g !== undefined) g.mutationHold = { presence: 0 };
      }
    } else if (step.kind === 'RELEASE_ESCROW') {
      disk.hold = null;
    }
    if (hits(step, 'AFTER')) die(`AFTER ${step.index}:${step.boundary}/${step.kind}`);
    return undefined;
  };
  port.readSelector = async () => {
    guard();
    return disk.selector === null ? null : Uint8Array.prototype.slice.call(disk.selector);
  };
  port.readGeneration = async (generation) => {
    guard();
    const g = disk.generations.get(generation);
    return g === undefined ? null : deepCopy(g);
  };
  port.readMemoryHold = async () => {
    guard();
    return disk.hold === null ? null : deepCopy(disk.hold);
  };
  return port;
}

// ---------------------------------------------------------------------------------------------
// Test SS session state (opaque to every integrated module; stored as record-1 plaintext).
// ---------------------------------------------------------------------------------------------

export const epochKey = (epoch) => hex(sha256('epoch-key', SESSION_ID, String(epoch)));
const encodeState = (state) => utf8(JSON.stringify(state));
const decodeState = (bytes) => JSON.parse(fromUtf8(bytes));
const messageTag = (key, id, text) => hex(sha256('tag', key, id, text)).slice(0, 32);
export function sealMessage(epoch, id, text) {
  return utf8(JSON.stringify({ epoch, id, text, tag: messageTag(epochKey(epoch), id, text) }));
}
const parseMessage = (bytes) => JSON.parse(fromUtf8(bytes));

function generationFacts(P, generation, sessionState, presession) {
  const { codec, root } = P;
  const recordKey = (kind) => codec.encodeRecordKey({
    scope: presession ? 1 : 2,
    localContextId: SLOT,
    secureSessionIdentity: presession ? null : SESSION_ID,
    writeGeneration: generation,
    recordKind: kind,
  });
  const records = DATA_KINDS.map((kind) => {
    const plaintext = kind === STATE_KIND ? encodeState(sessionState) : sha256('filler', String(generation), String(kind)).slice(0, 9);
    const ciphertext = Uint8Array.from(plaintext, (b, i) => b ^ (0x5a + i) & 0xff);
    return { recordKey: recordKey(kind), recordKind: kind, plaintext, ciphertext, tag: sha256('tag', ciphertext).slice(0, 16) };
  });
  const manifestBytes = root.encodeManifest(records.map((r) => root.manifestEntry({
    recordKey: r.recordKey,
    recordKind: r.recordKind,
    ciphertextDigest: root.ciphertextDigest({ recordKey: r.recordKey, recordKind: r.recordKind, ciphertext: r.ciphertext, tag: r.tag }),
  })));
  const manifestKey = root.encodeManifestKey({
    localContextId: SLOT, scope: presession ? 1 : 2, secureSessionIdentity: presession ? null : SESSION_ID, writeGeneration: generation,
  });
  return {
    generation,
    records,
    manifestKey,
    manifestBytes,
    manifestCipherDigest: sha256('manifest-cipher', manifestBytes),
    keyedRoot: root.computeKeyedRoot({ manifestRootKey: ROOT_KEY, manifestKey, generation, manifestBytes }),
    sessionBindingDigest: presession ? null : BINDING_DIGEST,
  };
}

function selectorBytes(P, facts, state, candidate = facts) {
  const { codec, root } = P;
  return codec.encodePlaintext(codec.M2_KIND.GENERATION_SELECTOR, {
    presence: 1,
    generation: facts.generation,
    manifestKeyDigest: root.manifestKeyDigest(facts.manifestKey),
    manifestCipherDigest: facts.manifestCipherDigest,
    keyedRoot: facts.keyedRoot,
    state,
    candidateGeneration: candidate.generation,
    candidateManifestKey: candidate.manifestKey,
    candidateManifestKeyDigest: root.manifestKeyDigest(candidate.manifestKey),
    candidateManifestCipherDigest: candidate.manifestCipherDigest,
    candidateKeyedRoot: candidate.keyedRoot,
  });
}

const errCode = (e) => (e === null || e === undefined ? null : (e.code ?? e.message));

// ---------------------------------------------------------------------------------------------
// The device: one SS process over one disk.
// ---------------------------------------------------------------------------------------------

export class Device {
  /** Boot a process over `disk` (a fresh one when omitted). `P` reuses an already loaded process. */
  static async boot(disk = null, seed = 1, P = null) {
    const proc = P ?? await loadProcess();
    const d = new Device(proc, disk ?? makeDisk(), seed);
    if (disk === null) d.seedPresession();
    return d;
  }

  constructor(P, disk, seed) {
    this.P = P;
    this.disk = disk;
    this.rand = prng(seed);
    this.clock = manualClock();
    this.trace = [];
    this.wireRefusals = []; // adapter results the worker wire codec could not encode
    this.emitted = []; // every output the AP actually received: { requestOp, output }
    this.restarts = 0;
  }

  /** Restart: the process dies; only a deep copy of the durable disk survives; all modules reload. */
  async restart() {
    const disk = deepCopy(this.disk);
    disk.hold = null; // the SS memory hold is process memory
    const next = await Device.boot(disk, 0x5eed0000 + this.restarts + 1);
    next.emitted = this.emitted; // what the AP already received lives outside the SS process
    next.trace = this.trace;
    next.wireRefusals = this.wireRefusals;
    next.restarts = this.restarts + 1;
    return next;
  }

  seedPresession() {
    const g = this.disk.nextGeneration;
    this.disk.nextGeneration += 1n;
    const facts = generationFacts(this.P, g, { epoch: null, epochKeys: {}, accepted: [], sent: 0 }, true);
    this.disk.generations.set(g, {
      ...deepCopy(facts), mutationHold: { presence: 0 }, escrow: null, resultEvidence: null,
    });
    this.disk.selector = selectorBytes(this.P, facts, SEL.EMPTY);
    this.disk.snapshot = deepCopy(this.P.sm.createAdapterSnapshot('EMPTY'));
  }

  snapshot() { return deepCopy(this.disk.snapshot); }

  decodeSelector(bytes = this.disk.selector) {
    return this.P.codec.decodePlaintext(this.P.codec.M2_KIND.GENERATION_SELECTOR, bytes);
  }

  /** The stored selector facts; null when none. */
  selectorFacts() {
    return this.disk.selector === null ? null : this.decodeSelector();
  }

  /** The SS reads its own state from the generation the stored selector names as authority. */
  current() {
    const facts = this.selectorFacts();
    const g = this.disk.generations.get(facts.generation);
    const rec = g.records.find((r) => r.recordKind === STATE_KIND);
    return { generation: facts.generation, selectorState: facts.state, state: decodeState(rec.plaintext) };
  }

  /** The I-TXN acceptance oracle; `{ error }` instead of a throw. */
  async authority(oldGeneration, newGeneration) {
    try {
      const a = await this.P.txn.classifyAuthority({
        storage: makePort(this.disk), manifestRootKey: ROOT_KEY, oldGeneration, newGeneration,
      });
      return { authority: a.authority, generation: a.generation, held: a.held, state: a.state, error: null };
    } catch (e) {
      return { authority: null, generation: null, held: null, state: null, error: errCode(e) };
    }
  }

  request(operation, input) {
    const req = {
      api: this.P.adapter.M2_ADAPTER.API,
      operation,
      requestId: `req-${this.trace.length + 1}`,
      profile: { ...this.P.adapter.M2_ADAPTER.PROFILE },
      bindingRef: Uint8Array.prototype.slice.call(SLOT),
      input,
    };
    // Every request crosses the worker wire codec before the adapter sees it.
    return this.P.wire.fromWireBytes(this.P.wire.toWireBytes(req));
  }

  /** Call the adapter; the result crosses the wire codec back; the next snapshot is persisted. */
  decide(req, observation, tag) {
    const t = this.P.adapter.invokeAdapterTransition({ request: req, snapshot: this.snapshot(), observation });
    // A result the worker wire codec refuses is recorded (invariant I5) and the raw adapter result
    // is used, so the rest of the cell still runs.
    let result;
    try {
      result = this.P.wire.fromWireBytes(this.P.wire.toWireBytes(t.result));
    } catch (error) {
      this.wireRefusals.push({ operation: req.operation, kind: t.result.kind, successCode: t.result.successCode ?? null, code: errCode(error) });
      result = deepCopy(t.result);
    }
    if (t.snapshot !== null) this.disk.snapshot = deepCopy(t.snapshot);
    this.trace.push({
      at: this.clock.tick(), tag, operation: req.operation, kind: result.kind,
      code: result.successCode ?? result.error?.code ?? null,
    });
    return result;
  }

  emit(result, requestOp) {
    if (result.output !== undefined) this.emitted.push({ requestOp, output: deepCopy(result.output) });
  }

  // ----- I-TXN plumbing --------------------------------------------------------------------

  envelopeFor(operation, opBytes, parent) {
    const { txn } = this.P;
    const scenario = SCENARIO_BY_OPERATION[operation];
    const row = txn.mutationRow(scenario);
    return txn.buildMutationEnvelope({
      operationIdentity: { value: opBytes, assignedBy: 'SS_RS', fresh: true, reusable: false, apRequestIdEqual: false },
      operation: row.operation,
      scenario,
      originalApiState: row.stateBefore,
      originalAuthority: { digest: parent.keyedRoot, reference: sha256('authority-ref', parent.manifestKey) },
      bindingProfileIdentity: { bindingRef: SLOT, profile: PROFILE_DIGEST },
      candidate: { digest: sha256('candidate', opBytes), reference: sha256('candidate-ref', opBytes) },
      componentSet: {
        digest: sha256('components', scenario), reference: sha256('components-ref', scenario),
        entries: row.components.map((c) => ({ ...c })),
      },
      heldOutput: row.outputKind === 'NONE'
        ? { kind: 'NONE', digest: null, reference: null }
        : { kind: row.outputKind, digest: sha256('held', opBytes), reference: sha256('held-ref', opBytes) },
      expectedSuccess: { code: row.successCode, stateAfter: row.stateAfterCommitted },
      reconciliationIdentity: { reference: sha256('reconcile-ref', opBytes), owner: 'SS_RS' },
    });
  }

  evidenceFor(envelope, outcome) {
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
    };
  }

  /**
   * Prepare one mutating request: fix the SS_RS identity, form the envelope and candidate, and record
   * the in-flight request durably (`disk.pending`). Returns everything `runMutation` needs plus the
   * original observation members the adapter will be given.
   */
  prepare(operation, input, nextState, output, obsBase, rs) {
    const { txn } = this.P;
    const cur = this.current();
    const parent = this.disk.generations.get(cur.generation);
    const opBytes = nonzeroBytes(this.rand, 32);
    const operationIdentity = `op-${hex(opBytes).slice(0, 40)}`;
    const generation = this.disk.nextGeneration;
    this.disk.nextGeneration += 1n;
    const scenario = SCENARIO_BY_OPERATION[operation];
    const row = txn.mutationRow(scenario);
    const envelope = this.envelopeFor(operation, opBytes, parent);
    const facts = generationFacts(this.P, generation, nextState, false);
    const outcome = txn.M2_OUTCOME[rs];
    // A held selector (state 3) cannot be re-encoded as a parent tuple; the parent's own logical state
    // is ACTIVE there. I-TXN refuses the request from the stored selector before reading this field.
    const parentState = cur.selectorState === SEL.RECONCILIATION_REQUIRED ? SEL.ACTIVE : cur.selectorState;
    const escrow = row.outputKind === 'NONE' ? null : {
      kind: row.outputKind, digest: envelope.heldOutput.digest, reference: envelope.heldOutput.reference, output,
    };
    const candidate = {
      ...facts,
      escrow,
      resultEvidence: this.evidenceFor(envelope, outcome),
      selectorBytes: selectorBytes(this.P, facts, SEL.ACTIVE),
      holdSelectorBytes: selectorBytes(this.P, parent, SEL.RECONCILIATION_REQUIRED, facts),
      parentSelectorBytes: selectorBytes(this.P, parent, parentState),
      parentGeneration: cur.generation,
      parentKeyedRoot: parent.keyedRoot,
    };
    this.disk.pending = {
      operation, operationIdentity, generation, parentGeneration: cur.generation,
      requestInput: deepCopy(input), envelope: deepCopy(envelope), outputKind: row.outputKind,
      escrowOutput: escrow === null ? null : deepCopy(output), obsBase: deepCopy(obsBase),
      stateBefore: row.stateBefore, stateAfter: row.stateAfterCommitted,
    };
    return { envelope, candidate, outcome, operationIdentity, generation, parentGeneration: cur.generation, row };
  }

  /** The step plan I-TXN will run for this prepared request (`mutationSteps`, ORIGINAL phase). */
  planFor(prep) {
    const c = prep.candidate;
    return this.P.txn.mutationSteps({
      envelope: prep.envelope,
      candidate: {
        generation: c.generation, parentGeneration: c.parentGeneration, records: c.records,
        manifestKey: c.manifestKey, manifestBytes: c.manifestBytes, manifestCipherDigest: c.manifestCipherDigest,
        keyedRoot: c.keyedRoot, sessionBindingDigest: c.sessionBindingDigest, selectorBytes: c.selectorBytes,
        holdSelectorBytes: c.holdSelectorBytes, parentSelectorBytes: c.parentSelectorBytes,
        resultEvidence: c.resultEvidence, escrow: c.escrow, mutationHold: null,
      },
      outcome: prep.outcome,
      phase: 'ORIGINAL',
    });
  }

  /** The RECONCILIATION-phase plan for the pending request and readback outcome `rs`. */
  reconcilePlanFor(rs) {
    const p = this.disk.pending;
    const dummy = new Uint8Array(8).fill(1);
    return this.P.txn.mutationSteps({
      envelope: this.P.txn.buildMutationEnvelope(p.envelope),
      candidate: {
        generation: p.generation, parentGeneration: p.parentGeneration, records: [],
        manifestKey: null, manifestBytes: null, manifestCipherDigest: null, selectorBytes: dummy,
        holdSelectorBytes: null, parentSelectorBytes: dummy, resultEvidence: null,
        escrow: p.escrowOutput === null ? null : { output: p.escrowOutput }, keyedRoot: null,
        sessionBindingDigest: null, mutationHold: null,
      },
      outcome: this.P.txn.M2_OUTCOME[rs],
      phase: 'RECONCILIATION',
    });
  }

  /** Run the prepared transaction over a port with an optional crash. */
  async runTxn(prep, crash = null) {
    const port = makePort(this.disk, crash);
    const txnResult = await this.P.txn.runMutation({
      storage: port, manifestRootKey: ROOT_KEY, envelope: prep.envelope, candidate: prep.candidate, outcome: prep.outcome,
    });
    return { txnResult, port };
  }

  /**
   * The output bytes durably escrowed in `generation`, read back through the storage port; null when
   * the generation or its escrow is absent. The SS releases only these bytes: the pending request's
   * own copy (`escrowOutput`) is kept solely as the independent expected value the oracle compares
   * against, so a lost or altered durable escrow surfaces as an I4 violation instead of being masked.
   */
  async durableEscrowOutput(generation) {
    const g = await makePort(this.disk).readGeneration(generation);
    if (g === null || g.escrow === null || g.escrow === undefined) return null;
    const out = g.escrow.output;
    return out === null || out === undefined ? null : Uint8Array.prototype.slice.call(out);
  }

  /** The adapter observation for the pending request with commit outcome `rs` and the escrow `output`. */
  observationFor(p, rs, output) {
    const obs = { ...deepCopy(p.obsBase), commitOutcome: rs, operationIdentity: p.operationIdentity };
    if (p.operation !== 'JOIN_WELCOME') {
      obs.stagedOutput = rs === 'COMMITTED' && output !== null && p.outputKind !== 'NONE'
        ? { [OUTPUT_MEMBER[p.outputKind]]: output } : null;
    }
    return obs;
  }

  /** Ask the adapter to decide the pending request from the outcome the SS observed. */
  async decidePending(rs, withEscrow, tag) {
    const p = this.disk.pending;
    const req = this.request(p.operation, deepCopy(p.requestInput));
    const output = withEscrow && rs === 'COMMITTED' ? await this.durableEscrowOutput(p.generation) : null;
    const result = this.decide(req, this.observationFor(p, rs, output), tag);
    if (rs !== 'INDETERMINATE' && result.kind !== 'INDETERMINATE') this.disk.pending = null;
    return result;
  }

  /**
   * RECONCILE_INDETERMINATE for the pending request: the SS asks I-TXN to reconcile from the RS
   * readback `rs` (when it has something to reconcile), then reports to the adapter the outcome the
   * storage actually reached. `crash` injects a crash into the I-TXN call (which then propagates).
   * Returns `{ result, txnOutcome, txnError, readback }`.
   */
  async reconcile(rs, crash = null) {
    const { txn } = this.P;
    const p = this.disk.pending;
    const snap = this.snapshot();
    const ref = snap.held === null ? 'I-SM-HOLD:none' : snap.held.reconciliationRef;
    const req = this.request('RECONCILE_INDETERMINATE', { reconciliationRef: ref });
    const before = await this.authority(p.parentGeneration, p.generation);
    const memoryHold = this.disk.hold;
    let txnOutcome = null;
    let txnError = null;
    let reported = rs;
    if (before.error === null && before.held === false && memoryHold === null) {
      // Nothing held anywhere: the authenticated readback is already terminal. The SS reports it.
      reported = before.authority === 'COMPLETE_NEW' ? 'COMMITTED' : 'NOT_COMMITTED';
    } else {
      const port = makePort(this.disk, crash);
      try {
        txnOutcome = await txn.reconcileIndeterminate({
          storage: port,
          manifestRootKey: ROOT_KEY,
          hold: memoryHold,
          evidence: this.evidenceFor(p.envelope, txn.M2_OUTCOME[rs]),
          reference: memoryHold === null ? p.envelope.reconciliationIdentity.reference : memoryHold.reconciliationReference,
        });
      } catch (e) {
        if (port.crashed) throw e; // a crash is a crash: the caller handles the process death
        txnError = e;
      }
      // The SS can only report what the storage reached: an I-TXN refusal leaves the request pending.
      if (txnError !== null) reported = 'INDETERMINATE';
      else reported = txnOutcome.reconciliation === 'RECONCILED_COMMITTED' ? 'COMMITTED'
        : (txnOutcome.reconciliation === 'NOT_COMMITTED' ? 'NOT_COMMITTED' : 'INDETERMINATE');
    }
    const committed = reported === 'COMMITTED';
    const member = OUTPUT_MEMBER[p.outputKind] ?? null;
    // A COMMITTED report releases the held output: it is what I-TXN read back from the selected
    // generation's durable escrow when it reconciled, or, on a terminal readback with nothing held,
    // what the SS reads from that escrow itself, never the pending request's own copy. Any other
    // report releases nothing; the adapter still checks the shape of the escrow the hold names, so the
    // SS presents the escrow it retained for the request.
    let held = null;
    if (member !== null) {
      if (!committed) held = p.escrowOutput === null ? null : deepCopy(p.escrowOutput);
      else if (txnOutcome !== null) held = txnOutcome.output === null || txnOutcome.output === undefined ? null : Uint8Array.prototype.slice.call(txnOutcome.output);
      else held = await this.durableEscrowOutput(p.generation);
    }
    const result = this.decide(req, {
      slotContext: SLOT.slice(),
      commitOutcome: reported,
      responseEmission: committed ? 'SUCCEEDED' : null,
      heldOutput: held === null ? null : { [member]: held },
    }, `reconcile-${rs}`);
    if (result.kind !== 'INDETERMINATE' && result.kind !== 'REJECTED') this.disk.pending = null;
    return { result, txnOutcome, txnError: errCode(txnError), reported, readback: before };
  }

  // ----- the operations: prepared requests -------------------------------------------------

  prepCreate(rs) {
    const welcome = nonzeroBytes(this.rand, 24);
    const input = { peerFramedKeyPackage: nonzeroBytes(this.rand, 16) };
    const next = { epoch: 0, epochKeys: { 0: epochKey(0) }, accepted: [], sent: 0 };
    return this.prepare('CREATE', input, next, welcome, { onboarding: 'SUPPORTED' }, rs);
  }

  prepJoin(rs) {
    const input = { embeddedTreeWelcome: nonzeroBytes(this.rand, 24) };
    const next = { epoch: 0, epochKeys: { 0: epochKey(0) }, accepted: [], sent: 0 };
    return this.prepare('JOIN_WELCOME', input, next, null, { keyPackage: 'MATCHED' }, rs);
  }

  prepProtect(rs, text = 'hello') {
    const cur = this.current().state;
    const id = `m-${cur.epoch}-${cur.sent + 1}`;
    const message = sealMessage(cur.epoch, id, text);
    const next = { ...cur, sent: cur.sent + 1 };
    return this.prepare('PROTECT_APPLICATION', { applicationBytes: utf8(text) }, next, message, {}, rs);
  }

  prepOpen(rs, message) {
    const cur = this.current().state;
    const framed = parseMessage(message);
    const next = { ...cur, accepted: [...cur.accepted, framed.id] };
    const obsBase = {
      currentEpoch: cur.epoch, framingEpoch: framed.epoch, authentication: 'AUTHENTICATED', replayIdentity: 'UNSEEN',
    };
    return this.prepare('OPEN_APPLICATION', { protectedApplicationMessage: message }, next, utf8(framed.text), obsBase, rs);
  }

  prepSelfUpdate(rs) {
    const cur = this.current().state;
    const epoch = cur.epoch + 1;
    const window = this.P.adapter.M2_ADAPTER.RETENTION.PAST_EPOCHS_ONCE_AVAILABLE;
    const epochKeys = {};
    for (const [e, k] of Object.entries(cur.epochKeys)) if (epoch - Number(e) <= window) epochKeys[e] = k;
    epochKeys[epoch] = epochKey(epoch);
    const next = { ...cur, epoch, epochKeys };
    const commitBytes = sha256('commit', String(epoch), nonzeroBytes(this.rand, 8));
    return this.prepare('SELF_UPDATE', {}, next, commitBytes, { slotContext: SLOT.slice(), updateForm: 'SUPPORTED' }, rs);
  }

  /** Run a prepared request with no crash and let the adapter decide; emits any output. */
  async runClean(prep, tag) {
    const { txnResult } = await this.runTxn(prep);
    const rs = txnResult.commitOutcome;
    const result = await this.decidePending(rs, true, tag);
    this.emit(result, prep.envelope.operation);
    return result;
  }

  /** The follow-up mutation: PROTECT_APPLICATION when ACTIVE, CREATE when EMPTY. */
  async followUp() {
    const state = this.disk.snapshot.state;
    let prep;
    try {
      prep = state === 'EMPTY' ? this.prepCreate('COMMITTED') : this.prepProtect('COMMITTED', 'follow-up');
    } catch (e) {
      return { accepted: false, code: `PREPARE:${errCode(e)}`, result: null, generation: null };
    }
    try {
      await this.runTxn(prep);
    } catch (e) {
      this.disk.pending = null; // the SS drops a request I-TXN refused before any write
      return { accepted: false, code: errCode(e), result: null, generation: prep.generation, parent: prep.parentGeneration };
    }
    const result = await this.decidePending('COMMITTED', true, 'follow-up');
    this.emit(result, prep.envelope.operation);
    return {
      accepted: result.kind === 'SUCCESS', code: result.successCode ?? result.error?.code ?? result.kind,
      result, generation: prep.generation, parent: prep.parentGeneration,
    };
  }
}

export { errCode };
