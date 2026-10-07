// session-transaction-recovery.test.js — I-TXN recovery through the public composed surface.
//
// The harness is the T-COMPOSE one (combined I-UPD + I-MSG over the real M2 storage stack, with
// interruption and restart), with a C-FMT-conformant port: WRITE_HOLD stores the complete kind-13
// MUTATION_HOLD record in the candidate generation. The tests at the end are the T-COMPOSE recovery
// wedges R1-R3 and the full SELF_UPDATE crash-point sweep (C-MUT /crashBoundaries, §5, §6, §8).
//
// Every operation goes through the public adapter surface (`invokeAdapterTransition`), every request
// and result crosses the I-WORK wire codec (`toWireBytes` / `fromWireBytes`), and every durable effect
// is an I-TXN transaction (`runMutation`, `reconcileIndeterminate`, `classifyAuthority`) over one
// in-memory disk. A "restart" drops every module instance (`jest.resetModules()` followed by a fresh
// dynamic import of the adapter, the I-SM core, the worker codec and I-TXN) and every in-process
// object; only the durable disk survives, and it is re-read through `structuredClone`.
//
// Nothing integrated is mocked. The decision is the merged I-SM core's (through the adapter), the
// authority is the merged I-TXN readback's. The test-local "SS" below is glue only: it owns what the
// integrated modules leave to their caller (the session-state bytes it stores in the candidate
// generation, which RS outcome is reported, when the adapter's next snapshot is persisted). It never
// decides an outcome the integrated modules decide; every assertion is made on a value an integrated
// module returned or on the durable bytes it wrote.
//
// Randomness and time are injected: a seeded PRNG drives every identity and payload, and a manual
// clock stamps the trace. No `Math.random`, no `Date.now`.

import { createHash } from 'node:crypto';
import { describe, expect, jest, test } from '@jest/globals';

const SRC = '../../../src';
const MODULE_PATHS = {
  adapter: `${SRC}/crypto/mls/m2/adapter.js`,
  sm: `${SRC}/crypto/mls/m2/state-machine.js`,
  wire: `${SRC}/crypto/mls/m2/worker-protocol.js`,
  txn: `${SRC}/storage/m2/session-transaction.js`,
  codec: `${SRC}/storage/m2/session-codec.js`,
  root: `${SRC}/storage/m2/session-root.js`,
};

/** One process: a fresh module registry, so no module-level state survives a restart. */
async function loadProcess() {
  jest.resetModules();
  const out = {};
  for (const [name, path] of Object.entries(MODULE_PATHS)) out[name] = await import(path);
  return Object.freeze(out);
}

// ---------------------------------------------------------------------------------------------
// Deterministic randomness and clock.
// ---------------------------------------------------------------------------------------------

function prng(seed) {
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
const hex = (u8) => Buffer.from(u8).toString('hex');
const sha256 = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(typeof p === 'string' ? Buffer.from(p) : Buffer.from(p));
  return new Uint8Array(h.digest());
};
const utf8 = (s) => new Uint8Array(Buffer.from(s, 'utf8'));
const fromUtf8 = (u8) => Buffer.from(u8).toString('utf8');

/**
 * In-realm deep copy of durable data (plain objects, arrays, Map, Uint8Array, bigint, primitives).
 * `structuredClone` is not used: under Jest it returns objects of the host realm, whose prototypes
 * the integrated closed-record readers rightly refuse.
 */
function deepCopy(v) {
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

const ROOT_KEY = new Uint8Array(32).fill(0x11);
const SLOT = new Uint8Array(32).fill(0xa1);
const OTHER_SLOT = new Uint8Array(32).fill(0xb2);
const SESSION_ID = new Uint8Array(32).fill(0x41);
const BINDING_DIGEST = new Uint8Array(32).fill(0x51);
const PROFILE_DIGEST = new Uint8Array(32).fill(0x31);
const DATA_KINDS = Array.from({ length: 15 }, (_, i) => i + 1);
const STATE_KIND = 1; // the data record whose plaintext carries the test SS session state

const SCENARIO_BY_OPERATION = Object.freeze({
  CREATE: 'CAPI-S001',
  PROTECT_APPLICATION: 'CAPI-S009',
  OPEN_APPLICATION: 'CAPI-S010',
  SELF_UPDATE: 'CAPI-S014',
});
const OUTPUT_MEMBER = Object.freeze({
  EMBEDDED_TREE_WELCOME: 'embeddedTreeWelcome',
  PROTECTED_APPLICATION_BYTES: 'protectedApplicationBytes',
  APPLICATION_BYTES: 'applicationBytes',
  PROTECTED_COMMIT_BYTES: 'protectedCommitBytes',
});

// ---------------------------------------------------------------------------------------------
// The durable disk: the only thing that survives a restart.
// ---------------------------------------------------------------------------------------------

function makeDisk() {
  return {
    generations: new Map(), // bigint -> stored generation (records, manifest, hold, escrow, evidence)
    selector: null, // the stored kind-14 selector plaintext bytes
    selectorEnvelope: null, // F2: the opaque stored envelope of that selector (fresh nonce per write)
    hold: null, // the durable immutable hold record I-TXN wrote
    snapshot: null, // the persisted adapter snapshot (plain data)
    pending: null, // the in-flight request the SS fixed before the RS call (C-MUT: SS_RS identity)
    nextGeneration: 1n,
  };
}
const cloneDisk = (disk) => deepCopy(disk);

/**
 * The I-TXN storage port over the disk. `faults` crash at an exact plan step: a fault
 * `{ boundary?, kind, mode: 'BEFORE' | 'AFTER', remaining }` raises before or after the durable effect
 * of the first matching step. A crash is a process death: the caller drops every in-process object.
 */
let ENVELOPE_WRITES = 0;
function sealSelector(plaintext) {
  ENVELOPE_WRITES += 1;
  const out = new Uint8Array(12 + plaintext.length + 16);
  new DataView(out.buffer).setUint32(8, ENVELOPE_WRITES);
  out.set(plaintext, 12);
  out.set(sha256('seal', out.subarray(0, 12), plaintext).subarray(0, 16), 12 + plaintext.length);
  return out;
}
function checkSelectorPrecondition(p, envelope) {
  if (!Object.hasOwn(p, 'expectedSelectorBytes')) throw new Error('REPLACE_SELECTOR without expectedSelectorBytes');
  const e = p.expectedSelectorBytes;
  const same = e === null ? envelope === null
    : envelope !== null && e.length === envelope.length && e.every((b, i) => b === envelope[i]);
  if (!same) {
    throw Object.assign(new Error('the stored selector envelope differs from expectedSelectorBytes'),
      { code: 'SELECTOR_PRECONDITION_FAILED' });
  }
}

function makePort(disk, faults = []) {
  const port = { applied: [] };
  const staged = new Map();
  let calls = 0;
  const take = (step, mode) => {
    if (mode === 'BEFORE') calls += 1;
    for (const f of faults) {
      if (f.at !== undefined) { // positional fault: the `at`-th apply call of this port (1-based)
        if (f.remaining > 0 && f.mode === mode && f.at === calls) { f.remaining -= 1; return true; }
        continue;
      }
      if (f.remaining > 0 && f.mode === mode && f.kind === step.kind
        && (f.boundary === undefined || f.boundary === step.boundary)) {
        f.remaining -= 1;
        return true;
      }
    }
    return false;
  };
  port.apply = async (step) => {
    port.applied.push(`${step.boundary}/${step.kind}`);
    if (take(step, 'BEFORE')) throw new Error(`crash BEFORE ${step.boundary}/${step.kind}`);
    const p = step.payload;
    if (step.kind === 'STAGE_DATA') {
      if (!staged.has(p.generation)) staged.set(p.generation, new Map());
      staged.get(p.generation).set(p.recordKind, deepCopy({
        recordKey: p.recordKey, recordKind: p.recordKind, plaintext: p.plaintext, ciphertext: p.ciphertext, tag: p.tag,
      }));
    } else if (step.kind === 'STAGE_MANIFEST') {
      const s = staged.get(p.generation);
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
        // A C-FMT-conformant port stores the complete kind-13 MUTATION_HOLD record in the candidate.
        g.mutationHold = deepCopy(p.hold);
      }
      disk.hold = p.hold === null || p.holdRecordKey === undefined || p.holdRecordKey === null
        ? deepCopy(p.hold) : { ...deepCopy(p.hold), recordKey: Uint8Array.prototype.slice.call(p.holdRecordKey) };
    } else if (step.kind === 'CLEAR_CANDIDATE') {
      disk.generations.delete(p.generation);
      staged.delete(p.generation);
      disk.hold = null;
    } else if (step.kind === 'REPLACE_SELECTOR') {
      checkSelectorPrecondition(p, disk.selectorEnvelope);
      disk.selector = Uint8Array.prototype.slice.call(p.selectorBytes);
      disk.selectorEnvelope = sealSelector(disk.selector);
      if (p.resolveHoldGeneration !== null && p.resolveHoldGeneration !== undefined) {
        const g = disk.generations.get(p.resolveHoldGeneration);
        if (g !== undefined) g.mutationHold = { presence: 0 };
      }
    } else if (step.kind === 'RELEASE_ESCROW') {
      disk.hold = null;
    }
    if (take(step, 'AFTER')) throw new Error(`crash AFTER ${step.boundary}/${step.kind}`);
    return undefined;
  };
  port.readSelector = async () => (disk.selector === null ? null : {
    plaintext: Uint8Array.prototype.slice.call(disk.selector),
    envelope: Uint8Array.prototype.slice.call(disk.selectorEnvelope),
  });
  port.readGeneration = async (generation) => {
    const g = disk.generations.get(generation);
    return g === undefined ? null : deepCopy(g);
  };
  port.readMemoryHold = async () => (disk.hold === null ? null : deepCopy(disk.hold));
  // Number-only inventory: every generation number with any stored artifact, complete or staged.
  port.readGenerationNumbers = async () => [...new Set([...disk.generations.keys(), ...staged.keys()])];
  return port;
}

// ---------------------------------------------------------------------------------------------
// Test SS session state (opaque to every integrated module; stored as record-1 plaintext).
// ---------------------------------------------------------------------------------------------

/**
 * `epoch` is the authoritative current epoch; `epochKeys` maps an epoch to the receive key the SS
 * retains for it; `accepted` lists the replay identities already accepted; `sent` counts protected
 * messages. The key of epoch `e` is derived from the session root and `e`, so a deleted key can only
 * come back by re-derivation, which the SS never does.
 */
const epochKey = (epoch) => hex(sha256('epoch-key', SESSION_ID, String(epoch)));
const encodeState = (state) => utf8(JSON.stringify(state));
const decodeState = (bytes) => JSON.parse(fromUtf8(bytes));

function stateFromDisk(disk, txn) {
  const sel = disk.selector;
  if (sel === null) return null;
  // The SS reads its own state from the generation the stored selector names as authority.
  const facts = decodeSelector(sel, txn);
  const g = disk.generations.get(facts.generation);
  const rec = g.records.find((r) => r.recordKind === STATE_KIND);
  return { generation: facts.generation, selectorState: facts.state, state: decodeState(rec.plaintext) };
}

let CODEC = null; // set per process; used only to decode selector bytes the integrated code wrote
function decodeSelector(bytes) {
  return CODEC.decodePlaintext(CODEC.M2_KIND.GENERATION_SELECTOR, bytes);
}

// ---------------------------------------------------------------------------------------------
// Generation construction (the candidate the SS hands to I-TXN).
// ---------------------------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------------------------
// The device: one SS process over one disk.
// ---------------------------------------------------------------------------------------------

const SEL = Object.freeze({ EMPTY: 1, ACTIVE: 2, RECONCILIATION_REQUIRED: 3 });

class Device {
  /** Boot a process over `disk` (a fresh one when omitted). */
  static async boot(disk = null, seed = 1) {
    const P = await loadProcess();
    CODEC = P.codec;
    const d = new Device(P, disk ?? makeDisk(), seed);
    if (disk === null) d.seedPresession();
    return d;
  }

  constructor(P, disk, seed) {
    this.P = P;
    this.disk = disk;
    this.rand = prng(seed);
    this.clock = manualClock();
    this.trace = [];
    this.emitted = []; // every output member the AP actually received, in order
  }

  /** Restart: the process dies, only a structured clone of the disk survives, all modules reload. */
  async restart(seed = 99) {
    const disk = cloneDisk(this.disk);
    const emitted = this.emitted; // what the AP already received lives outside the SS process
    const next = await Device.boot(disk, seed);
    next.emitted = emitted;
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
    this.disk.selectorEnvelope = sealSelector(this.disk.selector);
    this.disk.snapshot = deepCopy(this.P.sm.createAdapterSnapshot('EMPTY'));
  }

  snapshot() { return deepCopy(this.disk.snapshot); }

  port(faults = []) { return makePort(this.disk, faults); }

  get rootKey() { return ROOT_KEY; }

  authority(oldGeneration = null, newGeneration = null) {
    return this.P.txn.classifyAuthority({
      storage: makePort(this.disk), manifestRootKey: ROOT_KEY, oldGeneration, newGeneration,
    });
  }

  current() { return stateFromDisk(this.disk, this.P.txn); }

  request(operation, input, bindingRef = SLOT) {
    const req = {
      api: this.P.adapter.M2_ADAPTER.API,
      operation,
      requestId: `req-${this.trace.length + 1}`,
      profile: { ...this.P.adapter.M2_ADAPTER.PROFILE },
      bindingRef: Uint8Array.prototype.slice.call(bindingRef),
      input,
    };
    // Every request crosses the worker wire codec before the adapter sees it.
    return this.P.wire.fromWireBytes(this.P.wire.toWireBytes(req));
  }

  /** Call the adapter; the result crosses the wire codec back; the next snapshot is persisted. */
  decide(req, observation) {
    const t = this.P.adapter.invokeAdapterTransition({ request: req, snapshot: this.snapshot(), observation });
    const result = this.P.wire.fromWireBytes(this.P.wire.toWireBytes(t.result));
    if (t.snapshot !== null) this.disk.snapshot = deepCopy(t.snapshot);
    this.trace.push({ at: this.clock.tick(), operation: req.operation, kind: result.kind, code: result.successCode ?? result.error?.code ?? null });
    return { result, snapshot: t.snapshot };
  }

  /** Release the output member to the AP (the local emission). */
  emit(result) {
    if (result.output !== undefined) this.emitted.push(deepCopy(result.output));
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
   * One mutating operation: fix the SS_RS identity, run the I-TXN transaction with the RS outcome
   * `rs`, then let the adapter decide from what the transaction returned. A crash fault propagates as
   * a process death before the adapter is ever asked.
   */
  async mutate(operation, input, nextState, output, rs = 'COMMITTED', faults = []) {
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
    const parentFacts = { ...parent };
    // A held selector (state 3) cannot be re-encoded as a parent tuple; the parent's own logical state
    // is ACTIVE there. I-TXN refuses the request from the stored selector before reading this field.
    const parentState = cur.selectorState === SEL.RECONCILIATION_REQUIRED ? SEL.ACTIVE : cur.selectorState;
    const escrow = row.outputKind === 'NONE' ? null : {
      kind: row.outputKind, digest: envelope.heldOutput.digest, reference: envelope.heldOutput.reference, output,
    };
    this.disk.pending = {
      operation, operationIdentity, opBytes, generation, parentGeneration: cur.generation,
      requestInput: deepCopy(input), envelope: deepCopy(envelope), outputKind: row.outputKind,
    };
    const candidate = {
      ...facts,
      escrow,
      resultEvidence: this.evidenceFor(envelope, outcome),
      selectorBytes: selectorBytes(this.P, facts, SEL.ACTIVE),
      holdSelectorBytes: selectorBytes(this.P, parentFacts, SEL.RECONCILIATION_REQUIRED, facts),
      parentSelectorBytes: selectorBytes(this.P, parentFacts, parentState),
      parentGeneration: cur.generation,
      parentKeyedRoot: parent.keyedRoot,
    };
    const port = makePort(this.disk, faults);
    const txnResult = await txn.runMutation({ storage: port, manifestRootKey: ROOT_KEY, envelope, candidate, outcome });
    if (txnResult.commitOutcome !== 'INDETERMINATE') this.disk.pending = null;
    return { txnResult, operationIdentity, port };
  }

  // ----- the operations -------------------------------------------------------------------

  async create(rs = 'COMMITTED', faults = []) {
    const welcome = nonzeroBytes(this.rand, 24);
    const req = this.request('CREATE', { peerFramedKeyPackage: nonzeroBytes(this.rand, 16) });
    const next = { epoch: 0, epochKeys: { 0: epochKey(0) }, accepted: [], sent: 0 };
    const { txnResult, operationIdentity } = await this.mutate('CREATE', req.input, next, welcome, rs, faults);
    return this.decide(req, {
      onboarding: 'SUPPORTED',
      commitOutcome: txnResult.commitOutcome,
      operationIdentity,
      stagedOutput: txnResult.output === null ? null : { embeddedTreeWelcome: txnResult.output },
    });
  }

  async selfUpdate(rs = 'COMMITTED', faults = [], bindingRef = SLOT) {
    const req = this.request('SELF_UPDATE', {}, bindingRef);
    const cur = this.current().state;
    const epoch = cur.epoch + 1;
    const window = this.P.adapter.M2_ADAPTER.RETENTION.PAST_EPOCHS_ONCE_AVAILABLE;
    // C-RET epochRule: the SS keeps the current epoch plus the declared past-epoch window, and deletes
    // the receive material of every epoch that leaves it as part of the same committed transition.
    const epochKeys = {};
    for (const [e, k] of Object.entries(cur.epochKeys)) if (epoch - Number(e) <= window) epochKeys[e] = k;
    epochKeys[epoch] = epochKey(epoch);
    const next = { ...cur, epoch, epochKeys };
    const commitBytes = sha256('commit', String(epoch), nonzeroBytes(this.rand, 8));
    const { txnResult, operationIdentity } = await this.mutate('SELF_UPDATE', {}, next, commitBytes, rs, faults);
    return this.decide(req, {
      slotContext: SLOT.slice(),
      updateForm: 'SUPPORTED',
      commitOutcome: txnResult.commitOutcome,
      operationIdentity,
      stagedOutput: txnResult.output === null ? null : { protectedCommitBytes: txnResult.output },
    });
  }

  async protect(text, rs = 'COMMITTED', faults = []) {
    const req = this.request('PROTECT_APPLICATION', { applicationBytes: utf8(text) });
    const cur = this.current().state;
    const id = `m-${cur.epoch}-${cur.sent + 1}`;
    const message = sealMessage(cur.epoch, id, text);
    const next = { ...cur, sent: cur.sent + 1 };
    const { txnResult, operationIdentity } = await this.mutate('PROTECT_APPLICATION', req.input, next, message, rs, faults);
    return this.decide(req, {
      commitOutcome: txnResult.commitOutcome,
      operationIdentity,
      stagedOutput: txnResult.output === null ? null : { protectedApplicationBytes: txnResult.output },
    });
  }

  /** Open a peer message; the SS reads the framing epoch structurally and looks up its own state. */
  async open(message, rs = 'COMMITTED', faults = []) {
    const req = this.request('OPEN_APPLICATION', { protectedApplicationMessage: message });
    const cur = this.current().state;
    const framed = parseMessage(message);
    const distance = cur.epoch - framed.epoch;
    const window = this.P.adapter.M2_ADAPTER.RETENTION.PAST_EPOCHS_ONCE_AVAILABLE;
    if (distance < 0 || distance > window) {
      // The framing epoch makes authentication, replay and the commit unreachable: exact nulls.
      return this.decide(req, {
        currentEpoch: cur.epoch, framingEpoch: framed.epoch, authentication: null, replayIdentity: null,
        commitOutcome: null, operationIdentity: null, stagedOutput: null,
      });
    }
    const key = cur.epochKeys[framed.epoch];
    const authentic = key !== undefined && framed.tag === messageTag(key, framed.id, framed.text);
    if (!authentic) {
      return this.decide(req, {
        currentEpoch: cur.epoch, framingEpoch: framed.epoch, authentication: 'AUTHENTICATION_FAILED', replayIdentity: null,
        commitOutcome: null, operationIdentity: null, stagedOutput: null,
      });
    }
    if (cur.accepted.includes(framed.id)) {
      return this.decide(req, {
        currentEpoch: cur.epoch, framingEpoch: framed.epoch, authentication: 'AUTHENTICATED', replayIdentity: 'DUPLICATE',
        commitOutcome: null, operationIdentity: null, stagedOutput: null,
      });
    }
    const next = { ...cur, accepted: [...cur.accepted, framed.id] };
    const { txnResult, operationIdentity } = await this.mutate('OPEN_APPLICATION', req.input, next, utf8(framed.text), rs, faults);
    return this.decide(req, {
      currentEpoch: cur.epoch, framingEpoch: framed.epoch, authentication: 'AUTHENTICATED', replayIdentity: 'UNSEEN',
      commitOutcome: txnResult.commitOutcome,
      operationIdentity,
      stagedOutput: txnResult.output === null ? null : { applicationBytes: txnResult.output },
    });
  }

  /**
   * After a restart with an in-flight request whose response never reached the AP, the SS reports
   * the only outcome it can prove for that request: the RS outcome is unknown, i.e. INDETERMINATE
   * (C-API `/rules/rsTriState`). The adapter's held snapshot is the result of that report.
   */
  recoverLostResponse() {
    const p = this.disk.pending;
    if (p === null) return null;
    const req = this.request(p.operation, p.requestInput);
    const base = { commitOutcome: 'INDETERMINATE', operationIdentity: p.operationIdentity, stagedOutput: null };
    const obs = p.operation === 'SELF_UPDATE' ? { slotContext: SLOT.slice(), updateForm: 'SUPPORTED', ...base }
      : p.operation === 'CREATE' ? { onboarding: 'SUPPORTED', ...base }
        : p.operation === 'PROTECT_APPLICATION' ? base
          : null;
    if (obs === null) throw new Error(`no recovery glue for ${p.operation}`);
    return this.decide(req, obs);
  }

  /**
   * RECONCILE_INDETERMINATE: read the held escrow, ask I-TXN to reconcile from the RS readback
   * `rs`, then let the adapter decide. `emission` is whether the local emission of the response
   * succeeded; an interrupted emission is a crash before I-TXN releases the escrow.
   */
  async reconcile(rs, { emission = 'SUCCEEDED', faults = [], reference = null } = {}) {
    const { txn } = this.P;
    const snap = this.snapshot();
    const ref = reference ?? (snap.held === null ? 'I-SM-HOLD:none' : snap.held.reconciliationRef);
    const req = this.request('RECONCILE_INDETERMINATE', { reconciliationRef: ref });
    const p = this.disk.pending;
    const heldGen = p === null ? undefined : this.disk.generations.get(p.generation);
    const escrowOut = heldGen === undefined || heldGen.escrow === null ? null : heldGen.escrow.output;
    const member = p === null ? null : OUTPUT_MEMBER[p.outputKind];
    let txnOutcome = null;
    let txnError = null;
    if (this.disk.hold !== null && p !== null) {
      const port = makePort(this.disk, emission === 'INTERRUPTED' ? [{ kind: 'RELEASE_ESCROW', mode: 'BEFORE', remaining: 1 }, ...faults] : faults);
      try {
        txnOutcome = await txn.reconcileIndeterminate({
          storage: port,
          manifestRootKey: ROOT_KEY,
          hold: this.disk.hold,
          evidence: this.evidenceFor(p.envelope, txn.M2_OUTCOME[rs]),
          reference: this.disk.hold.reconciliationReference,
        });
      } catch (e) {
        txnError = e;
      }
    }
    if (txnOutcome !== null && txnOutcome.reconciliation !== 'INDETERMINATE') this.disk.pending = null;
    const committed = rs === 'COMMITTED';
    const decision = this.decide(req, {
      slotContext: SLOT.slice(),
      commitOutcome: rs,
      responseEmission: committed ? emission : null,
      heldOutput: escrowOut === null || member === null ? null : { [member]: escrowOut },
    });
    return { ...decision, txnOutcome, txnError };
  }
}

// ---------------------------------------------------------------------------------------------
// Peer message framing (test-local; the adapter treats the message as opaque bytes).
// ---------------------------------------------------------------------------------------------

const messageTag = (key, id, text) => hex(sha256('tag', key, id, text)).slice(0, 32);
function sealMessage(epoch, id, text) {
  return utf8(JSON.stringify({ epoch, id, text, tag: messageTag(epochKey(epoch), id, text) }));
}
const parseMessage = (bytes) => JSON.parse(fromUtf8(bytes));

// ---------------------------------------------------------------------------------------------
// Recovery tests (T-COMPOSE R1-R3 and the SELF_UPDATE crash-point sweep).
// ---------------------------------------------------------------------------------------------

const errCode = (e) => (e === null || e === undefined ? null : e.code ?? e.message);
async function attempt(fn) { try { await fn(); return 'OK'; } catch (e) { return errCode(e); } }

describe('I-TXN recovery through the composed surface', () => {
  // R1: C-MUT §8 / crashBoundaries AFTER_INDETERMINATE LOST: after SS memory loss the durable hold in
  // the bound candidate is reconciled by authenticated evidence before another operation.
  for (const rs of ['COMMITTED', 'NOT_COMMITTED']) {
    test(`R1 INDETERMINATE + restart with memory hold lost: ${rs} evidence reconciles, then new work is accepted`, async () => {
      let d = await Device.boot();
      await d.create();
      const ind = await d.selfUpdate('INDETERMINATE');
      expect(ind.result.kind).toBe('INDETERMINATE');
      d = await d.restart();
      d.disk.hold = null; // the memory hold does not survive the process
      const p = d.disk.pending;
      expect(await d.authority(p.parentGeneration, p.generation)).toMatchObject({ authority: 'COMPLETE_OLD', held: true });
      expect(await attempt(() => d.protect('blocked'))).toBe('BLIND_RETRY');
      const durable = d.disk.generations.get(p.generation).mutationHold;
      const out = await d.P.txn.reconcileIndeterminate({
        storage: d.port(), manifestRootKey: d.rootKey, hold: null,
        evidence: d.evidenceFor(p.envelope, d.P.txn.M2_OUTCOME[rs]), reference: durable.reconciliationReference,
      });
      expect(out.reconciliation).toBe(rs === 'COMMITTED' ? 'RECONCILED_COMMITTED' : 'NOT_COMMITTED');
      const after = await d.authority(p.parentGeneration, p.generation);
      expect(after.held).toBe(false);
      expect(after.authority).toBe(rs === 'COMMITTED' ? 'COMPLETE_NEW' : 'COMPLETE_OLD');
      d.disk.pending = null;
      expect(await attempt(() => d.protect('after-restart'))).toBe('OK');
    });
  }

  test('R1 a wrong reference leaves the durable hold unchanged', async () => {
    let d = await Device.boot();
    await d.create();
    await d.selfUpdate('INDETERMINATE');
    d = await d.restart();
    d.disk.hold = null;
    const p = d.disk.pending;
    const sel = hex(d.disk.selector);
    expect(await attempt(() => d.P.txn.reconcileIndeterminate({
      storage: d.port(), manifestRootKey: d.rootKey, hold: null,
      evidence: d.evidenceFor(p.envelope, d.P.txn.M2_OUTCOME.COMMITTED), reference: new Uint8Array(32).fill(1),
    }))).toBe('REFERENCE_MISMATCH');
    expect(hex(d.disk.selector)).toBe(sel);
    expect((await d.authority(p.parentGeneration, p.generation)).held).toBe(true);
  });

  // R2: C-MUT crashBoundaries DURING_RS_WORK RETAINED: OLD_PLUS_ONE_IMMUTABLE_HOLD must be reconcilable.
  for (const rs of ['COMMITTED', 'NOT_COMMITTED']) {
    test(`R2 COMMITTED run crashes before REPLACE_SELECTOR: ${rs} evidence reconciles the bound hold`, async () => {
      const d = await Device.boot();
      await d.create();
      const crash = await attempt(() => d.selfUpdate('COMMITTED', [{ kind: 'REPLACE_SELECTOR', mode: 'BEFORE', remaining: 1 }]));
      expect(crash).toMatch(/^crash BEFORE/);
      const p = d.disk.pending;
      expect(await d.authority(p.parentGeneration, p.generation)).toMatchObject({ authority: 'COMPLETE_OLD', held: true });
      expect(d.disk.hold).not.toBeNull();
      const out = await d.P.txn.reconcileIndeterminate({
        storage: d.port(), manifestRootKey: d.rootKey, hold: d.disk.hold,
        evidence: d.evidenceFor(p.envelope, d.P.txn.M2_OUTCOME[rs]), reference: d.disk.hold.reconciliationReference,
      });
      expect(out.reconciliation).toBe(rs === 'COMMITTED' ? 'RECONCILED_COMMITTED' : 'NOT_COMMITTED');
      expect(d.disk.hold).toBeNull();
      d.disk.pending = null;
      expect(await attempt(() => d.protect('next'))).toBe('OK');
    });
  }

  // R3: C-MUT §5/§6, DURING_ESCROW_OUTPUT_RESPONSE POST_INDETERMINATE: an interrupted local emission is
  // repeated with the same escrow bytes; only its success clears the hold.
  test('R3 reconcile COMMITTED with interrupted emission: the repeat returns the same escrow and clears the hold', async () => {
    const d = await Device.boot();
    await d.create();
    await d.selfUpdate('INDETERMINATE');
    const p = d.disk.pending;
    const r1 = await d.reconcile('COMMITTED', { emission: 'INTERRUPTED' });
    expect(errCode(r1.txnError)).toMatch(/^crash BEFORE .*RELEASE_ESCROW/);
    expect((await d.authority(p.parentGeneration, p.generation)).authority).toBe('COMPLETE_NEW');
    expect(d.disk.hold).not.toBeNull();
    const escrow = hex(d.disk.generations.get(p.generation).escrow.output);
    expect(await attempt(() => d.P.txn.reconcileIndeterminate({
      storage: d.port(), manifestRootKey: d.rootKey, hold: d.disk.hold,
      evidence: d.evidenceFor(p.envelope, d.P.txn.M2_OUTCOME.NOT_COMMITTED), reference: d.disk.hold.reconciliationReference,
    }))).toBe('EVIDENCE_MISMATCH');
    expect(d.disk.hold).not.toBeNull();
    const selBefore = hex(d.disk.selector);
    const r2 = await d.reconcile('COMMITTED');
    expect(r2.txnError).toBeNull();
    expect(r2.txnOutcome).toMatchObject({ reconciliation: 'RECONCILED_COMMITTED', authority: 'COMPLETE_NEW', holds: 0 });
    expect(hex(r2.txnOutcome.output)).toBe(escrow);
    expect(hex(d.disk.selector)).toBe(selBefore); // nothing re-selected
    expect(d.disk.hold).toBeNull();
    expect(await attempt(() => d.protect('next'))).toBe('OK');
  });

  // Every durable step of a SELF_UPDATE COMMITTED run, fault BEFORE and AFTER, memory retained and lost:
  // each point ends COMPLETE_NEW, clean COMPLETE_OLD, or a bound hold that reconciles; then new work runs.
  test('SELF_UPDATE crash-point sweep: every point ends reconcilable or clean', async () => {
    const probe = await Device.boot();
    await probe.create();
    const ok = await probe.selfUpdate('COMMITTED');
    expect(ok.result.kind).toBe('SUCCESS');
    const seen = { COMPLETE_NEW: 0, CLEAN_OLD: 0, HELD: 0 };
    let points = 0;
    for (let at = 1; at <= 64; at += 1) {
      let fired = false;
      for (const mode of ['BEFORE', 'AFTER']) {
        for (const memory of ['RETAINED', 'LOST']) {
          let d = await Device.boot();
          await d.create();
          const crash = await attempt(() => d.selfUpdate('COMMITTED', [{ at, mode, remaining: 1 }]));
          if (crash === 'OK') continue;
          fired = true;
          expect(crash).toMatch(/^crash /);
          points += 1;
          const p = d.disk.pending;
          if (memory === 'LOST') { d = await d.restart(); d.disk.hold = null; }
          const auth = await d.authority(p.parentGeneration, p.generation);
          if (auth.authority === 'COMPLETE_NEW') {
            seen.COMPLETE_NEW += 1;
          } else if (!auth.held) {
            seen.CLEAN_OLD += 1;
            expect(d.disk.hold).toBeNull();
          } else {
            seen.HELD += 1;
            const hold = d.disk.generations.get(p.generation).mutationHold;
            const out = await d.P.txn.reconcileIndeterminate({
              storage: d.port(), manifestRootKey: d.rootKey, hold: memory === 'LOST' ? null : d.disk.hold,
              evidence: d.evidenceFor(p.envelope, d.P.txn.M2_OUTCOME.COMMITTED), reference: hold.reconciliationReference,
            });
            expect(out.reconciliation).toBe('RECONCILED_COMMITTED');
            expect((await d.authority(p.parentGeneration, p.generation)).held).toBe(false);
          }
          d.disk.pending = null;
          d.disk.hold = null; // released, or (LOST) never in this process
          expect(await attempt(() => d.protect(`after-${at}-${mode}-${memory}`))).toBe('OK');
        }
      }
      if (!fired) break;
    }
    expect(points).toBeGreaterThanOrEqual(12 * 4);
    expect(points % 4).toBe(0);
    expect(seen.HELD).toBeGreaterThan(0);
    expect(seen.COMPLETE_NEW).toBeGreaterThan(0);
    console.log('sweep', JSON.stringify({ points, ...seen }));
  });
});

// ---------------------------------------------------------------------------------------------
// R2a: the B3-1 port clause and the frozen interfaces F1-F3 (I-TXN-FIX-R2a contract).
// ---------------------------------------------------------------------------------------------

/** The C-MUT RS_TRI_STATE mutation rows (C-API decisionRows with persistence RS_TRI_STATE). */
const TRI_STATE_ROWS = Object.freeze(['CAPI-S001', 'CAPI-S006', 'CAPI-S009', 'CAPI-S010', 'CAPI-S014', 'CAPI-S016', 'CAPI-S017']);
const eqBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const copyBytes = (u8) => Uint8Array.prototype.slice.call(u8);
/** The non-conformant seal of the NONCE_REUSE control: the nonce is a function of the plaintext. */
function sealWithReusedNonce(plaintext) {
  const out = new Uint8Array(12 + plaintext.length + 16);
  out.set(sha256('fixed-nonce', plaintext).subarray(0, 12), 0);
  out.set(plaintext, 12);
  out.set(sha256('seal', out.subarray(0, 12), plaintext).subarray(0, 16), 12 + plaintext.length);
  return out;
}

/**
 * A storage port over the disk with a switchable conformance profile. With the defaults it implements
 * the B3-1 port clause:
 * - `stage: 'ATOMIC'` (items 1, F1): every STAGE_* and WRITE_HOLD is buffered and becomes durable only
 *   in the REPLACE_SELECTOR write that names its generation; `'EAGER'` writes each STAGE_* at once
 *   (the F1 non-conformant control).
 * - `memoryHold: 'AT_BIND'` (item 5): the memory hold appears in the binding selector write;
 *   `'AT_BUFFER'` sets it at WRITE_HOLD time (the item 1/5 control).
 * - `unbind: 'ATOMIC'` (item 3): a selector write that stops binding a candidate removes that
 *   candidate in the same write; `'SPLIT'` leaves the removal to a later CLEAR_CANDIDATE (the item 3
 *   control).
 * - `seal: 'FRESH'` (F2): every selector write is a new envelope with a fresh nonce; `'SKIP_UNCHANGED'`
 *   skips a write whose plaintext equals the stored one and `'NONCE_REUSE'` seals deterministically
 *   (the two F2 controls).
 * `faults` kill the process at an exact apply call (`{ at, mode }`) or step kind (`{ kind, mode }`):
 * a kill drops every buffered byte. `view` makes the read side return a stale pre-image (a second
 * writer that planned earlier). `hook(step)` runs before each apply (a concurrent writer).
 */
function makeClausePort(disk, opts = {}) {
  const {
    faults = [], stage = 'ATOMIC', memoryHold = 'AT_BIND', unbind = 'ATOMIC', seal = 'FRESH', view = null, hook = null,
  } = opts;
  if (disk.selections === undefined) disk.selections = [];
  const port = { applied: [], reads: [], issued: [], dead: false };
  const staged = new Map();
  let tx = { generations: new Map(), holds: new Map(), memoryHold: undefined };
  let calls = 0;
  const fire = (step, mode) => {
    for (const f of faults) {
      const hit = f.at !== undefined ? f.at === calls : (f.kind === step.kind && (f.boundary === undefined || f.boundary === step.boundary));
      if (f.remaining > 0 && f.mode === mode && hit) {
        f.remaining -= 1;
        port.dead = true;
        staged.clear();
        tx = { generations: new Map(), holds: new Map(), memoryHold: undefined };
        throw new Error(`kill ${mode} ${step.boundary}/${step.kind}`);
      }
    }
  };
  const sealFor = (plaintext) => (seal === 'NONCE_REUSE' ? sealWithReusedNonce(plaintext) : sealSelector(plaintext));
  const generationOf = (g) => (stage === 'EAGER' ? disk.generations.get(g) : (tx.generations.get(g) ?? disk.generations.get(g)));
  const memoryCopy = (p) => (p.hold === null || p.holdRecordKey === undefined || p.holdRecordKey === null
    ? deepCopy(p.hold) : { ...deepCopy(p.hold), recordKey: copyBytes(p.holdRecordKey) });

  port.apply = async (step) => {
    if (port.dead) throw new Error('the process was killed');
    calls += 1;
    port.applied.push(`${step.boundary}/${step.kind}`);
    if (hook !== null) hook(step, port);
    fire(step, 'BEFORE');
    const p = step.payload;
    if (step.kind === 'STAGE_DATA') {
      if (!staged.has(p.generation)) staged.set(p.generation, new Map());
      staged.get(p.generation).set(p.recordKind, deepCopy({
        recordKey: p.recordKey, recordKind: p.recordKind, plaintext: p.plaintext, ciphertext: p.ciphertext, tag: p.tag,
      }));
    } else if (step.kind === 'STAGE_MANIFEST') {
      const s = staged.get(p.generation);
      const g = deepCopy({
        generation: p.generation, records: s === undefined ? [] : [...s.values()], manifestKey: p.manifestKey,
        manifestBytes: p.manifestBytes, manifestCipherDigest: p.manifestCipherDigest, keyedRoot: p.keyedRoot,
        sessionBindingDigest: p.sessionBindingDigest, mutationHold: { presence: 0 }, escrow: null, resultEvidence: null,
      });
      if (stage === 'EAGER') disk.generations.set(p.generation, g); else tx.generations.set(p.generation, g);
    } else if (step.kind === 'STAGE_EVIDENCE') {
      const g = generationOf(p.generation);
      if (g !== undefined) g.resultEvidence = deepCopy(p.evidence);
    } else if (step.kind === 'STAGE_ESCROW') {
      const g = generationOf(p.generation);
      if (g !== undefined) g.escrow = deepCopy(p.escrow);
    } else if (step.kind === 'WRITE_HOLD') {
      if (stage === 'EAGER') {
        const g = disk.generations.get(p.generation);
        if (g !== undefined) g.mutationHold = deepCopy(p.hold);
      } else if (tx.generations.has(p.generation)) {
        tx.generations.get(p.generation).mutationHold = deepCopy(p.hold);
      } else {
        tx.holds.set(p.generation, deepCopy(p.hold));
      }
      if (memoryHold === 'AT_BUFFER') disk.hold = memoryCopy(p); else tx.memoryHold = memoryCopy(p);
    } else if (step.kind === 'CLEAR_CANDIDATE') {
      tx.generations.delete(p.generation);
      staged.delete(p.generation);
      disk.generations.delete(p.generation);
      disk.hold = null;
    } else if (step.kind === 'REPLACE_SELECTOR') {
      port.issued.push(Object.hasOwn(p, 'expectedSelectorBytes') && p.expectedSelectorBytes !== null
        ? hex(p.expectedSelectorBytes) : (Object.hasOwn(p, 'expectedSelectorBytes') ? null : 'ABSENT'));
      checkSelectorPrecondition(p, disk.selectorEnvelope);
      // One atomic write from here to the end of this branch.
      const before = disk.selector === null ? null : decodeSelector(disk.selector);
      const after = decodeSelector(p.selectorBytes);
      for (const [g, value] of tx.generations) disk.generations.set(g, value);
      for (const [g, hold] of tx.holds) {
        const value = disk.generations.get(g);
        if (value !== undefined) value.mutationHold = hold;
      }
      const unchanged = disk.selector !== null && eqBytes(disk.selector, p.selectorBytes);
      if (!(seal === 'SKIP_UNCHANGED' && unchanged)) {
        disk.selector = copyBytes(p.selectorBytes);
        disk.selectorEnvelope = sealFor(disk.selector);
      }
      if (p.resolveHoldGeneration !== null && p.resolveHoldGeneration !== undefined) {
        const g = disk.generations.get(p.resolveHoldGeneration);
        if (g !== undefined) g.mutationHold = { presence: 0 };
      }
      if (tx.memoryHold !== undefined) disk.hold = tx.memoryHold;
      if (unbind === 'ATOMIC' && before !== null && before.candidateGeneration !== before.generation) {
        const c = before.candidateGeneration;
        if (after.generation !== c && after.candidateGeneration !== c) {
          disk.generations.delete(c);
          disk.hold = null;
        }
      }
      disk.selections.push({ generation: after.generation, root: hex(after.keyedRoot) });
      tx = { generations: new Map(), holds: new Map(), memoryHold: undefined };
    } else if (step.kind === 'RELEASE_ESCROW') {
      disk.hold = null;
    }
    fire(step, 'AFTER');
    return undefined;
  };
  port.readSelector = async () => {
    if (port.dead) throw new Error('the process was killed');
    const src = view ?? disk;
    const out = src.selector === null ? null : { plaintext: copyBytes(src.selector), envelope: copyBytes(src.selectorEnvelope) };
    port.reads.push(out === null ? null : hex(out.envelope));
    return out;
  };
  port.readGeneration = async (generation) => {
    const g = disk.generations.get(generation);
    return g === undefined ? null : deepCopy(g);
  };
  port.readMemoryHold = async () => {
    const h = view === null ? disk.hold : view.hold;
    return h === null ? null : deepCopy(h);
  };
  port.readGenerationNumbers = async () => (view !== null ? [...view.numbers]
    : [...new Set([...disk.generations.keys(), ...tx.generations.keys(), ...staged.keys()])]);
  return port;
}

function scenarioEnvelope(P, scenario, opBytes, parent) {
  const row = P.txn.mutationRow(scenario);
  return P.txn.buildMutationEnvelope({
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

/** Replace the plaintext of one data record kind and re-derive the manifest and keyed root. */
function withRecordPlaintext(P, facts, recordKind, plaintext) {
  const { root } = P;
  const records = facts.records.map((r) => {
    if (r.recordKind !== recordKind) return r;
    const ciphertext = Uint8Array.from(plaintext, (b, i) => b ^ (0x5a + i) & 0xff);
    return { ...r, plaintext, ciphertext, tag: sha256('tag', ciphertext).slice(0, 16) };
  });
  const manifestBytes = root.encodeManifest(records.map((r) => root.manifestEntry({
    recordKey: r.recordKey,
    recordKind: r.recordKind,
    ciphertextDigest: root.ciphertextDigest({ recordKey: r.recordKey, recordKind: r.recordKind, ciphertext: r.ciphertext, tag: r.tag }),
  })));
  return {
    ...facts,
    records,
    manifestBytes,
    manifestCipherDigest: sha256('manifest-cipher', manifestBytes),
    keyedRoot: root.computeKeyedRoot({ manifestRootKey: ROOT_KEY, manifestKey: facts.manifestKey, generation: facts.generation, manifestBytes }),
  };
}

/** Plan one mutation of `scenario` over the current authority of `d`, with RS outcome `rs`. */
function planMutation(d, scenario, rs, { tweak = null } = {}) {
  const { txn } = d.P;
  const cur = d.current();
  const parent = d.disk.generations.get(cur.generation);
  const row = txn.mutationRow(scenario);
  const opBytes = nonzeroBytes(d.rand, 32);
  const generation = d.disk.nextGeneration;
  d.disk.nextGeneration += 1n;
  const envelope = scenarioEnvelope(d.P, scenario, opBytes, parent);
  let facts = generationFacts(d.P, generation, { epoch: Number(generation), epochKeys: {}, accepted: [], sent: 0 }, false);
  if (tweak !== null) facts = tweak(facts, envelope);
  const parentState = cur.selectorState === SEL.RECONCILIATION_REQUIRED ? SEL.ACTIVE : cur.selectorState;
  const candidate = {
    ...facts,
    escrow: row.outputKind === 'NONE' ? null : {
      kind: row.outputKind, digest: envelope.heldOutput.digest, reference: envelope.heldOutput.reference, output: sha256('output', opBytes),
    },
    resultEvidence: d.evidenceFor(envelope, txn.M2_OUTCOME[rs]),
    selectorBytes: selectorBytes(d.P, facts, SEL.ACTIVE),
    holdSelectorBytes: selectorBytes(d.P, parent, SEL.RECONCILIATION_REQUIRED, facts),
    parentSelectorBytes: selectorBytes(d.P, parent, parentState),
    parentGeneration: cur.generation,
    parentKeyedRoot: parent.keyedRoot,
  };
  return { scenario, rs, envelope, candidate, generation, parentGeneration: cur.generation };
}

async function runPlan(d, plan, portOpts = {}) {
  const port = makeClausePort(d.disk, portOpts);
  try {
    const result = await d.P.txn.runMutation({
      storage: port, manifestRootKey: ROOT_KEY, envelope: plan.envelope, candidate: plan.candidate,
      outcome: d.P.txn.M2_OUTCOME[plan.rs],
    });
    return { result, error: null, port };
  } catch (error) {
    return { result: null, error, port };
  }
}

async function reconcilePlan(d, plan, rs, portOpts = {}) {
  const hold = d.disk.hold;
  const stored = d.disk.generations.get(plan.generation);
  const durable = stored === undefined ? null : stored.mutationHold;
  const reference = hold !== null ? hold.reconciliationReference
    : (durable !== null && durable.presence === 1 ? durable.reconciliationReference : null);
  const port = makeClausePort(d.disk, portOpts);
  if (reference === null) return { code: 'NO_REFERENCE', out: null, port };
  try {
    const out = await d.P.txn.reconcileIndeterminate({
      storage: port, manifestRootKey: ROOT_KEY, hold, evidence: d.evidenceFor(plan.envelope, d.P.txn.M2_OUTCOME[rs]), reference,
    });
    return { code: 'OK', out, port };
  } catch (e) {
    return { code: errCode(e), out: null, port };
  }
}

/**
 * Lineage oracle, independent of generation numbers: the sequence of durable selections, each as
 * (generation, keyed root). A generation number claimed under a second identity is a FORK; a return
 * to an identity that was already superseded is a LOST_UPDATE.
 */
function lineage(disk) {
  const violations = [];
  const rootOf = new Map();
  const seen = new Set();
  let last = null;
  let highest = null;
  for (const s of disk.selections ?? []) {
    const key = `${s.generation}:${s.root}`;
    if (rootOf.has(s.generation) && rootOf.get(s.generation) !== s.root) violations.push(`FORK ${s.generation}`);
    else if (key !== last && seen.has(key)) violations.push(`LOST_UPDATE ${key}`);
    // The durable authority only moves forward: a selection below the highest generation ever
    // selected is a rollback, whatever its root.
    if (highest !== null && s.generation < highest) violations.push(`ROLLBACK ${s.generation} below ${highest}`);
    if (highest === null || s.generation > highest) highest = s.generation;
    if (!rootOf.has(s.generation)) rootOf.set(s.generation, s.root);
    seen.add(key);
    last = key;
  }
  for (const [g, value] of disk.generations) {
    if (rootOf.has(g) && rootOf.get(g) !== hex(value.keyedRoot)) violations.push(`FORK stored ${g}`);
  }
  return { violations, last, rootOf };
}

function selectInitial(d) {
  const facts = decodeSelector(d.disk.selector);
  d.disk.selections = [{ generation: facts.generation, root: hex(facts.keyedRoot) }];
}

/** A prepared device on the B3-1 port: presession, then one committed mutation into ACTIVE for rows that need it. */
async function preparedDevice(scenario) {
  const d = await Device.boot();
  selectInitial(d);
  if (d.P.txn.mutationRow(scenario).stateBefore === 'ACTIVE') {
    const r = await runPlan(d, planMutation(d, 'CAPI-S001', 'COMMITTED'));
    if (r.error !== null) throw r.error;
  }
  return d;
}
const forkDevice = (d) => {
  const next = new Device(d.P, cloneDisk(d.disk), 7);
  next.rand = prng(Number(d.disk.nextGeneration) * 131);
  return next;
};

/**
 * After a kill: optionally lose the SS memory (process restart), classify, close any pending hold (both
 * terminal reconciliations are checked on a copy, then one is applied), and run the next mutation.
 * Returns every violated invariant: readback failure, debris, wedge, fork, lost update, refused next.
 */
async function settle(dIn, plan, memory, preferred) {
  let d = dIn;
  const v = [];
  if (memory === 'LOST') { d = await d.restart(); d.disk.hold = null; }
  let auth;
  try {
    auth = await d.authority(plan.parentGeneration, plan.generation);
  } catch (e) {
    return { violations: [`READBACK ${errCode(e)}`], outcome: 'MIXTURE' };
  }
  const lin0 = lineage(d.disk);
  const named = decodeSelector(d.disk.selector);
  const junk = [...d.disk.generations.keys()].filter((g) => g !== named.generation && g !== named.candidateGeneration && !lin0.rootOf.has(g));
  if (junk.length > 0) v.push(`DEBRIS ${junk.join(',')}`);
  const pending = auth.held || d.disk.hold !== null;
  const outcome = auth.authority === 'COMPLETE_NEW' ? (pending ? 'NEW_HELD' : 'NEW') : (pending ? 'HELD' : 'CLEAN_OLD');
  if (pending) {
    const options = auth.authority === 'COMPLETE_NEW' ? ['COMMITTED'] : ['COMMITTED', 'NOT_COMMITTED'];
    for (const rs of options) {
      const copy = forkDevice(d);
      const r = await reconcilePlan(copy, plan, rs);
      const after = r.code === 'OK' ? await copy.authority(plan.parentGeneration, plan.generation) : null;
      if (r.code !== 'OK' || after.held || copy.disk.hold !== null) v.push(`WEDGE ${rs} ${r.code}`);
    }
    const rs = options.includes(preferred) ? preferred : options[0];
    const r = await reconcilePlan(d, plan, rs);
    if (r.code !== 'OK') return { violations: v, outcome };
  }
  const cur = d.current();
  const lin = lineage(d.disk);
  v.push(...lin.violations);
  const parentKey = `${cur.generation}:${hex(d.disk.generations.get(cur.generation).keyedRoot)}`;
  if (parentKey !== lin.last) v.push(`PARENT ${parentKey} is not the last selection ${lin.last}`);
  const next = planMutation(d, cur.selectorState === SEL.EMPTY ? 'CAPI-S001' : 'CAPI-S009', 'COMMITTED');
  const run = await runPlan(d, next);
  if (run.error !== null) v.push(`NEXT ${errCode(run.error)}`);
  else {
    const end = lineage(d.disk);
    v.push(...end.violations.filter((x) => !lin.violations.includes(x)));
    if (end.last !== `${next.generation}:${hex(next.candidate.keyedRoot)}`) v.push('NEXT not selected');
  }
  return { violations: v, outcome };
}

/**
 * The B3-1 kill sweep: for each row and outcome, kill before and after every apply call of the
 * ORIGINAL plan and of the RECONCILIATION plan that follows an INDETERMINATE original, memory
 * RETAINED and LOST. `portOpts` is the conformance profile of the port under test.
 */
async function killSweep({ rows = TRI_STATE_ROWS, outcomes = ['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE'], phases = ['ORIGINAL', 'RECONCILIATION'], portOpts = {} } = {}) {
  const report = { points: 0, violations: [], outcomes: {} };
  const note = (label, r) => {
    report.points += 1;
    report.outcomes[r.outcome] = (report.outcomes[r.outcome] ?? 0) + 1;
    for (const x of r.violations) report.violations.push(`${label}: ${x}`);
  };
  for (const scenario of rows) {
    const base = await preparedDevice(scenario);
    for (const phase of phases) {
      for (const rs of outcomes) {
        if (phase === 'RECONCILIATION' && rs === 'INDETERMINATE') {
          // A continued INDETERMINATE reconciliation applies nothing: the hold stays and still closes.
          for (const memory of ['RETAINED', 'LOST']) {
            const d = forkDevice(base);
            const plan = planMutation(d, scenario, 'INDETERMINATE');
            const first = await runPlan(d, plan, portOpts);
            if (first.error !== null) { report.violations.push(`${scenario} prepare ${errCode(first.error)}`); continue; }
            const r = await reconcilePlan(d, plan, 'INDETERMINATE', portOpts);
            note(`${scenario} RECONCILIATION INDETERMINATE ${memory}`, r.code === 'OK' && r.port.applied.length === 0
              ? await settle(d, plan, memory, 'COMMITTED') : { outcome: 'ERROR', violations: [`continued ${r.code}`] });
          }
          continue;
        }
        for (let at = 1; at <= 64; at += 1) {
          let fired = false;
          for (const mode of ['BEFORE', 'AFTER']) {
            for (const memory of ['RETAINED', 'LOST']) {
              const d = forkDevice(base);
              const plan = planMutation(d, scenario, phase === 'ORIGINAL' ? rs : 'INDETERMINATE');
              const fault = [{ at, mode, remaining: 1 }];
              let killed;
              if (phase === 'ORIGINAL') {
                killed = (await runPlan(d, plan, { ...portOpts, faults: fault })).error;
              } else {
                const first = await runPlan(d, plan, portOpts);
                if (first.error !== null) { report.violations.push(`${scenario} prepare ${errCode(first.error)}`); continue; }
                const r = await reconcilePlan(d, plan, rs, { ...portOpts, faults: fault });
                killed = r.code === 'OK' ? null : { message: r.code };
              }
              if (killed === null) continue;
              fired = true;
              const label = `${scenario} ${phase} ${rs} ${mode}#${at} ${memory}`;
              if (!/^kill /.test(errCode(killed) ?? '')) {
                report.violations.push(`${label}: not a kill: ${errCode(killed)}`);
                continue;
              }
              note(label, await settle(d, plan, memory, rs));
            }
          }
          if (!fired) break;
        }
      }
    }
  }
  return report;
}

describe('R2a B3-1 kill sweep through the I-TXN public surface', () => {
  test('the sweep rows are exactly the C-MUT RS_TRI_STATE mutation plans', async () => {
    const P = await loadProcess();
    expect([...TRI_STATE_ROWS]).toEqual(Object.keys(P.sm.MUTATION_PLANS).sort());
    for (const s of TRI_STATE_ROWS) expect(P.txn.mutationRow(s).scenario).toBe(s);
  });

  test('on a conformant B3-1 port every kill point ends NEW, clean OLD or a bound hold that both terminal reconciliations close', async () => {
    const report = await killSweep();
    console.log('b3-1 sweep', JSON.stringify({ points: report.points, outcomes: report.outcomes, violations: report.violations.length }));
    expect(report.violations).toEqual([]);
    expect(report.points).toBeGreaterThan(TRI_STATE_ROWS.length * 5 * 4 * 10);
    expect(report.outcomes.HELD).toBeGreaterThan(0);
    expect(report.outcomes.NEW).toBeGreaterThan(0);
    expect(report.outcomes.CLEAN_OLD).toBeGreaterThan(0);
    expect(report.outcomes.NEW_HELD).toBeGreaterThan(0); // interrupted emission after a committed reconciliation
  }, 600_000);

  test('control: a port that sets the memory hold at buffer time (items 1/5) fails the sweep', async () => {
    const report = await killSweep({ rows: ['CAPI-S014'], outcomes: ['INDETERMINATE'], phases: ['ORIGINAL'], portOpts: { memoryHold: 'AT_BUFFER' } });
    expect(report.violations.some((x) => / WEDGE /.test(x))).toBe(true);
  }, 120_000);

  test('control: a port that unbinds and removes the candidate in two writes (item 3) fails the sweep', async () => {
    const report = await killSweep({ rows: ['CAPI-S014'], outcomes: ['NOT_COMMITTED'], phases: ['RECONCILIATION'], portOpts: { unbind: 'SPLIT' } });
    expect(report.violations.some((x) => / DEBRIS /.test(x))).toBe(true);
  }, 120_000);

  test('control F1: a port that commits STAGE_* before its selector fails the sweep', async () => {
    const report = await killSweep({ rows: ['CAPI-S014'], outcomes: ['COMMITTED', 'NOT_COMMITTED'], phases: ['ORIGINAL'], portOpts: { stage: 'EAGER' } });
    expect(report.violations.some((x) => / DEBRIS /.test(x))).toBe(true);
  }, 120_000);

  test('lineage control: re-creating the authority generation number under another identity fails the oracle', async () => {
    const d = await preparedDevice('CAPI-S009');
    expect(lineage(d.disk).violations).toEqual([]);
    const cur = d.current();
    // I-TXN itself refuses to form such a candidate.
    const plan = planMutation(d, 'CAPI-S009', 'COMMITTED');
    const same = generationFacts(d.P, cur.generation, { epoch: 99, epochKeys: {}, accepted: [], sent: 0 }, false);
    const refused = await runPlan(d, { ...plan, candidate: { ...plan.candidate, ...same, selectorBytes: selectorBytes(d.P, same, SEL.ACTIVE) } });
    expect(errCode(refused.error)).toBe('CONTEXT_MISMATCH');
    // A raw writer that does it anyway is caught by the oracle.
    const port = makeClausePort(d.disk);
    const steps = d.P.txn.mutationSteps({
      envelope: plan.envelope,
      candidate: {
        generation: cur.generation, parentGeneration: cur.generation, records: same.records, manifestKey: same.manifestKey,
        manifestBytes: same.manifestBytes, manifestCipherDigest: same.manifestCipherDigest, keyedRoot: same.keyedRoot,
        sessionBindingDigest: same.sessionBindingDigest, selectorBytes: selectorBytes(d.P, same, SEL.ACTIVE),
        holdSelectorBytes: null, parentSelectorBytes: null, resultEvidence: plan.candidate.resultEvidence,
        escrow: plan.candidate.escrow, mutationHold: null, expectedSelectorBytes: copyBytes(d.disk.selectorEnvelope),
      },
      outcome: d.P.txn.M2_OUTCOME.COMMITTED,
      phase: 'ORIGINAL',
    });
    for (const step of steps) {
      if (['STAGE_DATA', 'STAGE_MANIFEST', 'REPLACE_SELECTOR'].includes(step.kind)) await port.apply(step);
    }
    expect(lineage(d.disk).violations).toEqual([`FORK ${cur.generation}`, `FORK stored ${cur.generation}`]);
  });

  test('lineage control: a descending selection with fresh roots fails the oracle', () => {
    const disk = {
      generations: new Map(),
      selections: [{ generation: 1, root: 'a' }, { generation: 3, root: 'c' }, { generation: 2, root: 'b' }],
    };
    expect(lineage(disk).violations).toEqual(['ROLLBACK 2 below 3']);
  });
});

describe('R2a F2 compare-and-set on every authority write', () => {
  test('every REPLACE_SELECTOR carries expectedSelectorBytes equal to the envelope readSelector returned', async () => {
    const issued = [];
    for (const [rs, close] of [['COMMITTED', null], ['INDETERMINATE', 'COMMITTED'], ['INDETERMINATE', 'NOT_COMMITTED']]) {
      const d = await preparedDevice('CAPI-S014');
      const plan = planMutation(d, 'CAPI-S014', rs);
      const before = hex(d.disk.selectorEnvelope);
      const run = await runPlan(d, plan);
      expect(run.error).toBeNull();
      expect(run.port.issued).toEqual([before]);
      expect(run.port.reads).toContain(before);
      issued.push(...run.port.issued);
      if (close !== null) {
        const mid = hex(d.disk.selectorEnvelope);
        const r = await reconcilePlan(d, plan, close);
        expect(r.code).toBe('OK');
        expect(r.port.issued).toEqual([mid]);
        expect(r.port.reads).toContain(mid);
        issued.push(...r.port.issued);
      }
    }
    expect(issued).toHaveLength(5);
    expect(issued).not.toContain('ABSENT');
    expect(issued).not.toContain(null);
  });

  for (const rs of ['COMMITTED', 'INDETERMINATE']) {
    test(`a stored envelope that changed after planning (${rs}) is SELECTOR_PRECONDITION_FAILED with no further write, no hold and no result`, async () => {
      const d = await preparedDevice('CAPI-S014');
      const plan = planMutation(d, 'CAPI-S014', rs);
      const authorityBefore = hex(d.disk.selector);
      // A concurrent writer re-seals the same selector just before this request's authority write.
      const hook = (step) => {
        if (step.kind === 'REPLACE_SELECTOR') d.disk.selectorEnvelope = sealSelector(d.disk.selector);
      };
      const run = await runPlan(d, plan, { hook });
      expect(errCode(run.error)).toBe('SELECTOR_PRECONDITION_FAILED');
      expect(run.error.code).toBe(d.P.txn.M2_TXN.SELECTOR_PRECONDITION_FAILED);
      expect(run.result).toBeNull();
      expect(run.port.applied[run.port.applied.length - 1]).toMatch(/\/REPLACE_SELECTOR$/);
      expect(run.port.applied.filter((s) => /REPLACE_SELECTOR|WRITE_HOLD|CLEAR_CANDIDATE/.test(s)).length)
        .toBe(rs === 'INDETERMINATE' ? 2 : 1);
      expect(d.disk.hold).toBeNull();
      expect(hex(d.disk.selector)).toBe(authorityBefore);
      expect(d.disk.generations.has(plan.generation)).toBe(false);
      expect(await d.authority(plan.parentGeneration, plan.generation)).toMatchObject({ authority: 'COMPLETE_OLD', held: false });
    });
  }

  test('a compare-and-set refused on the recovery bind is propagated unchanged in place of the original fault', async () => {
    const d = await preparedDevice('CAPI-S014');
    const plan = planMutation(d, 'CAPI-S014', 'INDETERMINATE');
    let selectorWrites = 0;
    // The ORIGINAL binding write fails with an ordinary I/O error; before the recovery bind, a
    // concurrent writer re-seals the stored selector, so the recovery compare-and-set is refused.
    const hook = (step) => {
      if (step.kind !== 'REPLACE_SELECTOR') return;
      selectorWrites += 1;
      if (selectorWrites === 1) {
        // The candidate is staged; the hold and the selector write did not land.
        d.disk.generations.get(plan.generation).mutationHold = { presence: 0 };
        d.disk.hold = null;
        throw new Error('io: the original binding write failed');
      }
      d.disk.selectorEnvelope = sealSelector(d.disk.selector);
    };
    const run = await runPlan(d, plan, { stage: 'EAGER', hook });
    expect(selectorWrites).toBe(2);
    expect(run.port.applied.filter((s) => /\/REPLACE_SELECTOR$/.test(s))).toHaveLength(2);
    expect(errCode(run.error)).toBe('SELECTOR_PRECONDITION_FAILED');
    expect(run.error.code).toBe(d.P.txn.M2_TXN.SELECTOR_PRECONDITION_FAILED);
    expect(run.result).toBeNull();
  });

  test('a reconciliation whose stored envelope changed after planning is SELECTOR_PRECONDITION_FAILED and leaves the hold', async () => {
    const d = await preparedDevice('CAPI-S014');
    const plan = planMutation(d, 'CAPI-S014', 'INDETERMINATE');
    expect((await runPlan(d, plan)).error).toBeNull();
    const hook = (step) => {
      if (step.kind === 'REPLACE_SELECTOR') d.disk.selectorEnvelope = sealSelector(d.disk.selector);
    };
    const r = await reconcilePlan(d, plan, 'COMMITTED', { hook });
    expect(r.code).toBe('SELECTOR_PRECONDITION_FAILED');
    expect(r.port.applied[r.port.applied.length - 1]).toMatch(/\/REPLACE_SELECTOR$/);
    expect(d.disk.hold).not.toBeNull();
    expect(await d.authority(plan.parentGeneration, plan.generation)).toMatchObject({ authority: 'COMPLETE_OLD', held: true });
    expect((await reconcilePlan(d, plan, 'COMMITTED')).code).toBe('OK');
  });

  /**
   * The retained-unbound state: the binding selector write never landed (a non-conformant port that
   * wrote the hold and the candidate eagerly), so the stored selector still names the parent with the
   * same tuple. A NOT_COMMITTED reconciliation then re-seals the unchanged tuple. A second writer that
   * planned before the reconciliation holds the pre-reconciliation envelope.
   */
  async function retainedUnbound(reconcileSeal) {
    const d = await preparedDevice('CAPI-S014');
    const plan = planMutation(d, 'CAPI-S014', 'INDETERMINATE');
    const unbound = await runPlan(d, plan, {
      stage: 'EAGER', memoryHold: 'AT_BUFFER', unbind: 'SPLIT', faults: [{ kind: 'REPLACE_SELECTOR', mode: 'BEFORE', remaining: 1 }],
    });
    expect(errCode(unbound.error)).toMatch(/^kill BEFORE/);
    expect(d.disk.hold).not.toBeNull();
    expect(decodeSelector(d.disk.selector).candidateGeneration).toBe(plan.parentGeneration);
    // A nonce-reusing port sealed the stored selector the same way when it last wrote it.
    if (reconcileSeal === 'NONCE_REUSE') d.disk.selectorEnvelope = sealWithReusedNonce(d.disk.selector);
    const stale = { selector: copyBytes(d.disk.selector), selectorEnvelope: copyBytes(d.disk.selectorEnvelope), hold: null, numbers: [] };
    const writer = planMutation(d, 'CAPI-S014', 'COMMITTED');
    const r = await reconcilePlan(d, plan, 'NOT_COMMITTED', { seal: reconcileSeal });
    expect(r.code).toBe('OK');
    expect(r.port.applied.filter((s) => /\/REPLACE_SELECTOR$/.test(s))).toHaveLength(1);
    return { d, stale, writer };
  }

  test('a NOT_COMMITTED reconciliation re-seals the unchanged tuple, and a stale writer is then rejected', async () => {
    const { d, stale, writer } = await retainedUnbound('FRESH');
    expect(hex(d.disk.selector)).toBe(hex(stale.selector)); // the same tuple
    expect(hex(d.disk.selectorEnvelope)).not.toBe(hex(stale.selectorEnvelope)); // a new envelope
    const late = await runPlan(d, writer, { view: stale });
    expect(errCode(late.error)).toBe('SELECTOR_PRECONDITION_FAILED');
    expect(late.result).toBeNull();
    expect(d.disk.generations.has(writer.generation)).toBe(false);
  });

  for (const seal of ['SKIP_UNCHANGED', 'NONCE_REUSE']) {
    test(`control: a port that ${seal === 'SKIP_UNCHANGED' ? 'skips an unchanged plaintext' : 'reuses a nonce'} lets the stale writer through`, async () => {
      const { d, stale, writer } = await retainedUnbound(seal);
      expect(hex(d.disk.selectorEnvelope)).toBe(hex(stale.selectorEnvelope));
      const late = await runPlan(d, writer, { view: stale, seal });
      expect(late.error).toBeNull();
      expect(late.result.commitOutcome).toBe('COMMITTED');
    });
  }
});

describe('R2a F3 no sidecar is authoritative', () => {
  async function heldWithRecord(memory = 'LOST') {
    const d = await preparedDevice('CAPI-S014');
    // The hold I-TXN writes for this envelope, captured from a dry run on a copy of the disk.
    const probe = forkDevice(d);
    probe.rand = prng(4242);
    const dry = planMutation(probe, 'CAPI-S014', 'INDETERMINATE');
    let written = null;
    await runPlan(probe, dry, { hook: (step) => { if (step.kind === 'WRITE_HOLD') written = step.payload.hold; } });
    expect(written).not.toBeNull();
    // The candidate's kind-13 record carries that canonical hold plaintext, as a C-FMT writer stores it.
    d.rand = prng(4242);
    const plan = planMutation(d, 'CAPI-S014', 'INDETERMINATE', {
      tweak: (facts) => withRecordPlaintext(d.P, facts, d.P.codec.M2_KIND.MUTATION_HOLD,
        d.P.codec.encodePlaintext(d.P.codec.M2_KIND.MUTATION_HOLD, { ...written })),
    });
    expect(hex(plan.envelope.operationIdentity.value)).toBe(hex(dry.envelope.operationIdentity.value));
    const run = await runPlan(d, plan);
    expect(run.error).toBeNull();
    // LOST: SS memory lost, only the durable record can say what is held. RETAINED: the memory hold
    // the binding write left stays, and reconciliation still reads the bound candidate through F3.
    if (memory === 'LOST') d.disk.hold = null;
    else expect(d.disk.hold).not.toBeNull();
    return { d, plan };
  }

  for (const memory of ['LOST', 'RETAINED']) {
    for (const rs of ['COMMITTED', 'NOT_COMMITTED']) {
      test(`a sidecar that matches the authenticated kind-13 record is accepted (memory ${memory}, ${rs})`, async () => {
        const { d, plan } = await heldWithRecord(memory);
        expect(await d.authority(plan.parentGeneration, plan.generation)).toMatchObject({ authority: 'COMPLETE_OLD', held: true });
        expect((await reconcilePlan(d, plan, rs)).code).toBe('OK');
      });
    }
  }

  for (const [label, mutate] of [
    ['an absent sidecar', (g) => { g.mutationHold = { presence: 0 }; }],
    ['a sidecar with another reconciliation reference', (g) => { g.mutationHold.reconciliationReference = new Uint8Array(32).fill(7); }],
    ['a sidecar with another parent root', (g) => { g.mutationHold.parentKeyedRoot = new Uint8Array(32).fill(9); }],
  ]) {
    for (const memory of ['LOST', 'RETAINED']) {
      for (const rs of ['COMMITTED', 'NOT_COMMITTED']) {
        test(`${label} beside the authenticated record is refused before any decision (memory ${memory}, ${rs})`, async () => {
          const { d, plan } = await heldWithRecord(memory);
          mutate(d.disk.generations.get(plan.generation));
          const selector = hex(d.disk.selectorEnvelope);
          expect(await attempt(() => d.authority(plan.parentGeneration, plan.generation))).toBe('PARTIAL_APPLICATION');
          const r = await reconcilePlan(d, plan, rs);
          expect(['PARTIAL_APPLICATION', 'NO_REFERENCE']).toContain(r.code);
          if (memory === 'RETAINED') expect(r.code).toBe('PARTIAL_APPLICATION');
          expect(r.port.applied).toEqual([]);
          expect(hex(d.disk.selectorEnvelope)).toBe(selector);
          expect(d.disk.generations.has(plan.generation)).toBe(true);
        });
      }
    }
  }
});
