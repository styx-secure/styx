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
    selector: null, // the stored kind-14 selector bytes
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
      disk.hold = deepCopy(p.hold);
    } else if (step.kind === 'CLEAR_CANDIDATE') {
      disk.generations.delete(p.generation);
      staged.delete(p.generation);
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
    if (take(step, 'AFTER')) throw new Error(`crash AFTER ${step.boundary}/${step.kind}`);
    return undefined;
  };
  port.readSelector = async () => (disk.selector === null ? null : Uint8Array.prototype.slice.call(disk.selector));
  port.readGeneration = async (generation) => {
    const g = disk.generations.get(generation);
    return g === undefined ? null : deepCopy(g);
  };
  port.readMemoryHold = async () => (disk.hold === null ? null : deepCopy(disk.hold));
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
