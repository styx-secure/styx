// compose-update-message.test.js — T-COMPOSE: combined I-UPD + I-MSG conformance over the real M2
// storage stack, with interruption and restart (scenarios (a)-(e), harness ported to C-FMT v2 port).
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

/**
 * The port follows the B3-1 clause of I-TXN-FIX R2a (the conformant profile of the recovery suite's
 * `makeClausePort`): STAGE_* and WRITE_HOLD only buffer; the REPLACE_SELECTOR that binds or selects a
 * candidate makes the buffered generation, its kind-13 hold and the memory hold durable in that one
 * write; a selector write that stops binding a candidate removes it and the memory hold in the same
 * write; every selector write is a fresh envelope. A crash fault kills the process: every buffered
 * byte is dropped and the port refuses further calls.
 */
function makePort(disk, faults = []) {
  const port = { applied: [], dead: false };
  const staged = new Map();
  let tx = { generations: new Map(), holds: new Map(), memoryHold: undefined };
  let calls = 0;
  const take = (step, mode) => {
    for (const f of faults) {
      const hit = f.at !== undefined ? f.at === calls // positional: the `at`-th apply call (1-based)
        : f.kind === step.kind && (f.boundary === undefined || f.boundary === step.boundary);
      if (f.remaining > 0 && f.mode === mode && hit) {
        f.remaining -= 1;
        // `fatal: false` is a failed write the process survives (an I/O error): nothing is dropped.
        if (f.fatal === false) return 'io-error';
        port.dead = true;
        staged.clear();
        tx = { generations: new Map(), holds: new Map(), memoryHold: undefined };
        return 'crash';
      }
    }
    return null;
  };
  const generationOf = (g) => tx.generations.get(g) ?? disk.generations.get(g);
  const memoryCopy = (p) => (p.hold === null || p.holdRecordKey === undefined || p.holdRecordKey === null
    ? deepCopy(p.hold) : { ...deepCopy(p.hold), recordKey: Uint8Array.prototype.slice.call(p.holdRecordKey) });
  port.apply = async (step) => {
    if (port.dead) throw new Error('the process was killed');
    calls += 1;
    port.applied.push(`${step.boundary}/${step.kind}`);
    const before = take(step, 'BEFORE');
    if (before !== null) throw new Error(`${before} BEFORE ${step.boundary}/${step.kind}`);
    const p = step.payload;
    if (step.kind === 'STAGE_DATA') {
      if (!staged.has(p.generation)) staged.set(p.generation, new Map());
      staged.get(p.generation).set(p.recordKind, deepCopy({
        recordKey: p.recordKey, recordKind: p.recordKind, plaintext: p.plaintext, ciphertext: p.ciphertext, tag: p.tag,
      }));
    } else if (step.kind === 'STAGE_MANIFEST') {
      const s = staged.get(p.generation);
      tx.generations.set(p.generation, deepCopy({
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
      const g = generationOf(p.generation);
      if (g !== undefined) g.resultEvidence = deepCopy(p.evidence);
    } else if (step.kind === 'STAGE_ESCROW') {
      const g = generationOf(p.generation);
      if (g !== undefined) g.escrow = deepCopy(p.escrow);
    } else if (step.kind === 'WRITE_HOLD') {
      // The complete kind-13 MUTATION_HOLD record goes with the candidate; the memory hold appears
      // only with the binding selector write.
      if (tx.generations.has(p.generation)) tx.generations.get(p.generation).mutationHold = deepCopy(p.hold);
      else tx.holds.set(p.generation, deepCopy(p.hold));
      tx.memoryHold = memoryCopy(p);
    } else if (step.kind === 'CLEAR_CANDIDATE') {
      tx.generations.delete(p.generation);
      staged.delete(p.generation);
      disk.generations.delete(p.generation);
      disk.hold = null;
    } else if (step.kind === 'REPLACE_SELECTOR') {
      checkSelectorPrecondition(p, disk.selectorEnvelope);
      // One atomic write from here to the end of this branch.
      const before = disk.selector === null ? null : decodeSelector(disk.selector);
      const after = decodeSelector(p.selectorBytes);
      for (const [g, value] of tx.generations) disk.generations.set(g, value);
      for (const [g, hold] of tx.holds) {
        const value = disk.generations.get(g);
        if (value !== undefined) value.mutationHold = hold;
      }
      disk.selector = Uint8Array.prototype.slice.call(p.selectorBytes);
      disk.selectorEnvelope = sealSelector(disk.selector);
      if (p.resolveHoldGeneration !== null && p.resolveHoldGeneration !== undefined) {
        const g = disk.generations.get(p.resolveHoldGeneration);
        if (g !== undefined) g.mutationHold = { presence: 0 };
      }
      if (tx.memoryHold !== undefined) disk.hold = tx.memoryHold;
      if (before !== null && before.candidateGeneration !== before.generation) {
        const c = before.candidateGeneration;
        if (after.generation !== c && after.candidateGeneration !== c) {
          disk.generations.delete(c);
          disk.hold = null;
        }
      }
      tx = { generations: new Map(), holds: new Map(), memoryHold: undefined };
    } else if (step.kind === 'RELEASE_ESCROW') {
      disk.hold = null;
    }
    const after = take(step, 'AFTER');
    if (after !== null) throw new Error(`${after} AFTER ${step.boundary}/${step.kind}`);
    return undefined;
  };
  port.readSelector = async () => {
    if (port.dead) throw new Error('the process was killed');
    return disk.selector === null ? null : {
      plaintext: Uint8Array.prototype.slice.call(disk.selector),
      envelope: Uint8Array.prototype.slice.call(disk.selectorEnvelope),
    };
  };
  port.readGeneration = async (generation) => {
    const g = disk.generations.get(generation);
    return g === undefined ? null : deepCopy(g);
  };
  port.readMemoryHold = async () => (disk.hold === null ? null : deepCopy(disk.hold));
  // Number-only inventory: every generation number with any stored artifact, complete or staged.
  port.readGenerationNumbers = async () => [...new Set([...disk.generations.keys(), ...tx.generations.keys(), ...staged.keys()])];
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

/** Replace one record's plaintext and recompute the manifest and keyed root over the new records. */
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
    const outcome = txn.M2_OUTCOME[rs];
    const parentState = cur.selectorState === SEL.RECONCILIATION_REQUIRED ? SEL.ACTIVE : cur.selectorState;
    const escrow = row.outputKind === 'NONE' ? null : {
      kind: row.outputKind, digest: envelope.heldOutput.digest, reference: envelope.heldOutput.reference, output,
    };
    const candidateFor = (f, o) => ({
      ...f,
      escrow,
      resultEvidence: this.evidenceFor(envelope, o),
      selectorBytes: selectorBytes(this.P, f, SEL.ACTIVE),
      holdSelectorBytes: selectorBytes(this.P, parent, SEL.RECONCILIATION_REQUIRED, f),
      parentSelectorBytes: selectorBytes(this.P, parent, parentState),
      parentGeneration: cur.generation,
      parentKeyedRoot: parent.keyedRoot,
    });
    let facts = generationFacts(this.P, generation, nextState, false);
    // The kind-13 record carries filler plaintext, as in every integrated M2 suite. With the canonical
    // MUTATION_HOLD plaintext of this envelope (C-FMT /recordKinds[13]) a reconciled COMMITTED
    // candidate becomes the authority while its immutable kind-13 record still says "hold present" and
    // the resolved sidecar says "absent"; the integrated classifyAuthority then refuses it as
    // PARTIAL_APPLICATION (reproduced with the unchanged recovery suite's own F3 fixture). That is an
    // I-TXN/C-FMT gap outside this test-only card, filed separately; it is not papered over here.
    this.disk.pending = {
      operation, operationIdentity, opBytes, generation, parentGeneration: cur.generation,
      requestInput: deepCopy(input), envelope: deepCopy(envelope), outputKind: row.outputKind,
    };
    // A held selector (state 3) cannot be re-encoded as a parent tuple; the parent's own logical state
    // is ACTIVE there. I-TXN refuses the request from the stored selector before reading this field.
    const candidate = candidateFor(facts, outcome);
    const port = makePort(this.disk, faults);
    let txnResult;
    try {
      txnResult = await txn.runMutation({ storage: port, manifestRootKey: ROOT_KEY, envelope, candidate, outcome });
    } catch (e) {
      // A process death propagates: nothing in this process decides anything any more.
      if (port.dead || !/^io-error /.test(e.message)) throw e;
      // A failed write the process survives (C-MUT DURING_RS_WORK): the RS outcome is not reported. Only
      // the integrated readback says what is pending: the hold I-TXN bound for this very request makes
      // the outcome INDETERMINATE for the AP; anything else propagates.
      const a = await this.authority(cur.generation, generation);
      if (!(a.authority === 'COMPLETE_OLD' && a.held === true && this.disk.hold !== null
        && hex(this.disk.hold.reconciliationReference) === hex(envelope.reconciliationIdentity.reference))) throw e;
      txnResult = { commitOutcome: 'INDETERMINATE', output: null, ioError: e };
    }
    if (txnResult.commitOutcome !== 'INDETERMINATE') this.disk.pending = null;
    return { txnResult, operationIdentity, port };
  }

  /**
   * SS-internal recovery after a restart with a request whose response never left the process
   * (C-MUT §5 original terminal path). The integrated readback decides; the AP sees nothing, and no
   * reconciliation row exists without a reference the AP already received. A held authority stays
   * pending for RECONCILE_INDETERMINATE.
   */
  async recoverAfterRestart() {
    const p = this.disk.pending;
    if (p === null) return null;
    const a = await this.authority(p.parentGeneration, p.generation);
    const gen = this.disk.generations.get(p.generation);
    if (!a.held) this.disk.pending = null;
    return { authority: a, resultEvidence: gen === undefined ? null : gen.resultEvidence, escrow: gen === undefined ? null : gen.escrow };
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
   * RECONCILE_INDETERMINATE. The SS asks I-TXN to reconcile its pending request from the RS readback
   * `rs` (with the memory hold when the process still has it, or from the durable kind-13 record when
   * it does not), and lets the adapter decide only from what I-TXN established:
   * - a terminal I-TXN result: its reconciliation outcome and its validated escrow output;
   * - an emission interrupted after the authority selection (`emission: 'INTERRUPTED'` crashes the
   *   process before RELEASE_ESCROW): only once the integrated readback proves COMPLETE_NEW with the
   *   hold still bound to this request does the SS report the interrupted emission (C-MUT §5).
   * Any other I-TXN failure is a process death or a typed refusal: nothing is decided, the pending
   * bookkeeping stays, and the error propagates. Pending clears only on the integrated clearing event.
   */
  async reconcile(rs, { emission = 'SUCCEEDED', faults = [], reference = null } = {}) {
    const { txn } = this.P;
    const snap = this.snapshot();
    const ref = reference ?? (snap.held === null ? 'I-SM-HOLD:none' : snap.held.reconciliationRef);
    const req = this.request('RECONCILE_INDETERMINATE', { reconciliationRef: ref });
    const p = this.disk.pending;
    if (p === null) {
      // Nothing is in flight for the SS: the adapter refuses from its own snapshot (CAPI-E012).
      const decision = this.decide(req, {
        slotContext: SLOT.slice(), commitOutcome: rs, responseEmission: rs === 'COMMITTED' ? 'SUCCEEDED' : null, heldOutput: null,
      });
      return { ...decision, txnOutcome: null, txnError: null };
    }
    const member = OUTPUT_MEMBER[p.outputKind];
    // C-API RECONCILE_INDETERMINATE hands the held escrow over for every readback: the SS reads it from
    // the stored candidate through the port before I-TXN runs (I-TXN releases it on a terminal outcome).
    const stored = await makePort(this.disk).readGeneration(p.generation);
    const escrowOut = stored === null || stored.escrow === null ? null : stored.escrow.output;
    const heldOutput = escrowOut === null || member === null ? null : { [member]: escrowOut };
    const interrupted = emission === 'INTERRUPTED';
    // An interrupted adapter-local emission: the SS does not reach RELEASE_ESCROW (a refused write the
    // process survives), the escrow and the memory hold stay.
    const port = makePort(this.disk, interrupted
      ? [{ kind: 'RELEASE_ESCROW', mode: 'BEFORE', remaining: 1, fatal: false }, ...faults] : faults);
    let txnOutcome = null;
    let txnError = null;
    const heldBefore = this.disk.hold === null ? null : deepCopy(this.disk.hold);
    try {
      txnOutcome = await txn.reconcileIndeterminate({
        storage: port,
        manifestRootKey: ROOT_KEY,
        hold: heldBefore,
        evidence: this.evidenceFor(p.envelope, txn.M2_OUTCOME[rs]),
        reference: p.envelope.reconciliationIdentity.reference,
      });
    } catch (e) {
      txnError = e;
    }
    let observation;
    if (txnOutcome !== null) {
      const proven = { RECONCILED_COMMITTED: 'COMMITTED', NOT_COMMITTED: 'NOT_COMMITTED', INDETERMINATE: 'INDETERMINATE' }[txnOutcome.reconciliation];
      // A proven COMMITTED releases exactly the escrow I-TXN validated, byte for byte the stored one.
      if (proven === 'COMMITTED' && (txnOutcome.output === null || escrowOut === null || hex(txnOutcome.output) !== hex(escrowOut))) {
        throw new Error('I-TXN released an output that is not the held escrow');
      }
      observation = {
        slotContext: SLOT.slice(),
        commitOutcome: proven,
        responseEmission: proven === 'COMMITTED' ? 'SUCCEEDED' : null,
        heldOutput,
      };
      if (proven !== 'INDETERMINATE') this.disk.pending = null; // the integrated clearing event happened
    } else {
      if (!interrupted || port.dead || rs !== 'COMMITTED' || !/^io-error BEFORE .*RELEASE_ESCROW/.test(txnError.message)) {
        throw Object.assign(txnError, { pending: p });
      }
      // The emission failed after the authority selection. Only the integrated readback can say the
      // selection is proven while the hold for this request is still bound.
      const a = await this.authority(p.parentGeneration, p.generation);
      if (a.authority !== 'COMPLETE_NEW' || this.disk.hold === null
        || hex(this.disk.hold.reconciliationReference) !== hex(p.envelope.reconciliationIdentity.reference)) {
        throw Object.assign(txnError, { pending: p });
      }
      observation = { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'INTERRUPTED', heldOutput };
    }
    const decision = this.decide(req, observation);
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
// Assertions over integrated outputs.
// ---------------------------------------------------------------------------------------------

const code = (result) => (result.kind === 'NOT_COMMITTED' || result.kind === 'INDETERMINATE'
  ? result.kind : result.successCode ?? result.error?.code ?? null);
const errCode = (e) => (e === null || e === undefined ? null : e.code ?? e.message);
async function attempt(fn) { try { await fn(); return 'OK'; } catch (e) { return errCode(e); } }
/** The AP-visible output member; a reconciled success carries the original output under `originalOutput`. */
const outputBytes = (result, member) => {
  if (result.output === undefined) return null;
  return result.output.originalOutput !== undefined ? result.output.originalOutput[member] : result.output[member];
};
const epochsOf = (d) => Object.keys(d.current().state.epochKeys).map(Number).sort((a, b) => a - b);

/** Boot and create (CAPI-S001); the device is ACTIVE at epoch 0. */
async function activeDevice(seed = 1) {
  const d = await Device.boot(null, seed);
  const created = await d.create();
  expect(created.result.kind).toBe('SUCCESS');
  expect(code(created.result)).toBe('CREATED');
  return d;
}

const WINDOW = 5; // C-RET /epochRule/pastEpochsOnceAvailable; checked against the adapter below.

// Scenario ids cited per test: O-SCEN (blind-scenarios.json, OSC-*) and the C-API row it exercises.
//   OSC-a2300e08707a1c8e CAPI-S001 CREATE        OSC-039d2541ca381eb6 CAPI-S009 PROTECT
//   OSC-272164b3f6ced9b4 CAPI-S010 OPEN          OSC-f2d864ee58cc0784 CAPI-S011 OPEN duplicate
//   OSC-b92a2b9a90af255f CAPI-S012 OPEN past     OSC-040428778da7f360 CAPI-S013 OPEN future
//   OSC-4e6a91e8fd134c5c CAPI-S014 SELF_UPDATE   OSC-c90d3d132707cad8 CAPI-S022 reconcile COMMITTED
//   OSC-c7441026f4b0594f CAPI-S023 reconcile NOT_COMMITTED  OSC-7298412dac6a8db3 CAPI-S024 still INDETERMINATE
//   OSC-8c6968efb4972ccf C-FMT /crashModel/5 AFTER_DURABLE_COMMIT_BEFORE_RESPONSE (original terminal path)
//   OSC-6086dd97b6ef94b0 C-FMT /crashModel/10 DURING_ESCROW_OUTPUT_RESPONSE (interrupted emission)
//   OSC-6818fbd5a19c9a3d C-REC /reconciliation/crashBoundaryIds (DURING_RS_WORK, DURING_RECONCILIATION, ...)
//   OSC-20663d6756e478a4 CAPI-E006 BINDING_MISMATCH  OSC-5a23d7268d61c6c1 CAPI-E014 VALUE_OUT_OF_RANGE
//   OSC-ad26b270e382b2fb / OSC-9ed400b7a6602e62 / OSC-c86b474d44feabd4 C-RET /epochRule
//   OSC-92cb820392c2bc62 C-RET /epochRule/outOfOrderDuplicateFutureOutsideWindow
//   OSC-2a042900cfba5cb7 / OSC-bc87562e4f763a5b / OSC-4a5c7b3eeb3046d7 / OSC-2bf8c572c6345e5c C-RET /resultHoldEscrowRule
//   OSC-4eb177dcce9cc123 / OSC-5fbff302d019a663 C-RET /lifecycleMatrix/21 (EPOCH_ADVANCE), /26 (RESTART)

describe('T-COMPOSE I-UPD + I-MSG over the M2 storage stack', () => {
  test('the harness window equals the integrated C-RET window (OSC-9ed400b7a6602e62)', async () => {
    const d = await Device.boot();
    expect(d.P.adapter.M2_ADAPTER.RETENTION).toMatchObject({ CURRENT_EPOCHS: 1, MAXIMUM_PAST_EPOCHS: 5, PAST_EPOCHS_ONCE_AVAILABLE: WINDOW });
  });

  // (a) Normal sequence.
  test('(a) create -> protect/open -> SELF_UPDATE committed -> current and past window, replay rejected '
    + '(OSC-a2300e08707a1c8e, OSC-039d2541ca381eb6, OSC-272164b3f6ced9b4, OSC-4e6a91e8fd134c5c, OSC-f2d864ee58cc0784, '
    + 'OSC-b92a2b9a90af255f, OSC-040428778da7f360, OSC-ad26b270e382b2fb, OSC-92cb820392c2bc62)', async () => {
    const d = await activeDevice();
    const p0 = await d.protect('hello-0');
    expect(code(p0.result)).toBe('APPLICATION_PROTECTED');
    d.emit(p0.result);
    expect(parseMessage(outputBytes(p0.result, 'protectedApplicationBytes')).epoch).toBe(0);

    const peerAt0 = sealMessage(0, 'peer-0', 'from peer at 0');
    const o0 = await d.open(peerAt0);
    expect(code(o0.result)).toBe('APPLICATION_OPENED');
    expect(fromUtf8(outputBytes(o0.result, 'applicationBytes'))).toBe('from peer at 0');

    const u1 = await d.selfUpdate('COMMITTED');
    expect(u1.result.kind).toBe('SUCCESS');
    expect(code(u1.result)).toBe('SELF_UPDATED');
    expect(outputBytes(u1.result, 'protectedCommitBytes')).not.toBeNull();
    expect(d.current().state.epoch).toBe(1);

    // CAPI-S010 at the new epoch and in the past window (distance 1).
    expect(code((await d.open(sealMessage(1, 'peer-1', 'at 1'))).result)).toBe('APPLICATION_OPENED');
    expect(code((await d.open(sealMessage(0, 'peer-0b', 'late at 0'))).result)).toBe('APPLICATION_OPENED');
    // CAPI-S011: the replay of an accepted identity is NO_CHANGE and writes nothing durable.
    const gens = d.disk.generations.size;
    const dup = await d.open(peerAt0);
    expect(dup.result.kind).toBe('NO_CHANGE');
    expect(code(dup.result)).toBe('DUPLICATE_IGNORED');
    expect(d.disk.generations.size).toBe(gens);
    // CAPI-S013: a future epoch.
    expect(code((await d.open(sealMessage(2, 'peer-f', 'future'))).result)).toBe('FUTURE_EPOCH');

    // Advance to epoch WINDOW + 1: epoch 0 leaves the window (distance 6 -> CAPI-S012), epoch 1 is at 5.
    for (let i = 0; i < WINDOW; i += 1) expect(code((await d.selfUpdate('COMMITTED')).result)).toBe('SELF_UPDATED');
    expect(d.current().state.epoch).toBe(WINDOW + 1);
    expect(epochsOf(d)).toEqual([1, 2, 3, 4, 5, 6]);
    expect(code((await d.open(sealMessage(1, 'peer-edge', 'edge'))).result)).toBe('APPLICATION_OPENED');
    const out = await d.open(sealMessage(0, 'peer-old', 'too old'));
    expect(out.result.kind).toBe('REJECTED');
    expect(code(out.result)).toBe('EPOCH_OUTSIDE_RETAINED_WINDOW');
    expect(epochsOf(d)).toEqual([1, 2, 3, 4, 5, 6]); // neither extended nor shrunk
  });

  // (b) INDETERMINATE during SELF_UPDATE, restart, reconcile.
  for (const rs of ['COMMITTED', 'NOT_COMMITTED']) {
    for (const memory of ['RETAINED', 'LOST']) {
      test(`(b) SELF_UPDATE INDETERMINATE -> restart (memory hold ${memory}) -> reconcile ${rs}: exactly one outcome `
        + '(OSC-4e6a91e8fd134c5c, OSC-7298412dac6a8db3, OSC-c90d3d132707cad8, OSC-c7441026f4b0594f, OSC-2a042900cfba5cb7, OSC-5fbff302d019a663)', async () => {
        let d = await activeDevice();
        await d.open(sealMessage(0, 'peer-before', 'before'));
        const ind = await d.selfUpdate('INDETERMINATE');
        expect(ind.result.kind).toBe('INDETERMINATE');
        expect(ind.result.output).toBeUndefined();
        const ref = ind.result.reconciliationRef;
        const p = d.disk.pending;
        expect(ref).toBeDefined();

        d = await d.restart();
        if (memory === 'LOST') d.disk.hold = null;
        // The held adapter snapshot survives; a non-reconcile operation is refused (CAPI-E011).
        expect(d.snapshot().held).not.toBeNull();
        const blocked = d.decide(d.request('PROTECT_APPLICATION', { applicationBytes: utf8('x') }), {
          commitOutcome: null, operationIdentity: null, stagedOutput: null,
        });
        expect(code(blocked.result)).toBe('RECONCILIATION_REQUIRED');
        expect(await d.authority(p.parentGeneration, p.generation)).toMatchObject({ authority: 'COMPLETE_OLD', held: true });

        let r;
        if (memory === 'RETAINED') {
          // CAPI-S024 first: RS still INDETERMINATE keeps the hold.
          const still = await d.reconcile('INDETERMINATE');
          expect(still.result.kind).toBe('INDETERMINATE');
          expect(d.snapshot().held).not.toBeNull();
          expect((await d.authority(p.parentGeneration, p.generation)).held).toBe(true);
          r = await d.reconcile(rs);
          expect(r.txnError).toBeNull();
        } else {
          // R1 path: the memory hold is lost; I-TXN reconciles from the durable hold in the bound candidate.
          expect(d.disk.generations.get(p.generation).mutationHold.presence).toBe(1);
          r = await d.reconcile(rs);
          expect(r.txnError).toBeNull();
        }
        expect(r.txnOutcome.reconciliation).toBe(rs === 'COMMITTED' ? 'RECONCILED_COMMITTED' : 'NOT_COMMITTED');
        expect(r.txnOutcome.authority).toBe(rs === 'COMMITTED' ? 'COMPLETE_NEW' : 'COMPLETE_OLD');
        if (rs === 'COMMITTED') expect(hex(outputBytes(r.result, 'protectedCommitBytes'))).toBe(hex(r.txnOutcome.output));
        expect(d.disk.pending).toBeNull();
        expect(code(r.result)).toBe(rs === 'COMMITTED' ? 'RECONCILED_COMMITTED' : 'NOT_COMMITTED');
        expect(d.snapshot().held).toBeNull();
        expect(await d.authority(p.parentGeneration, p.generation))
          .toMatchObject({ authority: rs === 'COMMITTED' ? 'COMPLETE_NEW' : 'COMPLETE_OLD', held: false });
        expect(d.disk.hold).toBeNull();
        const epoch = rs === 'COMMITTED' ? 1 : 0;
        expect(d.current().state.epoch).toBe(epoch);

        // A repeated terminal reconcile is CAPI-E012 and changes nothing.
        const sel = hex(d.disk.selector);
        expect(code((await d.reconcile(rs === 'COMMITTED' ? 'NOT_COMMITTED' : 'COMMITTED')).result)).toBe('NO_RECONCILIATION_PENDING');
        expect(hex(d.disk.selector)).toBe(sel);

        // Messages before and after follow C-RET.
        expect(code((await d.open(sealMessage(0, 'peer-before', 'before'))).result)).toBe('DUPLICATE_IGNORED');
        expect(code((await d.open(sealMessage(0, 'peer-after', 'after'))).result)).toBe('APPLICATION_OPENED');
        expect(code((await d.open(sealMessage(1, 'peer-e1', 'e1'))).result)).toBe(rs === 'COMMITTED' ? 'APPLICATION_OPENED' : 'FUTURE_EPOCH');
        expect(code((await d.selfUpdate('COMMITTED')).result)).toBe('SELF_UPDATED');
        expect(d.current().state.epoch).toBe(epoch + 1);
      });
    }
  }

  // (c) COMMITTED, crash after the durable commit but before the response reaches the AP. This is the
  // original terminal path (C-MUT §5, C-FMT /crashModel/5): the hold is already resolved, the AP never
  // received a reference, so no AP reconciliation row exists; the SS recovers internally by readback.
  for (const kind of ['REPLACE_SELECTOR', 'RELEASE_ESCROW']) {
    test(`(c) SELF_UPDATE COMMITTED, crash AFTER ${kind} before emission -> restart: one apply, internal readback, no AP reconciliation row `
      + '(OSC-4e6a91e8fd134c5c, OSC-8c6968efb4972ccf, OSC-6818fbd5a19c9a3d, OSC-bc87562e4f763a5b)', async () => {
      let d = await activeDevice();
      const crash = await attempt(() => d.selfUpdate('COMMITTED', [{ kind, mode: 'AFTER', remaining: 1 }]));
      expect(crash).toMatch(/^crash AFTER/);
      const p = d.disk.pending;
      const snapBefore = d.snapshot();
      d = await d.restart();
      const rec = await d.recoverAfterRestart();
      expect(rec.authority).toMatchObject({ authority: 'COMPLETE_NEW', held: false });
      expect(rec.resultEvidence).toMatchObject({ outcome: d.P.txn.M2_OUTCOME.COMMITTED, authenticatedByRS: true });
      expect(d.disk.hold).toBeNull();
      expect(d.disk.pending).toBeNull();
      expect(d.current().state.epoch).toBe(1);
      // The adapter never decided this request: no held snapshot, and the AP has nothing to reconcile.
      expect(d.snapshot()).toEqual(snapBefore);
      expect(d.snapshot().held).toBeNull();
      expect(code((await d.reconcile('COMMITTED')).result)).toBe('NO_RECONCILIATION_PENDING');
      expect(d.current().state.epoch).toBe(1);
      expect(code((await d.protect('after')).result)).toBe('APPLICATION_PROTECTED');
      expect(code((await d.selfUpdate('COMMITTED')).result)).toBe('SELF_UPDATED');
      expect(d.current().state.epoch).toBe(2);
    });
  }

  // R2 (C-MUT DURING_RS_WORK, C-REC crash boundaries): the RS reports COMMITTED, but the binding write
  // fails before REPLACE_SELECTOR selects. Every staged byte is dropped with the process; after restart
  // the old authority is complete, nothing is held, and nothing is resurrected.
  for (const kind of ['STAGE_DATA', 'STAGE_MANIFEST', 'STAGE_EVIDENCE', 'STAGE_ESCROW', 'REPLACE_SELECTOR']) {
    test(`(c) R2 SELF_UPDATE COMMITTED, crash BEFORE ${kind} -> restart: complete old authority, no partial candidate `
      + '(OSC-4e6a91e8fd134c5c, OSC-6818fbd5a19c9a3d)', async () => {
      let d = await activeDevice();
      const crash = await attempt(() => d.selfUpdate('COMMITTED', [{ kind, mode: 'BEFORE', remaining: 1 }]));
      expect(crash).toMatch(/^crash BEFORE/);
      const p = d.disk.pending;
      d = await d.restart();
      expect(await d.authority(p.parentGeneration, p.generation)).toMatchObject({ authority: 'COMPLETE_OLD', held: false });
      expect(d.disk.generations.has(p.generation)).toBe(false);
      expect(d.disk.hold).toBeNull();
      const rec = await d.recoverAfterRestart();
      expect(rec.authority.authority).toBe('COMPLETE_OLD');
      expect(d.disk.pending).toBeNull();
      expect(d.current().state.epoch).toBe(0);
      expect(code((await d.selfUpdate('COMMITTED')).result)).toBe('SELF_UPDATED');
      expect(d.current().state.epoch).toBe(1);
    });
  }

  // R2 with the binding write landed (C-MUT DURING_RS_WORK RETAINED: OLD_PLUS_ONE_IMMUTABLE_HOLD): a
  // failed write the process survives after the hold is bound leaves the request INDETERMINATE for the
  // AP, decided only from the integrated readback; reconciliation then resolves it either way.
  for (const rs of ['COMMITTED', 'NOT_COMMITTED']) {
    test(`(c) R2 SELF_UPDATE INDETERMINATE, I/O failure AFTER the binding REPLACE_SELECTOR -> restart -> reconcile ${rs} `
      + '(OSC-4e6a91e8fd134c5c, OSC-6818fbd5a19c9a3d, OSC-7298412dac6a8db3, OSC-c90d3d132707cad8, OSC-c7441026f4b0594f)', async () => {
      let d = await activeDevice();
      const ind = await d.selfUpdate('INDETERMINATE', [{ kind: 'REPLACE_SELECTOR', mode: 'AFTER', remaining: 1, fatal: false }]);
      expect(ind.result.kind).toBe('INDETERMINATE');
      const p = d.disk.pending;
      d = await d.restart();
      expect(await d.authority(p.parentGeneration, p.generation)).toMatchObject({ authority: 'COMPLETE_OLD', held: true });
      const r = await d.reconcile(rs);
      expect(r.txnOutcome.reconciliation).toBe(rs === 'COMMITTED' ? 'RECONCILED_COMMITTED' : 'NOT_COMMITTED');
      expect(code(r.result)).toBe(rs === 'COMMITTED' ? 'RECONCILED_COMMITTED' : 'NOT_COMMITTED');
      expect(await d.authority(p.parentGeneration, p.generation))
        .toMatchObject({ authority: rs === 'COMMITTED' ? 'COMPLETE_NEW' : 'COMPLETE_OLD', held: false });
      expect(d.current().state.epoch).toBe(rs === 'COMMITTED' ? 1 : 0);
    });
  }

  // A reconciliation that dies before its selector write decides nothing (C-REC DURING_RECONCILIATION).
  test('(c) a reconcile COMMITTED that crashes BEFORE REPLACE_SELECTOR decides nothing; restart + reconcile resolves once '
    + '(OSC-6818fbd5a19c9a3d, OSC-c90d3d132707cad8)', async () => {
    let d = await activeDevice();
    await d.selfUpdate('INDETERMINATE');
    const p = d.disk.pending;
    const snap = d.snapshot();
    const crash = await attempt(() => d.reconcile('COMMITTED', { faults: [{ kind: 'REPLACE_SELECTOR', mode: 'BEFORE', remaining: 1 }] }));
    expect(crash).toMatch(/^crash BEFORE .*REPLACE_SELECTOR/);
    expect(d.snapshot()).toEqual(snap); // the adapter was never asked
    expect(d.disk.pending).not.toBeNull();
    d = await d.restart();
    expect(await d.authority(p.parentGeneration, p.generation)).toMatchObject({ authority: 'COMPLETE_OLD', held: true });
    const r = await d.reconcile('COMMITTED');
    expect(r.txnOutcome).toMatchObject({ reconciliation: 'RECONCILED_COMMITTED', authority: 'COMPLETE_NEW' });
    expect(code(r.result)).toBe('RECONCILED_COMMITTED');
    expect(d.current().state.epoch).toBe(1);
  });

  test('(c) p16: once RS proved COMMITTED, an interrupted emission + restart repeats the same escrow, never REJECTED '
    + '(OSC-c90d3d132707cad8, OSC-6086dd97b6ef94b0, OSC-bc87562e4f763a5b, OSC-2bf8c572c6345e5c)', async () => {
    let d = await activeDevice();
    const ind = await d.selfUpdate('INDETERMINATE');
    expect(ind.result.reconciliationRef).toBeDefined(); // the AP already holds the reference
    const p = d.disk.pending;
    const r1 = await d.reconcile('COMMITTED', { emission: 'INTERRUPTED' });
    expect(errCode(r1.txnError)).toMatch(/^io-error BEFORE .*RELEASE_ESCROW/);
    expect(r1.result.kind).not.toBe('REJECTED');
    expect(d.snapshot().held).not.toBeNull();
    expect(d.disk.pending).not.toBeNull();
    expect(await d.authority(p.parentGeneration, p.generation)).toMatchObject({ authority: 'COMPLETE_NEW' });
    const escrow = hex(d.disk.generations.get(p.generation).escrow.output);
    d = await d.restart();
    const r2 = await d.reconcile('COMMITTED');
    expect(r2.txnError).toBeNull();
    expect(r2.txnOutcome).toMatchObject({ reconciliation: 'RECONCILED_COMMITTED', authority: 'COMPLETE_NEW' });
    expect(code(r2.result)).toBe('RECONCILED_COMMITTED');
    expect(hex(r2.txnOutcome.output)).toBe(escrow);
    expect(r2.result.output.originalSuccessCode).toBe('SELF_UPDATED');
    expect(hex(outputBytes(r2.result, 'protectedCommitBytes'))).toBe(escrow);
    expect(d.snapshot().held).toBeNull();
    expect(d.disk.hold).toBeNull();
    expect(d.disk.pending).toBeNull();
    expect(d.current().state.epoch).toBe(1);
  });

  // (d) Retention across restart.
  test('(d) past-epoch keys leave with EPOCH_ADVANCE and nothing is resurrected after restart '
    + '(OSC-c86b474d44feabd4, OSC-ad26b270e382b2fb, OSC-4eb177dcce9cc123, OSC-5fbff302d019a663, OSC-b92a2b9a90af255f)', async () => {
    let d = await activeDevice();
    for (let i = 0; i < WINDOW + 2; i += 1) {
      expect(code((await d.selfUpdate('COMMITTED')).result)).toBe('SELF_UPDATED');
      d = await d.restart(100 + i);
    }
    const epoch = WINDOW + 2;
    expect(d.current().state.epoch).toBe(epoch);
    expect(epochsOf(d)).toEqual([2, 3, 4, 5, 6, 7]);
    expect(code((await d.open(sealMessage(epoch - WINDOW, 'edge', 'edge'))).result)).toBe('APPLICATION_OPENED');
    expect(code((await d.open(sealMessage(epoch - WINDOW - 1, 'old', 'old'))).result)).toBe('EPOCH_OUTSIDE_RETAINED_WINDOW');
    d = await d.restart(7);
    expect(epochsOf(d)).toEqual([2, 3, 4, 5, 6, 7]);
    // The authority selector names the newest generation; superseded ones are never selected again.
    const sel = decodeSelector(d.disk.selector);
    const maxGen = [...d.disk.generations.keys()].reduce((a, b) => (a > b ? a : b));
    expect(sel.generation).toBe(maxGen);
  });

  test('(d) a NOT_COMMITTED reconcile across restarts does not resurrect the discarded epoch '
    + '(OSC-4a5c7b3eeb3046d7, OSC-c90d3d132707cad8)', async () => {
    let d = await activeDevice();
    await d.selfUpdate('COMMITTED');
    await d.selfUpdate('INDETERMINATE');
    d = await d.restart();
    expect(code((await d.reconcile('NOT_COMMITTED')).result)).toBe('NOT_COMMITTED');
    d = await d.restart();
    expect(d.current().state.epoch).toBe(1);
    expect(epochsOf(d)).toEqual([0, 1]);
    expect(code((await d.open(sealMessage(2, 'x', 'x'))).result)).toBe('FUTURE_EPOCH');
  });

  // C-RET eviction: a NOT_COMMITTED reconcile of a SELF_UPDATE that would evict the oldest past epoch
  // restores the complete old window, including that oldest epoch; nothing of the candidate survives.
  test('(d) a NOT_COMMITTED reconcile at the full window keeps the oldest past epoch and resurrects nothing '
    + '(OSC-4a5c7b3eeb3046d7, OSC-c7441026f4b0594f, OSC-ad26b270e382b2fb, OSC-c86b474d44feabd4)', async () => {
    let d = await activeDevice();
    const peers = [];
    for (let i = 0; i < WINDOW; i += 1) {
      peers.push(sealMessage(i, `peer-${i}`, `m-${i}`));
      expect(code((await d.selfUpdate('COMMITTED')).result)).toBe('SELF_UPDATED');
    }
    const windowBefore = epochsOf(d);
    expect(windowBefore).toEqual(Array.from({ length: WINDOW + 1 }, (_, i) => i)); // the next advance evicts epoch 0
    const ind = await d.selfUpdate('INDETERMINATE');
    expect(ind.result.kind).toBe('INDETERMINATE');
    const p = d.disk.pending;
    d = await d.restart();
    const r = await d.reconcile('NOT_COMMITTED');
    expect(r.txnOutcome.reconciliation).toBe('NOT_COMMITTED');
    expect(code(r.result)).toBe('NOT_COMMITTED');
    d = await d.restart();
    expect(d.disk.generations.has(p.generation)).toBe(false);
    expect(epochsOf(d)).toEqual(windowBefore);
    expect(d.current().state.epoch).toBe(WINDOW);
    // The oldest past epoch still opens (it was not evicted) ...
    expect(code((await d.open(peers[0])).result)).toBe('APPLICATION_OPENED');
    // ... and the candidate epoch never existed.
    expect(code((await d.open(sealMessage(WINDOW + 1, 'x', 'x'))).result)).toBe('FUTURE_EPOCH');
  });

  // (e) bindingRef mismatch on SELF_UPDATE after restart.
  test('(e) SELF_UPDATE with a foreign bindingRef after restart is BINDING_MISMATCH and persists nothing '
    + '(OSC-20663d6756e478a4, OSC-4e6a91e8fd134c5c)', async () => {
    let d = await activeDevice();
    await d.selfUpdate('COMMITTED');
    d = await d.restart();
    const sel = hex(d.disk.selector);
    const gens = d.disk.generations.size;
    const snap = d.snapshot();
    // A well-formed observation (P01 precedes P03): the SS reports a full commit shape, yet the P03 binding
    // check refuses before anything is applied. The harness runs no I-TXN transaction for this request.
    for (const commitOutcome of ['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']) {
      const r = d.decide(d.request('SELF_UPDATE', {}, OTHER_SLOT), {
        slotContext: SLOT.slice(), updateForm: 'SUPPORTED', commitOutcome, operationIdentity: 'op-mismatch',
        stagedOutput: commitOutcome === 'COMMITTED' ? { protectedCommitBytes: new Uint8Array([1, 2, 3]) } : null,
      });
      expect(r.result.kind).toBe('REJECTED');
      expect(code(r.result)).toBe('BINDING_MISMATCH');
      expect(r.result.output).toBeUndefined();
      expect(r.snapshot).toBeNull();
    }
    const r = d.decide(d.request('SELF_UPDATE', {}, OTHER_SLOT), {
      slotContext: SLOT.slice(), updateForm: 'SUPPORTED', commitOutcome: 'INDETERMINATE', operationIdentity: 'op-mismatch-2', stagedOutput: null,
    });
    expect(code(r.result)).toBe('BINDING_MISMATCH');
    expect(r.snapshot).toBeNull();
    expect(hex(d.disk.selector)).toBe(sel);
    expect(d.disk.generations.size).toBe(gens);
    expect(d.snapshot()).toEqual(snap);
    expect(d.current().state.epoch).toBe(1);
    expect(code((await d.selfUpdate('COMMITTED')).result)).toBe('SELF_UPDATED');
  });

  // p06 lesson: an over-bound operationIdentity is refused up front, before any hold.
  test('p06 sweep: an over-bound operationIdentity is VALUE_OUT_OF_RANGE before any hold (OSC-5a23d7268d61c6c1)', async () => {
    let d = await activeDevice();
    d = await d.restart();
    const max = d.P.adapter.M2_ADAPTER.BOUNDS.MAX_OPERATION_IDENTITY_CHARS;
    const rand = prng(606);
    for (let i = 0; i < 24; i += 1) {
      const extra = 1 + Math.floor(rand() * 64);
      for (const commitOutcome of ['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']) {
        const sel = hex(d.disk.selector);
        const r = d.decide(d.request('SELF_UPDATE', {}), {
          slotContext: SLOT.slice(), updateForm: 'SUPPORTED', commitOutcome,
          operationIdentity: 'i'.repeat(max + extra),
          stagedOutput: commitOutcome === 'COMMITTED' ? { protectedCommitBytes: new Uint8Array([9]) } : null,
        });
        expect(code(r.result)).toBe('VALUE_OUT_OF_RANGE');
        expect(r.snapshot).toBeNull();
        expect(d.snapshot().held).toBeNull();
        expect(hex(d.disk.selector)).toBe(sel);
      }
    }
    expect(code((await d.selfUpdate('COMMITTED')).result)).toBe('SELF_UPDATED');
  });

  // Seeded property-style sweep over interleavings with interruption and restart.
  test('seeded sweep: random I-UPD/I-MSG interleavings with INDETERMINATE + restart keep one authority and C-RET', async () => {
    const stats = { ops: 0, held: 0, committed: 0, notCommitted: 0 };
    for (let seed = 1; seed <= 12; seed += 1) {
      const rand = prng(seed * 7919);
      let d = await activeDevice(seed);
      let model = 0;
      for (let step = 0; step < 14; step += 1) {
        const pick = rand();
        stats.ops += 1;
        if (pick < 0.3) {
          const id = `s${seed}-${step}`;
          const e = Math.max(0, model - Math.floor(rand() * (WINDOW + 3)));
          const expected = model - e > WINDOW ? 'EPOCH_OUTSIDE_RETAINED_WINDOW' : 'APPLICATION_OPENED';
          expect(code((await d.open(sealMessage(e, id, id))).result)).toBe(expected);
          if (expected === 'APPLICATION_OPENED') {
            expect(code((await d.open(sealMessage(e, id, id))).result)).toBe('DUPLICATE_IGNORED');
          }
        } else if (pick < 0.5) {
          expect(code((await d.protect(`t${step}`)).result)).toBe('APPLICATION_PROTECTED');
        } else if (pick < 0.75) {
          expect(code((await d.selfUpdate('COMMITTED')).result)).toBe('SELF_UPDATED');
          model += 1;
        } else {
          stats.held += 1;
          expect((await d.selfUpdate('INDETERMINATE')).result.kind).toBe('INDETERMINATE');
          d = await d.restart(seed * 100 + step);
          const rs = rand() < 0.5 ? 'COMMITTED' : 'NOT_COMMITTED';
          const r = await d.reconcile(rs);
          expect(r.txnError).toBeNull();
          expect(code(r.result)).toBe(rs === 'COMMITTED' ? 'RECONCILED_COMMITTED' : 'NOT_COMMITTED');
          if (rs === 'COMMITTED') { model += 1; stats.committed += 1; } else stats.notCommitted += 1;
          expect(d.disk.hold).toBeNull();
        }
        if (rand() < 0.2) d = await d.restart(seed * 1000 + step);
        // One authority, as the integrated readback classifies it, matching the model.
        const a = await d.authority(d.current().generation, null);
        expect(a).toMatchObject({ authority: 'COMPLETE_OLD', generation: d.current().generation, held: false });
        expect(d.current().state.epoch).toBe(model);
        expect(d.snapshot().held).toBeNull();
        const keep = epochsOf(d);
        expect(keep[keep.length - 1]).toBe(model);
        expect(keep[0]).toBe(Math.max(0, model - WINDOW));
        expect(keep.length).toBe(Math.min(model, WINDOW) + 1);
      }
    }
    expect(stats.held).toBeGreaterThan(0);
    expect(stats.committed).toBeGreaterThan(0);
    expect(stats.notCommitted).toBeGreaterThan(0);
  });
});
