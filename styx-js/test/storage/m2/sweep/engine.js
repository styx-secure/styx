// T-SWEEP engine: the deterministic mutation × crash-point matrix. Not a test file.
//
// A cell is one (phase, operation, RS outcome, RS truth, plan step, crash position, fault mode).
// `runCell` builds the device, runs the setup cleanly, injects exactly one crash, restarts when the
// fault loses SS memory, runs the SS recovery protocol through the public surface, then a follow-up
// mutation and one more restart, and evaluates the invariants of IMPACT.md §3 on what the integrated
// modules returned and wrote.

import { Device, OUTPUT_MEMBER, ROOT_KEY, deepCopy, errCode, loadProcess, makePort, sealMessage } from './harness.js';
import { startCutover, confirmAfterRecovery, markerAfterRestart } from './marker.js';

export const OPERATIONS = Object.freeze(['CREATE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION', 'SELF_UPDATE']);
export const OUTCOMES = Object.freeze(['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']);
export const FAULTS_ORIGINAL = Object.freeze(['EXC_RETAINED', 'EXC_LOST', 'KILL']);
export const FAULTS_RECONCILIATION = Object.freeze(['EXC_RETAINED', 'EXC_LOST', 'KILL']);
export const SEEDS = Object.freeze([11, 23, 37]);
const MEMORY_ONLY = new Set([
  'VALIDATE_ENVELOPE', 'COMPUTE_CANDIDATE', 'STAGE_LOCAL', 'OPEN_RS_REQUEST', 'CONFIRM_AUTHORITY', 'REPORT_RESULT',
]);

/**
 * C-MUT `/crashBoundaries` (mutation-table.md:366-378, SHA-256 6c2c045c…3deb3060), projected onto the
 * stored authority: the set of `COMPLETE_OLD` / `COMPLETE_NEW` the readback may show at that boundary
 * for each memory condition. `OLD_PLUS_ONE_IMMUTABLE_HOLD` projects onto `COMPLETE_OLD`; whether the
 * hold is resolvable is invariant I3.
 */
const OLD = 'COMPLETE_OLD';
const NEW = 'COMPLETE_NEW';
export const ALLOWED = Object.freeze({
  BEFORE_STAGING: { RETAINED: [OLD], LOST: [OLD] },
  AFTER_CANDIDATE_COMPUTATION: { RETAINED: [OLD], LOST: [OLD] },
  AFTER_LOCAL_STAGING: { RETAINED: [OLD], LOST: [OLD] },
  BEFORE_RS_REQUEST: { RETAINED: [OLD], LOST: [OLD] },
  DURING_RS_WORK: { RETAINED: [OLD, NEW], LOST: [OLD, NEW] },
  AFTER_DURABLE_COMMIT_BEFORE_RESPONSE: { RETAINED: [NEW], LOST: [NEW] },
  AFTER_NOT_COMMITTED: { RETAINED: [OLD], LOST: [OLD] },
  AFTER_INDETERMINATE: { RETAINED: [OLD], LOST: [OLD, NEW] },
  DURING_RECONCILIATION: { RETAINED: [OLD, NEW], LOST: [OLD, NEW] },
  AFTER_AUTHORITY_SELECTION_BEFORE_OUTPUT_RESPONSE: { RETAINED: [NEW], LOST: [NEW] },
  DURING_ESCROW_OUTPUT_RESPONSE: { RETAINED: [NEW], LOST: [NEW] },
  AFTER_OUTPUT_RESPONSE_LOSS: { RETAINED: [NEW], LOST: [NEW] },
});

/**
 * C-MUT `/crashBoundaries` (mutation-table.md:366-378) verbatim, hold dimension included: the stored
 * readback values each boundary admits per memory condition. OLD_PLUS_ONE_IMMUTABLE_HOLD is
 * COMPLETE_OLD with exactly one hold retained (durable selector hold, or the SS memory hold).
 */
const HOLD = 'OLD_PLUS_ONE_IMMUTABLE_HOLD';
export const READBACK = Object.freeze({
  BEFORE_STAGING: { RETAINED: [OLD], LOST: [OLD] },
  AFTER_CANDIDATE_COMPUTATION: { RETAINED: [OLD], LOST: [OLD] },
  AFTER_LOCAL_STAGING: { RETAINED: [OLD], LOST: [OLD] },
  BEFORE_RS_REQUEST: { RETAINED: [OLD], LOST: [OLD] },
  DURING_RS_WORK: { RETAINED: [OLD, NEW, HOLD], LOST: [OLD, NEW] },
  AFTER_DURABLE_COMMIT_BEFORE_RESPONSE: { RETAINED: [NEW], LOST: [NEW] },
  AFTER_NOT_COMMITTED: { RETAINED: [OLD], LOST: [OLD] },
  AFTER_INDETERMINATE: { RETAINED: [HOLD], LOST: [OLD, NEW] },
  DURING_RECONCILIATION: { RETAINED: [OLD, NEW, HOLD], LOST: [OLD, NEW] },
  AFTER_AUTHORITY_SELECTION_BEFORE_OUTPUT_RESPONSE: { RETAINED: [NEW], LOST: [NEW] },
  DURING_ESCROW_OUTPUT_RESPONSE: { RETAINED: [NEW], LOST: [NEW] },
  AFTER_OUTPUT_RESPONSE_LOSS: { RETAINED: [NEW], LOST: [NEW] },
});

/** The C-MUT readback value of an authenticated readback plus the SS memory hold. */
function readbackValue(rb) {
  if (rb.authority === OLD && (rb.held === true || rb.memoryHold)) return HOLD;
  return rb.authority;
}

/** The known divergences of the card (IMPACT.md §5). Fix: PR #435, contract #436. */
export const KNOWN = Object.freeze({
  'T-COMPOSE-R1': 'memory lost, durable RECONCILIATION_REQUIRED selector, reconcile HOLD_UNAVAILABLE, new mutation BLIND_RETRY',
  'T-COMPOSE-R2': 'original run fault leaves COMPLETE_OLD held:false plus a memory hold; reconcile NO_RECONCILIATION_PENDING; new mutation BLIND_RETRY',
  'T-COMPOSE-R3': 'COMMITTED reconciliation interrupted at RELEASE_ESCROW leaves COMPLETE_NEW plus a memory hold; repeat NO_RECONCILIATION_PENDING; new mutation BLIND_RETRY',
  'I-TXN-FIX-r2-recovery-faults': 'unbound memory hold after a NOT_COMMITTED path interrupted between the parent-selector restore and CLEAR_CANDIDATE (owner question 1 of #436; reachable here by one fault in a NOT_COMMITTED reconciliation)',
});

// ---------------------------------------------------------------------------------------------
// Setup and request preparation.
// ---------------------------------------------------------------------------------------------

const PEER_MESSAGE = () => sealMessage(0, 'peer-1', 'from-peer');

// The first process of every cell is shared: a fresh disk is what makes a cell independent. Every
// restart inside a cell still loads a fresh module registry.
let SHARED = null;
async function sharedProcess() {
  if (SHARED === null) SHARED = await loadProcess();
  return SHARED;
}

async function setup(op, seed) {
  const d = await Device.boot(null, seed, await sharedProcess());
  // CREATE is the distinct post-start session of the L-MARK cutover (C-REC §6): START precedes it,
  // and CONFIRM is attempted once the interrupted CREATE is recovered.
  if (op === 'CREATE') startCutover(d);
  if (op !== 'CREATE' && op !== 'JOIN_WELCOME') {
    const r = await d.runClean(d.prepCreate('COMMITTED'), 'setup-create');
    if (r.kind !== 'SUCCESS') throw new Error(`setup CREATE did not succeed: ${r.kind}`);
  }
  return d;
}

function prepFor(d, op, rs) {
  switch (op) {
    case 'CREATE': return d.prepCreate(rs);
    case 'JOIN_WELCOME': return d.prepJoin(rs);
    case 'PROTECT_APPLICATION': return d.prepProtect(rs);
    case 'OPEN_APPLICATION': return d.prepOpen(rs, PEER_MESSAGE());
    case 'SELF_UPDATE': return d.prepSelfUpdate(rs);
    default: throw new Error(`no preparation for ${op}`);
  }
}

// ---------------------------------------------------------------------------------------------
// Crash points (IMPACT.md §2 labelling rule).
// ---------------------------------------------------------------------------------------------

/** Every crash point of one plan: `{ step, when, boundary, crash }` where `crash.target` drives the port. */
export function crashPoints(plan) {
  const out = [];
  const firstDurable = plan.findIndex((s) => !MEMORY_ONLY.has(s.kind));
  for (let i = 0; i < plan.length; i += 1) {
    const s = plan[i];
    if (MEMORY_ONLY.has(s.kind)) {
      const next = plan.slice(i + 1).find((x) => !MEMORY_ONLY.has(x.kind));
      let target;
      if (firstDurable === -1 || i < firstDurable) target = { when: 'FIRST_READ', index: -1 };
      else if (next !== undefined) target = { when: 'BEFORE', index: next.index };
      else target = { when: 'POST_RETURN', index: -1 };
      out.push({ step: s.index, kind: s.kind, when: 'AT', boundary: s.boundary, target });
    } else {
      const prev = i === 0 ? s : plan[i - 1];
      const beforeBoundary = s.boundary.startsWith('DURING_') ? s.boundary : prev.boundary;
      out.push({ step: s.index, kind: s.kind, when: 'BEFORE', boundary: beforeBoundary, target: { when: 'BEFORE', index: s.index } });
      out.push({ step: s.index, kind: s.kind, when: 'AFTER', boundary: s.boundary, target: { when: 'AFTER', index: s.index } });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Matrix enumeration.
// ---------------------------------------------------------------------------------------------

const truthsFor = (rs) => (rs === 'INDETERMINATE' ? ['COMMITTED', 'NOT_COMMITTED'] : [rs]);

export const cellId = (c) => [c.phase, c.op, c.rs, c.truth, `${c.step}:${c.kind}`, c.when, c.fault].join('|');

/** The complete, ordered cell list. Plans are read from the integrated `mutationSteps`. */
export async function enumerateCells() {
  const cells = [];
  for (const op of OPERATIONS) {
    for (const rs of OUTCOMES) {
      const d = await setup(op, SEEDS[0]);
      const plan = d.planFor(prepFor(d, op, rs));
      for (const pt of crashPoints(plan)) {
        for (const fault of FAULTS_ORIGINAL) {
          for (const truth of truthsFor(rs)) {
            cells.push({ phase: 'ORIGINAL', op, rs, truth, step: pt.step, kind: pt.kind, when: pt.when, boundary: pt.boundary, target: pt.target, fault });
          }
        }
      }
    }
    for (const rs of OUTCOMES) {
      const d = await setup(op, SEEDS[0]);
      const prep = prepFor(d, op, 'INDETERMINATE');
      await d.runClean(prep, 'setup-indeterminate');
      const plan = d.reconcilePlanFor(rs);
      for (const pt of crashPoints(plan)) {
        for (const fault of FAULTS_RECONCILIATION) {
          for (const truth of truthsFor(rs)) {
            cells.push({ phase: 'RECONCILIATION', op, rs, truth, step: pt.step, kind: pt.kind, when: pt.when, boundary: pt.boundary, target: pt.target, fault });
          }
        }
      }
    }
  }
  return cells.map((c, i) => Object.freeze({ ...c, id: cellId(c), seed: SEEDS[i % SEEDS.length] }));
}

// ---------------------------------------------------------------------------------------------
// One cell.
// ---------------------------------------------------------------------------------------------

const resultCode = (r) => `${r.kind}/${r.successCode ?? r.error?.code ?? '-'}`;
const RECONCILE_ATTEMPTS = 3;

function bytesIn(value, out = []) {
  if (value instanceof Uint8Array) out.push(value);
  else if (value !== null && typeof value === 'object') for (const v of Object.values(value)) bytesIn(v, out);
  return out;
}
const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

/** True when `bytes` sits under a member named `member` somewhere in the released output. */
function releasedUnder(value, member, bytes) {
  if (value === null || typeof value !== 'object' || value instanceof Uint8Array) return false;
  for (const [k, v] of Object.entries(value)) {
    if (k === member && v === bytes) return true;
    if (releasedUnder(v, member, bytes)) return true;
  }
  return false;
}

/** Run one cell and return its frontier record (plain JSON-safe data; no bytes). */
export async function runCell(cell) {
  let d = await setup(cell.op, cell.seed);
  const memory = cell.fault === 'EXC_RETAINED' ? 'RETAINED' : 'LOST';
  const crash = { target: cell.target, fault: cell.fault === 'KILL' ? 'KILL' : 'EXCEPTION' };
  const adapterResults = []; // every adapter result for the interrupted request
  const txnErrors = [];
  let prep;
  let crashed = false;
  let applied = [];

  if (cell.phase === 'ORIGINAL') {
    prep = prepFor(d, cell.op, cell.rs);
    if (cell.target.when === 'POST_RETURN') {
      await d.runTxn(prep); // I-TXN returns; the SS dies before the adapter is asked
      crashed = true;
    } else {
      try {
        const { port } = await d.runTxn(prep, crash);
        applied = port.applied;
      } catch (e) {
        crashed = true;
        if (!/crash|dead/.test(String(e.message))) throw e; // a non-crash refusal is a harness defect
      }
    }
  } else {
    prep = prepFor(d, cell.op, 'INDETERMINATE');
    const held = await d.runClean(prep, 'original-indeterminate');
    adapterResults.push(resultCode(held));
    if (cell.target.when === 'POST_RETURN') {
      // I-TXN reconciles; the SS dies before the adapter is asked.
      const p = d.disk.pending;
      await d.P.txn.reconcileIndeterminate({
        storage: makePort(d.disk), manifestRootKey: ROOT_KEY,
        hold: d.disk.hold, evidence: d.evidenceFor(p.envelope, d.P.txn.M2_OUTCOME[cell.rs]),
        reference: d.disk.hold.reconciliationReference,
      });
      crashed = true;
    } else {
      try {
        await d.reconcile(cell.rs, crash);
      } catch (e) {
        crashed = true;
        if (!/crash|dead/.test(String(e.message))) throw e;
      }
    }
  }
  if (!crashed) throw new Error(`cell ${cell.id}: the crash point was never reached (applied ${applied.join(',')})`);

  if (memory === 'LOST') d = await d.restart();
  const p = d.disk.pending;
  const rb = await d.authority(p.parentGeneration, p.generation);
  const readback = { authority: rb.authority, held: rb.held, memoryHold: d.disk.hold !== null, error: rb.error };
  const preRs = cell.phase === 'ORIGINAL' && cell.target.when === 'FIRST_READ';

  let path;
  if (preRs) {
    // C-MUT §8 (l.79): failure strictly before any RS request: FAIL_CLOSED_INTERNAL, candidate and
    // escrow discarded, no RS evidence. Nothing was written; the SS drops the request.
    path = 'PRE_RS';
    d.disk.pending = null;
  } else if (rb.error === null && rb.held === false && d.disk.hold === null && cell.phase === 'ORIGINAL') {
    // Nothing held anywhere: the authenticated readback is terminal; the SS reports it (C-MUT §5 l.57).
    path = 'TERMINAL_READBACK';
    const rs = rb.authority === NEW ? 'COMMITTED' : 'NOT_COMMITTED';
    const r = await d.decidePending(rs, true, 'readback-report');
    adapterResults.push(resultCode(r));
    d.emit(r, 'interrupted');
  } else {
    path = 'RECONCILE';
    if (cell.phase === 'ORIGINAL') {
      // The response to the original request is lost: to the SS its outcome is unknown (C-MUT §5 l.53).
      const r = await d.decidePending('INDETERMINATE', false, 'lost-response');
      adapterResults.push(resultCode(r));
    }
    for (let i = 0; i < RECONCILE_ATTEMPTS && d.disk.pending !== null; i += 1) {
      const r = await d.reconcile(cell.truth);
      adapterResults.push(resultCode(r.result));
      if (r.txnError !== null) txnErrors.push(r.txnError);
      d.emit(r.result, 'interrupted');
      if (r.result.kind !== 'INDETERMINATE') break;
    }
  }

  const sel = d.selectorFacts();
  const settled = await d.authority(p.parentGeneration, p.generation);
  const final = {
    adapterState: d.disk.snapshot.state,
    authority: settled.authority,
    held: settled.held,
    memoryHold: d.disk.hold !== null,
    selectorState: sel === null ? null : sel.state,
    error: settled.error,
  };
  const interruptedOutputs = d.emitted.filter((e) => e.requestOp === 'interrupted').map((e) => e.output);
  // The selected generation's durable escrow, read back before the follow-up can supersede it.
  const finalEscrow = await d.durableEscrowOutput(p.generation);
  // SELF_UPDATE retention (C-RET PAST_EPOCHS_ONCE_AVAILABLE): the session state the SS reads back from
  // the selected authority is the one I-TXN selected (candidate for COMPLETE_NEW, parent for
  // COMPLETE_OLD), and its past-epoch window does not exceed the retention bound.
  let retention = null;
  if (cell.op === 'SELF_UPDATE' && settled.error === null && !settled.held) {
    const cur = d.current();
    const window = d.P.adapter.M2_ADAPTER.RETENTION.PAST_EPOCHS_ONCE_AVAILABLE;
    const epochs = Object.keys(cur.state.epochKeys).map(Number);
    const wantGen = settled.authority === NEW ? p.generation : p.parentGeneration;
    retention = {
      selected: cur.generation === wantGen,
      oldest: Math.min(...epochs), epoch: cur.state.epoch, window,
    };
  }
  // L-MARK × CREATE: CONFIRM from the recovered state, before the follow-up.
  const cutover = cell.op === 'CREATE' ? await confirmAfterRecovery(d, p.parentGeneration, p.generation) : null;

  const follow = await d.followUp();
  const followUp = { accepted: follow.accepted, code: follow.code };
  d = await d.restart();
  let after;
  if (follow.accepted) {
    const a = await d.authority(follow.parent, follow.generation);
    after = { authority: a.authority, generationIsFollowUp: a.generation === follow.generation, held: a.held, memoryHold: d.disk.hold !== null, error: a.error };
  } else {
    const a = await d.authority(p.parentGeneration, p.generation);
    after = { authority: a.authority, generationIsFollowUp: false, held: a.held, memoryHold: d.disk.hold !== null, error: a.error };
  }

  // ----- invariants (IMPACT.md §3) ---------------------------------------------------------
  const violations = [];
  // I1 no mixture, and the readback is allowed at this boundary for this memory condition.
  if (readback.error !== null) violations.push(`I1:MIXTURE:${readback.error}`);
  else if (!ALLOWED[cell.boundary][memory].includes(readback.authority)) {
    violations.push(`I1:READBACK_NOT_ALLOWED:${readback.authority}@${cell.boundary}/${memory}`);
  }
  // I1 with the hold dimension: the C-MUT readback value, hold included, is one the boundary admits.
  // Only where the boundary names a hold (or must not have one) can this differ from the projection;
  // where the run never interrupted the original request before the RS call there is nothing held.
  else if (!preRs) {
    const value = readbackValue(readback);
    if (!READBACK[cell.boundary][memory].includes(value)) {
      violations.push(`I1:HOLD_NOT_ALLOWED:${value}@${cell.boundary}/${memory}`);
    }
  }
  if (final.error !== null) violations.push(`I1:MIXTURE_AFTER_RECOVERY:${final.error}`);
  // I2 no REJECTED after COMMITTED/INDETERMINATE for the interrupted request.
  const interruptedOutcome = cell.phase === 'RECONCILIATION' ? 'INDETERMINATE' : cell.rs;
  if (interruptedOutcome !== 'NOT_COMMITTED' && !preRs) {
    const rej = adapterResults.filter((c) => c.startsWith('REJECTED/'));
    if (rej.length > 0) violations.push(`I2:REJECTED_AFTER_${interruptedOutcome}:${rej.join(',')}`);
  }
  // I3 liveness: terminal resolution, nothing held, follow-up accepted.
  if (final.adapterState === 'RECONCILIATION_REQUIRED') violations.push('I3:ADAPTER_STILL_RECONCILIATION_REQUIRED');
  if (final.held === true || final.selectorState === 3) violations.push('I3:DURABLE_HOLD_UNRESOLVED');
  if (final.memoryHold) violations.push('I3:MEMORY_HOLD_UNRESOLVED');
  if (!followUp.accepted) violations.push(`I3:FOLLOW_UP_REFUSED:${followUp.code}`);
  // I3b agreement with the RS truth whenever the request was reconciled from a hold.
  if (path === 'RECONCILE' && final.error === null && final.held === false && !final.memoryHold) {
    const want = cell.truth === 'COMMITTED' ? NEW : OLD;
    if (final.authority !== want) violations.push(`I3:AUTHORITY_DISAGREES_WITH_RS_TRUTH:${final.authority}!=${want}`);
  }
  // I4 output only for a committed authority, and byte-equal to the staged escrow (no regeneration).
  // `escrowOutput` is the pending request's own copy: an expected value only. The SS released what it
  // read back from durable storage (or what I-TXN returned from it), so a lost or altered escrow
  // shows up here as a missing or different output.
  const escrow = p.escrowOutput;
  if (final.authority === OLD && interruptedOutputs.length > 0) violations.push('I4:OUTPUT_FOR_UNCOMMITTED_REQUEST');
  for (const out of interruptedOutputs) {
    const bytes = bytesIn(out);
    // An operation with no escrow (JOIN_WELCOME: outputKind NONE) may release no bytes at all; one
    // with an escrow releases exactly that escrow, once, under its own output member.
    const ok = escrow === null ? bytes.length === 0
      : bytes.length === 1 && sameBytes(bytes[0], escrow) && releasedUnder(out, OUTPUT_MEMBER[p.outputKind], bytes[0]);
    if (!ok) violations.push('I4:OUTPUT_NOT_THE_STAGED_ESCROW');
  }
  // I4 a committed request with an escrow that was answered SUCCESS released exactly that escrow.
  const succeeded = adapterResults.some((c) => c.startsWith('SUCCESS/'));
  if (final.authority === NEW && escrow !== null && succeeded
    && !interruptedOutputs.some((out) => bytesIn(out).some((b) => sameBytes(b, escrow)))) {
    violations.push('I4:COMMITTED_OUTPUT_NOT_RELEASED');
  }
  // I4 the selected generation still holds the staged escrow, byte for byte (C-MUT /crashBoundaries:
  // the escrow is retained until the response is released, and the release never rewrites it).
  if (final.authority === NEW && escrow !== null) {
    if (finalEscrow === null || !sameBytes(finalEscrow, escrow)) violations.push('I4:DURABLE_ESCROW_LOST_OR_ALTERED');
  }
  // I4 no resurrection after the follow-up and one more restart.
  if (retention !== null) {
    if (!retention.selected) violations.push('I4:SESSION_STATE_NOT_FROM_SELECTED_AUTHORITY');
    if (retention.epoch - retention.oldest > retention.window) violations.push(`I4:RETENTION_WINDOW_EXCEEDED:${retention.epoch - retention.oldest}>${retention.window}`);
  }
  if (follow.accepted) {
    if (after.error !== null || after.authority !== NEW || !after.generationIsFollowUp) violations.push(`I4:FOLLOW_UP_NOT_DURABLE:${after.authority}/${after.error}`);
    if (after.held || after.memoryHold) violations.push('I4:HOLD_RESURRECTED');
  }

  // I5 every adapter result is encodable by the integrated worker wire codec (C-API response grammar).
  for (const w of d.wireRefusals) violations.push(`I5:WIRE_REFUSED:${w.operation}/${w.kind}/${w.successCode}/${w.code}`);
  // M5 L-MARK × CREATE: CONFIRM decided from the recovered authority; the marker survives the final restart.
  let marker = null;
  if (cutover !== null) {
    const again = markerAfterRestart(d, cutover.state);
    violations.push(...cutover.violations, ...again.violations);
    marker = { confirmed: cutover.confirmed, state: cutover.state, afterRestart: again.state };
  }

  const record = {
    id: cell.id, seed: cell.seed, phase: cell.phase, op: cell.op, rs: cell.rs, truth: cell.truth,
    step: cell.step, kind: cell.kind, when: cell.when, boundary: cell.boundary, memory, fault: cell.fault,
    readback, path, adapterResults, txnErrors, final, followUp, after, marker, wireRefusals: d.wireRefusals, violations,
  };
  record.classification = classify(record);
  return record;
}

/**
 * The exact violation set each explained wedge produces. An explanation applies only when the cell's
 * violations are exactly this set: any additional violation (a mixture, a wrong output, a resurrected
 * hold, ...) is a new defect on top of the wedge and makes the cell UNEXPLAINED.
 */
const WEDGE_DURABLE = ['I3:ADAPTER_STILL_RECONCILIATION_REQUIRED', 'I3:DURABLE_HOLD_UNRESOLVED', 'I3:FOLLOW_UP_REFUSED:BLIND_RETRY'];
const WEDGE_MEMORY = ['I3:ADAPTER_STILL_RECONCILIATION_REQUIRED', 'I3:MEMORY_HOLD_UNRESOLVED', 'I3:FOLLOW_UP_REFUSED:BLIND_RETRY'];
const exact = (s) => new RegExp(`^${s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);
// R1 is a durable hold that survives memory loss: C-MUT admits no hold in a LOST readback, so the same
// fact also shows as the I1 hold violation at the interrupted boundary (whichever boundary that was).
const R1_LOST_HOLD = /^I1:HOLD_NOT_ALLOWED:OLD_PLUS_ONE_IMMUTABLE_HOLD@[A-Z_]+\/LOST$/;
export const EXPLAINED_VIOLATIONS = Object.freeze({
  'EXPLAINED:T-COMPOSE-R1': [...WEDGE_DURABLE.map(exact), R1_LOST_HOLD],
  'EXPLAINED:T-COMPOSE-R2': WEDGE_MEMORY.map(exact),
  'EXPLAINED:T-COMPOSE-R3': WEDGE_MEMORY.map(exact),
  'EXPLAINED:r2-recovery-faults': WEDGE_MEMORY.map(exact),
});

/** True when `violations` is exactly the explanation's set: one violation per pattern, nothing else. */
export function matchesExplanation(id, violations) {
  const patterns = EXPLAINED_VIOLATIONS[id];
  if (patterns === undefined || patterns.length !== violations.length) return false;
  const used = new Set();
  return violations.every((v) => {
    const i = patterns.findIndex((re, k) => !used.has(k) && re.test(v));
    if (i < 0) return false;
    used.add(i);
    return true;
  });
}

/** EXPLAINED:<id> by exact signature and exact violation set, PASS when none, UNEXPLAINED otherwise. */
export function classify(r) {
  if (r.violations.length === 0) return 'PASS';
  const c = explain(r);
  return c !== null && matchesExplanation(c, r.violations) ? c : 'UNEXPLAINED';
}

function explain(r) {
  const wedge = r.followUp.code === 'BLIND_RETRY';
  if (wedge && r.memory === 'LOST' && r.readback.held === true && r.txnErrors.includes('HOLD_UNAVAILABLE')) {
    return 'EXPLAINED:T-COMPOSE-R1';
  }
  if (wedge && r.phase === 'ORIGINAL' && r.memory === 'RETAINED' && r.readback.authority === OLD
    && r.readback.held === false && r.readback.memoryHold && r.txnErrors.includes('NO_RECONCILIATION_PENDING')) {
    return 'EXPLAINED:T-COMPOSE-R2';
  }
  if (wedge && r.phase === 'RECONCILIATION' && r.rs === 'COMMITTED' && r.memory === 'RETAINED'
    && r.readback.authority === NEW && r.readback.held === false && r.readback.memoryHold
    && r.txnErrors.includes('NO_RECONCILIATION_PENDING')) {
    return 'EXPLAINED:T-COMPOSE-R3';
  }
  // I-TXN-FIX residual `r2-recovery-faults` (owner question 1 of contract #436): a NOT_COMMITTED path
  // interrupted between the parent-selector restore and CLEAR_CANDIDATE leaves COMPLETE_OLD, no durable
  // hold, and a memory hold no selector binds; reconcile answers NO_RECONCILIATION_PENDING and every
  // mutation BLIND_RETRY until the SS memory is lost. Same end state and root cause (the kind-13 hold
  // does not name its candidate generation), reached here by a single fault in a NOT_COMMITTED
  // reconciliation rather than the triple fault of the sandbox probe.
  if (wedge && r.phase === 'RECONCILIATION' && r.rs === 'NOT_COMMITTED' && r.memory === 'RETAINED'
    && r.readback.authority === OLD && r.readback.held === false && r.readback.memoryHold
    && r.txnErrors.length > 0 && r.txnErrors.every((e) => e === 'NO_RECONCILIATION_PENDING')
    && r.after.memoryHold === false && r.after.authority === OLD) {
    return 'EXPLAINED:r2-recovery-faults';
  }
  return null;
}

export { deepCopy, errCode };
