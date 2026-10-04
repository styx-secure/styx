// T-SWEEP marker sweep: the L-MARK one-way cutover crossed with the CREATE outcomes, plus the
// APPLY_PEER_UPDATE guard. Not a test file; imported by `sweep-frontier.test.js`.
//
// The marker bytes live in a durable test-local disk cell (`disk.marker`): L-MARK owns the encoding
// and the transition decision only, never storage (legacy-session-invalidation.js:26-28). The SS glue
// writes exactly the bytes `encodeMarker` returns for the decided `stateAfter`, and nothing else.
// The opaque start-authority token is a durable SS fact fixed at START (`disk.startToken`); CONFIRM
// presents it with `committed` and `restoreResult` derived only from the I-TXN readback and the
// persisted adapter state (C-REC l.892-901, §6 l.39).
//
// Crash points are the three C-REC marker boundaries (recovery-and-coexistence.md:2439-2489) and the
// two sides of every marker write.

import { Device, deepCopy, errCode, loadProcess } from './harness.js';

const EVENTS = Object.freeze({
  START: 'USER_CONFIRMED_START',
  CANCEL: 'USER_CANCEL_BEFORE_CONFIRMATION',
  CONFIRM: 'DISTINCT_POST_START_C_FMT_COMMITTED_AUTHORITY_RESTORED_ACTIVE',
  COMMIT: 'ATOMIC_MARKER_COMMIT',
  REPEAT: 'REPEAT_MARKER_COMPLETION',
});
const RESTORE_RESULTS = Object.freeze([
  'NO_M2_STATE', 'LEGACY_ONLY', 'RESTORED_ACTIVE', 'RESTORED_EMPTY', 'RESTORED_RECONCILIATION_REQUIRED',
]);
const RESTORE_BY_ADAPTER_STATE = Object.freeze({
  EMPTY: 'RESTORED_EMPTY', ACTIVE: 'RESTORED_ACTIVE', RECONCILIATION_REQUIRED: 'RESTORED_RECONCILIATION_REQUIRED',
});

/** CREATE outcomes swept under the marker: RS outcome and, for INDETERMINATE, the later RS truth. */
export const MARKER_CREATES = Object.freeze([
  ['COMMITTED', 'COMMITTED'], ['NOT_COMMITTED', 'NOT_COMMITTED'],
  ['INDETERMINATE', 'COMMITTED'], ['INDETERMINATE', 'NOT_COMMITTED'],
]);
/** Crash points of the cutover. `null` boundary = before any C-REC marker boundary is reached. */
export const MARKER_CRASHES = Object.freeze([
  ['NONE', null],
  ['BEFORE_START_WRITE', null],
  ['AFTER_START_WRITE', 'BEFORE_DISTINCT_SESSION_CONFIRMATION'],
  ['AFTER_CREATE', 'BEFORE_DISTINCT_SESSION_CONFIRMATION'],
  ['AFTER_CONFIRM_WRITE', 'AFTER_CONFIRMATION_BEFORE_MARKER_COMMIT'],
  ['AFTER_COMMIT_WRITE', 'AFTER_MARKER_COMMIT'],
]);
/** C-REC fixture readback per boundary (recovery-and-coexistence.md:2444-2488). */
const BOUNDARY_STATE = Object.freeze({
  BEFORE_DISTINCT_SESSION_CONFIRMATION: 'PENDING_NEW_SESSION',
  AFTER_CONFIRMATION_BEFORE_MARKER_COMMIT: 'NEW_SESSION_CONFIRMED',
  AFTER_MARKER_COMMIT: 'LEGACY_INVALIDATED',
});
const ONE_WAY = new Set(['NEW_SESSION_CONFIRMED', 'LEGACY_INVALIDATED']);

export function enumerateMarkerCells() {
  const cells = [];
  for (const [rs, truth] of MARKER_CREATES) {
    for (const [crash, boundary] of MARKER_CRASHES) {
      cells.push(Object.freeze({ id: ['MARKER', 'CREATE', rs, truth, crash].join('|'), rs, truth, crash, boundary }));
    }
  }
  return cells;
}

class Crash extends Error {
  constructor(at) { super(`crash ${at}`); this.at = at; }
}

const zeroToken = () => new Uint8Array(32);

function markerState(d) {
  return d.P.marker.readMarker(Uint8Array.from(d.disk.marker));
}

/** Apply one event; on acceptance the SS writes the encoded `stateAfter` (crash before/after the write). */
function apply(d, event, extra, crashAt, label, log) {
  const decision = d.P.marker.applyMarkerTransition({
    marker: Uint8Array.from(d.disk.marker), event, lockHeld: true, ...extra,
  });
  log.push({ event, accepted: decision.accepted, stateAfter: decision.stateAfter, reject: decision.reject });
  if (!decision.accepted) return decision;
  if (crashAt === `BEFORE_${label}_WRITE`) throw new Crash(crashAt);
  const token = decision.stateAfter === 'ABSENT' ? zeroToken() : Uint8Array.from(d.disk.startToken);
  d.disk.marker = d.P.marker.encodeMarker({ state: decision.stateAfter, bindingToken: token });
  if (crashAt === `AFTER_${label}_WRITE`) throw new Crash(crashAt);
  return decision;
}

/** The CREATE of the distinct post-start session, driven to a terminal outcome. */
async function createSession(d, rs, truth) {
  const first = await d.runClean(d.prepCreate(rs), 'marker-create');
  if (rs !== 'INDETERMINATE') return { device: d, first: first.kind };
  for (let i = 0; i < 3 && d.disk.pending !== null; i += 1) {
    const r = await d.reconcile(truth);
    if (r.result.kind !== 'INDETERMINATE') break;
  }
  return { device: d, first: first.kind };
}

async function confirmInputs(d) {
  const p = d.lastCreate;
  const a = p === null ? null : await d.authority(p.parentGeneration, p.generation);
  const committed = a !== null && a.error === null && a.held === false && a.authority === 'COMPLETE_NEW';
  return {
    restoreResult: RESTORE_BY_ADAPTER_STATE[d.disk.snapshot.state],
    committed,
    authorityToken: Uint8Array.from(d.disk.startToken),
  };
}

/** Run the cutover from wherever the durable marker is, to completion. Throws `Crash` at `crashAt`. */
async function cutover(d, cell, crashAt, log) {
  let state = markerState(d).state;
  if (state === 'ABSENT') {
    if (d.disk.startToken === undefined) d.disk.startToken = Uint8Array.from({ length: 32 }, () => 1 + Math.floor(d.rand() * 255));
    apply(d, EVENTS.START, { restoreResult: 'LEGACY_ONLY' }, crashAt, 'START', log);
    state = markerState(d).state;
  }
  if (state === 'PENDING_NEW_SESSION') {
    if (d.lastCreate === undefined) {
      const created = await createSession(d, cell.rs, cell.truth);
      d = created.device;
      d.lastCreate = deepCopy(d.lastPending);
      if (crashAt === 'AFTER_CREATE') throw new Crash(crashAt);
    }
    apply(d, EVENTS.CONFIRM, await confirmInputs(d), crashAt, 'CONFIRM', log);
    state = markerState(d).state;
  }
  if (state === 'NEW_SESSION_CONFIRMED') {
    apply(d, EVENTS.COMMIT, { restoreResult: 'RESTORED_ACTIVE' }, crashAt, 'COMMIT', log);
    state = markerState(d).state;
  }
  if (state === 'LEGACY_INVALIDATED') apply(d, EVENTS.REPEAT, { restoreResult: 'RESTORED_ACTIVE' }, null, 'REPEAT', log);
  return d;
}

/** Every event under every restore result from the current marker; a one-way state may never reverse. */
function probeOneWay(d) {
  const from = markerState(d).state;
  const reversals = [];
  for (const event of Object.values(EVENTS)) {
    for (const restoreResult of RESTORE_RESULTS) {
      const extra = event === EVENTS.CONFIRM
        ? { restoreResult, committed: true, authorityToken: Uint8Array.from(d.disk.startToken ?? zeroToken()) }
        : { restoreResult };
      const decision = d.P.marker.applyMarkerTransition({ marker: Uint8Array.from(d.disk.marker), event, lockHeld: true, ...extra });
      if (decision.accepted && decision.legacyEligible === true) reversals.push(`${event}/${restoreResult}->${decision.stateAfter}`);
    }
  }
  return { from, reversals };
}

let SHARED = null;

export async function runMarkerCell(cell) {
  if (SHARED === null) SHARED = await loadProcess();
  let d = await Device.boot(null, 0x4d41524b, SHARED);
  d.disk.marker = d.P.marker.encodeMarker({ state: 'ABSENT', bindingToken: zeroToken() });
  // The pending request of the last CREATE is captured by the harness before it is cleared.
  const capture = (dev) => {
    const orig = dev.runTxn.bind(dev);
    dev.runTxn = async (prep, crash) => { const r = await orig(prep, crash); dev.lastPending = deepCopy(dev.disk.pending); return r; };
    return dev;
  };
  capture(d);
  const log = [];
  const violations = [];
  let crashed = null;
  try {
    d = await cutover(d, cell, cell.crash === 'NONE' ? null : cell.crash, log);
  } catch (e) {
    if (!(e instanceof Crash)) throw e;
    crashed = e.at;
  }
  let readbackAfterCrash = null;
  if (crashed !== null) {
    const lastCreate = d.lastCreate;
    d = capture(await d.restart());
    d.lastCreate = lastCreate;
    readbackAfterCrash = deepCopy(markerState(d));
    // M1 the readback at a C-REC marker boundary is exactly the fixture state.
    if (cell.boundary !== null && readbackAfterCrash.state !== BOUNDARY_STATE[cell.boundary]) {
      violations.push(`M1:BOUNDARY_READBACK:${readbackAfterCrash.state}!=${BOUNDARY_STATE[cell.boundary]}`);
    }
    if (cell.crash === 'BEFORE_START_WRITE' && readbackAfterCrash.state !== 'ABSENT') violations.push(`M1:START_NOT_ATOMIC:${readbackAfterCrash.state}`);
    if (ONE_WAY.has(readbackAfterCrash.state) && readbackAfterCrash.legacyEligible !== false) violations.push('M3:LEGACY_ELIGIBLE_AFTER_RESTART');
    d = await cutover(d, cell, null, log);
  }

  const final = deepCopy(markerState(d));
  const ci = d.lastCreate === undefined ? null : await confirmInputs(d);
  const sessionCommitted = ci !== null && ci.committed && ci.restoreResult === 'RESTORED_ACTIVE';
  // M2 CONFIRM is accepted iff the distinct post-start session is a committed, restored ACTIVE authority.
  const confirmAccepted = log.some((e) => e.event === EVENTS.CONFIRM && e.accepted);
  if (confirmAccepted !== sessionCommitted) violations.push(`M2:CONFIRM_${confirmAccepted ? 'ACCEPTED' : 'REFUSED'}_WITH_SESSION_${sessionCommitted ? 'COMMITTED' : 'UNCOMMITTED'}`);
  // M4 the cutover completes: committed -> LEGACY_INVALIDATED; otherwise the marker stays PENDING
  // (legacy still eligible), and CANCEL returns it to ABSENT.
  const want = sessionCommitted ? 'LEGACY_INVALIDATED' : 'PENDING_NEW_SESSION';
  if (final.state !== want) violations.push(`M4:FINAL_STATE:${final.state}!=${want}`);
  // M3 one-way: no event from a one-way state leads back to a legacy-eligible state.
  const oneWay = probeOneWay(d);
  if (ONE_WAY.has(oneWay.from) && oneWay.reversals.length > 0) violations.push(`M3:REVERSAL:${oneWay.reversals.join(',')}`);
  let cancel = null;
  if (final.state === 'PENDING_NEW_SESSION') {
    const c = d.P.marker.applyMarkerTransition({ marker: Uint8Array.from(d.disk.marker), event: EVENTS.CANCEL, lockHeld: true, restoreResult: 'LEGACY_ONLY' });
    cancel = { accepted: c.accepted, stateAfter: c.stateAfter };
    if (!c.accepted || c.stateAfter !== 'ABSENT') violations.push('M4:CANCEL_REFUSED');
  }
  // M3 after one more restart the one-way state and its eligibility survive.
  d = await d.restart();
  const afterRestart = deepCopy(markerState(d));
  if (afterRestart.state !== final.state) violations.push(`M3:STATE_CHANGED_ON_RESTART:${afterRestart.state}`);
  if (ONE_WAY.has(afterRestart.state) && afterRestart.legacyEligible !== false) violations.push('M3:LEGACY_ELIGIBLE_AFTER_FINAL_RESTART');

  // M0 the crash point is reached whenever the cutover passes it (CONFIRM/COMMIT only when committed).
  const reachable = cell.crash !== 'NONE' && (sessionCommitted || !['AFTER_CONFIRM_WRITE', 'AFTER_COMMIT_WRITE'].includes(cell.crash));
  if (reachable && crashed === null) violations.push(`M0:CRASH_NOT_REACHED:${cell.crash}`);

  return {
    id: cell.id, crash: cell.crash, boundary: cell.boundary, rs: cell.rs, truth: cell.truth, crashed,
    log, readbackAfterCrash, final, sessionCommitted, cancel, afterRestart, violations,
    classification: violations.length === 0 ? 'PASS' : 'UNEXPLAINED',
  };
}

/** APPLY_PEER_UPDATE is not integrated at the base: closed refusal, no snapshot, no storage change. */
export async function runPeerUpdateGuard() {
  if (SHARED === null) SHARED = await loadProcess();
  const d = await Device.boot(null, 0x50454552, SHARED);
  await d.runClean(d.prepCreate('COMMITTED'), 'guard-create');
  const before = JSON.stringify(deepCopy(d.disk), (k, v) => (typeof v === 'bigint' ? `${v}n` : (v instanceof Uint8Array ? Buffer.from(v).toString('hex') : v)));
  const req = d.request('APPLY_PEER_UPDATE', { protectedCommitBytes: new Uint8Array([1, 2, 3, 4]) });
  let result;
  let snapshot;
  try {
    const t = d.P.adapter.invokeAdapterTransition({ request: req, snapshot: d.snapshot(), observation: null });
    result = d.P.wire.fromWireBytes(d.P.wire.toWireBytes(t.result));
    snapshot = t.snapshot;
  } catch (e) {
    result = { thrown: errCode(e) };
  }
  const after = JSON.stringify(deepCopy(d.disk), (k, v) => (typeof v === 'bigint' ? `${v}n` : (v instanceof Uint8Array ? Buffer.from(v).toString('hex') : v)));
  const violations = [];
  if (result.kind !== 'REJECTED' || result.error?.code !== 'UNSUPPORTED_OPERATION') violations.push(`G1:NOT_UNSUPPORTED:${JSON.stringify(result)}`);
  if (snapshot !== null && snapshot !== undefined) violations.push('G2:SNAPSHOT_RETURNED');
  if (before !== after) violations.push('G3:STORAGE_CHANGED');
  return {
    id: 'GUARD|APPLY_PEER_UPDATE', result: { kind: result.kind ?? null, code: result.error?.code ?? result.thrown ?? null, stateAfter: result.stateAfter ?? null },
    violations, classification: violations.length === 0 ? 'PASS' : 'UNEXPLAINED',
  };
}
