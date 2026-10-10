// B-CHR frozen conformance suite: expectations (act #317 6091950328 §1 "Expectations").
// Every expectation below cites the C-MUT / C-FMT / C-REST / C-REC clause it comes from. None is derived
// from observed port behaviour, and none depends on the factory: the same table judges every port.
// Clause references are to the ratified texts pinned in m2-kind13-resolve/pins (cmut.md, cfmt.md,
// crest.md, crec.md); "§n" is the section number of that contract.

export const ROWS = Object.freeze(['CAPI-S001', 'CAPI-S006', 'CAPI-S009', 'CAPI-S010', 'CAPI-S014', 'CAPI-S016', 'CAPI-S017']);
export const OUTCOMES = Object.freeze(['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']);
export const PHASES = Object.freeze(['ORIGINAL', 'RECONCILIATION']);
export const KILL_KINDS = Object.freeze(['BROWSER', 'RENDERER', 'COMMIT_SENT']);

// C-MUT /rows (cmut.md §4, §12): origin state and whether the row holds an output escrow.
const ORIGIN = Object.freeze({
  'CAPI-S001': 'EMPTY', 'CAPI-S006': 'EMPTY', 'CAPI-S009': 'ACTIVE', 'CAPI-S010': 'ACTIVE',
  'CAPI-S014': 'ACTIVE', 'CAPI-S016': 'ACTIVE', 'CAPI-S017': 'ACTIVE',
});
const HAS_OUTPUT = (row) => row !== 'CAPI-S006' && row !== 'CAPI-S016'; // C-MUT /rows outputKind NONE
const SELECTOR_STATE = Object.freeze({ EMPTY: 1, ACTIVE: 2, RECONCILIATION_REQUIRED: 3 });

/** The escrowed output the fixtures stage (fixtures.mjs mutationInput: bytesOf(24, 0xa3)). */
export const ESCROW_OUTPUT_HEX = Array.from({ length: 24 }, (_, i) => ((0xa3 + i * 7) & 0xff).toString(16).padStart(2, '0')).join('');

export const CITE = Object.freeze({
  OLD: 'C-MUT §8 (injected failure strictly before the commit point leaves the complete original authority); C-FMT §7 (before replacement readback is COMPLETE_OLD)',
  NEW: 'C-MUT §8 (injected failure after the commit point exposes the complete candidate, root, result evidence and escrow); C-FMT §7 (after replacement readback is COMPLETE_NEW)',
  NEVER_MIXED: 'C-MUT §8 (RS readback yields only complete old or complete committed new authority; never a partial mixture or two authoritative states); C-FMT §7',
  HELD: 'C-MUT §5 INDETERMINATE (original authority stays selected, exactly one immutable hold, RECONCILIATION_REQUIRED); C-FMT §7 (the same replacement that sets RECONCILIATION_REQUIRED binds the candidate)',
  NOT_COMMITTED: 'C-MUT §5 NOT_COMMITTED (discards candidate and escrow, leaves the complete original authority); C-MUT §6 (matching terminal NOT_COMMITTED discards candidate and escrow)',
  OUTPUT_ORIGINAL: 'C-MUT §5 (a successful original response releases escrow under the original success code; NOT_COMMITTED and INDETERMINATE expose no operation output)',
  OUTPUT_RECON: 'C-MUT §5/§6 (CAPI-S020/S022 return the already committed escrow; reconciliation never regenerates security-sensitive bytes; S021/S023/S024 expose no output)',
  INDET_RESPONSE: 'C-MUT §5 (the INDETERMINATE response carries commitOutcome INDETERMINATE, originalStateBefore and an opaque reconciliationRef, with no output)',
  CONTINUED: 'C-MUT §6 (continued INDETERMINATE is CAPI-S024 and leaves the hold logically unchanged)',
  REPEAT: 'C-MUT §6 (after clearing either terminal reconciliation, a repeat follows CAPI-G008/G016 NO_RECONCILIATION_PENDING with unchanged authority and no output)',
  RESUME: 'C-MUT §8 (after worker-memory loss, authenticated readback must terminally classify before another operation); C-REC §4 (indeterminate reconciliation from the durable hold); C-MUT §6 (reconciliation is idempotent)',
  DURABLE_HOLD: 'C-FMT §7 and /recordKinds[13] (the RECONCILIATION_REQUIRED selector binds the candidate and its kind-13 MUTATION_HOLD); C-REC §4; C-MUT §8',
  DEBRIS: 'C-FMT §7 / generationCommit.unboundCandidate (an unbound candidate is preserved non-authoritative debris; restore classifies by the selector alone and yields COMPLETE_OLD; it never stops the profile and is never discarded without terminal NOT_COMMITTED)',
  NEVER_REUSE: 'C-FMT §7 (a generation number is never reused: a later candidate exceeds every number present in the number-only inventory)',
  SURVIVES: 'C-MUT §8 / C-FMT §7 (the classified authority is durable; a further restart reads back the same authority and the same selector bytes)',
  LOCK: 'C-MUT §7 (one writer per profile; the lock of a dead context is released and re-acquired before readback, act §1 item 4)',
  READ_FAIL: 'C-REC §8 and C-REST §9 (a readback that cannot complete fails closed with the store byte-preserved and nothing emitted); C-MUT §6 (the hold is left unchanged)',
  TAMPER: 'C-REST §9 / C-FMT §4 (an AEAD authentication failure fails closed, bytes preserved, nothing emitted); C-MUT §6 (any mismatch leaves the hold unchanged)',
  PUT_THROW: 'C-MUT §8 (abort and exception before the commit point leave the complete original authority; failure before the commit point exposes no output)',
  NO_EARLY_HOLD: 'B-CHR obligation v2 item 6 (no memory hold is retained before the complete of the transaction whose selector binds the held candidate); C-MUT §5 NOT_COMMITTED',
  CAS: 'B-CHR obligation v2 item 10 (every REPLACE_SELECTOR carries expectedSelectorBytes; on any difference no write and SELECTOR_PRECONDITION_FAILED; every completed authority write changes the stored bytes); restart design T6b',
});

const authority = (classify) => (classify && !classify.error ? `${classify.authority}${classify.held ? '+HELD' : ''}` : `ERROR(${classify?.error?.code ?? '?'})`);

/** The two stored states a phase can leave (C-MUT §8: exactly these, never anything else). */
export function endStates({ row, outcome, phase }) {
  const held = 'COMPLETE_OLD+HELD';
  if (phase === 'ORIGINAL') {
    const initial = 'COMPLETE_OLD';
    const final = { COMMITTED: 'COMPLETE_NEW', NOT_COMMITTED: 'COMPLETE_OLD', INDETERMINATE: held }[outcome];
    return { initial, final };
  }
  const final = { COMMITTED: 'COMPLETE_NEW', NOT_COMMITTED: 'COMPLETE_OLD', INDETERMINATE: held }[outcome];
  return { initial: held, final };
}

/** Checks on an uninterrupted operation (no kill). Returns a list of failures with citations. */
export function checkUninterrupted({ row, outcome, phase }, response, rb) {
  const f = [];
  const want = (ok, what, cite) => { if (!ok) f.push({ what, cite }); };
  const { final } = endStates({ row, outcome, phase });
  want(authority(rb.classify) === final, `readback ${authority(rb.classify)} is ${final}`, outcome === 'COMMITTED' ? CITE.NEW : (outcome === 'NOT_COMMITTED' ? CITE.NOT_COMMITTED : CITE.HELD));
  want(response.error === null, `operation returned without error (got ${response.error?.code})`, phase === 'ORIGINAL' ? CITE.OUTPUT_ORIGINAL : CITE.OUTPUT_RECON);
  const r = response.result ?? {};
  if (phase === 'ORIGINAL') {
    want(r.commitOutcome === outcome, `commitOutcome ${r.commitOutcome} is ${outcome}`, CITE.OUTPUT_ORIGINAL);
    const output = outcome === 'COMMITTED' && HAS_OUTPUT(row) ? ESCROW_OUTPUT_HEX : null;
    want(r.output === output, `output ${r.output} is ${output}`, CITE.OUTPUT_ORIGINAL);
    if (outcome === 'INDETERMINATE') {
      want(r.state === 'RECONCILIATION_REQUIRED' && r.originalStateBefore === ORIGIN[row] && typeof r.reconciliationRef === 'string',
        'INDETERMINATE response carries RECONCILIATION_REQUIRED, originalStateBefore and reconciliationRef', CITE.INDET_RESPONSE);
      want(rb.selector?.state === SELECTOR_STATE.RECONCILIATION_REQUIRED && rb.selector.candidateGeneration !== rb.selector.generation,
        'the stored selector is RECONCILIATION_REQUIRED and binds the candidate', CITE.HELD);
    }
    if (outcome === 'NOT_COMMITTED') want(rb.candidatePresent === false, 'the candidate is discarded', CITE.NOT_COMMITTED);
  } else {
    const kind = { COMMITTED: 'RECONCILED_COMMITTED', NOT_COMMITTED: 'NOT_COMMITTED', INDETERMINATE: 'INDETERMINATE' }[outcome];
    want(r.reconciliation === kind, `reconciliation ${r.reconciliation} is ${kind}`, CITE.OUTPUT_RECON);
    const output = outcome === 'COMMITTED' && HAS_OUTPUT(row) ? ESCROW_OUTPUT_HEX : null;
    want(r.output === output, `reconciliation output ${r.output} is ${output}`, CITE.OUTPUT_RECON);
    if (outcome === 'NOT_COMMITTED') want(rb.candidatePresent === false, 'the candidate is discarded', CITE.NOT_COMMITTED);
    if (outcome === 'COMMITTED') want(rb.memoryHold === false, 'the hold is cleared by the local emission', CITE.OUTPUT_RECON);
  }
  return f;
}

/**
 * Checks after a kill at `point`. `firstPoint` is true for a point before the first request of the
 * operation; `committedPoint` is true for the `complete` of the operation's last readwrite transaction
 * and for the lost response (RETURNED). Both are computed from the port-neutral trace.
 */
export function checkKilled(cell, { point, firstPoint, committedPoint }, rb) {
  const f = [];
  const { initial, final } = endStates(cell);
  const got = authority(rb.classify);
  if (rb.lock !== true) f.push({ what: `kill at ${point}: the relaunched context re-acquired the writer lock`, cite: CITE.LOCK });
  if (firstPoint) {
    if (got !== initial) f.push({ what: `kill at ${point}: readback ${got} is ${initial}`, cite: cell.phase === 'ORIGINAL' ? CITE.OLD : CITE.CONTINUED });
  } else if (committedPoint) {
    if (got !== final) f.push({ what: `kill at ${point}: readback ${got} is ${final}`, cite: CITE.NEW });
  } else if (got !== initial && got !== final) {
    f.push({ what: `kill at ${point}: readback ${got} is ${initial} or ${final}`, cite: CITE.NEVER_MIXED });
  }
  return f;
}

/** After a RECONCILIATION-phase kill that left the hold: a fresh worker resumes and must reach the final state. */
export function checkResumed(cell, response, rb) {
  const f = [];
  const { final } = endStates(cell);
  if (authority(rb.classify) !== final) f.push({ what: `resumed readback ${authority(rb.classify)} is ${final}`, cite: CITE.RESUME });
  if (response.error !== null) f.push({ what: `resume returned without error (got ${response.error?.code})`, cite: CITE.RESUME });
  return f;
}

export function checkSurvives(before, after) {
  const f = [];
  if (authority(before.classify) !== authority(after.classify)) f.push({ what: `after a further restart ${authority(after.classify)} is ${authority(before.classify)}`, cite: CITE.SURVIVES });
  if ((before.selector?.envelope ?? null) !== (after.selector?.envelope ?? null)) f.push({ what: 'after a further restart the selector bytes are unchanged', cite: CITE.SURVIVES });
  return f;
}

/** Restart reconcile (T6 without steal): durable RR, context death, fresh worker at EMPTY memory. */
export function checkRestartReconcile({ row, outcome }, pre, response, rb, repeat) {
  const f = [];
  const want = (ok, what, cite) => { if (!ok) f.push({ what, cite }); };
  want(pre.lock === true, 'the fresh context re-acquired the writer lock released by context death', CITE.LOCK);
  want(pre.memoryHold === false, 'the fresh worker holds no memory hold', CITE.RESUME);
  want(authority(pre.classify) === 'COMPLETE_OLD+HELD', `relaunched readback ${authority(pre.classify)} is COMPLETE_OLD+HELD`, CITE.DURABLE_HOLD);
  f.push(...checkUninterrupted({ row, outcome, phase: 'RECONCILIATION' }, response, rb));
  if (outcome === 'INDETERMINATE') {
    want(rb.selector?.envelope === pre.selector?.envelope && rb.dbDigest === pre.dbDigest, 'continued INDETERMINATE leaves the stored bytes unchanged', CITE.CONTINUED);
  } else {
    want(repeat?.error?.code === 'NO_RECONCILIATION_PENDING' && (repeat?.result?.output ?? null) === null,
      `a repeat reconciliation is NO_RECONCILIATION_PENDING (got ${repeat?.error?.code ?? repeat?.result?.reconciliation})`, CITE.REPEAT);
  }
  return f;
}

/** T9 faults on the restart path: the reconciliation fails closed and the store is byte-preserved. */
export function checkFault(fault, pre, response, rb) {
  const f = [];
  const cite = fault === 'READ_FAIL' ? CITE.READ_FAIL : CITE.TAMPER;
  if (response.error === null) f.push({ what: `${fault}: reconciliation fails closed (got ${response.result?.reconciliation})`, cite });
  if ((response.result?.output ?? null) !== null) f.push({ what: `${fault}: nothing is emitted`, cite });
  if (rb.dbDigest !== pre.dbDigest) f.push({ what: `${fault}: the store is byte-preserved`, cite });
  if (authority(rb.classify) !== 'COMPLETE_OLD+HELD') f.push({ what: `${fault}: the hold is unchanged (${authority(rb.classify)})`, cite });
  return f;
}

/** T6b mutant: a put throws mid-enqueue during the original write. */
export function checkPutThrow(response, rb) {
  const f = [];
  if (response.error === null) f.push({ what: 'PUT_THROW: the operation fails', cite: CITE.PUT_THROW });
  if ((response.result?.output ?? null) !== null) f.push({ what: 'PUT_THROW: no output', cite: CITE.PUT_THROW });
  if (authority(rb.classify) !== 'COMPLETE_OLD') f.push({ what: `PUT_THROW: readback ${authority(rb.classify)} is COMPLETE_OLD`, cite: CITE.PUT_THROW });
  if (rb.memoryHold !== false) f.push({ what: 'PUT_THROW: no memory hold is retained after the abort', cite: CITE.NO_EARLY_HOLD });
  return f;
}

/** T6b CAS: a delayed writer with the selector bytes its plan read is refused after the authority changed. */
export function checkDelayedWriter(point, response, before, after) {
  const f = [];
  if (response.error?.code !== 'SELECTOR_PRECONDITION_FAILED') {
    f.push({ what: `after ${point}: a delayed REPLACE_SELECTOR is refused with SELECTOR_PRECONDITION_FAILED (got ${response.error?.code ?? 'success'})`, cite: CITE.CAS });
  }
  if (after !== before) f.push({ what: `after ${point}: the refused delayed write changed nothing`, cite: CITE.CAS });
  return f;
}

/** Debris, then a second mutation over it. */
export function checkDebris({ outcome }, stage, data) {
  const f = [];
  const want = (ok, what, cite) => { if (!ok) f.push({ what, cite }); };
  if (stage === 'DEBRIS') {
    want(authority(data.classify) === 'COMPLETE_OLD', `with debris present readback ${authority(data.classify)} is COMPLETE_OLD`, CITE.DEBRIS);
    want(Array.isArray(data.numbers) && data.numbers.includes('2'), 'the debris generation number is listed by the number-only inventory', CITE.NEVER_REUSE);
  } else if (stage === 'REUSE') {
    want(data.response.error?.code === 'STALE_PARENT', `a candidate reusing the debris number is refused (got ${data.response.error?.code ?? 'success'})`, CITE.NEVER_REUSE);
    want(data.rb.dbDigest === data.before, 'the refused request wrote nothing', CITE.NEVER_REUSE);
  } else if (stage === 'SECOND') {
    f.push(...checkUninterrupted({ row: data.row, outcome, phase: 'ORIGINAL' }, data.response, data.rb));
    want(data.debrisDigest === data.debrisAfter, 'the debris generation is preserved byte-identical', CITE.DEBRIS);
  }
  return f;
}
