// B-CHR frozen conformance suite: expectations (act #317 6091950328 §1 "Expectations"; B-CHR-CANON).
// Every expectation below cites the C-MUT / C-FMT / C-REST / C-REC clause or the B-CHR obligation item
// it comes from. None is derived from observed port behaviour, and none depends on the factory: the same
// table judges every port. Clause references are to the ratified texts pinned by the contract (C-MUT
// f37915f1, C-FMT bd94aed0, C-REST 4894991c, C-REC 8215e92e); "§n" is the section number of that text,
// "/x" a JSON pointer into its machine record. The B-CHR obligation is v2 (b767e3f2) as amended by #468
// rows B1-B4; R3 is the #468 disposition 6123056674, carried by the #468 act 6171085366 §3a.

export const ROWS = Object.freeze(['CAPI-S001', 'CAPI-S006', 'CAPI-S009', 'CAPI-S010', 'CAPI-S014', 'CAPI-S016', 'CAPI-S017']);
export const OUTCOMES = Object.freeze(['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']);
export const PHASES = Object.freeze(['ORIGINAL', 'RECONCILIATION']);
export const KILL_KINDS = Object.freeze(['BROWSER', 'RENDERER', 'COMMIT_SENT']);
/** The fixed T9 cells per row, in run order. */
export const T9_CELLS = Object.freeze([
  'CONTRADICT_RR_PARENT', 'CONTRADICT_RR_CANDIDATE', 'CONTRADICT_COMMITTED', 'CONTRADICT_RESULT',
  'CONTRADICT_RESULT_NONTERMINAL', 'CONTRADICT_ESCROW', 'CONTRADICT_PARTIAL', 'PRODUCE_COMMITTED', 'TAMPER_COMMITTED', 'PRODUCE', 'READ_FAIL_MEMORY', 'READ_FAIL_LOST',
  'TAMPER_FIRST', 'TAMPER_ALL', 'TAMPER_REST',
]);
/** The cells per row (#468 B3, B4 and the matrix of act §1): 3 debris, 3 restart, 15 T9, 4 KIND13, 3 PUT_THROW, 6 kill. */
export const CELLS_PER_ROW = 34;

// C-MUT /mutationRows: origin state and output kind.
const ORIGIN = Object.freeze({
  'CAPI-S001': 'EMPTY', 'CAPI-S006': 'EMPTY', 'CAPI-S009': 'ACTIVE', 'CAPI-S010': 'ACTIVE',
  'CAPI-S014': 'ACTIVE', 'CAPI-S016': 'ACTIVE', 'CAPI-S017': 'ACTIVE',
});
export const HAS_OUTPUT = (row) => row !== 'CAPI-S006' && row !== 'CAPI-S016'; // C-MUT /mutationRows outputKind NONE
/**
 * The row a next mutation from the resulting ACTIVE authority uses (#468 B3): the same row when its
 * C-FMT preconditions hold over its own result (an ACTIVE origin; CAPI-S017 needs the selection facts
 * CAPI-S014 establishes, which it terminates), CAPI-S014 otherwise.
 */
export const NEXT_ROW = (row) => (ORIGIN[row] === 'ACTIVE' && row !== 'CAPI-S017' ? row : 'CAPI-S014');
const SELECTOR_STATE = Object.freeze({ EMPTY: 1, ACTIVE: 2, RECONCILIATION_REQUIRED: 3 });
/** The four verification-failure codes of a trusted reader (I-RESTART port error obligation, item 12). */
export const VERIFY_CODES = Object.freeze(['AUTHENTICATION_FAILED', 'CONTEXT_MISMATCH', 'MALFORMED_INPUT', 'UNSUPPORTED_VALUE']);

const hexOf = (u8) => Array.from(u8, (x) => x.toString(16).padStart(2, '0')).join('');
/** The escrowed output the fixtures stage for a row (fixtures.mjs escrowOutput), or null. */
export function escrowHex(row) {
  if (!HAS_OUTPUT(row)) return null;
  if (row === 'CAPI-S017') return hexOf(new TextEncoder().encode('bchr-selected-candidate-ref-01'));
  return hexOf(Uint8Array.from({ length: 24 }, (_, i) => (0xa3 + i * 7) & 0xff));
}

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
  DEBRIS: 'C-FMT §7 / generationCommit.unboundCandidate and C-REST unboundDebris (an unbound candidate is preserved non-authoritative debris; restore classifies by the selector alone and yields COMPLETE_OLD; it never stops the profile and is never discarded without terminal NOT_COMMITTED)',
  NEVER_REUSE: 'C-FMT §7 (a generation number is never reused: a later candidate exceeds every number present in the number-only inventory); B-CHR obligation v2 item 9',
  SURVIVES: 'C-MUT §8 / C-FMT §7 (the classified authority is durable; a further restart reads back the same authority and the same selector bytes)',
  LOCK: 'C-MUT §7 (one writer per profile; the lock of a dead context is released and re-acquired before readback, act §1 item 4)',
  READ_FAIL: 'C-REC §8 and C-REST §9 (a readback that cannot complete fails closed with the store byte-preserved and nothing emitted); C-MUT §6 (the hold is left unchanged)',
  PUT_THROW: 'C-MUT §8 (abort and exception before the commit point leave the complete original authority; failure before the commit point exposes no output)',
  NO_EARLY_HOLD: 'B-CHR obligation v2 item 6 (no memory hold is retained before the complete of the transaction whose selector binds the held candidate)',
  CAS: 'B-CHR obligation v2 item 10 (every REPLACE_SELECTOR carries expectedSelectorBytes; on any difference no write and SELECTOR_PRECONDITION_FAILED; every completed authority write changes the stored bytes); restart design T6b',
  DURABILITY: 'B-CHR obligation v2 item 1 (each atomic write is one readwrite transaction opened with durability strict), as observed by the harness on the IndexedDB transaction; item 7 (adapter readback) is not claimed here',
  SCOPE: 'B-CHR obligation v2 item 1 (one transaction over every store that holds records and the selector; the reference port uses only `mls`, act §1)',
  ONE_TX: 'B-CHR obligation v2 items 1 and 2 (each atomic write of a plan, the ordinary commit included, is exactly one readwrite transaction; the selector unbind and the candidate removal are one transaction); C-FMT §7 generationCommit',
  MEMORY_HOLD: 'B-CHR obligation v2 item 6 and C-MUT §5 (a terminal COMMITTED or NOT_COMMITTED leaves no hold; INDETERMINATE retains exactly one hold, in SS memory after the binding write completed)',
  PRODUCER_NOT_COMMITTED: 'B-CHR obligation v2 item 13 (an RR selector that keeps the exact parent tuple and binds exactly this candidate gives NOT_COMMITTED, terminal) with A(1)-A(6); C-MUT §6 (matching terminal NOT_COMMITTED discards candidate and escrow)',
  PRODUCER_UNAVAILABLE: 'B-CHR obligation v2 item 13 (a readback that cannot be performed gives evidence INDETERMINATE, authenticatedByRS, hence CAPI-S024); C-MUT §6 (continued INDETERMINATE leaves the hold logically unchanged)',
  PRODUCER_NO_HOLD: 'B-CHR obligation v2 item 13 (identity fields are copied, none invented: with no readable hold no evidence can be produced), C-API failure code HOLD_UNAVAILABLE (src/storage/m2/session-transaction.js CODE.HOLD_UNAVAILABLE) and C-REST §9 (fail closed, bytes preserved, nothing emitted)',
  PRODUCER_TAMPER: 'B-CHR obligation v2 items 12 and 13 (only authenticated plaintext is used; an authenticated contradiction or an authentication failure is a fail-closed error, never S024); C-REST §9',
  PRODUCER_VERIFY: 'B-CHR obligation v2 item 12 (only AEAD-verified, canonically re-encoded plaintext is returned) with the I-RESTART port error obligation (a verification failure carries AUTHENTICATION_FAILED, CONTEXT_MISMATCH, MALFORMED_INPUT or UNSUPPORTED_VALUE)',
  FAULT_RECEIPT: 'contract #463 Observable outcome item 4 (every fault cell requires a receipt that the fault reached a producer read)',
  PRODUCER_COMMITTED: 'B-CHR obligation v2 item 13 (a selector naming the candidate whose complete new generation validates gives COMMITTED; identity fields are copied from the authenticated COMMIT_RESULT and the hold, none invented) and #468 B2 (a staged INDETERMINATE in selected authority is historical evidence); I-TXN validateCommitResultEvidence',
  PRODUCER_WRITES_NOTHING: 'B-CHR obligation v2 item 13 (the producer writes nothing: no write request, the store byte-identical)',
  ESCROW: 'B-CHR obligation v2 item 14 and C-REC §4 (after COMMITTED the generation keeps its OUTPUT_ESCROW as commit-result evidence; it is never cleared by restore)',
  NON_CANONICAL: 'owner act v2 §4 (a write with any argument outside domain D is NON_CANONICAL_WRITE: a FAIL of the port under B-CHR obligation v2 item 10, recorded before any native issuance, never PASS, partial or INCOMPLETE)',
  CORRESPONDENCE: 'owner act v2 §5 (each completed REPLACE_SELECTOR has exactly one complete readwrite transaction opened while it was pending, holding exactly one successful write request carrying its produced envelope; every such request belongs to exactly one completed event; the selector read back is the last such envelope, or unchanged) with B-CHR obligation v2 item 10',
  FRESH_NONCE: 'B-CHR obligation v2 item 10 and C-FMT §4 nonce rule (every selector write is sealed with a fresh 96-bit CSPRNG nonce, also when the plaintext is unchanged; a nonce is never reused under the selector key)',
  HISTORICAL: '#468 B1 (neither WRITE_HOLD nor a selector replacement changes an immutable generation record; a selected candidate keeps its present kind-13 record); C-FMT generationCommit.historicalHoldRule',
  HISTORICAL_READER: '#468 B4 (the trusted authenticating reader validates a present kind-13 record in selected authority under C-FMT historicalHoldRule; a failure is never authority); C-FMT generationCommit.historicalHoldRule',
  EMISSION_RETRY: '#468 B3 (the interrupted committed-emission retry, with canonical kind-13 records); C-MUT §6 (CAPI-S020/S022: only the local emission call is outstanding; it returns the committed escrow and clears the hold; the selection happens exactly once)',
  NEXT: '#468 B3 (the next COMMITTED and the next INDETERMINATE from the resulting authority, with canonical kind-13 records; a classification after every terminal reconciliation); C-FMT historicalHoldRule (historical evidence is never authority for another mutation)',
  R3: 'R3 (#468 6123056674; #468 act 6171085366 §3a): for CAPI-S006/S016, while no present NONE-output kind-13 hold is encodable, an INDETERMINATE request staging a tombstone gives EVIDENCE_MISMATCH before any write',
  K19: 'owner act on #317 6379513740 §2 and owner decision on #317 6384613341 §1 (K19: every port request of every worker life is collected and judged; a final audit after quiescence closes each life not intentionally killed; a request after it is an observer error; an unjudged request is an observer error, never PASS)',
  DURABLE: 'owner decision on #317 6384613341 §1 "Durable reconciliation" (after termination and before any new initialization, the complete durable state, side databases included, equals the state rebuilt from the documented initial state and the judged requests; any difference, omission or irreconcilable outcome prevents PASS)',
});

const authority = (classify) => (classify && !classify.error ? `${classify.authority}${classify.held ? '+HELD' : ''}` : `ERROR(${classify?.error?.code ?? '?'})`);
const OUTCOME_CITE = { COMMITTED: CITE.NEW, NOT_COMMITTED: CITE.NOT_COMMITTED, INDETERMINATE: CITE.HELD };

/** The two stored states a phase can leave (C-MUT §8: exactly these, never anything else). */
export function endStates({ outcome, phase, r3 = false }) {
  const held = 'COMPLETE_OLD+HELD';
  if (r3 && outcome === 'INDETERMINATE' && phase === 'ORIGINAL') return { initial: 'COMPLETE_OLD', final: 'COMPLETE_OLD' };
  const final = { COMMITTED: 'COMPLETE_NEW', NOT_COMMITTED: 'COMPLETE_OLD', INDETERMINATE: held }[outcome];
  return { initial: phase === 'ORIGINAL' ? 'COMPLETE_OLD' : held, final };
}

/** The readwrite transactions an uninterrupted operation issues (ONE_TX): one per authority write. */
export function expectedTransactions({ outcome, phase, r3 = false }) {
  if (phase === 'ORIGINAL') return r3 && outcome === 'INDETERMINATE' ? 0 : { COMMITTED: 1, NOT_COMMITTED: 0, INDETERMINATE: 1 }[outcome];
  return { COMMITTED: 1, NOT_COMMITTED: 1, INDETERMINATE: 0 }[outcome];
}

/** Every readwrite transaction the harness saw was opened with durability strict, over `mls` only. */
export function checkDurability(trace) {
  const f = [];
  for (const e of trace ?? []) {
    if (e.ev === 'OPEN' && e.durability !== 'strict') f.push({ what: `transaction T${e.tx} durability ${e.durability} is strict`, cite: CITE.DURABILITY });
    if (e.ev === 'OPEN' && (e.stores ?? []).join(',') !== 'mls') f.push({ what: `transaction T${e.tx} scope ${JSON.stringify(e.stores)} is ["mls"]`, cite: CITE.SCOPE });
  }
  return f;
}
const opens = (trace) => (trace ?? []).filter((e) => e.ev === 'OPEN').length;
const writes = (trace) => (trace ?? []).filter((e) => e.ev === 'REQ' && ['put', 'add', 'delete', 'clear'].includes(e.op)).length;

/** R3 refusal: the INDETERMINATE request is refused before any write and leaves everything as it was. */
export function checkR3Refusal(what, response, rb, beforeDigest) {
  const f = [];
  const want = (ok, w) => { if (!ok) f.push({ what: `${what}: ${w}`, cite: CITE.R3 }); };
  want(response.error?.code === 'EVIDENCE_MISMATCH', `the INDETERMINATE request is refused EVIDENCE_MISMATCH (got ${response.error?.code ?? 'success'})`);
  want(opens(response.trace) === 0, 'no readwrite transaction is opened');
  want(rb.dbDigest === beforeDigest, 'the store is byte-identical');
  want(authority(rb.classify) === 'COMPLETE_OLD', `readback ${authority(rb.classify)} is COMPLETE_OLD`);
  want(rb.memoryHold === false, 'no memory hold is retained');
  return f;
}

/** Checks on an uninterrupted operation (no kill). Returns a list of failures with citations. */
export function checkUninterrupted(cell, response, rb) {
  const { row, outcome, phase } = cell;
  const f = [];
  const want = (ok, what, cite) => { if (!ok) f.push({ what, cite }); };
  if (cell.r3 && phase === 'ORIGINAL' && outcome === 'INDETERMINATE') return checkR3Refusal('ORIGINAL INDETERMINATE', response, rb, cell.beforeDigest);
  const { final } = endStates(cell);
  want(authority(rb.classify) === final, `readback ${authority(rb.classify)} is ${final}`, OUTCOME_CITE[outcome]);
  want(response.error === null, `operation returned without error (got ${response.error?.code})`, phase === 'ORIGINAL' ? CITE.OUTPUT_ORIGINAL : CITE.OUTPUT_RECON);
  const r = response.result ?? {};
  const output = outcome === 'COMMITTED' ? escrowHex(row) : null;
  if (phase === 'ORIGINAL') {
    want(r.commitOutcome === outcome, `commitOutcome ${r.commitOutcome} is ${outcome}`, CITE.OUTPUT_ORIGINAL);
    want((r.output ?? null) === output, `output ${r.output} is ${output}`, CITE.OUTPUT_ORIGINAL);
    if (outcome === 'INDETERMINATE') {
      want(r.state === 'RECONCILIATION_REQUIRED' && r.originalStateBefore === ORIGIN[row] && typeof r.reconciliationRef === 'string',
        'INDETERMINATE response carries RECONCILIATION_REQUIRED, originalStateBefore and reconciliationRef', CITE.INDET_RESPONSE);
      want(rb.selector?.state === SELECTOR_STATE.RECONCILIATION_REQUIRED && rb.selector.candidateGeneration !== rb.selector.generation,
        'the stored selector is RECONCILIATION_REQUIRED and binds the candidate', CITE.HELD);
    }
    if (outcome === 'NOT_COMMITTED') want(rb.candidatePresent === false, 'the candidate is discarded', CITE.NOT_COMMITTED);
    want(rb.memoryHold === (outcome === 'INDETERMINATE'), `after ORIGINAL ${outcome} a memory hold is ${outcome === 'INDETERMINATE' ? '' : 'not '}retained`, CITE.MEMORY_HOLD);
    // Item 6, observed: every readwrite transaction the operation opened was probed in time, and no
    // answer reported a hold this ORIGINAL operation did not have when it opened.
    f.push(...checkProbeCoverage('ORIGINAL', response, { earlyHoldAsserts: true, expectedHoldAtOpen: false }));
  } else {
    const kind = { COMMITTED: 'RECONCILED_COMMITTED', NOT_COMMITTED: 'NOT_COMMITTED', INDETERMINATE: 'INDETERMINATE' }[outcome];
    want(r.reconciliation === kind, `reconciliation ${r.reconciliation} is ${kind}`, CITE.OUTPUT_RECON);
    want((r.output ?? null) === output, `reconciliation output ${r.output} is ${output}`, CITE.OUTPUT_RECON);
    if (outcome === 'NOT_COMMITTED') want(rb.candidatePresent === false, 'the candidate is discarded', CITE.NOT_COMMITTED);
    // Item 6, observed on the reconciliation too. A reconciliation with SS memory alive starts from the
    // memory hold it resolves; after a context death the fresh worker has none, and the durable kind-13
    // hold it reads is not a memory hold (review impl3 R3-4).
    f.push(...checkProbeCoverage(phase, response, { earlyHoldAsserts: true, expectedHoldAtOpen: phase === 'RECONCILIATION' }));
    if (outcome === 'COMMITTED') want(rb.memoryHold === false, 'the hold is cleared by the local emission', CITE.OUTPUT_RECON);
    if (outcome === 'NOT_COMMITTED') want(rb.memoryHold === false, 'terminal NOT_COMMITTED leaves no memory hold', CITE.MEMORY_HOLD);
    if (outcome === 'INDETERMINATE' && phase === 'RECONCILIATION') want(rb.memoryHold === true, 'a continued INDETERMINATE keeps the memory hold', CITE.MEMORY_HOLD);
  }
  if (outcome === 'COMMITTED') {
    if (output !== null) want(rb.escrowOutput === output, `the committed generation keeps its OUTPUT_ESCROW (got ${rb.escrowOutput})`, CITE.ESCROW);
    // #468 B1: the selected candidate keeps exactly the kind-13 record it staged.
    if (typeof cell.stagedHold === 'string') want(rb.candidateHold === cell.stagedHold,
      'the selected candidate keeps the kind-13 record it staged, byte for byte', CITE.HISTORICAL);
  }
  const n = opens(response.trace);
  const tx = expectedTransactions(cell);
  want(n === tx, `the operation issues exactly ${tx} readwrite transaction(s) (got ${n})`, CITE.ONE_TX);
  f.push(...checkDurability(response.trace));
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
    if (got !== final) f.push({ what: `kill at ${point}: readback ${got} is ${final}`, cite: OUTCOME_CITE[cell.outcome] });
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
  const kind = { COMMITTED: 'RECONCILED_COMMITTED', NOT_COMMITTED: 'NOT_COMMITTED', INDETERMINATE: 'INDETERMINATE' }[cell.outcome];
  if (response.error === null && response.result?.reconciliation !== kind) f.push({ what: `resumed reconciliation ${response.result?.reconciliation} is ${kind}`, cite: CITE.OUTPUT_RECON });
  const output = cell.outcome === 'COMMITTED' ? escrowHex(cell.row) : null;
  if ((response.result?.output ?? null) !== output) f.push({ what: `resumed output ${response.result?.output ?? null} is ${output}`, cite: CITE.OUTPUT_RECON });
  const n = opens(response.trace);
  const tx = expectedTransactions({ ...cell, phase: 'RECONCILIATION' });
  if (n !== tx) f.push({ what: `the resumed reconciliation issues exactly ${tx} readwrite transaction(s) (got ${n})`, cite: CITE.ONE_TX });
  f.push(...checkDurability(response.trace));
  // The resumed reconciliation runs in the relaunched context: no memory hold survived the kill (R3-4).
  f.push(...checkProbeCoverage('a resumed reconciliation', response, { earlyHoldAsserts: true, expectedHoldAtOpen: false }));
  return f;
}

export function checkSurvives(before, after) {
  const f = [];
  if (authority(before.classify) !== authority(after.classify)) f.push({ what: `after a further restart ${authority(after.classify)} is ${authority(before.classify)}`, cite: CITE.SURVIVES });
  if ((before.selector?.envelope ?? null) !== (after.selector?.envelope ?? null)) f.push({ what: 'after a further restart the selector bytes are unchanged', cite: CITE.SURVIVES });
  if (before.dbDigest !== after.dbDigest) f.push({ what: 'after a further restart the whole store is unchanged', cite: CITE.SURVIVES });
  if (before.escrowOutput !== after.escrowOutput) f.push({ what: 'after a further restart the escrow is unchanged', cite: CITE.ESCROW });
  return f;
}

/** Restart reconcile (T6 without steal): durable RR, context death, fresh worker at EMPTY memory. */
export function checkRestartReconcile(cell, pre, response, rb, repeat) {
  const { outcome } = cell;
  const f = [];
  const want = (ok, what, cite) => { if (!ok) f.push({ what, cite }); };
  want(pre.lock === true, 'the fresh context re-acquired the writer lock released by context death', CITE.LOCK);
  want(pre.memoryHold === false, 'the fresh worker holds no memory hold', CITE.RESUME);
  want(authority(pre.classify) === 'COMPLETE_OLD+HELD', `relaunched readback ${authority(pre.classify)} is COMPLETE_OLD+HELD`, CITE.DURABLE_HOLD);
  // The memory hold was lost with the killed context; the durable kind-13 hold carries the reconciliation.
  f.push(...checkUninterrupted({ ...cell, phase: 'RECONCILIATION_AFTER_RESTART' }, response, rb));
  if (outcome === 'INDETERMINATE') {
    want(rb.selector?.envelope === pre.selector?.envelope && rb.dbDigest === pre.dbDigest, 'continued INDETERMINATE leaves the stored bytes unchanged', CITE.CONTINUED);
  } else {
    want(repeat?.error?.code === 'NO_RECONCILIATION_PENDING' && (repeat?.result?.output ?? null) === null,
      `a repeat reconciliation is NO_RECONCILIATION_PENDING (got ${repeat?.error?.code ?? repeat?.result?.reconciliation})`, CITE.REPEAT);
  }
  return f;
}

/**
 * The memory-hold probe (obligation item 6; review impl1 F3): for every armed readwrite transaction the
 * operation opened, the port answered the harness. With `earlyHoldAsserts`, at least one answer arrived
 * before that transaction's completion, and every such answer reports the hold the operation started with
 * (`expectedHoldAtOpen`). An answer that arrived after the completion is coverage only: it says nothing about
 * the hold while the transaction ran, so it is never compared (review impl3 R3-4). "Could not observe in
 * time" is never a pass: since cycle 4 (review impl4 R4-1) it is reported apart, as an entry marked
 * `unobserved: true` that the run counts separately from port failures (a correct port that samples its
 * hold at once and answers late is not rejected); only a timely answer reporting the wrong hold is a port
 * failure.
 */
export function checkProbeCoverage(cell, response, { earlyHoldAsserts = true, expectedHoldAtOpen = false } = {}) {
  const f = [];
  const txs = new Set((response?.trace ?? []).filter((e) => e.ev === 'OPEN').map((e) => e.tx));
  const probes = response?.probes ?? [];
  for (const tx of txs) {
    const answers = probes.filter((p) => p.tx === tx);
    const aborted = (response.trace ?? []).some((e) => e.tx === tx && e.ev === 'ABORT');
    for (const a of answers.filter((p) => p.phase === 'AUX')) {
      const d = a.diagnostic;
      if (d.kind === 'timeout') f.push({ unobserved: true, what: `${cell}: T${tx} probe bound elapsed`, cite: CITE.NO_EARLY_HOLD });
      else if (d.kind !== 'inactive' && !(aborted && d.error === 'AbortError')) f.push({ harnessError: true, what: `${cell}: T${tx} observer ${d.kind}: ${d.error}`, cite: CITE.NO_EARLY_HOLD });
    }
    for (const phase of aborted ? ['OPEN'] : ['OPEN', 'POST']) {
      const phaseAnswers = answers.filter((a) => a.phase === phase && !a.invalidated);
      if (!phaseAnswers.length) { f.push({ unobserved: true, what: `${cell}: T${tx} ${phase} sample unavailable`, cite: CITE.NO_EARLY_HOLD }); continue; }
      const timely = phaseAnswers.filter((a) => a.error === undefined && a.late === false);
      if (!timely.length) { f.push({ unobserved: true, what: `${cell}: T${tx} ${phase} sample late/error`, cite: CITE.NO_EARLY_HOLD }); continue; }
      if (earlyHoldAsserts) {
        // A surviving reconciliation hold may be legitimately cleared before POST.
        // An absent original hold may never become a new authoritative hold early.
        const wrong = timely.find((a) => expectedHoldAtOpen ? phase === 'OPEN' && !a.held : a.held);
        if (wrong) f.push({ what: `${cell}: T${tx} ${phase} premature/new or missing opening hold`, cite: CITE.NO_EARLY_HOLD });
      }
    }
  }
  return f;
}

/**
 * T9 on the port's own terminal readback producer (obligation item 13), in fixed, port-independent cells
 * (T9_CELLS). Every cell judges the producer's own section (`response.producer`, the same shape from every
 * worker helper: error, trace, probes, fingerprint), which must be present (review impl3 R3-2, R2-6). A
 * fault case whose fault never reached a producer read fails (receipt, searched in the producer's trace,
 * R3-3). A forged state the port refuses to write (nothing written) is a pass for every forging cell, the
 * selector ones included (review impl1 F1). Every producer path must write nothing: no write request and
 * the fingerprint around it unchanged; a readwrite transaction holding only reads is permitted (contract
 * Acceptance, get-only readwrite control; R3-1), its durability and scope are still checked. A failed
 * producer is not followed by any reconciliation (no evidence is synthesized, R3-3). `memoryHold` says
 * whether SS memory survived into the reconciliation (only `READ_FAIL_MEMORY`, R3-4).
 */
export function checkProducer(kind, pre, response, rb, { memoryHold = false } = {}) {
  const f = [];
  const want = (ok, what, cite) => { if (!ok) f.push({ what, cite }); };
  const trace = response.trace ?? [];
  const output = response.result?.output ?? null;
  const p = response.producer;
  if (p === undefined || p === null || !Array.isArray(p.trace)) {
    f.push({ what: `${kind}: the producer was exercised and its section recorded`, cite: CITE.PRODUCER_WRITES_NOTHING });
    return f;
  }
  const ptrace = p.trace;
  const producerError = p.error ?? null;
  const producerWritesNothing = () => {
    want(typeof p.before === 'string' && p.before === p.after, `${kind}: the producer writes nothing (store byte-identical around it)`, CITE.PRODUCER_WRITES_NOTHING);
    want(writes(ptrace) === 0, `${kind}: the producer issues no write request (got ${writes(ptrace)})`, CITE.PRODUCER_WRITES_NOTHING);
    f.push(...checkDurability(ptrace));
    f.push(...checkProbeCoverage(`${kind}: the producer`, p, { earlyHoldAsserts: false }));
  };
  producerWritesNothing();
  const failClosed = (label) => {
    want(response.produced === null && producerError !== null && [...VERIFY_CODES, 'EVIDENCE_MISMATCH'].includes(producerError.code),
      `${label}: fails closed with a verification code, never NOT_COMMITTED, COMMITTED or S024 (got ${JSON.stringify(response.produced)} ${producerError?.code ?? ''})`, CITE.PRODUCER_TAMPER);
  };
  const receipt = (fault) => (fault === 'READ_FAIL'
    ? ptrace.some((e) => e.ev === 'FAULT' && e.fault === 'READ_FAIL')
    : ptrace.some((e) => e.ev === 'TAMPERED' && e.changed === true));
  if (kind.startsWith('CONTRADICT_')) {
    // The forging step writes through the public port interface; a port that refuses it writes nothing,
    // and the producer that then runs against the unchanged healthy state is judged as any other.
    want(response.hadHold === true, 'setup: the SS hold is kept', CITE.PRODUCER_TAMPER);
    if (response.setup !== null) {
      want(response.wrote === false && [...VERIFY_CODES, 'EVIDENCE_MISMATCH'].includes(response.setup.code),
        `a refused forged write leaves the store unchanged with a verification code (got ${response.setup.code}, wrote ${response.wrote})`, CITE.PRODUCER_VERIFY);
      want(producerError === null && typeof response.produced?.outcome === 'number',
        `the producer against the unchanged healthy state answers (got ${producerError?.code ?? JSON.stringify(response.produced)})`, CITE.PRODUCER_NOT_COMMITTED);
      return f;
    }
    failClosed('an authenticated contradiction');
    return f;
  }
  if (kind === 'PRODUCE_COMMITTED' || kind === 'TAMPER_COMMITTED') {
    want(response.setup === null && response.hadHold === true, `setup: the commit landed with the SS hold kept (${response.setup?.code ?? 'ok'})`, CITE.PRODUCER_COMMITTED);
    if (kind === 'PRODUCE_COMMITTED') {
      want(response.produced?.outcome === 1 && response.produced?.terminal === true && producerError === null,
        `the producer gives COMMITTED terminal (got ${JSON.stringify(response.produced)} ${producerError?.code ?? ''})`, CITE.PRODUCER_COMMITTED);
      want(response.identity === 'VALID', `the produced evidence validates against the envelope (got ${JSON.stringify(response.identity)})`, CITE.PRODUCER_COMMITTED);
    } else {
      want(receipt('TAMPER'), 'TAMPER_COMMITTED: the fault reached a producer read', CITE.FAULT_RECEIPT);
      want(response.produced === null && VERIFY_CODES.includes(producerError?.code),
        `TAMPER_COMMITTED: a tampered committed generation fails closed with a verification code (got ${JSON.stringify(response.produced)} ${producerError?.code ?? ''})`, CITE.PRODUCER_VERIFY);
    }
    return f;
  }
  if (kind === 'PRODUCE') {
    want(response.produced?.outcome === 2 && response.produced?.terminal === true && producerError === null,
      `the producer gives NOT_COMMITTED terminal (got ${JSON.stringify(response.produced)} ${producerError?.code ?? ''})`, CITE.PRODUCER_NOT_COMMITTED);
    want(response.result?.reconciliation === 'NOT_COMMITTED', `reconciliation ${response.result?.reconciliation ?? response.error?.code} is NOT_COMMITTED`, CITE.PRODUCER_NOT_COMMITTED);
    want(authority(rb.classify) === 'COMPLETE_OLD' && rb.candidatePresent === false, `readback ${authority(rb.classify)} is COMPLETE_OLD with the candidate discarded`, CITE.NOT_COMMITTED);
    want(output === null, 'nothing is emitted', CITE.OUTPUT_RECON);
    // The reconciliation is its own armed section: its transactions, durability and probes are counted.
    want(opens(trace) === 1, `the reconciliation after the producer issues exactly 1 readwrite transaction (got ${opens(trace)})`, CITE.ONE_TX);
    f.push(...checkDurability(trace));
    f.push(...checkProbeCoverage('the reconciliation after the producer', response, { earlyHoldAsserts: true, expectedHoldAtOpen: memoryHold }));
    return f;
  }
  want(receipt(kind.startsWith('READ_FAIL') ? 'READ_FAIL' : 'TAMPER'), `${kind}: the fault reached a producer read`, CITE.FAULT_RECEIPT);
  value: {
    if (kind === 'READ_FAIL_MEMORY') {
      want(response.produced?.outcome === 3 && producerError === null && response.error === null, `READ_FAIL_MEMORY: the producer gives INDETERMINATE evidence (got ${JSON.stringify(response.produced)} ${producerError?.code ?? ''})`, CITE.PRODUCER_UNAVAILABLE);
      want(response.result?.reconciliation === 'INDETERMINATE', `READ_FAIL_MEMORY: reconciliation ${response.result?.reconciliation ?? response.error?.code} is INDETERMINATE (S024)`, CITE.PRODUCER_UNAVAILABLE);
      // A continued INDETERMINATE writes no authority.
      want(opens(trace) === 0, `READ_FAIL_MEMORY: the S024 reconciliation opens no readwrite transaction (got ${opens(trace)})`, CITE.ONE_TX);
      break value;
    }
    if (kind === 'READ_FAIL_LOST') {
      // The required code (cycle 4, review impl4 R4-3): with no readable hold the producer answers the
      // frozen API's HOLD_UNAVAILABLE (session-transaction CODE.HOLD_UNAVAILABLE), no other code.
      want(response.produced === null && producerError?.code === 'HOLD_UNAVAILABLE',
        `READ_FAIL_LOST: the producer fails closed with HOLD_UNAVAILABLE (got ${response.result?.reconciliation ?? JSON.stringify(response.produced)} ${producerError?.code ?? ''})`, CITE.PRODUCER_NO_HOLD);
    } else {
      want(response.produced === null && VERIFY_CODES.includes(producerError?.code),
        `${kind}: the producer fails closed with a verification code before any evidence, never S024 (got ${response.result?.reconciliation ?? producerError?.code ?? ''})`, CITE.PRODUCER_VERIFY);
    }
    // No evidence is synthesized after a failed producer: no reconciliation runs (R3-3).
    want(response.reconciled === false && opens(trace) === 0, `${kind}: no reconciliation runs after the failed producer (reconciled ${response.reconciled})`, CITE.PRODUCER_NO_HOLD);
  }
  want(output === null, `${kind}: nothing is emitted`, CITE.PRODUCER_NO_HOLD);
  f.push(...checkDurability(trace));
  want(rb.dbDigest === pre.dbDigest, `${kind}: the store is byte-preserved`, CITE.READ_FAIL);
  want(authority(rb.classify) === 'COMPLETE_OLD+HELD', `${kind}: the hold is unchanged (${authority(rb.classify)})`, CITE.CONTINUED);
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

/**
 * Fresh seals across one cell (obligation item 10; C-FMT §4 nonce rule), judged on write events, never on
 * plaintext equality (review impl3 R3-6): two fresh seals of unchanged plaintext are lawful. `add` takes an
 * envelope the port was seen reading (envelope, nonce); `addWrite` one selector write event of the worker
 * (`token` identifies the event; `envelope`/`nonce` what it produced; `expected` the envelope it replaced).
 * Failures: a nonce under two different envelopes; two distinct write events that produced the same
 * envelope (identical plaintext sealed with a reused nonce); a completed write whose envelope is the one
 * it replaced; a completed write whose envelope could not be observed (never a silent pass).
 */
export function nonceBook() {
  const byNonce = new Map();
  const byEnvelope = new Map();
  const putEnvelopes = new Map();
  const readEnvelopes = new Set(); // envelopes read in earlier calls: a later put of one reuses its nonce
  const tokens = new Set();
  const f = [];
  const noteNonce = (sel) => {
    const seen = byNonce.get(sel.nonce);
    if (seen === undefined) byNonce.set(sel.nonce, sel.envelope);
    else if (seen !== sel.envelope) f.push({ what: `selector nonce ${sel.nonce} is reused by a different envelope`, cite: CITE.FRESH_NONCE });
  };
  return {
    add(selector) {
      if (selector?.envelope && selector.nonce) { noteNonce(selector); readEnvelopes.add(selector.envelope); }
    },
    addWrite(w) {
      if (!w?.token || tokens.has(w.token)) return;
      tokens.add(w.token);
      if (w.status !== 'written') return;
      if (!w.envelope || !w.nonce) { f.push({ what: `selector write ${w.token}: the envelope it produced was observed`, cite: CITE.FRESH_NONCE }); return; }
      noteNonce(w);
      const other = byEnvelope.get(w.envelope);
      if (other !== undefined) f.push({ what: `selector writes ${other} and ${w.token} produced the same envelope (a reused nonce)`, cite: CITE.FRESH_NONCE });
      else byEnvelope.set(w.envelope, w.token);
      if (w.expected !== null && w.expected === w.envelope) f.push({ what: `selector write ${w.token} left the stored envelope unchanged`, cite: CITE.FRESH_NONCE });
    },
    /**
     * One selector `put` request (cycle 4, review impl4 R4-2): every put is its own write event, so two
     * puts of one envelope, in one transaction or in two, reuse a nonce under the selector key.
     */
    addPut(p) {
      if (!p?.token || tokens.has(p.token)) return;
      tokens.add(p.token);
      // Act §4: read BEFORE any filter on issuance; a non-canonical write fails even if never issued.
      if (p.nonCanonical === true) {
        f.push({ what: `request ${p.token} (${p.method}): NON_CANONICAL_WRITE (${(p.reasons ?? []).join(',')})`, cite: CITE.NON_CANONICAL });
      }
      if (typeof p.observerError === 'string') f.push({ harnessError: true, what: `request ${p.token}: observer error: ${p.observerError}`, cite: CITE.NON_CANONICAL });
      if (p.issued === false) return; // PRECLONE_REJECTED or a synchronous throw is not issuance (A2)
      if (p.issued !== true) {
        f.push({ unobserved: true, what: `request ${p.token}: native issuance metadata unavailable`, cite: CITE.FRESH_NONCE }); return;
      }
      if (p.nonCanonical !== true && p.attribution !== 'complete') {
        f.push({ unobserved: true, what: `request ${p.token}: byte attribution ${p.attribution} (${(p.reasons ?? []).join(',')})`, cite: CITE.FRESH_NONCE });
      }
      for (const s of p.envelopes ?? []) {
        noteNonce(s);
        if (readEnvelopes.has(s.envelope)) f.push({ what: `selector put ${p.token} re-emits an envelope already read before it (a reused nonce, even if the request fails or aborts)`, cite: CITE.FRESH_NONCE });
        const other = putEnvelopes.get(s.envelope);
        if (other !== undefined && other !== p.token) f.push({ what: `selector puts ${other} and ${p.token} wrote the same envelope (a reused nonce)`, cite: CITE.FRESH_NONCE });
        else putEnvelopes.set(s.envelope, p.token);
      }
    },
    /** Everything a worker response observed: `{ reads, writes, puts }`. */
    addObserved(selectors) {
      // Puts first: reads of the same response (read-backs of its own writes) are not "before" its puts.
      for (const p of selectors?.puts ?? []) this.addPut(p);
      for (const w of selectors?.writes ?? []) this.addWrite(w);
      for (const s of selectors?.reads ?? []) this.add(s);
    },
    /** Audit failures the worker attached to a reply (act §3 wrapper check, act §5 correspondence). */
    addAudit(list) { for (const x of list ?? []) f.push(x); },
    failures: () => f,
  };
}

/**
 * Owner act v2 §5, judged on observer records: `events` are the settled REPLACE_SELECTOR events of the
 * worker (status, startSeq, endSeq, derived envelope), `txs` the terminal transactions opened since the
 * last audit with their write records, `stored` the stored selector envelope read after them and
 * `lastStored` the one read at the previous audit (undefined when unknown, e.g. a fresh worker).
 */
const SELECTOR_WRITES = new Set(['put', 'add', 'update']);
/**
 * `carried`: the last completed selector request of earlier batches judged while the read-back was still
 * deferred; `out.last` receives this batch's last completed request (or `carried`) for the next batch.
 */
/**
 * Item 10 on observer order (red-team Fase 4): a port write whose envelope was known before it was
 * issued (returned by an earlier read, given as the expected envelope of a REPLACE_SELECTOR, or written by
 * an earlier request) reuses that envelope's nonce, whatever the request's fate. `known`: [{ envelope, seq }].
 */
export function checkReemission(puts, known) {
  // Every request, whether or not it was issued during a port call (D17): the obligation is on what the
  // port writes, not on when. A request reuses a nonce if it carries an envelope known before it, or a
  // different envelope sealed with a nonce known before it (D18), or two different envelopes under one
  // nonce; whatever the fate of the request or of its transaction.
  const f = [];
  for (const p of puts) {
    // Emission, not attempt (act v2 §4): PRECLONE_REJECTED or a synchronous throw is not issuance; missing
    // issuance metadata is never read as "not issued" (CP1).
    if (p.issued === false) continue;
    if (p.issued !== true) { f.push({ unobserved: true, what: `request ${p.token}: native issuance metadata unavailable`, cite: CITE.FRESH_NONCE }); continue; }
    const env = p.envelopes ?? [];
    for (let i = 0; i < env.length; i++) {
      for (let j = i + 1; j < env.length; j++) {
        if (env[i].nonce && env[i].nonce === env[j].nonce && env[i].envelope !== env[j].envelope) f.push({ what: `selector put ${p.token} carries two different envelopes sealed with nonce ${env[i].nonce} (a reused nonce)`, cite: CITE.FRESH_NONCE });
      }
      const s = env[i];
      const k = known.find((x) => x.seq < p.seq && x.token !== p.token && (x.envelope === s.envelope || (typeof x.nonce === 'string' && x.nonce === s.nonce)));
      if (k !== undefined) {
        const how = k.envelope === s.envelope ? 'an envelope' : `a different envelope with nonce ${s.nonce}, a nonce`;
        f.push({ what: `selector put ${p.token} re-emits ${how} known since ${k.via ?? 'an earlier request'} at ${k.seq} (a reused nonce)`, cite: CITE.FRESH_NONCE });
      }
    }
  }
  return f;
}
export function checkCorrespondence({ events, txs, stored, lastStored, carried = null, out = null }) {
  const f = [];
  const want = (ok, what) => { if (!ok) f.push({ what, cite: CITE.CORRESPONDENCE }); };
  const carrying = (t) => t.writes.filter((w) => SELECTOR_WRITES.has(w.method) && w.status === 'success' && (w.envelopes ?? []).length > 0);
  const matched = new Set();
  let last = null;
  for (const e of events) {
    if (e.status !== 'written') continue;
    const cands = txs.filter((t) => t.mode === 'readwrite' && t.openSeq > e.startSeq && t.openSeq < e.endSeq && t.terminal === 'complete' && carrying(t).length > 0);
    want(cands.length === 1, `REPLACE_SELECTOR ${e.token}: exactly one complete transaction opened while it was pending carries a selector write (got ${cands.length})`);
    if (cands.length !== 1) continue;
    const reqs = carrying(cands[0]);
    want(reqs.length === 1, `REPLACE_SELECTOR ${e.token}: its transaction holds exactly one successful selector-carrying request (got ${reqs.length})`);
    if (reqs.length !== 1) continue;
    const r = reqs[0];
    want(r.envelopes.length === 1, `REPLACE_SELECTOR ${e.token}: request ${r.token} carries exactly one selector envelope (got ${r.envelopes.length})`);
    if (e.envelope !== null && e.envelope !== undefined) want(r.envelopes[0].envelope === e.envelope, `REPLACE_SELECTOR ${e.token}: request ${r.token} carries its produced envelope`);
    want(!matched.has(r.token), `request ${r.token} corresponds to more than one completed REPLACE_SELECTOR`);
    matched.add(r.token);
    if (last === null || (r.settledSeq ?? r.issuedSeq) > (last.settledSeq ?? last.issuedSeq)) last = r;
  }
  for (const t of txs) {
    if (t.terminal !== 'complete') continue;
    for (const r of carrying(t)) want(matched.has(r.token), `request ${r.token} (${r.method}) wrote a selector envelope that belongs to no completed REPLACE_SELECTOR`);
  }
  if (last === null) last = carried;
  // `stored` is undefined while an event or transaction is still pending: the read-back rule waits for it.
  if (stored !== undefined && last !== null) want(stored === last.envelopes[0].envelope, 'the selector read back is the envelope of the last completed selector request');
  else if (stored !== undefined && lastStored !== undefined) want(stored === lastStored, 'with no completed selector request the stored selector is unchanged');
  if (out !== null) out.last = last;
  return f;
}

/** Debris, then a second mutation over it. */
export function checkDebris(cell, stage, data) {
  const { outcome } = cell;
  const f = [];
  const want = (ok, what, cite) => { if (!ok) f.push({ what, cite }); };
  if (stage === 'DEBRIS') {
    want(authority(data.classify) === 'COMPLETE_OLD', `with debris present readback ${authority(data.classify)} is COMPLETE_OLD`, CITE.DEBRIS);
    want(Array.isArray(data.numbers) && data.numbers.join(',') === '1,2', `the number-only inventory is exactly {1,2} (got ${JSON.stringify(data.numbers)})`, CITE.NEVER_REUSE);
  } else if (stage === 'REUSE') {
    const code = cell.r3 && outcome === 'INDETERMINATE' ? 'EVIDENCE_MISMATCH' : 'STALE_PARENT';
    want(data.response.error?.code === code, `a candidate reusing the debris number is refused ${code} (got ${data.response.error?.code ?? 'success'})`, cell.r3 && outcome === 'INDETERMINATE' ? CITE.R3 : CITE.NEVER_REUSE);
    want(data.rb.dbDigest === data.before, 'the refused request wrote nothing', CITE.NEVER_REUSE);
  } else if (stage === 'RESEAL') {
    // seedDebris replaced the selector with the same plaintext: the envelope must still change, and a
    // writer holding the earlier envelope must be refused with nothing written.
    want(data.after !== null && data.after.plaintext === data.before.plaintext && data.after.envelope !== data.before.envelope,
      'an unchanged-plaintext selector replacement is re-sealed (new envelope)', CITE.FRESH_NONCE);
    want(data.after !== null && data.after.nonce !== data.before.nonce, 'the re-seal uses a fresh nonce', CITE.FRESH_NONCE);
    f.push(...checkDelayedWriter('RESEAL', data.delayed, data.digestBefore, data.digestAfter));
  } else if (stage === 'SECOND') {
    f.push(...checkUninterrupted({ ...cell, phase: 'ORIGINAL', beforeDigest: data.beforeDigest }, data.response, data.rb));
    want(data.debrisDigest === data.debrisAfter, 'the debris generation is preserved byte-identical', CITE.DEBRIS);
    const n = Array.isArray(data.rb.numbers) ? data.rb.numbers.join(',') : JSON.stringify(data.rb.numbers);
    const expected = outcome === 'NOT_COMMITTED' || (cell.r3 && outcome === 'INDETERMINATE') ? '1,2' : '1,2,3';
    want(n === expected, `after the second mutation the inventory ${n} is exactly ${expected} (parent kept, debris kept, the new candidate iff staged)`, CITE.NEVER_REUSE);
  }
  return f;
}

/** #468 B3: the interrupted committed-emission retry. */
export function checkEmissionRetry(cell, d) {
  const f = [];
  const want = (ok, what) => { if (!ok) f.push({ what, cite: CITE.EMISSION_RETRY }); };
  want(d.first.error?.code === 'BCHR_EMISSION_INTERRUPTED', `the interrupted emission fails (got ${d.first.error?.code ?? 'success'})`);
  want(authority(d.mid.classify) === 'COMPLETE_NEW', `after the interrupted emission the authority is COMPLETE_NEW (got ${authority(d.mid.classify)})`);
  want(d.mid.memoryHold === true, 'the hold stays in SS memory until the local emission returns');
  want(d.retry.error === null && d.retry.result?.reconciliation === 'RECONCILED_COMMITTED', `the retry is RECONCILED_COMMITTED (got ${d.retry.error?.code ?? d.retry.result?.reconciliation})`);
  want((d.retry.result?.output ?? null) === escrowHex(cell.row), `the retry returns the committed escrow (got ${d.retry.result?.output ?? null})`);
  want(opens(d.retry.trace) === 0, 'the retry writes no authority (the selection happened exactly once)');
  want(authority(d.rb.classify) === 'COMPLETE_NEW' && d.rb.memoryHold === false, `after the retry COMPLETE_NEW with no hold (got ${authority(d.rb.classify)}, hold ${d.rb.memoryHold})`);
  want(d.rb.candidateHold === d.stagedHold, 'the selected candidate keeps its kind-13 record byte for byte');
  want(d.repeat.error?.code === 'NO_RECONCILIATION_PENDING', `a further repeat is NO_RECONCILIATION_PENDING (got ${d.repeat.error?.code ?? d.repeat.result?.reconciliation})`);
  return f;
}

/**
 * #468 B3: from the authority a terminal COMMITTED left (generation 2, keeping its kind-13 record), the
 * next mutation (generation 3): COMMITTED selects it; INDETERMINATE holds it, and after context death
 * the durable hold reconciles it COMMITTED. Under R3 a NONE row's next INDETERMINATE is refused. The
 * next operation and the reconciliation are judged by the same transaction, durability and memory-hold
 * rules as every other operation (B-CHR-CANON r1 C4).
 */
export function checkNext(cell, d) {
  const f = [];
  const want = (ok, what, cite = CITE.NEXT) => { if (!ok) f.push({ what, cite }); };
  want(d.base.error === null && authority(d.baseRb.classify) === 'COMPLETE_NEW', `setup: the resulting authority is generation 2 (got ${d.base.error?.code ?? authority(d.baseRb.classify)})`);
  const kept = d.baseRb.candidateHold;
  want(d.oldHold === kept, 'generation 2 keeps its kind-13 record byte for byte after the next mutation');
  if (cell.r3Next) {
    f.push(...checkR3Refusal('next INDETERMINATE', d.next, d.nextRb, d.baseDigest));
    want(d.numbers === '1,2', `the inventory is exactly {1,2} (got ${d.numbers})`);
    return f;
  }
  const output = cell.outcome === 'COMMITTED' ? escrowHex(cell.nextRow) : null;
  const tx = expectedTransactions({ outcome: cell.outcome, phase: 'ORIGINAL' });
  want(opens(d.next.trace) === tx, `the next ${cell.outcome} issues exactly ${tx} readwrite transaction(s) (got ${opens(d.next.trace)})`, CITE.ONE_TX);
  f.push(...checkDurability(d.next.trace));
  f.push(...checkProbeCoverage(`the next ${cell.outcome}`, d.next, { earlyHoldAsserts: true, expectedHoldAtOpen: false }));
  if (d.recon !== undefined) f.push(...checkProbeCoverage('the reconciliation of the next INDETERMINATE', d.recon, { earlyHoldAsserts: true, expectedHoldAtOpen: false }));
  if (cell.outcome === 'COMMITTED') {
    want(d.next.error === null && d.next.result?.commitOutcome === 'COMMITTED' && (d.next.result?.output ?? null) === output,
      `the next COMMITTED commits with its output (got ${d.next.error?.code ?? d.next.result?.commitOutcome})`);
    want(authority(d.nextRb.classify) === 'COMPLETE_NEW' && d.nextRb.classify.generation === '3', `after it the authority is generation 3 (got ${authority(d.nextRb.classify)} ${d.nextRb.classify?.generation})`);
    want(d.nextRb.candidateHold === d.next.stagedHold, 'generation 3 keeps the kind-13 record it staged', CITE.HISTORICAL);
  } else {
    want(d.next.error === null && d.next.result?.commitOutcome === 'INDETERMINATE', `the next INDETERMINATE holds (got ${d.next.error?.code ?? d.next.result?.commitOutcome})`);
    want(authority(d.nextRb.classify) === 'COMPLETE_OLD+HELD', `after it generation 2 stays authority, held (got ${authority(d.nextRb.classify)})`);
    want(d.pre.memoryHold === false && authority(d.pre.classify) === 'COMPLETE_OLD+HELD', 'after context death the durable hold is all that is left');
    want(d.recon.error === null && d.recon.result?.reconciliation === 'RECONCILED_COMMITTED' && (d.recon.result?.output ?? null) === escrowHex(cell.nextRow),
      `the durable hold reconciles COMMITTED with its output (got ${d.recon.error?.code ?? d.recon.result?.reconciliation})`);
    want(opens(d.recon.trace) === 1, `the reconciliation issues exactly 1 readwrite transaction (got ${opens(d.recon.trace)})`, CITE.ONE_TX);
    f.push(...checkDurability(d.recon.trace));
    want(authority(d.reconRb.classify) === 'COMPLETE_NEW' && d.reconRb.classify.generation === '3', `after it the authority is generation 3 (got ${authority(d.reconRb.classify)})`);
  }
  want(d.numbers === '1,2,3', `the inventory is exactly {1,2,3} (got ${d.numbers})`);
  return f;
}

/** #468 B4: a selected generation whose present kind-13 record is not historical evidence is never authority. */
export function checkHistoricalForged(d) {
  const f = [];
  const want = (ok, what) => { if (!ok) f.push({ what, cite: CITE.HISTORICAL_READER }); };
  if (d.setup !== null) {
    want(d.wrote === false && VERIFY_CODES.includes(d.setup.code), `a refused write leaves the store unchanged with a verification code (got ${d.setup.code}, wrote ${d.wrote})`);
    want(authority(d.classify) === 'COMPLETE_OLD', `the seeded authority is still COMPLETE_OLD (got ${authority(d.classify)})`);
  } else {
    want(d.classify?.error !== undefined, `the forged generation is never classified as authority (got ${authority(d.classify)})`);
  }
  return f;
}

// ---- K19 durable reconciliation (owner decision on #317 6384613341 §1) --------------------------------------
/**
 * The durable state rebuilt from the documented initial state (no database: a fresh profile or browser
 * context) and the effects of the judged requests of every worker life, as the observer recorded them:
 * database identity and version, object stores, and per store the key -> value digest map. Effects apply
 * per transaction in commit order (its `terminalSeq`), requests in issue order: put/add/cursor update set
 * a key, delete/cursor delete remove it, clear empties the store; an aborted transaction applies nothing.
 * A transaction of an intentionally killed life without an observed outcome may or may not have
 * committed: every combination is a candidate, and the trusted reader's state selects one. Anything the
 * model cannot rebuild (an opaque key or value, a write into an unknown store, no outcome in a life that
 * was not killed) is a failure: an irreconcilable outcome never passes.
 */
export function durableModel() {
  let state = new Map(); // db -> { version, stores: Map(store -> Map(key -> digest)) }
  const copy = (s) => new Map([...s].map(([d, v]) => [d, { version: v.version, stores: new Map([...v.stores].map(([n, m]) => [n, new Map(m)])) }]));
  const order = (r) => r.issuedSeq ?? r.seq;
  const fail = (f, what) => f.push({ what: `K19 durable model: ${what}`, cite: CITE.DURABLE });
  function applyGroup(s, rs, unknown, f) {
    for (const r of [...rs].sort((a, b) => order(a) - order(b))) {
      if (r.kind === 'schema') {
        if (r.opaque) { fail(f, `schema record ${r.token} (${r.method}) cannot be rebuilt`); continue; }
        if (r.method === 'upgrade') { if (!s.has(r.db)) s.set(r.db, { version: r.newVersion, stores: new Map() }); else s.get(r.db).version = r.newVersion; continue; }
        if (r.method === 'deleteDatabase') { s.delete(r.db); continue; }
        const db = s.get(r.db);
        if (db === undefined) { fail(f, `schema record ${r.token} (${r.method}) on database ${r.db} absent from the model`); continue; }
        if (r.method === 'createObjectStore') db.stores.set(r.store, new Map());
        else if (r.method === 'deleteObjectStore') db.stores.delete(r.store);
        else if (r.method === 'renameObjectStore') {
          // D23: a rename keeps the store's content under its new name.
          const m = db.stores.get(r.from);
          if (m === undefined) { fail(f, `schema record ${r.token} renames ${r.db}/${r.from}, a store absent from the model`); continue; }
          db.stores.delete(r.from); db.stores.set(r.store, m);
        } else fail(f, `schema record ${r.token}: unknown method ${r.method}`);
        continue;
      }
      if (r.issued !== true) continue; // PRECLONE_REJECTED, synchronous throw: never issued, no effect
      if (r.status === 'error') continue; // a failed request of a committed transaction has no effect
      if (r.status !== 'success' && !(unknown && r.status === 'pending')) { fail(f, `request ${r.token} (${r.method}) in a committed transaction has status ${r.status}`); continue; }
      const m = s.get(r.db)?.stores.get(r.store);
      if (m === undefined) { fail(f, `request ${r.token} (${r.method}) on ${r.db}/${r.store}, a store absent from the model`); continue; }
      if (r.method === 'clear') { m.clear(); continue; }
      if (r.opaque || r.key === null || r.key === undefined) { fail(f, `request ${r.token} (${r.method}) on ${r.db}/${r.store} has no rebuildable key`); continue; }
      if (r.method === 'put' || r.method === 'add' || r.method === 'update') {
        if (r.digest === null || r.digest === undefined) { fail(f, `request ${r.token} (${r.method}) has no value digest`); continue; }
        m.set(r.key, r.digest);
      } else if (r.method === 'delete' || r.method === 'cursor-delete') m.delete(r.key);
      else fail(f, `request ${r.token}: unknown method ${r.method}`);
    }
  }
  const canonical = (s) => JSON.stringify([...s].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([d, v]) => [d, v.version,
    [...v.stores].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([n, m]) => [n, [...m].sort((a, b) => (a[0] < b[0] ? -1 : (a[0] > b[0] ? 1 : 0)))])]));
  // Each candidate is a durable state with the failures of its own reconstruction (D26): an unknown outcome
  // of a killed life is a choice between explicit alternatives (committed or not), and only the alternative
  // the trusted reader's state selects is judged; one that cannot be rebuilt never passes.
  let candidates = [{ s: state, f: [] }];
  return {
    /** Apply one finished worker life ({ id, records: Map, killed }). Returns failures. */
    applyLife(life) {
      const f = [];
      const groups = new Map(); const events = []; const unknown = [];
      for (const r of life.records.values()) {
        if (r.txg === null || r.txg === undefined) {
          if (r.kind === 'schema' && r.method === 'deleteDatabase') {
            if (r.status === 'success') events.push({ seq: r.settledSeq, rs: [r] });
            else if (r.status === 'pending' && life.killed) unknown.push({ seq: r.seq, rs: [r] });
            else if (r.status === 'pending') fail(f, `deleteDatabase ${r.token} of life ${life.id} has no outcome after its closure`);
          } else if (r.issued === true || r.kind === 'schema') fail(f, `record ${r.token} (${r.method}) of life ${life.id} belongs to no transaction`);
          continue;
        }
        if (!groups.has(r.txg)) groups.set(r.txg, []);
        groups.get(r.txg).push(r);
      }
      for (const [g, rs] of groups) {
        const t = rs.find((r) => r.terminal !== null && r.terminal !== undefined);
        if (t?.terminal === 'complete') events.push({ seq: t.terminalSeq, rs });
        else if (t?.terminal === 'abort') continue;
        else if (life.killed) unknown.push({ seq: Math.min(...rs.map(order)), rs });
        else if (rs.some((r) => r.issued === true || r.kind === 'schema')) fail(f, `transaction ${g} of life ${life.id} has no outcome after its closure`);
      }
      events.sort((a, b) => a.seq - b.seq); unknown.sort((a, b) => a.seq - b.seq);
      if (unknown.length > 6) { fail(f, `${unknown.length} transactions of the killed life ${life.id} without an outcome: irreconcilable`); return f; }
      const next = [];
      for (const base of candidates) {
        const s0 = copy(base.s);
        for (const e of events) applyGroup(s0, e.rs, false, f);
        for (let mask = 0; mask < 2 ** unknown.length; mask++) {
          const s = copy(s0); const own = [...base.f];
          unknown.forEach((u, i) => { if (mask & (1 << i)) applyGroup(s, u.rs, true, own); });
          next.push({ s, f: own });
        }
      }
      // Identical states: a clean reconstruction is kept in preference to an unrebuildable one.
      const byState = new Map();
      for (const c of next) { const k = canonical(c.s); const o = byState.get(k); if (o === undefined || (o.f.length > 0 && c.f.length === 0)) byState.set(k, c); }
      candidates = [...byState.values()];
      const once = new Set(); return f.filter((x) => (once.has(x.what) ? false : (once.add(x.what), true)));
    },
    /** Compare the trusted reader's state ({ dbs }) with the model; on a match the model becomes it. */
    match(read) {
      const f = [];
      if (!Array.isArray(read?.dbs)) { f.push({ harnessError: true, what: 'K19: the trusted reader returned no durable state', cite: CITE.DURABLE }); return f; }
      const s = new Map();
      for (const d of read.dbs) {
        if (d.error) { f.push({ what: `K19 durable reconciliation: database ${d.name} could not be read (${d.error})`, cite: CITE.DURABLE }); continue; }
        s.set(d.name, { version: d.version, stores: new Map(d.stores.map((x) => [x.name, new Map(x.entries)])) });
      }
      const got = canonical(s);
      const hit = candidates.find((c) => canonical(c.s) === got);
      if (hit !== undefined && hit.f.length > 0) {
        // The durable state is explained only by an alternative that could not be rebuilt.
        const once = new Set();
        for (const x of hit.f) if (!once.has(x.what)) { once.add(x.what); f.push(x); }
      }
      if (hit === undefined) {
        const want = candidates.find((c) => c.f.length === 0)?.s ?? candidates[0]?.s ?? new Map();
        const diffs = [];
        for (const name of new Set([...want.keys(), ...s.keys()])) {
          const a = want.get(name); const b = s.get(name);
          if (a === undefined || b === undefined) { diffs.push(`database ${name} ${a === undefined ? 'present but not rebuilt' : 'rebuilt but absent'}`); continue; }
          if (a.version !== b.version) diffs.push(`database ${name} version ${b.version}, rebuilt ${a.version}`);
          for (const st of new Set([...a.stores.keys(), ...b.stores.keys()])) {
            const x = a.stores.get(st); const y = b.stores.get(st);
            if (x === undefined || y === undefined) { diffs.push(`store ${name}/${st} ${x === undefined ? 'present but not rebuilt' : 'rebuilt but absent'}`); continue; }
            for (const k of new Set([...x.keys(), ...y.keys()])) if (x.get(k) !== y.get(k)) diffs.push(`${name}/${st} key ${k.slice(0, 40)}: durable ${y.has(k) ? y.get(k).slice(0, 12) : 'absent'}, rebuilt ${x.has(k) ? x.get(k).slice(0, 12) : 'absent'}`);
          }
        }
        f.push({ what: `K19 durable reconciliation: the durable state differs from the state rebuilt from the judged requests (${candidates.length} candidate(s)): ${diffs.slice(0, 6).join('; ')}`, cite: CITE.DURABLE });
      }
      candidates = [{ s, f: [] }]; // continue from what is durable, so one difference is reported once
      return f;
    },
    candidates: () => candidates.length,
  };
}

/**
 * The worker lives of one run, from the documented initial state (a fresh profile or context) on, as the
 * host sees them through the existing channels (RPC replies and /hook): their K19 records, how each life
 * ended (its final audit, or an intentional kill), late requests after a final audit, and the trusted
 * reader's state at the start of each new life. Every life must end by its final audit or by an
 * intentional kill; every life is reconciled by the reader of the next one.
 */
export function nonceLedger() {
  const byNonce = new Map(); // nonce -> { envelope, life, via }
  const f = [];
  return {
    /**
     * Enter one finished worker life, in run order: its issued requests and its selector reads (and the
     * expected envelopes of its REPLACE_SELECTOR events) in the life's own sequence order. An issued
     * request that carries an envelope or a nonce known before it, in this life or an earlier one, or two
     * different envelopes under one nonce, reuses a nonce, whatever the fate of the request or of its
     * transaction (CP1: a killed life never reaches its own final judgement).
     */
    enter(L) {
      const events = [];
      for (const r of L.records.values()) {
        if (r.kind !== 'write') continue;
        if (r.issued !== true && r.issued !== false) { f.push({ unobserved: true, what: `request ${r.token} (life ${L.id}): native issuance metadata unavailable`, cite: CITE.FRESH_NONCE }); continue; }
        if (r.issued === true && (r.envelopes ?? []).length > 0) events.push({ seq: r.seq, write: r });
      }
      for (const x of L.reads) {
        if (typeof x?.envelope === 'string') events.push({ seq: x.seq, read: x });
        else if (x?.limit === true) f.push({ unobserved: true, what: `K19: a ${x.via ?? 'read'} result (life ${L.id}) exceeded the object limit; the selector envelopes it returned are unknown`, cite: CITE.FRESH_NONCE });
      }
      events.sort((a, b) => a.seq - b.seq || (a.read ? -1 : 0) - (b.read ? -1 : 0));
      for (const e of events) {
        if (e.read) {
          const n = byNonce.get(e.read.nonce);
          if (n === undefined) byNonce.set(e.read.nonce, { envelope: e.read.envelope, life: L.id, via: `a ${e.read.via ?? 'read'} in life ${L.id}` });
          else if (n.envelope !== e.read.envelope) f.push({ what: `selector nonce ${e.read.nonce} sealed two different envelopes (read in life ${L.id}, known since ${n.via}) (a reused nonce)`, cite: CITE.FRESH_NONCE });
          continue;
        }
        const r = e.write; const env = r.envelopes;
        for (let i = 0; i < env.length; i++) {
          for (let j = i + 1; j < env.length; j++) if (env[i].nonce === env[j].nonce && env[i].envelope !== env[j].envelope) f.push({ what: `selector put ${r.token} (life ${L.id}) carries two different envelopes sealed with nonce ${env[i].nonce} (a reused nonce)`, cite: CITE.FRESH_NONCE });
          const n = byNonce.get(env[i].nonce);
          if (n !== undefined && n.via !== `request ${r.token}`) {
            f.push({ what: `selector put ${r.token} (life ${L.id}) re-emits ${n.envelope === env[i].envelope ? 'an envelope' : `a different envelope with nonce ${env[i].nonce}, a nonce`} known since ${n.via} (a reused nonce)`, cite: CITE.FRESH_NONCE });
          } else if (n === undefined) byNonce.set(env[i].nonce, { envelope: env[i].envelope, life: L.id, via: `request ${r.token}` });
        }
      }
    },
    failures: () => f.splice(0),
  };
}

/**
 * The worker lives of one run, from the documented initial state (a fresh profile or context) on, as the
 * host sees them through the existing channels (RPC replies and /hook): their K19 records, how each life
 * ended (its final audit, or an intentional kill), late requests after a final audit, and the trusted
 * reader's state at the start of each new life. Every life must end by its final audit or by an
 * intentional kill; every life is reconciled by the reader of the next one. `ledger`: the nonce ledger,
 * shared by every lifeChain of one launcher invocation (it survives a fresh profile).
 */
export function lifeChain({ ledger = nonceLedger() } = {}) {
  const model = durableModel(); const lives = new Map(); const order = []; const f = [];
  const life = (id) => {
    if (!lives.has(id)) { lives.set(id, { id, records: new Map(), reads: [], readSeen: new Set(), errorSeen: new Set(), closed: false, killed: false, applied: false, ledgered: false, late: 0 }); order.push(id); }
    return lives.get(id);
  };
  const enter = (L) => {
    if (!L.ledgered) {
      L.ledgered = true; ledger.enter(L);
      // A killed life never reached its final audit: its write records are judged here too (act v2 §4: a
      // NON_CANONICAL_WRITE is read before any filter on issuance; an observer error is never PASS).
      if (L.killed) {
        for (const r of L.records.values()) {
          if (r.kind !== 'write') continue;
          if (r.nonCanonical === true) f.push({ what: `NON_CANONICAL_WRITE: ${r.token} (${r.method}${r.store ? ` on ${r.store}` : ''}, killed life ${L.id}): ${(r.reasons ?? []).join(', ')}`, cite: CITE.NON_CANONICAL });
          if (typeof r.observerError === 'string') f.push({ harnessError: true, what: `observer error on ${r.token} (killed life ${L.id}): ${r.observerError}`, cite: CITE.NON_CANONICAL });
        }
      }
    }
    f.push(...ledger.failures());
  };
  // A record delivered twice (RPC reply and /hook) or updated (pending -> settled -> terminal) is one
  // request; an update never moves it back.
  const rank = (r) => (r.terminal !== null && r.terminal !== undefined ? 3 : (r.status === 'success' || r.status === 'error' ? 2 : (r.issued === true ? 1 : 0)));
  return {
    /** A `k19` delta of a reply or a hook. */
    absorb(k19) {
      if (typeof k19?.life !== 'string') return;
      const L = life(k19.life);
      for (const r of k19.records ?? []) { const o = L.records.get(r.token); if (o === undefined || rank(r) >= rank(o)) L.records.set(r.token, r); }
      for (const x of k19.reads ?? []) { const k = `${x.seq}:${x.via}:${x.envelope ?? 'limit'}`; if (!L.readSeen.has(k)) { L.readSeen.add(k); L.reads.push(x); } }
      // CP6: a delivery the host did not receive (a rejected hook) is a harness error of the run, whatever
      // happens to the life afterwards (killed before its next audit included).
      for (const e of k19.deliveryErrors ?? []) if (!L.errorSeen.has(e)) { L.errorSeen.add(e); f.push({ harnessError: true, what: `K19: ${e}`, cite: CITE.K19 }); }
      if (k19.closed === true) L.closed = true;
    },
    killed(id) { if (typeof id === 'string') life(id).killed = true; },
    /** A K19:LATE report of the observer (a request after the final audit of its life). */
    late(rep) {
      if (typeof rep?.life === 'string') life(rep.life).late += 1;
      f.push({ harnessError: true, what: `K19: request ${rep?.op} attempted after the final audit of worker life ${rep?.life} (seq ${rep?.seq})`, cite: CITE.K19 });
    },
    /** The trusted reader's state, read at the start of life `read.life`, before its initialization. */
    reconcile(read) {
      const reader = typeof read?.life === 'string' ? life(read.life) : null;
      for (const id of order) {
        const L = lives.get(id);
        if (L === reader || L.applied) continue;
        if (!L.closed && !L.killed) f.push({ harnessError: true, what: `K19: worker life ${id} ended neither by its final audit nor by an intentional kill (closure not demonstrated)`, cite: CITE.K19 });
        L.applied = true;
        f.push(...model.applyLife(L));
        enter(L);
      }
      if (reader !== null && reader.records.size > 0) f.push({ harnessError: true, what: `K19: worker life ${reader.id} issued requests before its trusted read`, cite: CITE.K19 });
      f.push(...model.match(read));
    },
    /** End of the run: the last life must be closed by its final audit and reconciled (a reader life with no request). */
    finish() {
      for (const id of order) {
        const L = lives.get(id);
        enter(L);
        if (L.applied) continue;
        if (!L.closed) f.push({ harnessError: true, what: `K19: worker life ${id} was not closed by its final audit at the end of the run`, cite: CITE.K19 });
        else if (L.records.size > 0) f.push({ harnessError: true, what: `K19: worker life ${id} has requests no trusted reader reconciled`, cite: CITE.K19 });
      }
      return f.splice(0);
    },
    failures: () => f.splice(0),
    lives: () => order.map((id) => ({ id, closed: lives.get(id).closed, killed: lives.get(id).killed, applied: lives.get(id).applied, records: lives.get(id).records.size, late: lives.get(id).late })),
  };
}
