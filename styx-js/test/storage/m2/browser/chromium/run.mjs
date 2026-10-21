// B-CHR frozen launcher (act #317 6091950328 §1 "Harness"; B-CHR-CANON). Run from styx-js/:
//   node test/storage/m2/browser/chromium/run.mjs [browser=chromium] [factory=reference]
// Environment: BCHR_OUT (output directory, default ./bchr-out), BCHR_EXE (browser executable, optional),
// BCHR_SMOKE=1 (first row only; the verdict is then INCOMPLETE, never PASS).
// It serves styx-js/src and the suite, drives the browser with a persistent profile (IndexedDB survives
// a process kill), kills at every hook point the harness instrumentation reports, relaunches and reads
// back. It never branches on the factory: the parameter is forwarded unchanged to the worker URL.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import {
  ROWS, OUTCOMES, PHASES, KILL_KINDS, T9_CELLS, CELLS_PER_ROW, HAS_OUTPUT, NEXT_ROW, checkUninterrupted, checkKilled,
  checkResumed, checkSurvives, checkRestartReconcile, checkProducer, checkPutThrow, checkDelayedWriter, checkDebris,
  checkDurability, checkR3Refusal, checkEmissionRetry, checkNext, checkHistoricalForged, nonceBook, endStates, CITE,
} from './suite/expectations.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STYX_JS = path.resolve(HERE, '../../../../..');
const SRC = path.join(STYX_JS, 'src');
const SUITE = path.join(HERE, 'suite');
const require = createRequire(path.join(STYX_JS, 'package.json'));
const playwright = require('playwright-core');

const [browserName = 'chromium', factory = 'reference'] = process.argv.slice(2);
const engine = { chromium: playwright.chromium, firefox: playwright.firefox }[browserName];
if (engine === undefined) throw new Error(`unknown browser ${browserName}`);
const OUT = path.resolve(process.env.BCHR_OUT ?? 'bchr-out');
const SMOKE = process.env.BCHR_SMOKE === '1';
const DB_NAME = 'styx-m2-bchr-suite';
fs.mkdirSync(OUT, { recursive: true });
const LOG = path.join(OUT, 'run.log');
const RESULTS = path.join(OUT, 'results.jsonl');
fs.writeFileSync(LOG, '');
fs.writeFileSync(RESULTS, '');
const log = (s) => { fs.appendFileSync(LOG, `${s}\n`); console.log(s); };

// ---- HTTP: static src + suite, and the synchronous hook rendezvous ----------------------------------
// The hook rendezvous answers every hook and records the transaction metadata the OPEN hook carries,
// so a killed context still leaves it with the host (B-CHR PR-r1 F9).
let hostOpens = [];
const noteOpen = (p, d) => { if (d !== null && /^T\d+:OPEN$/.test(p)) hostOpens.push({ ev: 'OPEN', tx: Number(p.slice(1, p.indexOf(':'))), ...d }); };
const answer = (p, res, d) => { noteOpen(p, d); res.end('ok'); };
let hookHandler = answer;
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/hook') {
    let data = null;
    try { data = url.searchParams.has('d') ? JSON.parse(url.searchParams.get('d')) : null; } catch { data = null; }
    return hookHandler(url.searchParams.get('p'), res, data);
  }
  if (url.pathname === '/') {
    res.setHeader('content-type', 'text/html');
    // Constant document: the page reads its own `factory` parameter from location; nothing from the
    // request is reflected into the HTML.
    return res.end('<!doctype html><meta charset="utf-8"><script type="module" src="/suite/page.mjs"></script>');
  }
  const [root, rel] = url.pathname.startsWith('/src/') ? [SRC, url.pathname.slice(5)]
    : (url.pathname.startsWith('/suite/') ? [SUITE, url.pathname.slice(7)] : [null, null]);
  const file = root === null ? null : path.resolve(root, rel);
  if (file === null || !file.startsWith(root + path.sep) || !fs.existsSync(file)) { res.statusCode = 404; return res.end(); }
  res.setHeader('content-type', 'text/javascript');
  res.setHeader('cache-control', 'no-store');
  return res.end(fs.readFileSync(file));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://127.0.0.1:${server.address().port}`;

// ---- browser lifecycle --------------------------------------------------------------------------------
const PROFILE = path.join(OUT, 'profile');
let maxProcs = 0;
let NONE_HOLD = null; // the served codec's R3 state, reported by the worker
function pids() {
  try { return execFileSync('pgrep', ['-f', '--', PROFILE]).toString().trim().split('\n').filter(Boolean).map(Number); } catch { return []; }
}
function processTree() {
  const roots = new Set(pids());
  const all = execFileSync('ps', ['-e', '-o', 'pid=,ppid=,args=']).toString().trim().split('\n').map((l) => {
    const m = l.trim().match(/^(\d+)\s+(\d+)\s+(.*)$/);
    return { pid: Number(m[1]), ppid: Number(m[2]), args: m[3] };
  });
  let grew = true;
  while (grew) { grew = false; for (const p of all) if (!roots.has(p.pid) && roots.has(p.ppid)) { roots.add(p.pid); grew = true; } }
  return all.filter((p) => roots.has(p.pid));
}
const isRenderer = (p) => p.args.includes('--type=renderer') || p.args.includes('-contentproc');
function kill(kind) {
  const tree = processTree();
  const victims = kind === 'RENDERER' ? tree.filter(isRenderer) : tree; // COMMIT_SENT kills the whole tree
  for (const v of victims) { try { process.kill(v.pid, 'SIGKILL'); } catch { /* gone */ } }
  // Delivery receipt: every victim is gone or a zombie (SIGKILL is not catchable; a killed child of this
  // process stays a zombie until Playwright reaps it).
  const dead = (pid) => {
    try { return fs.readFileSync(`/proc/${pid}/stat`, 'utf8').replace(/^.*\)\s+/, '')[0] === 'Z'; } catch { return true; }
  };
  let alive = victims;
  for (let i = 0; i < 50 && alive.length > 0; i++) {
    execFileSync('sleep', ['0.02']);
    alive = alive.filter((v) => !dead(v.pid));
  }
  return { victims: victims.length, total: tree.length, survivors: alive.length };
}
const RPC_TIMEOUT_MS = 60000;
async function call(page, op, args) {
  let timer = null;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`rpc ${op} timed out after ${RPC_TIMEOUT_MS} ms`)), RPC_TIMEOUT_MS);
  });
  let r;
  try {
    r = await Promise.race([page.evaluate(([o, a]) => window.bchr.call(o, a), [op, args]), timeout]);
  } finally {
    clearTimeout(timer);
  }
  if (r.error) throw Object.assign(new Error(`${op}: ${r.error.code} ${r.error.message}`), { code: r.error.code });
  return r.value;
}
/** Every browser context a cell opened, so that a failure anywhere still closes them all. */
const openContexts = new Set();
/** Launches still in flight, so that teardown waits for them and closes what they return. */
const pendingLaunches = new Set();
/**
 * The cell each piece of work belongs to, carried through its continuations. A cell whose watchdog fired,
 * or that finished, is cancelled (review impl3 R3-8): its body may still be running, since a race does not
 * stop the losing promise, but it can start no further context, and a context that its in-flight launch
 * returns afterwards is closed before any initialization; teardown waits for that close.
 */
const cellOf = new AsyncLocalStorage();
const NO_CELL = { cancelled: false, id: '(outside a cell)' };
const LAUNCH_SETTLE_MS = 60000;
async function tearDown() {
  hookHandler = answer;
  if (pendingLaunches.size > 0) {
    let t = null;
    await Promise.race([Promise.allSettled([...pendingLaunches]), new Promise((r) => { t = setTimeout(r, LAUNCH_SETTLE_MS); })]);
    clearTimeout(t);
  }
  for (const ctx of [...openContexts]) { openContexts.delete(ctx); await closeHard(ctx); }
}
/** A cell as a whole is bounded and always cleaned up, whatever fails inside it (review impl1 F5). */
async function withCell(id, fn) {
  const cell = { cancelled: false, id };
  let watchdog = null;
  try {
    return await Promise.race([cellOf.run(cell, fn), new Promise((_, reject) => {
      watchdog = setTimeout(() => { cell.cancelled = true; reject(new Error(`cell ${id} exceeded 900 s`)); }, 900000);
    })]);
  } finally {
    if (watchdog !== null) clearTimeout(watchdog);
    cell.cancelled = true; // nothing of this cell may start a context after its teardown
    await tearDown();
  }
}
// launch(): the context is registered as soon as it exists and closed if initialization fails, or if its
// cell was cancelled while the launch was in flight (R3-8).
// Navigation (cycle 4, harness stabilization): on the shared heavy-validation runner the suite runs at
// nice 19 and idle I/O priority, so a fresh browser profile can take longer than Playwright's default 30 s
// to load the static suite page (cycle 3 full run 1 stopped on such a `page.goto` timeout after 669 runs
// with 0 failures). The navigation gets a longer bound, and a navigation that times out is retried, at
// most NAVIGATION_RETRIES times: only `page.goto` itself, before the worker starts, never an RPC or an
// assertion. Every retry is counted in the aggregate.
const NAVIGATION_TIMEOUT_MS = 120000;
const NAVIGATION_RETRIES = 2;
let navigationRetries = 0;
async function navigate(page, url) {
  for (let attempt = 0; ; attempt++) {
    try { await page.goto(url, { timeout: NAVIGATION_TIMEOUT_MS }); return; } catch (e) {
      if (attempt >= NAVIGATION_RETRIES || e?.name !== 'TimeoutError') throw e;
      navigationRetries += 1;
      log(`    [harness] page.goto timed out after ${NAVIGATION_TIMEOUT_MS} ms; navigation retry ${attempt + 1} of ${NAVIGATION_RETRIES}`);
    }
  }
}
async function launchBody(owner) {
  if (owner.cancelled) throw new Error(`cell ${owner.id} was cancelled: no further context is launched`);
  const launching = engine.launchPersistentContext(PROFILE, {
    headless: true, executablePath: process.env.BCHR_EXE || undefined,
    args: browserName === 'chromium' ? ['--disable-gpu', '--no-first-run', '--disable-extensions', '--renderer-process-limit=1'] : [],
  });
  let release;
  const settled = new Promise((r) => { release = r; });
  pendingLaunches.add(settled); // settles once the context is registered, or closed if it came late
  let ctx;
  try {
    ctx = await launching;
    if (owner.cancelled) { await closeHard(ctx); throw new Error(`cell ${owner.id} was cancelled: the late context was closed`); }
    openContexts.add(ctx); // registered at once, so a failure during initialization is still cleaned up
  } finally {
    pendingLaunches.delete(settled);
    release();
  }
  const page = ctx.pages()[0] ?? await ctx.newPage();
  page.on('console', (m) => { if (m.type() === 'error' && !m.text().includes('404')) log(`    [console.error] ${m.text()}`); });
  await navigate(page, `${ORIGIN}/?factory=${encodeURIComponent(factory)}`);
  await page.waitForFunction(() => window.bchrReady === true, null, { timeout: NAVIGATION_TIMEOUT_MS });
  await page.evaluate(() => window.bchr.start());
  const init = await call(page, 'init', { dbName: DB_NAME });
  if (NONE_HOLD === null) NONE_HOLD = init.noneHoldEncodable;
  try { maxProcs = Math.max(maxProcs, processTree().length); } catch { /* ignore */ }
  return { ctx, page, init };
}
async function launch() {
  const owner = cellOf.getStore() ?? NO_CELL;
  try { return await launchBody(owner); } catch (e) { if (!owner.cancelled) await tearDown(); throw e; }
}
async function fresh() {
  fs.rmSync(PROFILE, { recursive: true, force: true });
  return launch();
}
async function closeHard(ctx) {
  try { await Promise.race([ctx.close(), new Promise((r) => setTimeout(r, 3000))]); } catch { /* dead */ }
  for (const p of pids()) { try { process.kill(p, 'SIGKILL'); } catch { /* gone */ } }
  await new Promise((r) => setTimeout(r, 200));
}
/** Context death: the dedicated worker (the SS) dies; a fresh worker and a fresh port start at EMPTY memory. */
async function contextDeath(page) {
  await page.evaluate(() => window.bchr.restart());
  return call(page, 'init', { dbName: DB_NAME });
}
// R3 (#468 6171085366 §3a): a row without an output while the served codec cannot encode its hold.
const r3 = (row) => !HAS_OUTPUT(row) && NONE_HOLD !== true;

/** Every selector envelope the worker's port read, and every selector write event, during `r`, into the nonce book. */
function addSelectors(book, r) {
  book.add(r.snap);
  book.add(r.rb?.selector);
  book.addObserved(r.response?.selectors);
}
/** Every selector observation of the operations `calls` (their worker responses, producer sections included). */
function addSelectorsOf(book, ...calls) {
  for (const c of calls) { book.addObserved(c?.selectors); book.addObserved(c?.producer?.selectors); }
}

// ---- results ----------------------------------------------------------------------------------------
const tally = { cells: 0, runs: 0, kills: 0, notKilled: 0, failures: 0, unobserved: 0 };
/**
 * One run's entry. A failure marked `unobserved` (the memory-hold probe could not observe in time, review
 * impl4 R4-1) is insufficient observation, not a port failure: it is counted, logged and kept apart, and
 * it keeps the verdict from PASS without making it FAIL.
 */
function record(entry) {
  tally.runs += 1;
  const unobserved = entry.failures.filter((f) => f.unobserved === true);
  entry.failures = entry.failures.filter((f) => f.unobserved !== true);
  if (unobserved.length > 0) {
    entry.unobserved = unobserved;
    tally.unobserved += unobserved.length;
    for (const f of unobserved) log(`  UNOBSERVED ${entry.id}: ${f.what}`);
  }
  if (entry.failures.length > 0) {
    tally.failures += entry.failures.length;
    for (const f of entry.failures) log(`  FAIL ${entry.id}: ${f.what}\n       [${f.cite}]`);
  }
  fs.appendFileSync(RESULTS, `${JSON.stringify(entry)}\n`);
}

/** R3 cell: seed, then the row's INDETERMINATE request must be refused before any write. */
async function r3Cell(row, id, phase) {
  await withCell(id, () => r3CellBody(row, id, phase));
}
async function r3CellBody(row, id, phase) {
  const { ctx, page } = await fresh();
  await call(page, 'seed', { scenario: row });
  const before = await call(page, 'readback', {});
  await call(page, 'arm', {});
  const response = await call(page, 'original', { scenario: row, outcome: 'INDETERMINATE' });
  const rb = await call(page, 'readback', {});
  await closeHard(ctx);
  record({ id, row, phase, r3: true, response: response.error?.code ?? 'success', failures: checkR3Refusal(id, response, rb, before.dbDigest) });
}
/** An INDETERMINATE setup that must succeed (rows outside R3). */
async function held(page, row, extra = {}) {
  const r = await call(page, 'original', { scenario: row, outcome: 'INDETERMINATE', ...extra });
  if (r.error !== null) throw new Error(`INDETERMINATE setup failed: ${r.error.code} ${r.error.message}`);
  return r;
}

// ---- one armed operation, optionally killed ------------------------------------------------------------
async function setup(page, cell) {
  await call(page, 'seed', { scenario: cell.row });
  if (cell.phase === 'RECONCILIATION') return (await held(page, cell.row)).stagedHold;
  return undefined;
}
const operate = (page, cell) => call(page, cell.phase === 'ORIGINAL' ? 'original' : 'reconcile', { scenario: cell.row, outcome: cell.outcome });

async function runArmed(cell, { killAt = null, killKind = null, plan = {}, fault = null, tamperAt = null } = {}) {
  let { ctx, page } = await fresh();
  const setupHold = await setup(page, cell);
  const snap = await call(page, 'snapshot', {}); // kept by the harness, outside the context it kills
  const beforeDigest = (await call(page, 'readback', {})).dbDigest;
  const points = [];
  let killed = null;
  hostOpens = [];
  hookHandler = (p, res, d) => {
    points.push(p);
    noteOpen(p, d);
    if (killAt !== null && p === killAt && killed === null) { killed = kill(killKind); return; } // never answer
    res.end('ok');
  };
  await call(page, 'arm', { plan, fault, tamperAt });
  let response = null;
  const crashed = new Promise((r) => { page.on('crash', () => r({ crashed: 'crash' })); page.on('close', () => r({ crashed: 'close' })); });
  let watchdogTimer = null;
  const watchdog = new Promise((r) => { watchdogTimer = setTimeout(() => r({ crashed: 'watchdog 60s' }), 60000); });
  try {
    response = await Promise.race([operate(page, cell), crashed, watchdog]);
  } catch (e) { response = { crashed: String(e.message).split('\n')[0] }; } finally { clearTimeout(watchdogTimer); }
  hookHandler = answer;
  const opened = hostOpens;
  // The kind-13 record the operation's candidate stages: from the setup (RECONCILIATION) or the operation.
  const stagedHold = setupHold !== undefined ? setupHold : response?.stagedHold;
  if (killAt === null && response?.crashed === undefined) {
    const rb = await call(page, 'readback', {});
    await closeHard(ctx);
    openContexts.delete(ctx);
    return { points, killed, response, rb, snap, ctx: null, opened, stagedHold, beforeDigest };
  }
  await closeHard(ctx);
  openContexts.delete(ctx);
  ({ ctx, page } = await launch());
  openContexts.add(ctx);
  const rb = await call(page, 'readback', {});
  return { points, killed, response, rb, snap, ctx, page, opened, stagedHold, beforeDigest };
}

function txPlan(trace) {
  const plan = {};
  for (const e of trace) if (e.ev === 'REQ') plan[e.tx] = Math.max(plan[e.tx] ?? -1, e.j);
  return plan;
}

// ---- 1. the kill matrix: 7 rows x 3 outcomes x 2 phases x {BROWSER, RENDERER, COMMIT_SENT} ---------------
async function killMatrix(rows) {
  for (const row of rows) for (const phase of PHASES) for (const outcome of OUTCOMES) {
    tally.cells += 1;
    await withCell(`${row}/${phase}/${outcome}`, () => killCell(row, phase, outcome));
  }
}
async function killCell(row, phase, outcome) {
  {
    if (r3(row) && phase === 'RECONCILIATION') { await r3CellBody(row, `${row}/${phase}/${outcome}/R3`, phase); return; }
    const base = { row, outcome, phase, r3: r3(row) };
    const dry = await runArmed(base);
    const cell = { ...base, stagedHold: dry.stagedHold, beforeDigest: dry.beforeDigest };
    const id0 = `${row}/${phase}/${outcome}/NONE`;
    const nonces = nonceBook();
    addSelectors(nonces, dry);
    record({ id: id0, ...base, kill: 'NONE', rb: dry.rb, response: dry.response, failures: [...checkUninterrupted(cell, dry.response, dry.rb), ...nonces.failures()] });
    const plan = txPlan(dry.response.trace ?? []);
    const txs = Object.keys(plan).map(Number);
    const lastTx = txs.length === 0 ? null : Math.max(...txs);
    const committed = new Set(['RETURNED', ...(lastTx === null ? [] : [`T${lastTx}:COMPLETE`])]);
    const first = dry.points.find((p) => p !== 'RETURNED') ?? null;
    const schedule = [];
    for (const kind of KILL_KINDS) {
      const at = kind === 'COMMIT_SENT'
        ? [...txs.map((t) => `T${t}:END`), ...dry.points.filter((p) => p.endsWith(':COMMIT_SENT'))]
        : dry.points;
      for (const p of at) schedule.push([kind, p]);
    }
    log(`## ${row} ${phase} ${outcome}: ${dry.points.length} points [${dry.points.join(' ')}], ${schedule.length} kills; no-kill ${dry.rb.classify.authority ?? dry.rb.classify.error?.code}`);
    for (const [kind, point] of schedule) {
      const r = await runArmed(base, { killAt: point, killKind: kind, plan });
      tally.kills += 1;
      const failures = [];
      const book = nonceBook();
      addSelectors(book, r);
      if (r.killed === null || r.killed.victims === 0 || r.killed.survivors !== 0) {
        tally.notKilled += 1;
        failures.push({ what: `kill ${kind} at ${point} was delivered (${JSON.stringify(r.killed)})`, cite: 'act §1 item 2 (every request boundary)' });
      }
      failures.push(...checkKilled(cell, { point, firstPoint: point === first, committedPoint: committed.has(point) }, r.rb));
      failures.push(...checkDurability(r.opened)); // the host-side record of the killed context (F9)
      const { initial, final } = endStates(cell);
      const got = r.rb.classify.error ? null : `${r.rb.classify.authority}${r.rb.classify.held ? '+HELD' : ''}`;
      if (got === 'COMPLETE_NEW' && r.rb.candidateDigest !== dry.rb.candidateDigest) {
        failures.push({ what: `kill at ${point}: the new authority's bytes equal the uninterrupted run's`, cite: CITE.NEW });
      }
      let resumed = null;
      if (phase === 'RECONCILIATION' && got === initial && initial !== final) {
        await call(r.page, 'arm', {}); // F9: the resumed reconciliation is armed and observed
        resumed = await call(r.page, 'reconcile', { scenario: row, outcome });
        const rb2 = await call(r.page, 'readback', {});
        addSelectors(book, { response: resumed, rb: rb2 });
        failures.push(...checkResumed(cell, resumed, rb2));
      }
      if (committed.has(point) && got === final && final !== initial && r.snap !== null) {
        // T6b CAS: a landed authority write must change the stored selector bytes (fresh nonce, item 10),
        // and a delayed writer holding the bytes its plan read before the operation is refused.
        if (r.rb.selector?.envelope === r.snap.envelope) failures.push({ what: `after ${point}: the completed authority write changed the stored selector bytes`, cite: CITE.CAS });
        const delayed = await call(r.page, 'delayedReplace', { snap: r.snap });
        const after = await call(r.page, 'readback', {});
        failures.push(...checkDelayedWriter(point, delayed, r.rb.dbDigest, after.dbDigest));
      }
      if (committed.has(point) && got === final) { // T6b: the classified state survives another restart
        await closeHard(r.ctx);
        openContexts.delete(r.ctx);
        const again = await launch();
        failures.push(...checkSurvives(r.rb, await call(again.page, 'readback', {})));
        r.ctx = again.ctx;
        r.page = again.page;
      }
      await closeHard(r.ctx);
      openContexts.delete(r.ctx);
      failures.push(...book.failures());
      record({ id: `${row}/${phase}/${outcome}/${kind}@${point}`, ...base, kill: kind, point, killed: r.killed, got, resumed: resumed?.result?.reconciliation ?? resumed?.error?.code ?? null, failures });
    }
  }
}

// ---- 2. debris, then a second mutation over it ------------------------------------------------------------
async function debris(row, outcome) {
  const cell = { row, outcome, r3: r3(row) };
  const { ctx, page } = await fresh();
  const nonces = nonceBook();
  await call(page, 'seed', { scenario: row });
  const sealed = await call(page, 'readback', {});
  nonces.add(sealed.selector);
  await call(page, 'seedDebris', { scenario: row, outcome });
  const failures = [];
  const d = await call(page, 'readback', {});
  nonces.add(d.selector);
  failures.push(...checkDebris(cell, 'DEBRIS', d));
  // Fresh seal (item 10): seedDebris re-wrote the selector with unchanged plaintext.
  const delayed = await call(page, 'delayedReplace', { snap: sealed.selector });
  const afterDelayed = await call(page, 'readback', {});
  failures.push(...checkDebris(cell, 'RESEAL', { before: sealed.selector, after: d.selector, delayed, digestBefore: d.dbDigest, digestAfter: afterDelayed.dbDigest }));
  const reuse = await call(page, 'original', { scenario: row, outcome, generation: '2' });
  const afterReuse = await call(page, 'readback', {});
  failures.push(...checkDebris(cell, 'REUSE', { response: reuse, rb: afterReuse, before: d.dbDigest }));
  await call(page, 'arm', {});
  const second = await call(page, 'original', { scenario: row, outcome, generation: '3' });
  const rb = await call(page, 'readback', { candidate: '3' });
  const debrisAfter = (await call(page, 'readback', { candidate: '2' })).candidateDigest;
  addSelectorsOf(nonces, reuse, second);
  failures.push(...checkDebris({ ...cell, stagedHold: second.stagedHold }, 'SECOND', { response: second, rb, debrisDigest: d.candidateDigest, debrisAfter, beforeDigest: afterReuse.dbDigest }));
  failures.push(...nonces.failures());
  await closeHard(ctx);
  openContexts.delete(ctx);
  record({ id: `${row}/DEBRIS/${outcome}`, row, outcome, phase: 'DEBRIS', reuse: reuse.error?.code ?? 'success', second: second.result?.commitOutcome ?? second.error?.code, failures });
}

async function debrisAll(rows) {
  for (const row of rows) for (const outcome of OUTCOMES) {
    tally.cells += 1;
    await withCell(`${row}/DEBRIS/${outcome}`, () => debris(row, outcome));
  }
}

// ---- 3. restart reconcile (T6 without steal), and T9 on the port's producer -------------------------------
async function heldThenContextDeath(row) {
  const { ctx, page } = await fresh();
  await call(page, 'seed', { scenario: row });
  const s0 = await call(page, 'snapshot', {});
  const h = await held(page, row);
  const s1 = await call(page, 'snapshot', {});
  const init = await contextDeath(page);
  const pre = await call(page, 'readback', {});
  return { ctx, page, pre: { ...pre, lock: init.lock }, stagedHold: h.stagedHold, selectors: [s0, s1] };
}

async function restartReconcile(rows) {
  for (const row of rows) for (const outcome of OUTCOMES) {
    tally.cells += 1;
    const id = `${row}/RESTART/${outcome}`;
    await withCell(id, () => (r3(row) ? r3CellBody(row, id, 'RESTART') : restartCell(row, id, outcome)));
  }
}
async function restartCell(row, id, outcome) {
  {
    const { ctx, page, pre, stagedHold, selectors } = await heldThenContextDeath(row);
    await call(page, 'arm', {}); // F9: the restart operation is armed and its transactions observed
    const response = await call(page, 'reconcile', { scenario: row, outcome });
    const rb = await call(page, 'readback', {});
    const repeat = outcome === 'INDETERMINATE' ? null : await call(page, 'reconcile', { scenario: row, outcome });
    const failures = checkRestartReconcile({ row, outcome, stagedHold }, pre, response, rb, repeat);
    const nonces = nonceBook();
    for (const s of [...selectors, pre.selector, rb.selector]) nonces.add(s);
    addSelectors(nonces, { response, rb, opened: [] });
    failures.push(...nonces.failures());
    await closeHard(ctx);
    openContexts.delete(ctx);
    const again = await launch();
    failures.push(...checkSurvives(rb, await call(again.page, 'readback', {})));
    await closeHard(again.ctx);
    openContexts.delete(again.ctx);
    record({ id, row, outcome, phase: 'RESTART', response: response.result?.reconciliation ?? response.error?.code, repeat: repeat?.error?.code ?? repeat?.result?.reconciliation ?? null, failures });
  }
}

async function faults(rows) {
  // T9 on the port's terminal readback producer: fourteen fixed cells per row, whatever the port reads.
  for (const row of rows) {
    for (const kind of T9_CELLS) {
      tally.cells += 1;
      const id = `${row}/T9/${kind}`;
      await withCell(id, () => faultCell(row, id, kind));
    }
  }
}
async function faultCell(row, id, kind) {
  {
      if (r3(row)) { await r3CellBody(row, id, 'T9'); return; }
      if (kind.startsWith('CONTRADICT_') || kind === 'PRODUCE_COMMITTED' || kind === 'TAMPER_COMMITTED') {
        // With the SS hold kept after an ORIGINAL INDETERMINATE.
        const { ctx, page } = await fresh();
        await call(page, 'seed', { scenario: row });
        await held(page, row);
        const response = kind.startsWith('CONTRADICT_')
          ? await call(page, 'contradict', { scenario: row, kind })
          : await call(page, 'produceAfterCommit', { scenario: row, tamper: kind === 'TAMPER_COMMITTED' });
        await closeHard(ctx);
        record({ id, row, phase: 'T9', fault: kind, produced: response.produced, response: response.error?.code ?? null, setup: response.setup?.code ?? null, failures: checkProducer(kind, null, response, null) });
        return;
      }
      let ctx; let page; let pre;
      if (kind === 'READ_FAIL_MEMORY') {
        // SS memory survives: INDETERMINATE in this worker, then the producer in the same worker.
        ({ ctx, page } = await fresh());
        await call(page, 'seed', { scenario: row });
        await held(page, row);
        pre = await call(page, 'readback', {});
      } else {
        ({ ctx, page, pre } = await heldThenContextDeath(row));
      }
      const fault = { PRODUCE: null, READ_FAIL_MEMORY: 'READ_FAIL', READ_FAIL_LOST: 'READ_FAIL', TAMPER_FIRST: 'TAMPER', TAMPER_ALL: 'TAMPER', TAMPER_REST: 'TAMPER' }[kind];
      const tamperAt = { TAMPER_FIRST: 0, TAMPER_REST: 'REST' }[kind] ?? null;
      await call(page, 'arm', {});
      const response = await call(page, 'reconcile', { scenario: row, produce: true, produceFault: fault, tamperAt });
      const rb = await call(page, 'readback', {});
      const book = nonceBook();
      addSelectorsOf(book, response);
      book.add(rb.selector); book.add(pre.selector);
      await closeHard(ctx);
      openContexts.delete(ctx);
      record({ id, row, phase: 'T9', fault: kind, produced: response.produced, response: response.result?.reconciliation ?? response.error?.code,
        failures: [...checkProducer(kind, pre, response, rb, { memoryHold: kind === 'READ_FAIL_MEMORY' }), ...book.failures()] });
  }
}

// ---- 4. KIND13 (#468 B3, B4): emission retry, the next mutation, a forged historical hold ------------------
async function kind13(rows) {
  for (const row of rows) {
    tally.cells += 1;
    await withCell(`${row}/KIND13/EMISSION_RETRY`, () => (r3(row) ? r3CellBody(row, `${row}/KIND13/EMISSION_RETRY`, 'KIND13') : emissionRetry(row)));
    for (const outcome of ['COMMITTED', 'INDETERMINATE']) {
      tally.cells += 1;
      await withCell(`${row}/KIND13/NEXT_${outcome}`, () => nextCell(row, outcome));
    }
    tally.cells += 1;
    await withCell(`${row}/KIND13/HISTORICAL_FORGED`, () => historicalCell(row));
  }
}

/** The selection lands, the local emission is interrupted, the SS retries it (#468 B3). */
async function emissionRetry(row) {
  const { ctx, page } = await fresh();
  const nonces = nonceBook();
  await call(page, 'seed', { scenario: row });
  const h = await held(page, row);
  const first = await call(page, 'reconcile', { scenario: row, outcome: 'COMMITTED', emissionFault: true });
  const mid = await call(page, 'readback', {});
  await call(page, 'arm', {});
  const retry = await call(page, 'reconcile', { scenario: row, outcome: 'COMMITTED' });
  const rb = await call(page, 'readback', {});
  const repeat = await call(page, 'reconcile', { scenario: row, outcome: 'COMMITTED' });
  addSelectorsOf(nonces, h, first, retry, repeat);
  nonces.add(rb.selector);
  await closeHard(ctx);
  openContexts.delete(ctx);
  record({ id: `${row}/KIND13/EMISSION_RETRY`, row, phase: 'KIND13', response: retry.result?.reconciliation ?? retry.error?.code,
    failures: [...checkEmissionRetry({ row }, { first, mid, retry, rb, repeat, stagedHold: h.stagedHold }), ...nonces.failures()] });
}

/** The next mutation from the authority a terminal COMMITTED left (generation 2). */
async function nextCell(row, outcome) {
  const next = NEXT_ROW(row);
  const cell = { row, nextRow: next, outcome, r3Next: r3(next) && outcome === 'INDETERMINATE' };
  const { ctx, page } = await fresh();
  const nonces = nonceBook();
  await call(page, 'seed', { scenario: row });
  let base; let parent; let setupCalls = [];
  if (r3(row)) {
    base = await call(page, 'original', { scenario: row, outcome: 'COMMITTED' });
    parent = { row, outcome: 'COMMITTED', op: 1 };
    setupCalls = [base];
  } else {
    const h = await held(page, row);
    base = await call(page, 'reconcile', { scenario: row, outcome: 'COMMITTED' });
    parent = { row, outcome: 'INDETERMINATE', op: 1 };
    setupCalls = [h, base];
  }
  const baseRb = await call(page, 'readback', {});
  const d = { base, baseRb, baseDigest: baseRb.dbDigest };
  await call(page, 'arm', {});
  d.next = await call(page, 'original', { scenario: next, outcome, parent, generation: '3', op: 2 });
  d.nextRb = await call(page, 'readback', { parent: '2', candidate: '3' });
  if (!cell.r3Next && outcome === 'INDETERMINATE') {
    const init = await contextDeath(page);
    d.pre = { ...await call(page, 'readback', { parent: '2', candidate: '3' }), lock: init.lock };
    await call(page, 'arm', {}); // the reconciliation after context death is observed (C4)
    d.recon = await call(page, 'reconcile', { scenario: next, outcome: 'COMMITTED', parent, generation: '3', op: 2 });
    d.reconRb = await call(page, 'readback', { parent: '2', candidate: '3' });
  }
  const old = await call(page, 'readback', { parent: '1', candidate: '2' });
  d.oldHold = old.candidateHold;
  d.numbers = Array.isArray(old.numbers) ? old.numbers.join(',') : JSON.stringify(old.numbers);
  // Item 10 over every write of this cell: setup, the next mutation and the restart reconciliation.
  addSelectorsOf(nonces, ...setupCalls, d.next, d.recon);
  for (const rb of [baseRb, d.nextRb, d.reconRb, old, d.pre]) if (rb !== undefined) nonces.add(rb.selector);
  await closeHard(ctx);
  openContexts.delete(ctx);
  record({ id: `${row}/KIND13/NEXT_${outcome}`, row, next, phase: 'KIND13', response: d.next.result?.commitOutcome ?? d.next.error?.code,
    failures: [...checkNext(cell, d), ...nonces.failures()] });
}

/** #468 B4: a selected generation whose present kind-13 record is not historical evidence. */
async function historicalCell(row) {
  const { ctx, page } = await fresh();
  await call(page, 'seed', { scenario: row });
  const d = await call(page, 'forgeHistorical', { scenario: row });
  await closeHard(ctx);
  openContexts.delete(ctx);
  record({ id: `${row}/KIND13/HISTORICAL_FORGED`, row, phase: 'KIND13', response: d.setup?.code ?? (d.classify?.error?.code ?? d.classify?.authority), failures: checkHistoricalForged(d) });
}

// ---- 5. T6b mutant: a put throws mid-enqueue during the original write, for every outcome ------------------
async function putThrow(rows) {
  for (const row of rows) for (const outcome of OUTCOMES) {
    tally.cells += 1;
    const id = `${row}/T6b/PUT_THROW/${outcome}`;
    await withCell(id, () => (r3(row) && outcome === 'INDETERMINATE' ? r3CellBody(row, id, 'T6b') : putThrowCell(row, outcome, id)));
  }
}
async function putThrowCell(row, outcome, id) {
  {
    const cell = { row, outcome, phase: 'ORIGINAL' };
    const r = await runArmed(cell, { fault: 'PUT_THROW' });
    const applied = (r.response.trace ?? []).some((e) => e.ev === 'FAULT' && e.fault === 'PUT_THROW');
    const wrote = (r.response.trace ?? []).some((e) => e.ev === 'REQ');
    const failures = applied ? checkPutThrow(r.response, r.rb)
      : (wrote ? [{ what: 'PUT_THROW: the fault was injected', cite: CITE.PUT_THROW }] : []);
    record({ id, ...cell, phase: 'T6b', applicable: applied, response: r.response.error?.code ?? 'success', failures });
  }
}

const t0 = Date.now();
const rows = SMOKE ? ROWS.slice(0, 1) : ROWS;
log(`# B-CHR frozen suite: browser=${browserName} factory=${factory} rows=${rows.join(',')} smoke=${SMOKE}`);
let crashed = null;
try {
  await debrisAll(rows);
  log(`# R3 state of the served codec: present NONE-output hold encodable = ${NONE_HOLD}`);
  await restartReconcile(rows);
  await faults(rows);
  await kind13(rows);
  await putThrow(rows);
  await killMatrix(rows);
  if (tally.cells !== CELLS_PER_ROW * rows.length) throw new Error(`scheduled ${tally.cells} cells, expected ${CELLS_PER_ROW * rows.length}`);
} catch (e) {
  crashed = String(e.stack ?? e);
  log(`HARNESS ERROR: ${crashed}`);
}
server.close();
// The report tells the classes apart (cycle 4): a harness error (the launcher or the browser failed,
// e.g. a navigation timeout), assertion failures (the port under test violated an expectation),
// undelivered kills, and insufficient probe observation.
const harnessErrorKind = crashed === null ? null
  : (/page\.goto|navigation|Navigation/.test(crashed) ? 'NAVIGATION' : (/rpc \S+ timed out/.test(crashed) ? 'RPC_TIMEOUT' : (/exceeded 900 s/.test(crashed) ? 'CELL_WATCHDOG' : 'OTHER')));
const failureClasses = [
  ...(crashed !== null ? ['HARNESS_ERROR'] : []), ...(tally.failures > 0 ? ['ASSERTION'] : []),
  ...(tally.notKilled > 0 ? ['NOT_KILLED'] : []), ...(tally.unobserved > 0 ? ['UNOBSERVED'] : []),
];
const verdict = crashed !== null || tally.failures > 0 || tally.notKilled > 0 ? 'FAIL'
  : (SMOKE || tally.unobserved > 0 ? 'INCOMPLETE' : 'PASS');
const aggregate = { browser: browserName, factory, smoke: SMOKE, ...tally, noneHoldEncodable: NONE_HOLD, maxProcs, navigationRetries, seconds: Math.round((Date.now() - t0) / 1000), harnessError: crashed, harnessErrorKind, failureClasses, verdict };
fs.writeFileSync(path.join(OUT, 'AGGREGATE.json'), `${JSON.stringify(aggregate, null, 2)}\n`);
log(`# AGGREGATE ${JSON.stringify(aggregate)}`);
process.exit(verdict === 'PASS' ? 0 : 1);
