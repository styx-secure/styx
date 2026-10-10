// B-CHR frozen launcher (act #317 6091950328 §1 "Harness"). Run from styx-js/:
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
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import {
  ROWS, OUTCOMES, PHASES, KILL_KINDS, checkUninterrupted, checkKilled, checkResumed, checkSurvives,
  checkRestartReconcile, checkFault, checkPutThrow, checkDelayedWriter, checkDebris, endStates, CITE,
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
let hookHandler = (p, res) => res.end('ok');
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/hook') return hookHandler(url.searchParams.get('p'), res);
  if (url.pathname === '/') {
    res.setHeader('content-type', 'text/html');
    return res.end('<!doctype html><meta charset="utf-8"><script type="module" src="/suite/page.mjs' + url.search + '"></script>');
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
  return { victims: victims.length, total: tree.length };
}
async function launch() {
  const ctx = await engine.launchPersistentContext(PROFILE, {
    headless: true, executablePath: process.env.BCHR_EXE || undefined,
    args: browserName === 'chromium' ? ['--disable-gpu', '--no-first-run', '--disable-extensions', '--renderer-process-limit=1'] : [],
  });
  const page = ctx.pages()[0] ?? await ctx.newPage();
  page.on('console', (m) => { if (m.type() === 'error' && !m.text().includes('404')) log(`    [console.error] ${m.text()}`); });
  await page.goto(`${ORIGIN}/?factory=${encodeURIComponent(factory)}`);
  await page.waitForFunction(() => window.bchrReady === true);
  await page.evaluate(() => window.bchr.start());
  const init = await call(page, 'init', { dbName: DB_NAME });
  try { maxProcs = Math.max(maxProcs, processTree().length); } catch { /* ignore */ }
  return { ctx, page, init };
}
async function closeHard(ctx) {
  try { await Promise.race([ctx.close(), new Promise((r) => setTimeout(r, 3000))]); } catch { /* dead */ }
  for (const p of pids()) { try { process.kill(p, 'SIGKILL'); } catch { /* gone */ } }
  await new Promise((r) => setTimeout(r, 200));
}
async function call(page, op, args) {
  const r = await page.evaluate(([o, a]) => window.bchr.call(o, a), [op, args]);
  if (r.error) throw Object.assign(new Error(`${op}: ${r.error.code} ${r.error.message}`), { code: r.error.code });
  return r.value;
}

// ---- results ----------------------------------------------------------------------------------------
const tally = { cells: 0, runs: 0, kills: 0, notKilled: 0, failures: 0 };
function record(entry) {
  tally.runs += 1;
  if (entry.failures.length > 0) {
    tally.failures += entry.failures.length;
    for (const f of entry.failures) log(`  FAIL ${entry.id}: ${f.what}\n       [${f.cite}]`);
  }
  fs.appendFileSync(RESULTS, `${JSON.stringify(entry)}\n`);
}

// ---- one armed operation, optionally killed ------------------------------------------------------------
async function setup(page, cell) {
  await call(page, 'seed', { scenario: cell.row });
  if (cell.phase === 'RECONCILIATION') {
    const r = await call(page, 'original', { scenario: cell.row, outcome: 'INDETERMINATE' });
    if (r.error !== null) throw new Error(`setup INDETERMINATE failed: ${r.error.code} ${r.error.message}`);
  }
}
const operate = (page, cell) => call(page, cell.phase === 'ORIGINAL' ? 'original' : 'reconcile', { scenario: cell.row, outcome: cell.outcome });

async function runArmed(cell, { killAt = null, killKind = null, plan = {}, fault = null, tamperAt = null } = {}) {
  fs.rmSync(PROFILE, { recursive: true, force: true });
  let { ctx, page } = await launch();
  await setup(page, cell);
  const snap = await call(page, 'snapshot', {}); // kept by the harness, outside the context it kills
  const points = [];
  let killed = null;
  hookHandler = (p, res) => {
    points.push(p);
    if (killAt !== null && p === killAt && killed === null) { killed = kill(killKind); return; } // never answer
    res.end('ok');
  };
  await call(page, 'arm', { plan, fault, tamperAt });
  let response = null;
  const crashed = new Promise((r) => { page.on('crash', () => r({ crashed: 'crash' })); page.on('close', () => r({ crashed: 'close' })); });
  const watchdog = new Promise((r) => setTimeout(() => r({ crashed: 'watchdog 60s' }), 60000));
  try {
    response = await Promise.race([operate(page, cell), crashed, watchdog]);
  } catch (e) { response = { crashed: String(e.message).split('\n')[0] }; }
  hookHandler = (p, res) => res.end('ok');
  if (killAt === null && response?.crashed === undefined) {
    const rb = await call(page, 'readback', {});
    await closeHard(ctx);
    return { points, killed, response, rb, snap, ctx: null };
  }
  await closeHard(ctx);
  ({ ctx, page } = await launch());
  const rb = await call(page, 'readback', {});
  return { points, killed, response, rb, snap, ctx, page };
}

function txPlan(trace) {
  const plan = {};
  for (const e of trace) if (e.ev === 'REQ') plan[e.tx] = Math.max(plan[e.tx] ?? -1, e.j);
  return plan;
}

// ---- 1. the kill matrix: 7 rows x 3 outcomes x 2 phases x {BROWSER, RENDERER, COMMIT_SENT} ---------------
async function killMatrix(rows) {
  for (const row of rows) for (const phase of PHASES) for (const outcome of OUTCOMES) {
    const cell = { row, outcome, phase };
    tally.cells += 1;
    const dry = await runArmed(cell);
    const id0 = `${row}/${phase}/${outcome}/NONE`;
    record({ id: id0, ...cell, kill: 'NONE', rb: dry.rb, response: dry.response, failures: checkUninterrupted(cell, dry.response, dry.rb) });
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
      const r = await runArmed(cell, { killAt: point, killKind: kind, plan });
      tally.kills += 1;
      const failures = [];
      if (r.killed === null) { tally.notKilled += 1; failures.push({ what: `kill ${kind} at ${point} was not delivered`, cite: 'act §1 item 2 (every request boundary)' }); }
      failures.push(...checkKilled(cell, { point, firstPoint: point === first, committedPoint: committed.has(point) }, r.rb));
      const { initial, final } = endStates(cell);
      const got = r.rb.classify.error ? null : `${r.rb.classify.authority}${r.rb.classify.held ? '+HELD' : ''}`;
      if (got === 'COMPLETE_NEW' && r.rb.candidateDigest !== dry.rb.candidateDigest) {
        failures.push({ what: `kill at ${point}: the new authority's bytes equal the uninterrupted run's`, cite: CITE.NEW });
      }
      let resumed = null;
      if (phase === 'RECONCILIATION' && got === initial && initial !== final) {
        resumed = await call(r.page, 'reconcile', { scenario: row, outcome });
        const rb2 = await call(r.page, 'readback', {});
        failures.push(...checkResumed(cell, resumed, rb2));
      }
      if (committed.has(point) && got === final && r.snap !== null && r.rb.selector?.envelope !== r.snap.envelope) {
        // T6b CAS: the landed commit changed the stored selector bytes, so a delayed writer holding the
        // bytes its plan read before the operation is refused and changes nothing.
        const delayed = await call(r.page, 'delayedReplace', { snap: r.snap });
        const after = await call(r.page, 'readback', {});
        failures.push(...checkDelayedWriter(point, delayed, r.rb.dbDigest, after.dbDigest));
      }
      if (committed.has(point) && got === final) { // T6b: the classified state survives another restart
        await closeHard(r.ctx);
        const again = await launch();
        failures.push(...checkSurvives(r.rb, await call(again.page, 'readback', {})));
        r.ctx = again.ctx;
      }
      await closeHard(r.ctx);
      record({ id: `${row}/${phase}/${outcome}/${kind}@${point}`, ...cell, kill: kind, point, killed: r.killed, got, resumed: resumed?.result?.reconciliation ?? resumed?.error?.code ?? null, failures });
    }
  }
}

// ---- 2. debris, then a second mutation over it ------------------------------------------------------------
async function debris(rows) {
  for (const row of rows) for (const outcome of OUTCOMES) {
    tally.cells += 1;
    fs.rmSync(PROFILE, { recursive: true, force: true });
    const { ctx, page } = await launch();
    await call(page, 'seed', { scenario: row });
    await call(page, 'seedDebris', { scenario: row, outcome });
    const failures = [];
    const d = await call(page, 'readback', {});
    failures.push(...checkDebris({ outcome }, 'DEBRIS', d));
    const reuse = await call(page, 'original', { scenario: row, outcome, generation: '2' });
    const afterReuse = await call(page, 'readback', {});
    failures.push(...checkDebris({ outcome }, 'REUSE', { response: reuse, rb: afterReuse, before: d.dbDigest }));
    const second = await call(page, 'original', { scenario: row, outcome, generation: '3' });
    const rb = await call(page, 'readback', { candidate: '3' });
    const debrisAfter = (await call(page, 'readback', { candidate: '2' })).candidateDigest;
    failures.push(...checkDebris({ outcome }, 'SECOND', { row, response: second, rb, debrisDigest: d.candidateDigest, debrisAfter }));
    await closeHard(ctx);
    record({ id: `${row}/DEBRIS/${outcome}`, row, outcome, phase: 'DEBRIS', reuse: reuse.error?.code ?? 'success', second: second.result?.commitOutcome ?? second.error?.code, failures });
  }
}

// ---- 3. restart reconcile (T6 without steal), and T9 faults on the restart path ---------------------------
async function heldThenContextDeath(row) {
  fs.rmSync(PROFILE, { recursive: true, force: true });
  const { ctx, page } = await launch();
  await call(page, 'seed', { scenario: row });
  const held = await call(page, 'original', { scenario: row, outcome: 'INDETERMINATE' });
  if (held.error !== null) throw new Error(`INDETERMINATE setup failed: ${held.error.code}`);
  // Context death: the dedicated worker (the SS) dies; a fresh worker and a fresh port start at EMPTY memory.
  await page.evaluate(() => window.bchr.restart());
  const init = await call(page, 'init', { dbName: DB_NAME });
  const pre = await call(page, 'readback', {});
  return { ctx, page, pre: { ...pre, lock: init.lock } };
}

async function restartReconcile(rows) {
  for (const row of rows) for (const outcome of OUTCOMES) {
    tally.cells += 1;
    const { ctx, page, pre } = await heldThenContextDeath(row);
    const response = await call(page, 'reconcile', { scenario: row, outcome });
    const rb = await call(page, 'readback', {});
    const repeat = outcome === 'INDETERMINATE' ? null : await call(page, 'reconcile', { scenario: row, outcome });
    const failures = checkRestartReconcile({ row, outcome }, pre, response, rb, repeat);
    await closeHard(ctx);
    const again = await launch();
    failures.push(...checkSurvives(rb, await call(again.page, 'readback', {})));
    await closeHard(again.ctx);
    record({ id: `${row}/RESTART/${outcome}`, row, outcome, phase: 'RESTART', response: response.result?.reconciliation ?? response.error?.code, repeat: repeat?.error?.code ?? repeat?.result?.reconciliation ?? null, failures });
  }
}

async function faults(rows) {
  for (const row of rows) {
    // Count the readonly requests of a restart reconciliation (port-neutral, from the trace).
    const probe = await heldThenContextDeath(row);
    await call(probe.page, 'arm', {});
    const dry = await call(probe.page, 'reconcile', { scenario: row, outcome: 'COMMITTED' });
    await closeHard(probe.ctx);
    const cases = [['READ_FAIL', null], ...Array.from({ length: dry.reads }, (_, k) => ['TAMPER', k])];
    for (const [fault, tamperAt] of cases) {
      tally.cells += 1;
      const { ctx, page, pre } = await heldThenContextDeath(row);
      await call(page, 'arm', { fault, tamperAt });
      const response = await call(page, 'reconcile', { scenario: row, outcome: 'COMMITTED' });
      const rb = await call(page, 'readback', {});
      await closeHard(ctx);
      const touched = fault === 'READ_FAIL' || (response.trace ?? []).some((e) => e.ev === 'TAMPERED' && e.k === tamperAt && e.changed);
      const failures = touched ? checkFault(fault, pre, response, rb) : [];
      record({ id: `${row}/T9/${fault}${tamperAt === null ? '' : `@${tamperAt}`}`, row, phase: 'T9', fault, tamperAt, applicable: touched, response: response.result?.reconciliation ?? response.error?.code, failures });
    }
  }
  // T6b mutant: a put throws mid-enqueue during the original write, for every outcome.
  for (const row of rows) for (const outcome of OUTCOMES) {
    tally.cells += 1;
    const cell = { row, outcome, phase: 'ORIGINAL' };
    const r = await runArmed(cell, { fault: 'PUT_THROW' });
    const applied = (r.response.trace ?? []).some((e) => e.ev === 'FAULT' && e.fault === 'PUT_THROW');
    const writes = (r.response.trace ?? []).some((e) => e.ev === 'REQ');
    const failures = applied ? checkPutThrow(r.response, r.rb)
      : (writes ? [{ what: 'PUT_THROW: the fault was injected', cite: CITE.PUT_THROW }] : []);
    record({ id: `${row}/T6b/PUT_THROW/${outcome}`, ...cell, phase: 'T6b', applicable: applied, response: r.response.error?.code ?? 'success', failures });
  }
}

const t0 = Date.now();
const rows = SMOKE ? ROWS.slice(0, 1) : ROWS;
log(`# B-CHR frozen suite: browser=${browserName} factory=${factory} rows=${rows.join(',')} smoke=${SMOKE}`);
let crashed = null;
try {
  await debris(rows);
  await restartReconcile(rows);
  await faults(rows);
  await killMatrix(rows);
} catch (e) {
  crashed = String(e.stack ?? e);
  log(`HARNESS ERROR: ${crashed}`);
}
server.close();
const verdict = crashed !== null || tally.failures > 0 || tally.notKilled > 0 ? 'FAIL' : (SMOKE ? 'INCOMPLETE' : 'PASS');
const aggregate = { browser: browserName, factory, smoke: SMOKE, ...tally, maxProcs, seconds: Math.round((Date.now() - t0) / 1000), harnessError: crashed, verdict };
fs.writeFileSync(path.join(OUT, 'AGGREGATE.json'), `${JSON.stringify(aggregate, null, 2)}\n`);
log(`# AGGREGATE ${JSON.stringify(aggregate)}`);
process.exit(verdict === 'PASS' ? 0 : 1);
