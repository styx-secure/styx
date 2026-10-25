// Native regression runner of the substituted-clone observer (owner act v2 on #317, §3-§6), Chromium only.
// Run from styx-js/:  node test/storage/m2/browser/chromium/observer-regressions.mjs
// Environment: BCHR_EXE (browser executable), BCHR_OUT (output directory), BCHR_ONLY (comma-separated case
// names, optional; the verdict is then INCOMPLETE).
// Parts, each asserted against the expected verdict fixed in the suite before running:
//   1. reference variants: the frozen reference port, transformed only in the HTTP response, driven
//      through the real worker; expected rejection reason per variant (act §6, K11, K13, K16);
//   2. request cases (suite/observer-cases.mjs), each in a fresh dedicated worker without and with the
//      observer: the act §3 non-interference comparison and the expected verdict (K1-K19);
//   3. K9 cases in the page with an iframe realm; COI cases in a cross-origin-isolated page;
//   4. K12: a worker killed after the native emission leaves its write records with the host;
//   5. unit checks of the act §4/§5 judges (expectations.mjs) on synthetic records (K11, K12).
// Every response body the server delivers is logged with its SHA-256 (served.jsonl, act §7).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';

const here = path.dirname(fileURLToPath(import.meta.url));
const jsRoot = path.resolve(here, '../../../../..');
const suite = path.join(here, 'suite');
const { chromium } = createRequire(path.join(jsRoot, 'package.json'))('playwright-core');
const out = path.resolve(process.env.BCHR_OUT ?? 'observer-regressions-out');
fs.mkdirSync(out, { recursive: true });
const ONLY = process.env.BCHR_ONLY ? new Set(process.env.BCHR_ONLY.split(',')) : null;
const sha = (b) => createHash('sha256').update(b).digest('hex');
const results = []; const errors = [];
const SERVED = path.join(out, 'served.jsonl'); fs.writeFileSync(SERVED, '');
let mode = 'control'; let context = 'init';

// ---- reference variants (transformations exist only in HTTP responses) ------------------------------------
export function transformReference(source, variant) {
  const replace = (a, b) => { assert.equal(source.split(a).length, 2, `reference boundary changed: ${a}`); source = source.replace(a, b); };
  if (['early', 'nested-early', 'transient'].includes(variant)) {
    replace('        await Promise.all(pending);', `        await Promise.all(pending);
        ${variant === 'nested-early' ? 'for (let i=0;i<8;i++) await Promise.resolve();' : ''}
        if (pendingMemoryHold !== undefined) {
          const previous = memoryHold;
          memoryHold = pendingMemoryHold;
          ${variant === 'transient' ? 'memoryHold = previous;' : ''}
        }`);
  }
  if (['alias', 'deep', 'map', 'set', 'view', 'getter', 'hex-selector'].includes(variant)) {
    const pack = { alias: '{ envelope: v, duplicate: v }', deep: '{ a:{ a:{ a:{ a:{ a:v } } } } }',
      map: "new Map([['envelope',v]])", set: 'new Set([v])', view: 'new DataView(v.buffer,v.byteOffset,v.byteLength)',
      getter: '({ get envelope(){ return v; } })', 'hex-selector': "Array.from(v,(b)=>b.toString(16).padStart(2,'0')).join('')" }[variant];
    const unpack = { deep: 'v.a.a.a.a.a', map: "v.get('envelope')", set: '[...v][0]',
      view: 'new Uint8Array(v.buffer,v.byteOffset,v.byteLength)', 'hex-selector': 'Uint8Array.from(v.match(/../g),(h)=>parseInt(h,16))' }[variant] ?? 'v.envelope';
    replace('export async function createPort({ db, context }) {', `export async function createPort({ db, context }) {
      const backend=db;
      const unpack=(k,v)=>k!=='sel'||v===undefined?v:${unpack};
      const pack=(k,v)=>k!=='sel'?v:${pack};
      db={ get:async(n,k)=>unpack(k,await backend.get(n,k)), list:(...a)=>backend.list(...a),
        transaction:(ns,cb)=>backend.transaction(ns,ops=>cb({...ops,
          get:async(n,k)=>unpack(k,await ops.get(n,k)),put:(n,k,v)=>ops.put(n,k,pack(k,v))})) };
    `);
    if (!['alias', 'hex-selector'].includes(variant)) {
      replace('        pending.push(ops.put(NS, SEL, envelope)); // the selector put last',
        '        pending.push(ops.put(NS, SEL, envelope));\n        pending.push(ops.put(NS, SEL, envelope));');
    }
  }
  if (variant === 'reemit-read') {
    // Red-team Fase 4 (Sol r3 #2, port-internal read): the stored envelope read inside the transaction is
    // written again before the fresh one.
    replace('        pending.push(ops.put(NS, SEL, envelope)); // the selector put last',
      "        if (cur !== undefined) pending.push(ops.put(NS, SEL, copy(cur)));\n        pending.push(ops.put(NS, SEL, envelope)); // the selector put last");
  }
  if (variant === 'ncw-in-seed') {
    // Red-team Fase 4 (Argon R5A, anchor adapted): one out-of-D write in the first selector transaction (seed).
    replace('        pending.push(ops.put(NS, SEL, envelope)); // the selector put last',
      "        if (!globalThis.__ncwDone) { globalThis.__ncwDone = true; pending.push(ops.put(NS, '__ncw', new DataView(new ArrayBuffer(4)))); }\n        pending.push(ops.put(NS, SEL, envelope)); // the selector put last");
  }
  // K19 (owner act on #317 6379513740 §2): writes of the port in every operation, armed or not, and in
  // every transaction mode including versionchange (a side database the port opens and upgrades).
  const side = (value) => `await new Promise((res) => { const r = indexedDB.open('bchr-k19-side-' + crypto.randomUUID(), 1);
      r.onupgradeneeded = () => { r.result.createObjectStore('s').put(${value}, 'k'); };
      r.onsuccess = () => { r.result.close(); res(); }; r.onerror = () => res(); });`;
  const ncwValue = 'new DataView(new ArrayBuffer(4))';
  if (variant === 'ncw-in-init') {
    replace('export async function createPort({ db, context }) {', `export async function createPort({ db, context }) {
      await db.transaction([NS], async (ops) => { await ops.put(NS, '__k19init', ${ncwValue}); });`);
  }
  if (variant === 'ncw-in-init-versionchange') {
    replace('export async function createPort({ db, context }) {', `export async function createPort({ db, context }) {
      ${side(ncwValue)}`);
  }
  if (variant === 'ncw-in-versionchange' || variant === 'ok-in-versionchange') {
    replace('    async readSelector() {', `    async readSelector() {
      if (!globalThis.__k19vc) { globalThis.__k19vc = true; ${side(variant === 'ok-in-versionchange' ? '{ a: 1 }' : ncwValue)} }`);
  }
  if (variant === 'ncw-in-armed-versionchange') {
    // The second REPLACE_SELECTOR of the flow is the one of the armed operation (the seed has the first).
    replace('async function replaceSelector(p) {', `async function replaceSelector(p) {
    globalThis.__k19rs = (globalThis.__k19rs ?? 0) + 1;
    if (globalThis.__k19rs === 2) { ${side(ncwValue)} }`);
  }
  if (variant === 'late-write') {
    // A write the port issues after its last operation returned, on a signal of the page.
    replace('export async function createPort({ db, context }) {', `export async function createPort({ db, context }) {
      new BroadcastChannel('bchr-k19-late').onmessage = () => { db.transaction([NS], async (ops) => { await ops.put(NS, '__k19late', ${ncwValue}); }).catch(() => {}); };`);
  }
  // K19 closure (owner decision on #317 6384613341 §1): requests after the final audit of the life, on a
  // signal of the page: a read (no durable effect) and an in-D write that commits (a durable effect).
  if (variant === 'late-read-after-final') {
    replace('export async function createPort({ db, context }) {', `export async function createPort({ db, context }) {
      new BroadcastChannel('bchr-k19-after').onmessage = () => { db.get(NS, '__k19none').catch(() => {}); };`);
  }
  if (variant === 'late-write-after-final') {
    replace('export async function createPort({ db, context }) {', `export async function createPort({ db, context }) {
      new BroadcastChannel('bchr-k19-after').onmessage = () => { db.transaction([NS], async (ops) => { await ops.put(NS, '__k19after', { a: 1 }); }).catch(() => {}); };`);
  }
  if (variant === 'ncw-in-restarted-life') {
    // A write outside D in createPort of a restarted worker life only (the store already holds a selector).
    replace('export async function createPort({ db, context }) {', `export async function createPort({ db, context }) {
      if ((await db.get(NS, SEL)) !== undefined) await db.transaction([NS], async (ops) => { await ops.put(NS, '__k19life2', ${ncwValue}); });`);
  }
  if (variant === 'review-gap-reuse') {
    replace(
      'export async function createPort({ db, context }) {',
      `export async function createPort({ db, context }) {
      new BroadcastChannel('bchr-k19-late').onmessage = async () => {
        try {
          const old = await db.get(NS, SEL);
          await db.transaction([NS], async (ops) => {
            await ops.put(NS, '__review1', old);
            await ops.put(NS, '__review2', old);
            ops.abort();
          });
        } catch {}
      };`
    );
  }
  if (variant === 'review-inline-auto') {
    replace(
      'export async function createPort({ db, context }) {',
      `export async function createPort({ db, context }) {
      await new Promise((resolve, reject) => {
        const r = indexedDB.open('review-inline-auto', 1);
        r.onupgradeneeded = () => {
          r.result.createObjectStore('s', {
            keyPath: 'id', autoIncrement: true
          }).put({ a: 1 });
        };
        r.onsuccess = () => { r.result.close(); resolve(); };
        r.onerror = () => reject(r.error);
      });`
    );
  }
  if (variant === 'review-store-rename') {
    replace(
      'export async function createPort({ db, context }) {',
      `export async function createPort({ db, context }) {
      await new Promise((resolve, reject) => {
        const r = indexedDB.open('review-store-rename', 1);
        r.onupgradeneeded = () => {
          const s = r.result.createObjectStore('before');
          s.put({ a: 1 }, 'k');
          s.name = 'after';
        };
        r.onsuccess = () => { r.result.close(); resolve(); };
        r.onerror = () => reject(r.error);
      });`
    );
  }
  // red-team K19 round, Argon (REVIEW-ARGON-k19.md) Finding 1 vector 1B and Finding 2, adapted to the real
  // reference anchors (Argon's quoted anchors do not exist in these files): between operations, a write of
  // a different envelope carrying the stored selector's nonce, aborted; a delete of the selector.
  if (variant === 'review-gap-nonce') {
    replace(
      'export async function createPort({ db, context }) {',
      `export async function createPort({ db, context }) {
      new BroadcastChannel('bchr-k19-late').onmessage = async () => {
        try {
          const old = await db.get(NS, SEL);
          const forged = old.slice(); forged[forged.length - 1] ^= 1;
          await db.transaction([NS], async (ops) => {
            await ops.put(NS, '__review3', forged);
            ops.abort();
          });
        } catch {}
      };`
    );
  }
  if (variant === 'review-late-delete-sel') {
    replace(
      'export async function createPort({ db, context }) {',
      `export async function createPort({ db, context }) {
      new BroadcastChannel('bchr-k19-late').onmessage = () => { db.transaction([NS], async (ops) => { await ops.delete(NS, SEL); }).catch(() => {}); };`
    );
  }
  // ---- consensus plan (CONSENSO-PIANO.md): controls and variants of the same classes -------------------
  const gapDelete = "new BroadcastChannel('bchr-k19-late').onmessage = () => { db.transaction([NS], async (ops) => { await ops.delete(NS, SEL); }).catch(() => {}); };";
  if (variant === 'plan-attempt-throw-read') {
    // P1 control (Astra CP1, literal): a put of the read envelope without a key on the out-of-line store is
    // never issued (DataError before the clone); the regular write of a fresh envelope follows.
    replace('        const pending = puts.map(([k, v]) => ops.put(NS, k, v));', `        if (cur !== undefined) {
          try { ops.put(NS, undefined, cur); } catch {}
        }
        const pending = puts.map(([k, v]) => ops.put(NS, k, v));`);
  }
  if (variant === 'plan-attempt-throw-after-clone') {
    // P1 control: between operations, the read envelope in a value whose inline key is missing: the clone is
    // taken (the envelope is attributed), then the native call throws DataError: an attempt, not an emission.
    replace('export async function createPort({ db, context }) {', `export async function createPort({ db, context }) {
      const __side = await new Promise((res, rej) => { const r = indexedDB.open('plan-attempt-side', 1); r.onupgradeneeded = () => { r.result.createObjectStore('s', { keyPath: 'id' }); }; r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
      new BroadcastChannel('bchr-k19-late').onmessage = async () => { const old = await db.get(NS, SEL); const t = __side.transaction('s', 'readwrite'); try { t.objectStore('s').put({ e: old }); } catch {} };`);
  }
  if (variant === 'plan-readselector-empty-rw' || variant === 'plan-readselector-empty-rw-delete') {
    // P2 (Astra CP2): every readSelector opens an empty readwrite transaction and waits for its completion.
    replace('    async readSelector() {', `    async readSelector() {
      await db.transaction([NS], () => {});`);
    if (variant === 'plan-readselector-empty-rw-delete') replace('export async function createPort({ db, context }) {', `export async function createPort({ db, context }) {
      ${gapDelete}`);
  }
  if (variant === 'plan-inline-auto-nested') {
    // P5(a): a generated key injected along a nested key path (a missing intermediate object is created).
    const [kp, values] = ['a.id', '{}, { a: {} }, { a: { b: 1 } }'];
    replace('export async function createPort({ db, context }) {', `export async function createPort({ db, context }) {
      await new Promise((resolve, reject) => {
        const r = indexedDB.open('${variant}', 1);
        r.onupgradeneeded = () => { const s = r.result.createObjectStore('s', { keyPath: '${kp}', autoIncrement: true }); for (const v of [${values}]) s.put(v); };
        r.onsuccess = () => { r.result.close(); resolve(); };
        r.onerror = () => reject(r.error);
      });`);
  }
  if (variant === 'plan-store-rename-write') {
    // P5(b): a rename between two writes of the same store object, then a second rename and a delete.
    replace('export async function createPort({ db, context }) {', `export async function createPort({ db, context }) {
      await new Promise((resolve, reject) => {
        const r = indexedDB.open('plan-store-rename-write', 1);
        r.onupgradeneeded = () => {
          const s = r.result.createObjectStore('before'); s.put({ a: 1 }, 'k1');
          s.name = 'after'; s.put({ a: 2 }, 'k2');
          s.name = 'final'; s.delete('k1');
          r.result.createObjectStore('other').put({ b: 1 }, 'x');
        };
        r.onsuccess = () => { r.result.close(); resolve(); };
        r.onerror = () => reject(r.error);
      });`);
  }
  if (variant === 'plan-known-inline-auto') {
    // P5(c) (Astra CP5): an inline key present in the value on a store with a key generator is known before
    // issuance; in a life killed after the commit was sent, the committed alternative is rebuildable.
    replace('export async function createPort({ db, context }) {', `export async function createPort({ db, context }) {
      let __calls = 0;
      const __side = await new Promise((resolve, reject) => {
        const r = indexedDB.open('plan-known-inline-auto', 1);
        r.onupgradeneeded = () => r.result.createObjectStore('s', { keyPath: 'id', autoIncrement: true });
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error);
      });`);
    replace('  async function replaceSelector(p) {', `  async function replaceSelector(p) {
      if (++__calls === 2) {
        const t = __side.transaction('s', 'readwrite');
        t.objectStore('s').put({ id: 7, a: 1 });
        t.commit();
      }`);
  }
  // ---- final consensus review (REVISIONE-FINALE, Astra R2/R3), literal ------------------------------------
const finalSetup = {
  'final-numeric-store': `
    r.result.createObjectStore('1');
    r.result.deleteObjectStore(1);
  `,
  'final-rename-reentrant': `
    const s = r.result.createObjectStore('before');
    s.put({ a: 1 }, 'k');
    s.name = {
      toString() {
        s.name = 'middle';
        return 'after';
      },
    };
  `,
  // Variants of the same classes: a numeric database name deleted, and a delete with an object name whose
  // conversion runs user code once (the count is asserted by the page).
  'final-numeric-database': `
    r.result.createObjectStore('x');
    globalThis.__finalDel = indexedDB.deleteDatabase(7);
  `,
  'final-object-store-name': `
    r.result.createObjectStore('obj');
    globalThis.__finalConv = 0;
    r.result.deleteObjectStore({ toString() { globalThis.__finalConv++; return 'obj'; } });
    if (globalThis.__finalConv !== 1) throw new Error('the name was converted ' + globalThis.__finalConv + ' times');
  `,
}[variant];

if (finalSetup !== undefined) {
  replace(
    'export async function createPort({ db, context }) {',
    `export async function createPort({ db, context }) {
      await new Promise((resolve, reject) => {
        const r = indexedDB.open('${variant}', 1);
        r.onupgradeneeded = () => {
          ${finalSetup}
        };
        r.onsuccess = () => {
          r.result.close();
          resolve();
        };
        r.onerror = () => reject(r.error);
      });`
  );
}
  return source;
}
/** Expected rejection per reference variant (act §6): null = no failure at all. */
const K19_REJECTED = /NON_CANONICAL_WRITE|observer or harness error/;
const VARIANTS = Object.freeze({
  control: null, alias: null, transient: null,
  deep: /nonce/, getter: /nonce/, map: /NON_CANONICAL_WRITE/, set: /NON_CANONICAL_WRITE/, view: /NON_CANONICAL_WRITE/,
  early: /item 6/, 'nested-early': /item 6/, 'hex-selector': /§5/, 'ncw-in-seed': /NON_CANONICAL_WRITE/, 'reemit-read': /re-emits/,
  // K19: an out-of-D write is NON_CANONICAL_WRITE wherever it happens; an unjudged one is an observer error.
  'ncw-in-init': K19_REJECTED, 'ncw-in-init-versionchange': K19_REJECTED, 'ncw-in-versionchange': /NON_CANONICAL_WRITE/,
  'ok-in-versionchange': null, 'ncw-in-armed-versionchange': /NON_CANONICAL_WRITE/,
});

// ---- HTTP: static src + suite, logged ---------------------------------------------------------------------
// K19: requests after the final audit of a worker life, reported by the observer through /hook.
let lateReports = [];
const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://local');
  if (u.pathname === '/hook' && u.searchParams.get('p') === 'K19:LATE') {
    let d = null; try { d = JSON.parse(u.searchParams.get('d')); } catch { d = { unparsable: u.searchParams.get('d') }; }
    lateReports.push(d); return res.end('ok');
  }
  if (u.pathname === '/hook') return hookHandler(u, res);
  const coi = u.searchParams.get('coi') === '1';
  if (coi || u.pathname.startsWith('/suite/') || u.pathname.startsWith('/src/')) {
    res.setHeader('cross-origin-embedder-policy', 'require-corp'); res.setHeader('cross-origin-resource-policy', 'same-origin');
  }
  if (u.pathname === '/' || u.pathname === '/frame') {
    if (coi) res.setHeader('cross-origin-opener-policy', 'same-origin');
    res.setHeader('content-type', 'text/html');
    const body = u.pathname === '/frame' ? '<!doctype html><title>realm</title>' : '<!doctype html><script type="module" src="/suite/page.mjs"></script>';
    fs.appendFileSync(SERVED, `${JSON.stringify({ context, variant: mode, url: req.url, file: null, transformation: null, sha256: sha(body) })}\n`);
    return res.end(body);
  }
  const root = u.pathname.startsWith('/src/') ? path.join(jsRoot, 'src') : suite;
  const file = path.resolve(root, u.pathname.startsWith('/src/') ? u.pathname.slice(5) : u.pathname.slice(7));
  if (!(u.pathname.startsWith('/src/') || u.pathname.startsWith('/suite/')) || !file.startsWith(root + path.sep) || !fs.existsSync(file)) { res.statusCode = 404; return res.end(); }
  let source = fs.readFileSync(file, 'utf8'); let transformation = null;
  if (file === path.join(suite, 'reference-port.mjs') && mode !== 'control') { source = transformReference(source, mode); transformation = `transformReference:${mode}`; }
  fs.appendFileSync(SERVED, `${JSON.stringify({ context, variant: mode, url: req.url, file: path.relative(jsRoot, file), original: sha(fs.readFileSync(file)), transformation, sha256: sha(source) })}\n`);
  res.setHeader('content-type', 'text/javascript'); res.setHeader('cache-control', 'no-store'); res.end(source);
});
let hookHandler = (u, res) => res.end('ok');
// CP6: a request rejected before any handler (e.g. beyond the header size limit) is a harness error.
let clientErrors = [];
server.on('clientError', (err, socket) => {
  clientErrors.push(err?.code ?? String(err?.message));
  try { socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); } catch { /* gone */ }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const browser = await chromium.launch({ executablePath: process.env.BCHR_EXE, headless: true,
  args: ['--disable-gpu', '--disable-extensions', '--no-zygote', '--renderer-process-limit=1'] });
const origin = `http://127.0.0.1:${server.address().port}`;
async function test(name, fn) {
  if (ONLY && !ONLY.has(name) && !ONLY.has(name.replace(/^[^/]+\//, ''))) return;
  context = name; lateReports = []; clientErrors = [];
  try { const data = await fn(); results.push({ name, ok: true, ...data }); }
  catch (e) { results.push({ name, ok: false, error: String(e.stack) }); errors.push(name); }
  fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify(results, null, 1));
  const last = results.at(-1);
  console.log(JSON.stringify({ name, ok: last.ok, error: last.error?.split('\n')[0] }));
}

/**
 * K19 page-side runner (owner decision on #317 6384613341 §1), installed in a page after navigation: the
 * RPC wrapper keeps every audit and the K19 records of every worker life in a lifeChain; `closeLife` is the
 * final audit, `restart` ends the life and starts a new one with the trusted reader before any
 * initialization, `endRun` closes the run with a last reader life. A missing final audit or reader (the
 * candidate before the K19 correction) is recorded as a harness error, never skipped silently.
 */
async function installK19(page) {
  await page.evaluate(async () => {
    const e = await import('/suite/expectations.mjs');
    window.k19 = () => {
      const chain = e.lifeChain(); const audit = []; const reads = [];
      const call = async (op, args = {}) => {
        const x = await window.bchr.call(op, args); audit.push(...(x.audit ?? [])); chain.absorb(x.k19);
        if (x.error) throw Error(JSON.stringify(x.error)); return x.value;
      };
      const closeLife = async () => {
        try { return await call('finalAudit'); } catch (err) { audit.push({ harnessError: true, what: `K19: final audit unavailable: ${err.message}`, cite: e.CITE.K19 ?? 'K19' }); return null; }
      };
      const reader = async () => {
        try { const read = await call('durable'); reads.push(read); chain.reconcile(read); audit.push(...chain.failures()); return read; } catch (err) { audit.push({ harnessError: true, what: `K19: trusted reader unavailable: ${err.message}`, cite: e.CITE.K19 ?? 'K19' }); return null; }
      };
      const restart = async ({ close = true } = {}) => { if (close) await closeLife(); await window.bchr.restart(); return reader(); };
      const endRun = async () => { const read = await restart(); await closeLife(); audit.push(...chain.finish()); return read; };
      return { call, closeLife, reader, restart, endRun, chain, audit, reads };
    };
  });
}
const lateFailures = () => [...lateReports.map((d) => ({ harnessError: true, what: `K19: request ${d?.op} attempted after the final audit of worker life ${d?.life}`, cite: 'K19 (host)' })),
  ...clientErrors.map((c) => ({ harnessError: true, what: `K19: the host rejected a request before its handler (${c})`, cite: 'K19 (host)' }))];
const durableKeys = (read) => (read?.dbs ?? []).flatMap((d) => (d.stores ?? []).flatMap((s) => s.entries.map(([k]) => `${d.name}/${s.name}/${k}`)));

let envelope = null;
try {
  // ---- 1. reference variants ------------------------------------------------------------------------------
  for (const variant of Object.keys(VARIANTS)) {
    mode = variant;
    await test(`reference/${variant}`, async () => {
      const ctx = await browser.newContext(); const page = await ctx.newPage();
      try {
        await page.goto(`${origin}/?factory=reference`);
        await page.waitForFunction(() => window.bchrReady); await page.evaluate(() => window.bchr.start());
        await installK19(page);
        const r = await page.evaluate(async (v) => {
          const k = window.k19(); const { call } = k;
          await call('init', { dbName: `observer-${v}` }); await call('seed', { scenario: 'CAPI-S001' });
          const snap = await call('snapshot'); const beforeDigest = (await call('readback')).dbDigest;
          await call('arm');
          const outcome = ['early', 'nested-early', 'transient', 'control'].includes(v) ? 'INDETERMINATE' : 'COMMITTED';
          const response = await call('original', { scenario: 'CAPI-S001', outcome }); const rb = await call('readback');
          await k.endRun(); // K19: final audit, trusted read in a new life, last life closed
          const e = await import('/suite/expectations.mjs'); const book = e.nonceBook(); book.addObserved(response.selectors); book.add(rb.selector); book.addAudit(k.audit);
          return { snap, response, lives: k.chain.lives(), failures: [...e.checkUninterrupted({ row: 'CAPI-S001', phase: 'ORIGINAL', outcome, beforeDigest, stagedHold: response.stagedHold }, response, rb), ...book.failures()] };
        }, variant);
        r.failures.push(...lateFailures());
        if (variant === 'control') envelope = r.snap.envelope;
        const hard = r.failures.filter((f) => !f.unobserved);
        if (VARIANTS[variant] === null) assert.deepEqual(r.failures, [], 'no failure, no unobserved entry');
        else assert(hard.some((f) => VARIANTS[variant].test(`${f.what} ${f.cite}`)), `the specific violation ${VARIANTS[variant]} is rejected`);
        return { failures: r.failures };
      } finally { await ctx.close(); }
    });
  }
  mode = 'late-write';
  // K19 D16: a write the port issues after its last operation returned (here on a page signal, after the
  // reply of `readback`) is judged by the final audit that closes the worker life, the only operation that
  // follows; an unjudged request is an observer error, never PASS. The trusted reader of the next life
  // shows, as evidence, that the late write is durable.
  await test('reference/late-write', async () => {
    const ctx = await browser.newContext(); const page = await ctx.newPage();
    try {
      await page.goto(`${origin}/?factory=reference`);
      await page.waitForFunction(() => window.bchrReady); await page.evaluate(() => window.bchr.start());
      await installK19(page);
      const r = await page.evaluate(async () => {
        const k = window.k19(); const { call } = k;
        await call('init', { dbName: 'observer-late-write' }); await call('seed', { scenario: 'CAPI-S001' });
        const rb = await call('readback');
        const before = k.audit.length;
        new BroadcastChannel('bchr-k19-late').postMessage('write');
        await new Promise((res) => setTimeout(res, 1500));
        const closed = await k.closeLife(); // the final audit: the next operation of this life
        const held = k.audit.slice(before).map((f) => ({ ...f }));
        const read = await k.restart({ close: false }); await k.closeLife(); k.audit.push(...k.chain.finish());
        return { held, closed: closed?.closed ?? null, read, firstEntries: rb.entries, failures: k.audit };
      });
      assert(durableKeys(r.read).some((x) => x.endsWith('/s9:__k19late')), 'the late write happened (durable, read by the trusted reader)');
      assert(r.held.filter((f) => !f.unobserved).some((f) => /NON_CANONICAL_WRITE/.test(`${f.what} ${f.cite}`)), 'the late write is judged NON_CANONICAL_WRITE by the final audit of its life');
      assert.equal(r.closed, true, 'the final audit closed the life');
      assert.deepEqual(lateReports, [], 'nothing was attempted after the final audit');
      return { held: r.held, entries: r.firstEntries };
    } finally { await ctx.close(); }
  });

  // K19 closure: requests after the final audit of the life. Without a durable effect (a read), the
  // observer error reaches the host and the durable state still reconciles; with one (an in-D write that
  // commits), the observer error reaches the host and the trusted reader's state does not reconcile.
  for (const [name, variant, durableEffect] of [['late-after-final-no-effect', 'late-read-after-final', false], ['late-after-final-effect', 'late-write-after-final', true]]) {
    mode = variant;
    await test(`reference/${name}`, async () => {
      const ctx = await browser.newContext(); const page = await ctx.newPage();
      try {
        await page.goto(`${origin}/?factory=reference`);
        await page.waitForFunction(() => window.bchrReady); await page.evaluate(() => window.bchr.start());
        await installK19(page);
        const r = await page.evaluate(async (n) => {
          const k = window.k19(); const { call } = k;
          await call('init', { dbName: `observer-${n}` }); await call('seed', { scenario: 'CAPI-S001' }); await call('readback');
          const closed = await k.closeLife();
          const atClose = k.audit.map((f) => ({ ...f }));
          new BroadcastChannel('bchr-k19-after').postMessage('go');
          await new Promise((res) => setTimeout(res, 1500));
          const read = await k.restart({ close: false }); await k.closeLife(); k.audit.push(...k.chain.finish());
          return { closed: closed?.closed ?? null, firstLife: closed?.life ?? null, atClose, read, failures: k.audit };
        }, name);
        assert.equal(r.closed, true, 'the final audit closed the first life');
        assert.deepEqual(r.atClose, [], 'the life was clean at its final audit');
        assert(lateReports.length > 0 && lateReports.every((d) => d?.k19late === true && d.life === r.firstLife), `the late request is reported to the host as an observer error of the closed life (${JSON.stringify(lateReports)})`);
        const durableFailures = r.failures.filter((f) => /durable reconciliation/.test(f.what));
        if (durableEffect) assert(durableFailures.some((f) => /__k19after/.test(f.what)), `the durable effect of the late write does not reconcile (${JSON.stringify(durableFailures)})`);
        else assert.deepEqual(durableFailures, [], 'a late request without durable effect leaves a reconciled durable state');
        const verdictFailures = [...r.failures, ...lateFailures()];
        assert(verdictFailures.some((f) => f.harnessError === true), 'the run is never PASS: an observer error is held');
        return { late: lateReports, durableFailures, keys: durableKeys(r.read).length };
      } finally { await ctx.close(); }
    });
  }

  // K19: a write outside D in a restarted worker life (createPort of the second life) is judged in that life.
  mode = 'ncw-in-restarted-life';
  await test('reference/ncw-in-restarted-life', async () => {
    const ctx = await browser.newContext(); const page = await ctx.newPage();
    try {
      await page.goto(`${origin}/?factory=reference`);
      await page.waitForFunction(() => window.bchrReady); await page.evaluate(() => window.bchr.start());
      await installK19(page);
      const r = await page.evaluate(async () => {
        const k = window.k19(); const { call } = k;
        await call('init', { dbName: 'observer-restarted-life' }); await call('seed', { scenario: 'CAPI-S001' });
        const first = k.audit.length;
        await k.restart(); // final audit of life 1, trusted reader of life 2
        const lifeTwo = k.reads.at(-1)?.life ?? null;
        const before = k.audit.length;
        await call('init', { dbName: 'observer-restarted-life' });
        const initAudit = k.audit.slice(before).map((f) => ({ ...f }));
        await k.endRun();
        return { lifeOne: first, lifeTwo, initAudit, failures: k.audit, lives: k.chain.lives() };
      });
      assert(typeof r.lifeTwo === 'string', 'the restarted life is identified by its trusted read');
      assert(r.initAudit.some((f) => /NON_CANONICAL_WRITE/.test(f.what) && f.what.includes(`${r.lifeTwo}:request`)), `the write of createPort in the restarted life is judged NON_CANONICAL_WRITE in that life (${JSON.stringify(r.initAudit)})`);
      assert.deepEqual(lateReports, [], 'nothing was attempted after a final audit');
      return { lives: r.lives, initAudit: r.initAudit };
    } finally { await ctx.close(); }
  });
  // ---- red-team K19 round, Sol (REVIEW-SOL-k19.md), literal flow for R1, R4, R5 ----
async function reviewK19(variant) {
  mode = variant;
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  try {
    await page.goto(`${origin}/?factory=reference`);
    await page.waitForFunction(() => window.bchrReady);
    await page.evaluate(() => window.bchr.start());
    await installK19(page);

    const r = await page.evaluate(async (v) => {
      const k = window.k19();
      await k.reader();
      await k.call('init', { dbName: `observer-${v}` });
      await k.call('seed', { scenario: 'CAPI-S001' });
      await k.call('readback');

      if (v === 'review-gap-reuse' || v === 'review-gap-nonce' || v === 'review-late-delete-sel') {
        const channel = new BroadcastChannel('bchr-k19-late');
        channel.postMessage('write');
        await new Promise((resolve) => setTimeout(resolve, 1500));
        channel.close();
      }

      const read = await k.endRun();
      return { failures: k.audit, read };
    }, variant);

    r.failures.push(...lateFailures());
    return r;
  } finally {
    await ctx.close();
  }
}

for (const variant of [
  'review-gap-reuse',
  'review-inline-auto',
  'review-store-rename',
  'review-gap-nonce',
  'review-late-delete-sel',
]) {
  await test(`reference/${variant}`, async () => {
    const r = await reviewK19(variant);
    if (variant === 'review-gap-reuse' || variant === 'review-gap-nonce') {
      assert(
        r.failures.some((f) =>
          /nonce|re-emits/.test(`${f.what} ${f.cite}`)),
        'selector requests between calls must reject nonce reuse'
      );
    } else if (variant === 'review-late-delete-sel') {
      assert(r.failures.some((f) => !f.unobserved), 'a selector deleted outside REPLACE_SELECTOR must be rejected (act v2 §5 read-back)');
    } else {
      assert.deepEqual(r.failures, [],
        'an in-D control must reconcile without failures');
    }
    return r;
  });
}
for (const variant of [
  'final-numeric-store',
  'final-rename-reentrant',
  'final-numeric-database',
  'final-object-store-name',
]) {
  await test(`reference/${variant}`, async () => {
    const r = await reviewK19(variant);
    assert.deepEqual(
      r.failures,
      [],
      'a valid schema operation must reconcile without failures'
    );
    return r;
  });
}
  // ---- consensus plan (CONSENSO-PIANO.md): reference controls and variants ------------------------------
  // Plain flow: init, seed, readback, an optional signal between operations, end of the run (final audit,
  // trusted reader in a new life, last life closed). `expect`: null = no failure at all, else a pattern.
  const PLAN_FLOWS = {
    'plan-attempt-throw-read': { signal: false, expect: null, ops: ['original'] },
    'plan-attempt-throw-after-clone': { signal: true, expect: null },
    'plan-readselector-empty-rw': { signal: false, expect: null },
    'plan-readselector-empty-rw-delete': { signal: true, expect: /read back|unchanged|§5/ },
    'plan-inline-auto-nested': { signal: false, expect: null },
    'plan-store-rename-write': { signal: false, expect: null },
  };
  for (const [variant, flow] of Object.entries(PLAN_FLOWS)) {
    mode = variant;
    await test(`reference/${variant}`, async () => {
      const ctx = await browser.newContext(); const page = await ctx.newPage();
      try {
        await page.goto(`${origin}/?factory=reference`);
        await page.waitForFunction(() => window.bchrReady); await page.evaluate(() => window.bchr.start());
        await installK19(page);
        const r = await page.evaluate(async ({ v, flow }) => {
          const k = window.k19();
          await k.reader();
          await k.call('init', { dbName: `observer-${v}` }); await k.call('seed', { scenario: 'CAPI-S001' }); await k.call('readback');
          for (const op of flow.ops ?? []) { await k.call('arm'); await k.call(op, { scenario: 'CAPI-S001', outcome: 'COMMITTED' }); await k.call('readback'); }
          if (flow.signal) { const c = new BroadcastChannel('bchr-k19-late'); c.postMessage('go'); await new Promise((res) => setTimeout(res, 1500)); c.close(); }
          const read = await k.endRun();
          return { failures: k.audit, read };
        }, { v: variant, flow });
        r.failures.push(...lateFailures());
        if (flow.expect === null) assert.deepEqual(r.failures, [], 'a lawful control: no failure, no unobserved entry');
        else assert(r.failures.some((f) => !f.unobserved && flow.expect.test(`${f.what} ${f.cite}`)), `rejected for ${flow.expect} (${JSON.stringify(r.failures)})`);
        return { failures: r.failures };
      } finally { await ctx.close(); }
    });
  }

  // Kill flows: the worker life is killed at a hook of an armed operation (never answered), its hook
  // evidence is kept by the page-side chain as the launcher keeps it, and the run is reconciled.
  async function killFlow(variant, { gap, point, op, reject = null }) {
    mode = variant;
    const ctx = await browser.newContext(); const page = await ctx.newPage();
    let evidence = null; let killed = false; const delivered = [];
    try {
      await page.goto(`${origin}/?factory=reference`);
      await page.waitForFunction(() => window.bchrReady); await page.evaluate(() => window.bchr.start());
      await installK19(page);
      await page.evaluate(async (v) => {
        window.__k = window.k19(); const k = window.__k;
        await k.reader();
        await k.call('init', { dbName: `observer-${v}` }); await k.call('seed', { scenario: 'CAPI-S001' }); await k.call('readback');
      }, variant);
      if (gap) await page.evaluate(async () => { const c = new BroadcastChannel('bchr-k19-late'); c.postMessage('go'); await new Promise((res) => setTimeout(res, 1500)); c.close(); });
      // Every accepted hook's K19 delivery is kept, as the launcher keeps it (run.mjs noteOpen).
      hookHandler = (u, res) => {
        if (reject !== null && u.searchParams.get('p') === reject) { res.statusCode = 431; return res.end(); }
        // After the kill point nothing of the killed life is delivered (a terminated worker may still run a
        // few steps before it stops; a killed context would not).
        if (killed) return res.end('ok');
        let d = null; try { d = JSON.parse(u.searchParams.get('d')); } catch { d = null; }
        if (d?.k19) delivered.push(d.k19);
        if (u.searchParams.get('p') === point && !killed) {
          killed = true; evidence = d;
          void page.evaluate(() => { window.bchr.restart().catch(() => {}); }).catch(() => {});
          return undefined; // never answered: the worker dies inside its hook
        }
        return res.end('ok');
      };
      // The killed operation's reply is never absorbed: as with a killed context, nothing of that life reaches
      // the host after the kill point except what its hooks delivered.
      await page.evaluate(async (o) => { await window.__k.call('arm'); void window.bchr.call(o, { scenario: 'CAPI-S001', outcome: 'COMMITTED' }).catch(() => {}); }, op);
      for (let i = 0; i < 100 && !killed; i++) await new Promise((r) => setTimeout(r, 50));
      assert(killed, `the worker reached ${point}`);
      hookHandler = (u, res) => res.end('ok');
      await new Promise((r) => setTimeout(r, 500));
      const r = await page.evaluate(async ({ ev, all }) => {
        const k = window.__k;
        for (const x of all) k.chain.absorb(x);
        k.chain.killed(ev.k19?.life);
        await k.reader(); await k.closeLife(); k.audit.push(...k.chain.finish());
        return { failures: k.audit };
      }, { ev: evidence, all: delivered });
      r.failures.push(...lateFailures());
      return { failures: r.failures, evidence: { life: evidence?.k19?.life, records: evidence?.k19?.records?.length ?? 0 } };
    } finally { hookHandler = (u, res) => res.end('ok'); await ctx.close(); }
  }
  await test('reference/plan-gap-reuse-killed', async () => {
    // P1 (Astra CP1): the literal gap re-emission of review-gap-reuse, then the next armed operation is
    // killed at T0:OPEN before any audit judged the gap: the run-wide nonce ledger rejects it.
    const r = await killFlow('review-gap-reuse', { gap: true, point: 'T0:OPEN', op: 'original' });
    assert(r.failures.some((f) => !f.unobserved && /nonce|re-emits/.test(`${f.what} ${f.cite}`)), `the re-emission of a killed life is rejected (${JSON.stringify(r.failures)})`);
    return r;
  });
  await test('reference/plan-gap-control-killed', async () => {
    // Its lawful control: the same kill without the gap writes reconciles without failure.
    const r = await killFlow('control', { gap: false, point: 'T0:OPEN', op: 'original' });
    assert.deepEqual(r.failures, [], 'no failure');
    return r;
  });
  await test('reference/plan-known-inline-auto', async () => {
    // P5(c) (Astra CP5): killed at T0:COMMIT_SENT of the side transaction, whose put({ id: 7 }) on a store
    // with a key generator has its key known before issuance: either outcome is rebuildable.
    const r = await killFlow('plan-known-inline-auto', { gap: false, point: 'T0:COMMIT_SENT', op: 'original' });
    assert.deepEqual(r.failures.filter((f) => /durable|rebuildable/.test(f.what)), [], `the committed alternative is rebuildable (${JSON.stringify(r.failures)})`);
    return r;
  });
  await test('reference/plan-hook-rejected-then-killed', async () => {
    // CP6 (Astra, giro 2): the first hook of the armed operation is rejected, the life is killed at the next
    // one before any audit: the rejected delta (the gap re-emission) and the delivery error reach the host.
    const r = await killFlow('review-gap-reuse', { gap: true, point: 'T0:OPEN', op: 'original', reject: 'R0' });
    assert(r.failures.some((f) => f.harnessError === true && /hook R0 .* not accepted by the host/.test(f.what)), `the rejected hook is a harness error (${JSON.stringify(r.failures)})`);
    assert(r.failures.some((f) => !f.unobserved && /nonce|re-emits/.test(`${f.what} ${f.cite}`)), `the re-emission of the rejected delta is judged (${JSON.stringify(r.failures)})`);
    return r;
  });
  await test('reference/plan-host-rejects-before-handler', async () => {
    // CP6: requests the HTTP server rejects before any handler (an oversized hook and an oversized
    // K19:LATE report) are harness errors.
    mode = 'control';
    const ctx = await browser.newContext(); const page = await ctx.newPage();
    try {
      await page.goto(`${origin}/?factory=reference`);
      await page.evaluate(async () => {
        const big = 'x'.repeat(40000);
        for (const p of ['T0:OPEN', 'K19:LATE']) { try { await fetch(`/hook?p=${encodeURIComponent(p)}&d=${big}`); } catch { /* rejected */ } }
      });
      const f = lateFailures();
      assert(f.filter((x) => x.harnessError === true && /rejected a request before its handler/.test(x.what)).length >= 2, `both rejections are harness errors (${JSON.stringify(f)})`);
      return { failures: f };
    } finally { clientErrors = []; await ctx.close(); }
  });
  await test('reference/plan-hook-rejected', async () => {
    // P6 (H1): a hook the host does not accept is an observer/harness error of the run, never silent.
    mode = 'control';
    const ctx = await browser.newContext(); const page = await ctx.newPage();
    try {
      await page.goto(`${origin}/?factory=reference`);
      await page.waitForFunction(() => window.bchrReady); await page.evaluate(() => window.bchr.start());
      await installK19(page);
      hookHandler = (u, res) => { if (u.searchParams.get('p') === 'T0:OPEN') { res.statusCode = 431; return res.end(); } return res.end('ok'); };
      const r = await page.evaluate(async () => {
        const k = window.k19();
        await k.reader();
        await k.call('init', { dbName: 'observer-plan-hook-rejected' }); await k.call('seed', { scenario: 'CAPI-S001' });
        await k.call('arm'); await k.call('original', { scenario: 'CAPI-S001', outcome: 'COMMITTED' });
        await k.endRun();
        return { failures: k.audit };
      });
      assert(r.failures.some((f) => f.harnessError === true && /not accepted by the host/.test(f.what)), `a rejected hook is a harness error (${JSON.stringify(r.failures)})`);
      return r;
    } finally { hookHandler = (u, res) => res.end('ok'); await ctx.close(); }
  });
  mode = 'control';
  assert(typeof envelope === 'string', 'the reference control produced the selector envelope the cases use');

  // ---- 2. request cases in dedicated workers ------------------------------------------------------------
  const listPage = await browser.newPage(); await listPage.goto(origin);
  const EXPECTED = await listPage.evaluate(async () => (await import('/suite/observer-cases.mjs')).EXPECTED);
  await listPage.close();
  const NI_FIELDS = ['thrown', 'requests', 'terminal', 'getters', 'traps', 'inner', 'durable'];
  // Results cross the page boundary as JSON text: Playwright's own serializer is not used on deep graphs.
  const inWorker = async (page, name, observer) => JSON.parse(await page.evaluate(({ name, observer, env }) => new Promise((resolve) => {
    const w = new Worker(`/suite/observer-cases.mjs?case=${encodeURIComponent(name)}&mode=${observer ? 'observer' : 'native'}&env=${env}`, { type: 'module' });
    const t = setTimeout(() => { w.terminate(); resolve({ name, harnessError: 'timeout' }); }, 20000);
    w.onerror = (e) => { clearTimeout(t); w.terminate(); resolve({ name, harnessError: `worker error ${e.message}` }); };
    w.onmessage = (ev) => { clearTimeout(t); w.terminate(); resolve(ev.data); };
  }).then((r) => JSON.stringify(r)), { name, observer, env: envelope }));
  const inPage = async (page, name, observer) => JSON.parse(await page.evaluate(async ({ name, observer, env }) => {
    const f = document.createElement('iframe'); f.src = '/frame'; document.body.append(f);
    await new Promise((r) => { f.onload = r; });
    const m = await import('/suite/observer-cases.mjs');
    try { return JSON.stringify(await m.runCase(name, observer, env, f.contentWindow)); } catch (e) { return JSON.stringify({ name, harnessError: String(e?.stack ?? e) }); }
  }, { name, observer, env: envelope }));
  for (const [name, exp] of Object.entries(EXPECTED)) {
    await test(`request/${name}`, async () => {
      const runs = [];
      for (const observer of [false, true]) {
        const page = await browser.newPage();
        try {
          await page.goto(`${origin}/${exp.coi ? '?coi=1' : ''}`);
          if (exp.coi) assert.equal(await page.evaluate(() => crossOriginIsolated), true, 'the COI page is cross-origin isolated');
          runs.push(exp.page ? await inPage(page, name, observer) : await inWorker(page, name, observer));
        } finally { await page.close(); }
      }
      fs.writeFileSync(path.join(out, `${name}-raw.json`), JSON.stringify(runs, null, 1));
      const [baseline, candidate] = runs;
      assert.equal(baseline.harnessError, undefined, `baseline harness error: ${baseline.harnessError}`);
      assert.equal(candidate.harnessError, undefined, `observer harness error: ${candidate.harnessError}`);
      assert(!String(baseline.thrown ?? '').startsWith('HARNESS'), `baseline case setup failed: ${baseline.thrown}`);
      if (exp.ni !== false) {
        for (const k of NI_FIELDS) assert.deepEqual(candidate[k], baseline[k], `non-interference: ${k}`);
      }
      assert.equal(candidate.verdict, exp.v, `expected verdict ${exp.v} (got ${candidate.verdict}: ${JSON.stringify(candidate.records.map((r) => [r.method, r.status, r.reasons]))})`);
      if (exp.env !== undefined) assert.equal(candidate.envelopes, exp.env, 'attributed selector envelopes');
      // Native semantics the expected verdict relies on, asserted on the arm without the observer.
      if (exp.thrown !== undefined) assert.equal(baseline.thrown, exp.thrown, `native outcome without the observer (got ${baseline.thrown})`);
      if (exp.native !== undefined) assert.deepEqual(baseline.requests, exp.native, 'native request outcomes without the observer');
      if (exp.recordKey !== undefined) assert.deepEqual(candidate.records.map((x) => x.key), [exp.recordKey], 'the key recorded before the request settled');
      return { expected: exp, verdict: candidate.verdict, envelopes: candidate.envelopes, getters: [baseline.getters, candidate.getters],
        traps: [baseline.traps, candidate.traps], thrown: [baseline.thrown, candidate.thrown], records: candidate.records.map((r) => ({ method: r.method, status: r.status, issued: r.issued, nonCanonical: r.nonCanonical, reasons: r.reasons, envelopes: r.envelopes.length })) };
    });
  }

  // ---- 4. K12: worker death after the native emission ---------------------------------------------------
  await test('k12/kill-after-emission', async () => {
    const ctx = await browser.newContext(); const page = await ctx.newPage();
    let evidence = null; let killed = false;
    try {
      await page.goto(`${origin}/?factory=reference`);
      await page.waitForFunction(() => window.bchrReady); await page.evaluate(() => window.bchr.start());
      await page.evaluate(async () => { await window.bchr.call('init', { dbName: 'observer-k12' }); await window.bchr.call('seed', { scenario: 'CAPI-S001' }); });
      // The plan of the dry run: the last request of T0 is the selector put.
      const dry = await page.evaluate(async () => { await window.bchr.call('arm', {}); return (await window.bchr.call('original', { scenario: 'CAPI-S001', outcome: 'COMMITTED', generation: '2' })).value; });
      const plan = {}; for (const e of dry.trace) if (e.ev === 'REQ') plan[e.tx] = Math.max(plan[e.tx] ?? -1, e.j);
      await page.evaluate(async () => { await window.bchr.restart(); await window.bchr.call('init', { dbName: 'observer-k12b' }); await window.bchr.call('seed', { scenario: 'CAPI-S001' }); });
      hookHandler = (u, res) => {
        if (u.searchParams.get('p') === 'T0:END' && !killed) {
          killed = true; evidence = JSON.parse(u.searchParams.get('d'));
          void page.evaluate(() => { window.bchr.restart().catch(() => {}); }).catch(() => {}); // the worker dies inside its hook
          return undefined; // never answered
        }
        return res.end('ok');
      };
      await page.evaluate(async (p) => { await window.bchr.call('arm', { plan: p }); void window.bchr.call('original', { scenario: 'CAPI-S001', outcome: 'COMMITTED' }); }, plan);
      for (let i = 0; i < 100 && !killed; i++) await new Promise((r) => setTimeout(r, 50));
      assert(killed, 'the worker reached T0:END');
      const sel = evidence.writes.filter((w) => w.issued === true && w.envelopes.length > 0);
      assert.equal(sel.length, 1, 'the host holds the issued selector write record of the killed worker');
      assert.equal(sel[0].nonCanonical, false, 'the reference selector write is in D');
      return { writes: evidence.writes.map((w) => ({ method: w.method, issued: w.issued, status: w.status, envelopes: w.envelopes.length })) };
    } finally { hookHandler = (u, res) => res.end('ok'); await ctx.close(); }
  });
} finally { await browser.close(); await new Promise((r) => server.close(r)); }

// ---- 5. unit checks of the judges ------------------------------------------------------------------------
const E = await import(pathToFileURL(path.join(suite, 'expectations.mjs')).href);
const W = (token, o) => ({ token, method: 'put', status: 'success', issued: true, nonCanonical: false, attribution: 'complete', envelopes: [], issuedSeq: 0, ...o });
const env = (e) => [{ envelope: e, nonce: `n-${e}` }];
const unit = (name, fn) => test(`unit/${name}`, async () => { fn(); return {}; });
await unit('correspondence-exact', () => {
  const f = E.checkCorrespondence({ events: [{ token: 'e', status: 'written', startSeq: 1, endSeq: 10, envelope: 'A' }],
    txs: [{ gid: 0, openSeq: 2, mode: 'readwrite', terminal: 'complete', writes: [W('r', { envelopes: env('A'), settledSeq: 3 })] }], stored: 'A', lastStored: 'X' });
  assert.deepEqual(f, []);
});
await unit('correspondence-failed-request-plus-string', () => {
  // K11: the completed replacement's transaction holds a failed request carrying the envelope and a
  // successful request writing it as a string: nothing satisfies the correspondence.
  const f = E.checkCorrespondence({ events: [{ token: 'e', status: 'written', startSeq: 1, endSeq: 10, envelope: null }],
    txs: [{ gid: 0, openSeq: 2, mode: 'readwrite', terminal: 'complete', writes: [W('bad', { status: 'error', envelopes: env('A') }), W('hex', {})] }], stored: 'A', lastStored: 'X' });
  assert(f.some((x) => /exactly one complete transaction/.test(x.what)));
});
await unit('correspondence-two-requests', () => {
  const f = E.checkCorrespondence({ events: [{ token: 'e', status: 'written', startSeq: 1, endSeq: 10, envelope: null }],
    txs: [{ gid: 0, openSeq: 2, mode: 'readwrite', terminal: 'complete', writes: [W('a', { envelopes: env('A') }), W('b', { envelopes: env('A') })] }], stored: 'A' });
  assert(f.some((x) => /exactly one successful selector-carrying request/.test(x.what)));
});
await unit('correspondence-unmatched-unarmed', () => {
  // A selector request outside any completed REPLACE_SELECTOR (e.g. an unarmed operation) fails.
  const f = E.checkCorrespondence({ events: [{ token: 'e', status: 'refused', startSeq: 1, endSeq: 10, envelope: null }],
    txs: [{ gid: 0, openSeq: 2, mode: 'readwrite', terminal: 'complete', writes: [W('a', { envelopes: env('A') })] }], stored: 'A', lastStored: 'X' });
  assert(f.some((x) => /belongs to no completed REPLACE_SELECTOR/.test(x.what)));
});
await unit('correspondence-shared-request', () => {
  // Red-team Fase 4 (Argon R6, adapted to the real event shape): two completed events, one transaction.
  const f = E.checkCorrespondence({ events: [{ token: 'e1', status: 'written', startSeq: 1, endSeq: 15, envelope: null }, { token: 'e2', status: 'written', startSeq: 2, endSeq: 16, envelope: null }],
    txs: [{ gid: 0, openSeq: 5, mode: 'readwrite', terminal: 'complete', writes: [W('a', { envelopes: env('A') })] }], stored: 'A', lastStored: 'X' });
  assert(f.some((x) => /more than one/.test(x.what)), JSON.stringify(f));
});
await unit('nonce-reemission-of-read-envelope', () => {
  // Red-team Fase 4 (Sol r3 #2), literal on nonceBook.
  const b = E.nonceBook();
  const old = { envelope: 'A', nonce: 'n-A' };
  b.add(old);
  b.addPut({ token: 'retry-old-envelope', method: 'put', issued: true, status: 'success', terminal: 'abort', nonCanonical: false, attribution: 'complete', envelopes: [old] });
  assert.ok(b.failures().some((f) => !f.unobserved), 'item 10: reject reuse of the previously read envelope');
});
await unit('correspondence-aborted-transaction', () => {
  const f = E.checkCorrespondence({ events: [{ token: 'e', status: 'written', startSeq: 1, endSeq: 10, envelope: null }],
    txs: [{ gid: 0, openSeq: 2, mode: 'readwrite', terminal: 'abort', writes: [W('a', { envelopes: env('A') })] }], stored: 'X', lastStored: 'X' });
  assert(f.some((x) => /exactly one complete transaction/.test(x.what)));
});
await unit('correspondence-readback', () => {
  const ok = E.checkCorrespondence({ events: [], txs: [], stored: 'X', lastStored: 'X' });
  assert.deepEqual(ok, []);
  const bad = E.checkCorrespondence({ events: [], txs: [], stored: 'Y', lastStored: 'X' });
  assert(bad.some((x) => /unchanged/.test(x.what)));
  const wrong = E.checkCorrespondence({ events: [{ token: 'e', status: 'written', startSeq: 1, endSeq: 10, envelope: null }],
    txs: [{ gid: 0, openSeq: 2, mode: 'readwrite', terminal: 'complete', writes: [W('a', { envelopes: env('A') })] }], stored: 'B' });
  assert(wrong.some((x) => /read back/.test(x.what)));
});
await unit('ncw-before-issuance-filter', () => {
  const b = E.nonceBook();
  b.addPut(W('p', { issued: false, status: 'throw', nonCanonical: true, attribution: 'non-canonical', reasons: ['class:Map'] }));
  b.addPut(W('q', { issued: false, status: 'PRECLONE_REJECTED' }));
  const f = b.failures();
  assert.equal(f.length, 1); assert.match(f[0].what, /NON_CANONICAL_WRITE/); assert.notEqual(f[0].unobserved, true);
});
await unit('k12-missing-metadata-is-not-zero', () => {
  const b = E.nonceBook(); b.addPut({ token: 'missing-killed-worker-metadata' });
  assert(b.failures().some((x) => x.unobserved === true));
});

// K19 durable reconciliation (owner decision on #317 6384613341 §1): the host model on synthetic records.
const SR = (token, method, o) => ({ token, kind: 'schema', method, db: 'd', txg: 0, status: 'success', terminal: 'complete', terminalSeq: 3, seq: 1, opaque: false, ...o });
const WR = (token, method, o) => ({ token, kind: 'write', method, db: 'd', store: 's', txg: 1, key: 's1:a', digest: 'v1', status: 'success', issued: true, terminal: 'complete', terminalSeq: 20, issuedSeq: 10, opaque: false, ...o });
const READ = (life, entries, extra = []) => ({ life, dbs: [{ name: 'd', version: 1, stores: [{ name: 's', entries }] }, ...extra] });
const schema = [SR('u', 'upgrade', { newVersion: 1, seq: 1 }), SR('c', 'createObjectStore', { store: 's', seq: 2 })];
const chainOf = (records, { killed = false, closed = true } = {}) => { const c = E.lifeChain(); c.absorb({ life: 'L1', closed, records: [...schema, ...records] }); if (killed) c.killed('L1'); return c; };
await unit('durable-overwrite-delete-clear', () => {
  const c = chainOf([WR('p1', 'put', { issuedSeq: 10 }), WR('p2', 'put', { issuedSeq: 11, digest: 'v2' }), WR('p3', 'put', { issuedSeq: 12, key: 's1:b' }),
    WR('d1', 'delete', { issuedSeq: 13, key: 's1:b', digest: null }), WR('p4', 'put', { txg: 2, terminalSeq: 30, key: 's1:c', digest: 'v3' }),
    WR('x1', 'clear', { txg: 3, terminalSeq: 40, key: null, digest: null }), WR('p5', 'put', { txg: 3, terminalSeq: 40, issuedSeq: 41, key: 's1:z', digest: 'v9' })]);
  c.reconcile(READ('L2', [['s1:z', 'v9']])); assert.deepEqual(c.failures(), []);
  const bad = chainOf([WR('p1', 'put'), WR('p2', 'put', { issuedSeq: 11, digest: 'v2' })]);
  bad.reconcile(READ('L2', [['s1:a', 'v1']])); assert(bad.failures().some((x) => /durable reconciliation/.test(x.what)), 'the overwrite order is reconciled');
});
await unit('durable-aborted-and-failed-requests', () => {
  const c = chainOf([WR('p1', 'put', { terminal: 'abort' }), WR('p2', 'put', { txg: 2, status: 'error', key: 's1:q' }), WR('p3', 'put', { txg: 2, issuedSeq: 12, key: 's1:r', issued: false, status: 'PRECLONE_REJECTED' })]);
  c.reconcile(READ('L2', [])); assert.deepEqual(c.failures(), []);
});
await unit('durable-unjudged-write', () => {
  // A durable entry no judged request explains (an unrecorded writer) never reconciles.
  const c = chainOf([WR('p1', 'put')]);
  c.reconcile(READ('L2', [['s1:a', 'v1'], ['s1:hidden', 'vx']])); assert(c.failures().some((x) => /present|rebuilt/.test(x.what)));
  const side = chainOf([WR('p1', 'put')]);
  side.reconcile(READ('L2', [['s1:a', 'v1']], [{ name: 'side', version: 1, stores: [] }])); assert(side.failures().some((x) => /database side present but not rebuilt/.test(x.what)), 'a side database must be rebuilt');
});
await unit('durable-killed-life-unknown-outcome', () => {
  for (const entries of [[], [['s1:a', 'v1']]]) {
    const c = chainOf([WR('p1', 'put', { terminal: null, terminalSeq: null, status: 'pending' })], { killed: true, closed: false });
    c.reconcile(READ('L2', entries)); assert.deepEqual(c.failures(), [], 'either outcome of an unobserved transaction of a killed life');
  }
  const c = chainOf([WR('p1', 'put', { terminal: null, terminalSeq: null, status: 'pending' })], { killed: true, closed: false });
  c.reconcile(READ('L2', [['s1:a', 'v2']])); assert(c.failures().some((x) => /durable reconciliation/.test(x.what)), 'no other state');
});
await unit('durable-unclosed-life', () => {
  const c = chainOf([WR('p1', 'put')], { closed: false });
  c.reconcile(READ('L2', [['s1:a', 'v1']])); assert(c.failures().some((x) => /neither by its final audit nor by an intentional kill/.test(x.what)));
  const open = chainOf([WR('p1', 'put', { terminal: null, terminalSeq: null })]);
  open.reconcile(READ('L2', [])); assert(open.failures().some((x) => /no outcome after its closure/.test(x.what)), 'a non-killed life leaves no transaction without outcome');
  const last = E.lifeChain(); last.absorb({ life: 'L9', closed: false, records: [] }); assert(last.finish().some((x) => /not closed by its final audit/.test(x.what)));
});
await unit('durable-late-report', () => {
  const c = E.lifeChain(); c.late({ k19late: true, life: 'L1', op: 'put', seq: 9 }); assert(c.failures().some((x) => x.harnessError === true && /after the final audit/.test(x.what)));
});
// ---- red-team K19 round (REVIEW-ARGON-k19.md Finding 1 unit part, Finding 3), literal logic -------------
await unit('review-reemission-outside-port-call', () => {
  // D17 (Argon F1 vector 1A), literal records (no issuance metadata): never a silent pass.
  const lit = E.checkReemission([{ token: 'p2', seq: 20, inPortCall: false, envelopes: [{ envelope: 'aa'.repeat(40), nonce: '11'.repeat(12) }] }],
    [{ token: 'p1', seq: 10, via: 'request p1', envelope: 'aa'.repeat(40), nonce: '11'.repeat(12) }]);
  assert(lit.length > 0, 'the literal probe is not a pass');
  // As the observer records it (issued), outside a port call: a re-emission.
  const f = E.checkReemission([{ token: 'p2', seq: 20, inPortCall: false, issued: true, envelopes: [{ envelope: 'aa'.repeat(40), nonce: '11'.repeat(12) }] }],
    [{ token: 'p1', seq: 10, via: 'request p1', envelope: 'aa'.repeat(40), nonce: '11'.repeat(12) }]);
  assert(f.some((x) => !x.unobserved && /re-emits/.test(x.what)), JSON.stringify(f));
  // Consensus plan P1: an attempt that was never issued is not an emission.
  assert.deepEqual(E.checkReemission([{ token: 'p3', seq: 30, issued: false, status: 'throw', envelopes: [{ envelope: 'aa'.repeat(40), nonce: '11'.repeat(12) }] }],
    [{ token: 'p1', seq: 10, via: 'request p1', envelope: 'aa'.repeat(40), nonce: '11'.repeat(12) }]), []);
});
await unit('review-reemission-same-nonce-other-envelope', () => {
  // D18 (Argon F1 vector 1B), literal records: never a silent pass; as recorded (issued): a reused nonce.
  const lit = E.checkReemission([{ token: 'p2', seq: 20, inPortCall: true, envelopes: [{ envelope: 'bb'.repeat(40), nonce: '11'.repeat(12) }] }],
    [{ token: 'p1', seq: 10, via: 'request p1', envelope: 'aa'.repeat(40), nonce: '11'.repeat(12) }]);
  assert(lit.length > 0, 'the literal probe is not a pass');
  const f = E.checkReemission([{ token: 'p2', seq: 20, inPortCall: true, issued: true, envelopes: [{ envelope: 'bb'.repeat(40), nonce: '11'.repeat(12) }] }],
    [{ token: 'p1', seq: 10, via: 'request p1', envelope: 'aa'.repeat(40), nonce: '11'.repeat(12) }]);
  assert(f.some((x) => !x.unobserved && /nonce/.test(x.what)), JSON.stringify(f));
  const two = E.checkReemission([{ token: 'p4', seq: 40, issued: true, envelopes: [{ envelope: 'cc'.repeat(40), nonce: '22'.repeat(12) }, { envelope: 'dd'.repeat(40), nonce: '22'.repeat(12) }] }], []);
  assert(two.some((x) => /two different envelopes/.test(x.what)), JSON.stringify(two));
});
await unit('review-killed-inline-key-not-committed', () => {
  // D26 (Argon F3): in an intentionally killed life a pending put without a known key; the trusted reader
  // shows the transaction did not commit: the not-committed alternative reconciles, nothing fails.
  const chain = E.lifeChain();
  chain.absorb({ life: 'worker-0', records: [
    { token: 's0', kind: 'schema', method: 'upgrade', db: 'd', newVersion: 1, txg: 0, seq: 1, terminal: 'complete', terminalSeq: 3 },
    { token: 's1', kind: 'schema', method: 'createObjectStore', db: 'd', store: 's', txg: 0, seq: 2, terminal: 'complete', terminalSeq: 3 },
    { token: 'p1', kind: 'write', method: 'put', db: 'd', store: 's', txg: 1, seq: 4, issued: true, status: 'pending', terminal: null, key: null, digest: '00'.repeat(32), opaque: false },
  ] });
  chain.killed('worker-0');
  chain.absorb({ life: 'worker-1', records: [], closed: true });
  chain.reconcile({ life: 'worker-1', dbs: [{ name: 'd', version: 1, stores: [{ name: 's', entries: [] }] }] });
  assert.deepEqual(chain.finish(), []);
});
// ---- consensus plan (CONSENSO-PIANO.md): nonce ledger and durable model units -----------------------------
const LW = (token, seq, env, o = {}) => ({ token, kind: 'write', method: 'put', db: 'd', store: 's', txg: 1, key: `s1:${token}`, digest: 'v', status: 'pending', issued: true, terminal: null, seq, issuedSeq: seq, opaque: false, envelopes: env, ...o });
const E1 = { envelope: 'aa'.repeat(40), nonce: '11'.repeat(12) }; const E2 = { envelope: 'bb'.repeat(40), nonce: '11'.repeat(12) }; const E3 = { envelope: 'cc'.repeat(40), nonce: '33'.repeat(12) };
const ledgerFailures = (lives) => {
  const c = E.lifeChain();
  for (const L of lives) { c.absorb({ life: L.id, records: [...schema, ...L.records], reads: L.reads ?? [], closed: !L.killed }); if (L.killed) c.killed(L.id); }
  c.absorb({ life: 'R', records: [], closed: true });
  c.reconcile({ life: 'R', dbs: null });
  return c.finish().filter((x) => /nonce/.test(x.cite ?? '') || /nonce|re-emits/.test(x.what));
};
await unit('plan-ledger-killed-life-identical', () => {
  // P1 (Astra CP1): two emissions of one envelope in one killed life, never judged by its own audit.
  assert(ledgerFailures([{ id: 'L1', killed: true, records: [LW('a', 10, [E1]), LW('b', 11, [E1])] }]).some((x) => /re-emits/.test(x.what)));
});
await unit('plan-ledger-cross-life-nonce', () => {
  // A nonce of an earlier life sealing a different envelope later (a counter that restarts).
  assert(ledgerFailures([{ id: 'L1', records: [LW('a', 10, [E1], { status: 'success', terminal: 'complete', terminalSeq: 12 })] }, { id: 'L2', records: [LW('b', 5, [E2], { status: 'success', terminal: 'abort', terminalSeq: 7 })] }]).some((x) => /nonce/.test(x.what)));
});
await unit('plan-ledger-read-then-write', () => {
  // An envelope read (in this life) before a write that carries it again; and its lawful control: the
  // read-back of an envelope after its own write, read again, then a fresh envelope.
  assert(ledgerFailures([{ id: 'L1', killed: true, records: [LW('a', 10, [E1])], reads: [{ envelope: E1.envelope, nonce: E1.nonce, seq: 5, via: 'get' }] }]).some((x) => /re-emits/.test(x.what)));
  assert.deepEqual(ledgerFailures([{ id: 'L1', killed: true, records: [LW('a', 10, [E1]), LW('c', 30, [E3])], reads: [{ envelope: E1.envelope, nonce: E1.nonce, seq: 20, via: 'get' }, { envelope: E1.envelope, nonce: E1.nonce, seq: 21, via: 'get' }] }]), []);
});
await unit('plan-ledger-double-delivery', () => {
  // One request delivered twice (hook while pending, reply once complete) is one emission; a later stale
  // delivery does not move it back.
  const c = E.lifeChain();
  c.absorb({ life: 'L1', records: [...schema, LW('a', 10, [E1])] });
  c.absorb({ life: 'L1', records: [LW('a', 10, [E1], { status: 'success', terminal: 'complete', terminalSeq: 12 })], closed: true });
  c.absorb({ life: 'L1', records: [LW('a', 10, [E1])] });
  c.absorb({ life: 'R', records: [], closed: true });
  c.reconcile({ life: 'R', dbs: [{ name: 'd', version: 1, stores: [{ name: 's', entries: [['s1:a', 'v']] }] }] });
  assert.deepEqual(c.finish(), []);
});
await unit('plan-ledger-missing-issuance', () => {
  assert(ledgerFailures([{ id: 'L1', killed: true, records: [LW('a', 10, [E1], { issued: undefined })] }]).filter((x) => !x.unobserved).length === 0);
  const c = E.lifeChain(); c.absorb({ life: 'L1', records: [...schema, LW('a', 10, [E1], { issued: undefined })] }); c.killed('L1');
  c.absorb({ life: 'R', records: [], closed: true }); c.reconcile({ life: 'R', dbs: null });
  assert(c.finish().some((x) => x.unobserved === true && /issuance metadata/.test(x.what)));
});
await unit('plan-killed-life-limit-ncw-metadata', () => {
  // CP6 (Astra, giro 2): what a killed life never judged itself is judged by the host.
  const run = (records, reads = []) => { const c = E.lifeChain(); c.absorb({ life: 'L', records: [...schema, ...records], reads }); c.killed('L'); c.absorb({ life: 'R', records: [], closed: true }); c.reconcile(READ('R', [])); return c.finish(); };
  assert(run([], [{ seq: 1, envelope: null, nonce: null, limit: true, via: 'getAll' }]).some((x) => x.unobserved === true && /object limit/.test(x.what)), 'a read beyond the limit in a killed life is unobserved');
  assert(run([WR('n1', 'put', { issued: false, status: 'throw', nonCanonical: true, reasons: ['class:Map'], terminal: null, terminalSeq: null })]).some((x) => !x.unobserved && /NON_CANONICAL_WRITE/.test(x.what)), 'a non-issued NCW attempt of a killed life is NCW');
  assert(run([WR('m1', 'put', { issued: undefined, envelopes: [], terminal: null, terminalSeq: null, status: 'pending' })]).some((x) => x.unobserved === true && /issuance metadata/.test(x.what)), 'missing issuance metadata without envelopes is unobserved');
  const d = E.lifeChain(); d.absorb({ life: 'L', records: [...schema], deliveryErrors: ['hook R0 of worker life L was not accepted by the host (status 431, URL of 1 characters)'] }); d.killed('L');
  d.absorb({ life: 'R', records: [], closed: true }); d.reconcile(READ('R', []));
  assert(d.finish().some((x) => x.harnessError === true && /not accepted by the host/.test(x.what)), 'a delivery error reaches the verdict');
  assert(E.checkReemission([{ token: 'q', seq: 5, envelopes: [] }], []).some((x) => x.unobserved === true), 'checkReemission: missing issuance metadata without envelopes is unobserved');
});
await test('unit/final-recognizer-equals-codec', async () => {
  // Review R1: the observer attributes a selector envelope iff the frozen codec decodes it as kind 17.
  const I = await import(pathToFileURL(path.join(suite, 'instrument.mjs')).href);
  const S = await import(pathToFileURL(path.join(here, '../../../../../src/storage/m2/session-codec.js')).href);
  const rnd = (n, seed) => Uint8Array.from({ length: n }, (_, i) => ((i * 131 + seed * 7 + 1) & 255) || 1);
  const make = async (scope, gen = 5n, pl = 40) => {
    const local = rnd(32, 1); const recordKey = S.encodeSelectorKey({ localContextId: local });
    const aad = await S.encodeAad({ recordKey, localContextId: local, productProfileDigest: rnd(32, 2), scope, secureSessionIdentity: scope === 2 ? rnd(32, 3) : null,
      canonicalBinding: scope === 2 ? rnd(389, 4) : null, writeGeneration: gen, mutationIdentity: rnd(32, 5), plaintextLength: pl, recordKind: 17 });
    return S.encodeEnvelope({ recordKind: 17, recordKey, aad, plaintextLength: pl, nonce: rnd(12, 6), ciphertext: rnd(pl, 7), tag: rnd(16, 8) });
  };
  const codecSays = (u) => { try { return S.decodeEnvelope(u).recordKind === 17; } catch { return false; } };
  const observerSays = (u) => I.recognizeSelector(u) !== null;
  const samples = [];
  for (const scope of [1, 2]) {
    const base = await make(scope);
    samples.push(base);
    // Every single-byte change of the envelope (three values per position) and every truncation/extension.
    for (let i = 0; i < base.length; i++) for (const v of [0, 1, base[i] ^ 0xff]) { const u = base.slice(); u[i] = v; samples.push(u); }
    for (const n of [base.length - 1, base.length + 1]) { const u = new Uint8Array(n); u.set(base.subarray(0, Math.min(n, base.length))); samples.push(u); }
  }
  // The literal bytes of review R1.
  const lit = new Uint8Array(64); lit.set([0x53, 0x54, 0x59, 0x58, 0x46, 0x4d, 0x54, 0x31]);
  const dv = new DataView(lit.buffer); for (const [p, v] of [[8, 1], [10, 17], [12, 65535], [14, 1], [16, 1], [18, 1], [34, 16]]) dv.setUint16(p, v);
  samples.push(lit);
  let agree = 0; const disagree = [];
  for (const u of samples) { if (codecSays(u) === observerSays(u)) agree++; else disagree.push(Array.from(u.subarray(0, 40))); }
  assert.deepEqual(disagree.slice(0, 3), [], `recogniser and codec disagree on ${disagree.length} of ${samples.length} samples`);
  assert.equal(observerSays(lit), false, 'the literal R1 bytes are not a selector envelope');
  assert(agree > 1000, `${agree} samples compared`);
  return { samples: samples.length, agree };
});
await unit('plan-model-unrebuildable-alternative', () => {
  // P5(c): a killed life, a pending put whose key is unknown (generated): the not-committed state
  // reconciles; a durable state that needs the committed alternative fails with its reason.
  const rec = [...schema, WR('p1', 'put', { key: null, status: 'pending', terminal: null, terminalSeq: null })];
  const ok = E.lifeChain(); ok.absorb({ life: 'L1', records: rec }); ok.killed('L1');
  ok.reconcile(READ('L2', [])); assert.deepEqual(ok.failures(), []);
  const bad = E.lifeChain(); bad.absorb({ life: 'L1', records: rec }); bad.killed('L1');
  bad.reconcile(READ('L2', [['n:1', 'v1']])); assert(bad.failures().some((x) => /durable/.test(x.what)), 'never a pass when the committed alternative cannot be rebuilt');
});
await unit('plan-model-rename', () => {
  const c = chainOf([SR('r', 'renameObjectStore', { from: 's', store: 't', seq: 5 }), WR('p1', 'put', { store: 't', txg: 0, issuedSeq: 6, terminalSeq: 3 })]);
  c.reconcile({ life: 'L2', dbs: [{ name: 'd', version: 1, stores: [{ name: 't', entries: [['s1:a', 'v1']] }] }] }); assert.deepEqual(c.failures(), []);
});

const manifest = Object.fromEntries(['run.mjs', 'suite/instrument.mjs', 'suite/worker.mjs', 'suite/expectations.mjs', 'suite/reference-port.mjs', 'suite/fixtures.mjs', 'suite/page.mjs', 'suite/observer-cases.mjs', 'observer-regressions.mjs', 'concrete-path.test.mjs'].map((f) => [f, sha(fs.readFileSync(path.join(here, f)))]));
const verdict = errors.length ? 'FAIL' : (ONLY ? 'INCOMPLETE' : 'PASS');
fs.writeFileSync(path.join(out, 'verdict.json'), JSON.stringify({ count: results.length, errors, manifest, served: sha(fs.readFileSync(SERVED)), verdict }, null, 2));
console.log(JSON.stringify({ count: results.length, errors, verdict }));
process.exitCode = errors.length ? 1 : 0;
