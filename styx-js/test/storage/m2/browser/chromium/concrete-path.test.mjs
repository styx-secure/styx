// Source-bound proof for the reference port (owner act v2 on #317, §7), Chromium + Node. Run from styx-js/:
//   node test/storage/m2/browser/chromium/concrete-path.test.mjs
// Environment: BCHR_EXE (browser executable), BCHR_OUT (output directory).
// Parts (the off-repository dossier explains every inventory entry):
//   A. static inventory of the port and its closure, bound to exact bytes (SHA-256 of every file and of the
//      canonical inventory): write and delete sites, randomness, commit(), forbidden code, mutation sites of
//      in-memory state, in-place writes, aliases, output exits and every branch of the port and of VaultDb;
//      plus semantic assertions (one fresh seal per selector request, values built from fresh bytes);
//   B. dynamic item-6 / output proof in Chromium on every required branch: the binding transaction is
//      identified by its observer identity; no hold and no output before its native `complete`, none after an
//      abort, error or synchronous throw; authoritative state unchanged around every readwrite transaction;
//   C. equivalence controls: every source transformation, with its flags off, against the untransformed
//      sources under the same recorded deterministic random stream: identical results, traces, durable digests;
//   D. mutants derived in memory only, each rejected by its named component.
// Transformed sources exist only in HTTP responses; every delivered body is logged with its SHA-256.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../../../..');
const suite = path.join(here, 'suite');
const { lifeChain } = await import(pathToFileURL(path.join(suite, 'expectations.mjs')).href);
const out = path.resolve(process.env.BCHR_OUT ?? 'concrete-path-out'); fs.mkdirSync(out, { recursive: true });
const requireJs = createRequire(path.join(root, 'package.json'));
const { chromium } = requireJs('playwright-core');
const acorn = requireJs('acorn');
const sha = (b) => createHash('sha256').update(b).digest('hex');
const rel = (f) => path.relative(root, f);
const REF = path.join(suite, 'reference-port.mjs');
const VAULT = path.join(root, 'src/storage/vault-db.js');
const DRIVER = path.join(root, 'src/storage/m2/session-transaction.js');
const WORKER = path.join(suite, 'worker.mjs');
const results = { static: {}, dynamic: [], equivalence: [], mutants: [] };
const failures = [];
const check = (ok, what) => { if (!ok) failures.push(what); return ok; };

// ============================================ A. static inventory ============================================
/** Static import closure of a module (relative and /src/ specifiers). */
function closureOf(entry) {
  const files = new Set();
  const visit = (file) => {
    if (files.has(file)) return; files.add(file);
    const ast = acorn.parse(fs.readFileSync(file, 'utf8'), { ecmaVersion: 'latest', sourceType: 'module' });
    for (const n of ast.body) {
      if ((n.type === 'ImportDeclaration' || n.type === 'ExportNamedDeclaration' || n.type === 'ExportAllDeclaration') && n.source) {
        const s = n.source.value;
        if (s.startsWith('.')) visit(path.resolve(path.dirname(file), s));
        else if (s.startsWith('/src/')) visit(path.join(root, s.slice(1)));
        else throw new Error(`unexpected import ${s} in ${rel(file)}`);
      }
    }
  };
  visit(entry);
  return [...files].sort();
}
function walk(node, visit, parents = []) {
  if (node === null || typeof node !== 'object') return;
  if (typeof node.type === 'string') visit(node, parents);
  for (const k of Object.keys(node)) {
    if (k === 'loc' || k === 'start' || k === 'end') continue;
    const v = node[k];
    if (Array.isArray(v)) for (const x of v) walk(x, visit, typeof node.type === 'string' ? [...parents, node] : parents);
    else if (v && typeof v === 'object') walk(v, visit, typeof node.type === 'string' ? [...parents, node] : parents);
  }
}
const BRANCH = new Set(['IfStatement', 'ConditionalExpression', 'LogicalExpression', 'SwitchCase', 'TryStatement', 'CatchClause',
  'ForStatement', 'ForOfStatement', 'ForInStatement', 'WhileStatement', 'DoWhileStatement', 'ChainExpression']);
const MUTATING = new Set(['push', 'pop', 'shift', 'unshift', 'splice', 'sort', 'reverse', 'fill', 'copyWithin', 'set', 'add', 'delete', 'clear']);
const IDB_WRITE = new Set(['put', 'add', 'delete', 'clear', 'update']);
/**
 * Inventory of one source. `branches` adds every branch point; `state` names the variables whose mutation
 * sites are inventoried (module or createPort state); every member assignment (in-place write) is listed.
 */
export function inventory(file, source, { branches = false } = {}) {
  const ast = acorn.parse(source, { ecmaVersion: 'latest', sourceType: 'module', locations: true });
  const lines = source.split('\n');
  const items = [];
  const snip = (n) => { const l = lines[n.loc.start.line - 1].trim(); return l.length > 160 ? `${l.slice(0, 157)}...` : l; };
  const add = (kind, n, extra = '') => items.push({ file: rel(file), line: n.loc.start.line, col: n.loc.start.column, kind, extra, code: snip(n) });
  // A computed member with a literal key names its property like a dot access (`Reflect['set']`).
  const propName = (m) => (!m.computed ? m.property.name : (m.property.type === 'Literal' && typeof m.property.value === 'string' ? m.property.value : null));
  const calleeName = (c) => (c.type === 'Identifier' ? c.name : (c.type === 'MemberExpression' ? propName(c) : null));
  const rootOf = (m) => { let x = m; while (x.type === 'MemberExpression') x = x.object; return x.type === 'Identifier' ? x.name : x.type; };
  walk(ast, (n) => {
    if (branches && BRANCH.has(n.type)) add('branch', n, n.type === 'LogicalExpression' ? n.operator : n.type);
    if (n.type === 'ReturnStatement' || n.type === 'ThrowStatement') add('exit', n, n.type);
    if (n.type === 'ImportExpression') add('forbidden', n, 'dynamic import()');
    if (n.type === 'Identifier' && ['eval', 'importScripts', 'Function', 'Worker', 'SharedWorker', 'createObjectURL', 'ServiceWorker'].includes(n.name)) add('forbidden', n, n.name);
    if (n.type === 'Literal' && typeof n.value === 'string' && /^(blob|data):/i.test(n.value)) add('forbidden', n, 'blob:/data: URL');
    if (n.type === 'TemplateElement' && /(^|[^a-z])(blob|data):/i.test(n.value.raw)) add('forbidden', n, 'blob:/data: URL');
    // Write targets, including every leaf of a destructuring pattern and for-in/of heads.
    const target = (t) => {
      if (t === null) return;
      if (t.type === 'Identifier') add('assign', n, t.name);
      else if (t.type === 'MemberExpression') add('member-write', n, `${rootOf(t)}${propName(t) === null ? '[]' : `.${propName(t)}`}`);
      else if (t.type === 'ArrayPattern') for (const e of t.elements) target(e);
      else if (t.type === 'ObjectPattern') for (const p of t.properties) target(p.type === 'RestElement' ? p.argument : p.value);
      else if (t.type === 'AssignmentPattern') target(t.left);
      else if (t.type === 'RestElement') target(t.argument);
      else add('assign', n, t.type);
    };
    if (n.type === 'AssignmentExpression') target(n.left);
    if (n.type === 'UpdateExpression') target(n.argument);
    if ((n.type === 'ForOfStatement' || n.type === 'ForInStatement') && n.left.type !== 'VariableDeclaration') target(n.left);
    if (n.type === 'UnaryExpression' && n.operator === 'delete') add('member-write', n, 'delete');
    if (n.type === 'CallExpression') {
      const name = calleeName(n.callee);
      if (n.callee.type === 'MemberExpression' && name === null) add('dynamic-call', n, rootOf(n.callee.object));
      if (n.callee.type === 'MemberExpression' && name !== null) {
        const recv = rootOf(n.callee.object);
        if (IDB_WRITE.has(name)) add('write-call', n, `${recv}.${name}`);
        else if (MUTATING.has(name)) add('mutating-call', n, `${recv}.${name}`);
        if (name === 'commit') add('commit', n, recv);
        if (name === 'getRandomValues' || name === 'randomUUID' || (name === 'random' && recv === 'Math')) add('random', n, name);
        if (['assign', 'defineProperty', 'defineProperties', 'setPrototypeOf', 'deleteProperty', 'set', 'freeze', 'seal', 'preventExtensions'].includes(name) && ['Object', 'Reflect'].includes(recv)) add('mutating-call', n, `${recv}.${name}`);
        // In-place byte writers: every Atomics write, DataView setters, encodeInto, getRandomValues.
        if (recv === 'Atomics' && name !== 'load' && name !== 'isLockFree' && name !== 'wait' && name !== 'waitAsync' && name !== 'notify') add('mutating-call', n, `Atomics.${name}`);
        if (/^set(U?Int(8|16|32)|Float(16|32|64)|Big(U)?Int64)$/.test(name) || name === 'encodeInto' || name === 'getRandomValues') add('mutating-call', n, `${recv}.${name}`);
        if (['apply', 'call', 'bind'].includes(name)) add('indirect-call', n, `${recv}.${name}`);
        if (['transaction', 'objectStore'].includes(name)) add('idb', n, `${recv}.${name}`);
      }
    }
  });
  return items;
}
const unline = (x) => x.replace(/^\d+:/, '');
const canonicalInventory = (items) => items.map((i) => `${i.file}:${i.line}:${i.col}:${i.kind}:${i.extra}:${i.code}`).join('\n');

function staticProof(sources) {
  const closure = closureOf(REF);
  const vaultClosure = closureOf(VAULT);
  const driverClosure = closureOf(DRIVER);
  const files = [...new Set([...closure, ...vaultClosure, ...driverClosure])].sort();
  const src = (f) => sources.get(f) ?? fs.readFileSync(f, 'utf8');
  const all = [];
  for (const f of files) all.push(...inventory(f, src(f), { branches: f === REF || f === VAULT }));
  const by = (kind, file = null) => all.filter((i) => i.kind === kind && (file === null || i.file === rel(file)));
  const f = [];
  const want = (ok, what) => { if (!ok) f.push(what); };
  // No other code: no forbidden construct anywhere in the port, VaultDb or driver closure.
  want(by('forbidden').length === 0, `forbidden constructs: ${JSON.stringify(by('forbidden'))}`);
  // No explicit commit() in the closure (the reference relies on auto-commit, VaultDb resolves on complete).
  want(by('commit').length === 0, `explicit commit(): ${JSON.stringify(by('commit'))}`);
  // Native write sites: the reference writes only through VaultDb transaction ops, in replaceSelector.
  const refWrites = by('write-call', REF).filter((i) => i.extra.startsWith('ops.'));
  want(refWrites.map((i) => i.code).join('|') === [
    'const pending = puts.map(([k, v]) => ops.put(NS, k, v));',
    'if (unbind !== null) pending.push(ops.delete(NS, genKey(unbind))); // obligation item 2 / B3-1 item 3',
    'pending.push(ops.put(NS, SEL, envelope)); // the selector put last',
  ].join('|'), `reference native write sites: ${JSON.stringify(refWrites.map((i) => i.code))}`);
  const vaultWrites = by('write-call', VAULT).filter((i) => i.extra.startsWith('tx.') || /objectStore/.test(i.code));
  want(vaultWrites.length === 3 && vaultWrites.every((i) => /requestToPromise\(tx\.objectStore\(ns\)\.(put\(value, key\)|delete\(key\)|clear\(\))\)/.test(i.code)), `VaultDb native write sites: ${JSON.stringify(vaultWrites.map((i) => i.code))}`);
  // Randomness: exactly the two nonce draws of the port, each a fresh 12-byte Uint8Array.
  const rnd = by('random', REF).map((i) => i.code);
  want(rnd.length === 2 && rnd[0] === 'const nonce = crypto.getRandomValues(new Uint8Array(12));' && rnd[1] === 'nonce: crypto.getRandomValues(new Uint8Array(12)),', `random sites: ${JSON.stringify(rnd)}`);
  want(by('random').filter((i) => i.file !== rel(REF) && i.file !== 'src/storage/m2/beta-gate.js').length === 0, 'no other randomness in the closure');
  // One fresh seal per selector request: replaceSelector seals once, unconditionally, before its transaction.
  const ref = src(REF);
  const rs = ref.slice(ref.indexOf('async function replaceSelector(p) {'), ref.indexOf('async function writeHold(p) {'));
  want((rs.match(/await seal\(/g) ?? []).length === 1 && rs.includes('envelope = await seal(copy(p.selectorBytes));'), 'replaceSelector seals exactly once from a copy of the request');
  want(rs.indexOf('envelope = await seal(') < rs.indexOf('await db.transaction('), 'the seal precedes the transaction');
  want((rs.match(/ops\.put\(NS, SEL, envelope\)/g) ?? []).length === 1, 'exactly one selector put per call');
  want(!/envelope\s*=\s*(?!await seal)/.test(rs.replace('envelope = await seal(copy(p.selectorBytes));', '')), 'no other assignment of the sealed envelope (no cache, no skip on unchanged plaintext)');
  const sealFn = ref.slice(ref.indexOf('async function seal(plaintext) {'), ref.indexOf('async function open(envelope) {'));
  want(/nonce: crypto\.getRandomValues\(new Uint8Array\(12\)\),/.test(sealFn) && /return sealRecord\(/.test(sealFn), 'seal draws a fresh nonce on every call and returns the codec envelope');
  // Values: generation values { nonce, ct } of fresh Uint8Arrays; string keys only.
  const sg = ref.slice(ref.indexOf('async function sealGeneration(v) {'), ref.indexOf('function canonicalRecord('));
  want(/const ct = new Uint8Array\(await crypto\.subtle\.encrypt\(/.test(sg) && /return \{ nonce, ct \};/.test(sg), 'generation values are { nonce, ct } of fresh Uint8Arrays');
  want(/puts\.push\(\[genKey\(v\.generation\), await sealGeneration\(v\)\]\);/.test(rs), 'every generation put carries a value sealed in this call under a string key');
  want(/const genKey = \(g\) => `gen:\$\{BigInt\(g\)\.toString\(\)\}`;/.test(ref) && /const SEL = 'sel';/.test(ref), 'keys are strings');
  // In-memory state: mutation sites of the authoritative hold and of pending staging.
  const holdSites = by('assign', REF).filter((i) => ['memoryHold', 'pendingMemoryHold', 'buffer'].includes(i.extra)).map((i) => `${i.line}:${i.code}`);
  // Compared without line numbers (the line-bound inventory hash below binds positions): a report names
  // the added or removed site, not a shifted line.
  const added = (got, frozen) => { const left = frozen.map(unline); return got.map(unline).filter((x) => { const i = left.indexOf(x); if (i < 0) return true; left.splice(i, 1); return false; }); };
  const removed = (got, frozen) => added(frozen, got);
  want(added(holdSites, HOLD_SITES).length === 0 && removed(holdSites, HOLD_SITES).length === 0,
    `hold mutation sites changed: +${JSON.stringify(added(holdSites, HOLD_SITES))} -${JSON.stringify(removed(holdSites, HOLD_SITES))}`);
  // No in-place write reaches the authoritative hold object (by name in the port; the driver and harness
  // receive it by reference from readMemoryHold and must never write through it).
  const inPlace = all.filter((i) => (i.kind === 'member-write' || i.kind === 'mutating-call') && /\b(memoryHold|pendingMemoryHold|hold|memory)\b/.test(i.extra));
  want(inPlace.length === 0, `in-place writes through a hold alias: ${JSON.stringify(inPlace.map((i) => `${i.file}:${i.line}:${i.code}`))}`);
  // Every in-place write (member assignment, delete, mutating call) of the port and of VaultDb is on the
  // frozen, reviewed list (dossier §3): each acts on a fresh local or on pending staging, never on the hold.
  const writesIn = (file) => all.filter((i) => i.file === rel(file) && (i.kind === 'member-write' || i.kind === 'mutating-call')).map((i) => `${i.line}:${i.extra}:${i.code}`);
  for (const [file, frozen] of [[REF, IN_PLACE.reference], [VAULT, IN_PLACE.vault]]) {
    const got = writesIn(file);
    want(added(got, frozen).length === 0 && removed(got, frozen).length === 0, `in-place write sites of ${rel(file)} changed: +${JSON.stringify(added(got, frozen))} -${JSON.stringify(removed(got, frozen))}`);
  }
  const fileHashes = Object.fromEntries(files.map((x) => [rel(x), sha(src(x))]));
  for (const [file, h] of Object.entries(FROZEN_FILES)) want(fileHashes[file] === h, `the bytes of ${file} are not the reviewed ones (${(fileHashes[file] ?? 'missing').slice(0, 16)})`);
  want(Object.keys(fileHashes).every((x) => FROZEN_FILES[x] !== undefined), `files outside the reviewed closure: ${Object.keys(fileHashes).filter((x) => FROZEN_FILES[x] === undefined)}`);
  const inv = canonicalInventory(all);
  return { files: Object.fromEntries(files.map((x) => [rel(x), sha(src(x))])), counts: Object.fromEntries([...new Set(all.map((i) => i.kind))].map((k) => [k, all.filter((i) => i.kind === k).length])),
    inventorySha256: sha(inv), inventory: all, failures: f };
}
/** The mutation sites of memoryHold, pendingMemoryHold and buffer in the reference (dossier §2). */
const HOLD_SITES = Object.freeze([
  "147:const resetBuffer = () => { buffer = new Map(); pendingMemoryHold = undefined; };",
  "147:const resetBuffer = () => { buffer = new Map(); pendingMemoryHold = undefined; };",
  "380:pendingMemoryHold = undefined; // nothing was written, so no hold is retained (B3-1 item 5)",
  "385:buffer = new Map();",
  "388:if (pendingMemoryHold !== undefined) { memoryHold = pendingMemoryHold; pendingMemoryHold = undefined; }",
  "388:if (pendingMemoryHold !== undefined) { memoryHold = pendingMemoryHold; pendingMemoryHold = undefined; }",
  "389:if (unbind !== null) memoryHold = null; // the unbound candidate's hold went with it (B3-1 item 3)",
  "416:pendingMemoryHold = p.holdRecordKey === null || p.holdRecordKey === undefined ? p.hold : { ...p.hold, recordKey: copy(p.holdRecordKey) };",
  "528:pendingMemoryHold = undefined;",
  "529:memoryHold = null;",
  "531:case 'RELEASE_ESCROW': memoryHold = null; return; // escrow bytes stay with their generation (item 14)",
]);
/** SHA-256 of every reviewed file of the closure (the inventory and the dossier are bound to these bytes). */
const FROZEN_FILES = Object.freeze({
  'src/crypto/m2-binding-v0.js': '78e4be3ab64826dee17175cd3fce44c8562db5354f2f2de8ce7feeba07332e2c',
  'src/crypto/vault-errors.js': '3304a78b4101c27d743e3804ddedc1d87d8a65372193c735fb3ec17426e31e2d',
  'src/storage/m2/session-codec.js': '8ce4d3e883a27ae9ceb47ab5d299b04b307ff25984cd9e926097e2f66592e7be',
  'src/storage/m2/session-root.js': 'c9a1f4aa27d07aa1c4e4434454619866b8a232bc5894a8fe0ecd699a6779df2e',
  'src/storage/m2/session-transaction.js': '46af80bdcecd1271dfc09cecf3800101b060408f0bb1f8a2a93f28b1ef7783fb',
  'src/storage/vault-db.js': '70569a64953be46055a59fbbe541e9bf4c241667ffc7d283becb219f894c243c',
  'test/storage/m2/browser/chromium/suite/reference-port.mjs': '55d333157665b3f3060df366c36e51ff2d51e3c07c9beaa89c1ae04b46cbceac',
});
/** The reviewed in-place write sites (null until reviewed). */
const IN_PLACE = Object.freeze({
  reference: Object.freeze([
  "40:Object.freeze:const OUTCOME = Object.freeze({ COMMITTED: 1, NOT_COMMITTED: 2, INDETERMINATE: 3 });",
  "60:ThisExpression.code:constructor() { super('the stored selector envelope differs from expectedSelectorBytes'); this.code = 'SELECTOR_PRECONDITION_FAILED'; }",
  "66:Object.assign:const failed = (code, message) => Object.assign(new Error(message), { code });",
  "84:CallExpression.sort:if (v !== null && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, encodeValue(v[k])]));",
  "105:out[]:out[f] = v instanceof Uint8Array ? copy(v) : v;",
  "144:buffer.set:if (!buffer.has(k)) buffer.set(k, { generation: k, records: [], manifest: null, evidence: undefined, escrow: undefined });",
  "155:crypto.getRandomValues:const nonce = crypto.getRandomValues(new Uint8Array(12));",
  "207:byKind.set:byKind.set(c.record.recordKind, c);",
  "212:ArrayExpression.sort:const sorted = [...records].sort((a, b) => compareBytes(a.recordKey, b.recordKey));",
  "306:crypto.getRandomValues:nonce: crypto.getRandomValues(new Uint8Array(12)),",
  "362:puts.push:puts.push([genKey(v.generation), await sealGeneration(v)]);",
  "375:pending.push:if (unbind !== null) pending.push(ops.delete(NS, genKey(unbind))); // obligation item 2 / B3-1 item 3",
  "376:pending.push:pending.push(ops.put(NS, SEL, envelope)); // the selector put last",
  "511:CallExpression.push:staged(p.generation).records.push(c.record);",
  "515:CallExpression.manifest:staged(p.generation).manifest = {",
  "520:CallExpression.evidence:case 'STAGE_EVIDENCE': staged(p.generation).evidence = p.evidence; return;",
  "521:CallExpression.escrow:case 'STAGE_ESCROW': staged(p.generation).escrow = p.escrow; return;",
]),
  vault: Object.freeze([
  "29:Object.freeze:export const VAULT_NAMESPACES = Object.freeze([",
  "57:Object.freeze:const SCHEMA_MIGRATIONS = Object.freeze({",
  "74:req.onsuccess:req.onsuccess = () => resolve(req.result);",
  "75:req.onerror:req.onerror = () => reject(req.error);",
  "94:req.onblocked:req.onblocked = () => {",
  "101:req.onupgradeneeded:req.onupgradeneeded = (ev) => {",
  "125:req.onerror:req.onerror = () => settle(reject, upgradeError || err(Codes.OPEN_FAILED,",
  "127:req.onsuccess:req.onsuccess = () => {",
  "131:db.onversionchange:db.onversionchange = () => db.close();",
  "174:ThisExpression._db:constructor(db, env) { this._db = db; this._env = env; }",
  "174:ThisExpression._env:constructor(db, env) { this._db = db; this._env = env; }",
  "241:tx.oncomplete:tx.oncomplete = () => resolve(result);",
  "242:tx.onabort:tx.onabort = () => {",
  "249:tx.onerror:tx.onerror = () => { /* onabort follows and carries tx.error */ };",
  "298:req.onsuccess:req.onsuccess = () => settle(resolve);",
  "299:req.onblocked:req.onblocked = () => {",
  "305:req.onerror:req.onerror = () => settle(reject, err(Codes.DESTROY_FAILED,",
  "327:out.persisted:if (storageImpl?.persisted) out.persisted = await bounded(storageImpl.persisted());",
  "328:out.persistGranted:if (storageImpl?.persist) out.persistGranted = await bounded(storageImpl.persist());",
  "331:out.quota:if (est !== 'timeout') { out.quota = est.quota; out.usage = est.usage; }",
  "331:out.usage:if (est !== 'timeout') { out.quota = est.quota; out.usage = est.usage; }",
]),
});
/** The frozen inventory of the exact sources (set after review of the dossier; any change invalidates). */
const FROZEN_INVENTORY_SHA256 = '86e5c44c709ec040a38267c26c3c389d9d6865198a3e871aa59227fa2404c794';

// ============================================ B/C. dynamic proof ============================================
// Recorder (observation) transformations, applied only in HTTP responses. Flags off = equivalence arm.
// Every worker life of a scenario gets its own segment of the stream (CP1-test: a seed that restarted in
// each life would replay the same nonces, a reuse the run-wide nonce ledger rejects), and the two arms of
// an equivalence control get the same sequence of segments: the n-th worker served in a scenario arm has
// seed n. Only the worker module is counted.
const prngPrefix = (seed) => `
// [concrete-path] recorded deterministic random stream (equivalence controls only; installed before the factory loads)
{ let s = ${seed} >>> 0; const nativeGRV = crypto.getRandomValues.bind(crypto);
  crypto.getRandomValues = (a) => { if (!(a instanceof Uint8Array)) return nativeGRV(a); for (let i = 0; i < a.length; i++) { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; a[i] = s & 255; } return a; }; }
`;
function once(source, a, b) { assert.equal(source.split(a).length, 2, `source boundary changed: ${a}`); return source.replace(a, b); }
const RECORDER = { reference: (s) => once(s, '  let memoryHold = null;', `  let __actualHold = null;
  const __hold = {}; Object.defineProperty(__hold, 'value', { get() { return __actualHold; }, set(v) { if (v !== __actualHold) globalThis.__path.hold(v); __actualHold = v; } });
  globalThis.__path.current = () => __actualHold;`).replace(/\bmemoryHold\b/g, '__hold.value'),
worker: (s) => {
  s = once(s, 'const { watchTransaction, tick, transactions, checkInstalled, writes: lifeWrites, reads: lifeReads, schema: lifeSchema, session: LIFE, lateLog } = WORKER_OBSERVER.api;',
    'const { watchTransaction, tick, transactions, checkInstalled, writes: lifeWrites, reads: lifeReads, schema: lifeSchema, session: LIFE, lateLog } = WORKER_OBSERVER.api;\nglobalThis.__path.observer = { tick, transactions };');
  s = once(s, 'const OPS = { init,', 'const OPS = { auditPath: () => globalThis.__path.audit(), setFault: ({ fault }) => { globalThis.__fault = fault; return fault; }, init,');
  s = once(s, 'async function close(r) {', 'async function close(r) {\n  if (r.ok?.output) globalThis.__path.output();');
  s = once(s, "if (!state.armed && op !== 'arm') beginSection();", "if (!state.armed && op !== 'arm' && op !== 'auditPath' && op !== 'setFault') beginSection();");
  return s;
},
vault: (s) => once(s, 'put: (ns, key, value) => requestToPromise(tx.objectStore(ns).put(value, key)),',
  "put: (ns, key, value) => requestToPromise(globalThis.__fault === 'sel-add' && key === 'sel' ? tx.objectStore(ns).add(value, key) : tx.objectStore(ns).put(value, key)),") };
// The recorder state lives in the worker; events are ordered by the observer's own sequence numbers.
const PATH_PREFIX = `
globalThis.__path = (() => {
  const events = []; let seqOf = () => -1;
  const digest = (v) => { const seen = new Set(); const walk = (x) => { if (x === null || typeof x !== 'object') return String(x); if (seen.has(x)) return '#'; seen.add(x);
    if (x instanceof Uint8Array) return Array.from(x).join(','); return '{' + Object.keys(x).sort().map((k) => k + ':' + walk(x[k])).join(';') + '}'; }; return walk(v); };
  const api = {
    hold: (v) => { events.push({ seq: api.observer ? api.observer.tick() : -1, ev: v === null ? 'hold-clear' : 'hold-set', digest: digest(v) }); },
    output: () => { events.push({ seq: api.observer.tick(), ev: 'output' }); },
    audit: () => ({ events: events.splice(0), txs: api.observer.transactions().map((t) => ({ gid: t.gid, openSeq: t.openSeq, mode: t.mode, terminal: t.terminal, terminalSeq: t.terminalSeq,
      writes: t.writes.map((w) => ({ method: w.method, status: w.status, envelopes: w.envelopes.length, nonCanonical: w.nonCanonical, seq: w.seq })) })), hold: digest(api.current ? api.current() : null), now: api.observer.tick() }),
  };
  return api;
})();
`;
/** Item-6 / output rules on one audit (act §7). */
export function judgePath(a, { label, errorOp = false, before = null, opStart = -1 }) {
  const f = [];
  const rw = a.txs.filter((t) => t.mode === 'readwrite');
  const openAt = (s) => rw.filter((t) => t.openSeq < s && (t.terminalSeq === null || t.terminalSeq > s));
  // The binding transaction belongs to the current operation: opened after it started (act §7: identified
  // by identity and operation); transactions of earlier operations never justify a new hold or output.
  const lastSelectorTx = (s) => rw.filter((t) => t.openSeq > opStart && t.terminalSeq !== null && t.terminalSeq < s && t.writes.some((w) => w.envelopes > 0 && ['put', 'add', 'update'].includes(w.method))).sort((x, y) => y.terminalSeq - x.terminalSeq)[0];
  const opSelectorTxs = rw.filter((t) => t.openSeq > opStart && t.writes.some((w) => w.envelopes > 0 && ['put', 'add', 'update'].includes(w.method)));
  for (const e of a.events) {
    if (e.ev === 'hold-set' || e.ev === 'output') {
      if (openAt(e.seq).length > 0) f.push(`${label}: ${e.ev} at ${e.seq} while readwrite transaction(s) ${openAt(e.seq).map((t) => t.gid)} are open (before their native complete)`);
      const b = lastSelectorTx(e.seq);
      if (e.ev === 'hold-set' && (b === undefined || b.terminal !== 'complete')) f.push(`${label}: hold-set at ${e.seq} is not causally after a complete binding transaction (${b ? `${b.gid}:${b.terminal}` : 'none'})`);
      if (e.ev === 'output' && b !== undefined && b.terminal !== 'complete') f.push(`${label}: output after an aborted selector transaction`);
      if (e.ev === 'output') for (const t of opSelectorTxs) if (t.terminalSeq === null || t.terminalSeq > e.seq) f.push(`${label}: output at ${e.seq} before the native complete of the operation's selector transaction T${t.gid}`);
    }
    if (e.ev === 'hold-clear' && openAt(e.seq).length > 0) f.push(`${label}: hold cleared at ${e.seq} while a readwrite transaction is open`);
  }
  for (const t of rw) for (const e of a.events) if (e.seq > t.openSeq && t.terminalSeq !== null && e.seq < t.terminalSeq && e.ev.startsWith('hold')) f.push(`${label}: authoritative hold changed inside T${t.gid} (${e.ev})`);
  if (errorOp && before !== null && a.hold !== before) f.push(`${label}: the hold changed across a failed operation`);
  return f;
}

// Scenarios: worker operations, each followed by an audit. `error: true` marks the operation expected to fail.
const S = 'CAPI-S001';
const SCENARIOS = {
  'original-COMMITTED': [['seed', { scenario: S }], ['arm'], ['original', { scenario: S, outcome: 'COMMITTED' }]],
  'original-NOT_COMMITTED': [['seed', { scenario: S }], ['arm'], ['original', { scenario: S, outcome: 'NOT_COMMITTED' }]],
  'original-INDETERMINATE': [['seed', { scenario: S }], ['arm'], ['original', { scenario: S, outcome: 'INDETERMINATE' }]],
  'reconcile-COMMITTED': [['seed', { scenario: S }], ['original', { scenario: S, outcome: 'INDETERMINATE' }], ['arm'], ['reconcile', { scenario: S, outcome: 'COMMITTED' }]],
  'reconcile-NOT_COMMITTED-RR': [['seed', { scenario: S }], ['original', { scenario: S, outcome: 'INDETERMINATE' }], ['arm'], ['reconcile', { scenario: S, outcome: 'NOT_COMMITTED' }]],
  'reconcile-INDETERMINATE': [['seed', { scenario: S }], ['original', { scenario: S, outcome: 'INDETERMINATE' }], ['arm'], ['reconcile', { scenario: S, outcome: 'INDETERMINATE' }]],
  'recovery-bind-COMMITTED': [['seed', { scenario: S }], ['original', { scenario: S, outcome: 'INDETERMINATE' }], ['RESTART'], ['arm'], ['reconcile', { scenario: S, outcome: 'COMMITTED' }]],
  'recovery-NOT_COMMITTED': [['seed', { scenario: S }], ['original', { scenario: S, outcome: 'INDETERMINATE' }], ['RESTART'], ['arm'], ['reconcile', { scenario: S, outcome: 'NOT_COMMITTED' }]],
  'reseal-without-RR': [['seed', { scenario: S }], ['seedDebris', { scenario: S, outcome: 'COMMITTED' }]],
  'emission-repeat': [['seed', { scenario: 'CAPI-S009' }], ['original', { scenario: 'CAPI-S009', outcome: 'INDETERMINATE' }], ['reconcile', { scenario: 'CAPI-S009', outcome: 'COMMITTED', emissionFault: true }, { error: true }], ['arm'], ['reconcile', { scenario: 'CAPI-S009', outcome: 'COMMITTED' }]],
  'cas-refusal-abort': [['seed', { scenario: S }], ['snapshot'], ['original', { scenario: S, outcome: 'INDETERMINATE' }], ['delayedReplace', { snap: '$snap' }, { error: true, same: true }]],
  'producer-readback': [['seed', { scenario: S }], ['original', { scenario: S, outcome: 'INDETERMINATE' }], ['arm'], ['reconcile', { scenario: S, produce: true }]],
  'put-throw': [['seed', { scenario: S }], ['arm', { fault: 'PUT_THROW' }], ['original', { scenario: S, outcome: 'INDETERMINATE' }, { error: true, same: true }]],
  'request-error': [['seed', { scenario: S }], ['setFault', { fault: 'sel-add' }], ['original', { scenario: S, outcome: 'INDETERMINATE' }, { error: true, same: true }], ['setFault', { fault: null }]],
  'worker-death': [['seed', { scenario: S }], ['original', { scenario: S, outcome: 'INDETERMINATE' }], ['RESTART'], ['readback']],
};
const EQUIVALENT = Object.keys(SCENARIOS).filter((k) => k !== 'request-error'); // the fault flag is on there

// Mutants (in memory only): { target, transform, scenario, component }.
const MUTANTS = {
  transient: { target: 'reference', scenario: 'original-INDETERMINATE', component: 'dynamic item-6 rule', transform: (s) => once(s, '        await Promise.all(pending);', '        await Promise.all(pending);\n        if (pendingMemoryHold !== undefined) { const __o = memoryHold; memoryHold = pendingMemoryHold; memoryHold = __o; }') },
  early: { target: 'reference', scenario: 'original-INDETERMINATE', component: 'dynamic item-6 rule', transform: (s) => once(s, '        await Promise.all(pending);', '        await Promise.all(pending);\n        if (pendingMemoryHold !== undefined) memoryHold = pendingMemoryHold;') },
  'nested-early': { target: 'reference', scenario: 'original-INDETERMINATE', component: 'dynamic item-6 rule', transform: (s) => once(s, '        await Promise.all(pending);', '        await Promise.all(pending);\n        for (let i = 0; i < 8; i++) await Promise.resolve();\n        if (pendingMemoryHold !== undefined) memoryHold = pendingMemoryHold;') },
  'early-output': { target: 'reference', scenario: 'original-COMMITTED', component: 'dynamic output rule', transform: (s) => once(s, '      await db.transaction([NS], async (ops) => {', '      void db.transaction([NS], async (ops) => {') },
  'request-success-promise': { target: 'vault', scenario: 'original-INDETERMINATE', component: 'dynamic item-6 rule', transform: (s) => once(s, '.then((r) => { result = r; })', '.then((r) => { result = r; resolve(r); })') },
  'hold-after-abort': { target: 'reference', scenario: 'request-error', component: 'dynamic item-6 rule', transform: (s) => once(s, '      pendingMemoryHold = undefined; // nothing was written, so no hold is retained (B3-1 item 5)', '      if (pendingMemoryHold !== undefined) memoryHold = pendingMemoryHold; pendingMemoryHold = undefined;') },
  'byte-change-restore': { target: 'reference', scenario: null, component: 'static inventory (hold mutation sites, in-place writes)', transform: (s) => once(s, '    // Inside the transaction only IndexedDB requests are awaited (obligation item 3).', '    if (memoryHold !== null) { const __b = memoryHold.parentKeyedRoot; if (__b) { __b[0] ^= 1; __b[0] ^= 1; } }\n    // Inside the transaction only IndexedDB requests are awaited (obligation item 3).') },
  // Red-team Fase 4 (Sol, K13): change and restore a hold byte through a computed Reflect call. Synchronous
  // change-and-restore is invisible to any observer by construction, so it is rejected statically only.
  'computed-byte-change-restore': { target: 'reference', scenario: null, component: 'static inventory (reviewed bytes, mutating Reflect call)', transform: (s) => once(s, '        await Promise.all(pending);', "        await Promise.all(pending); const __b = Object(Object(memoryHold).parentKeyedRoot); const __v = __b[0]; Reflect['set'](__b, 0, __v ^ 1); Reflect['set'](__b, 0, __v);") },
  // Red-team Fase 4 (Argon R2): hold promotion before the binding transaction opens (scenario adapted for the
  // transient one: on original-COMMITTED no hold is staged, so the mutant is vacuous there; anchor adapted: the
  // literal `const seal = await sealGeneration(v);` does not exist; this is the last statement before it).
  'transient-hold-before-tx-open': { target: 'reference', scenario: 'original-INDETERMINATE', component: 'dynamic item-6 rule', transform: (s) => once(s, '    // Inside the transaction only IndexedDB requests are awaited (obligation item 3).', '    if (pendingMemoryHold !== undefined) { const __oldHold = memoryHold; memoryHold = pendingMemoryHold; memoryHold = __oldHold; }\n    // Inside the transaction only IndexedDB requests are awaited (obligation item 3).') },
  'early-hold-promotion-before-tx-open': { target: 'reference', scenario: 'original-INDETERMINATE', component: 'dynamic item-6 rule', transform: (s) => once(s, '    // Inside the transaction only IndexedDB requests are awaited (obligation item 3).', '    if (pendingMemoryHold !== undefined) memoryHold = pendingMemoryHold;\n    // Inside the transaction only IndexedDB requests are awaited (obligation item 3).') },
  // Red-team Fase 4 (Argon R1): in-place byte change and restore through a destructuring pattern and Atomics.
  'destructure-byte-change-restore': { target: 'reference', scenario: null, component: 'static inventory (reviewed bytes, in-place writes)', transform: (s) => once(s, '        await Promise.all(pending);', '        await Promise.all(pending); if (memoryHold !== null && memoryHold.parentKeyedRoot) { [memoryHold.parentKeyedRoot[0]] = [memoryHold.parentKeyedRoot[0] ^ 1]; [memoryHold.parentKeyedRoot[0]] = [memoryHold.parentKeyedRoot[0] ^ 1]; }') },
  'atomics-byte-change-restore': { target: 'reference', scenario: null, component: 'static inventory (reviewed bytes, in-place writes)', transform: (s) => once(s, '        await Promise.all(pending);', '        await Promise.all(pending); if (memoryHold !== null && memoryHold.parentKeyedRoot) { Atomics.xor(memoryHold.parentKeyedRoot, 0, 1); Atomics.xor(memoryHold.parentKeyedRoot, 0, 1); }') },
  'nonce-cache': { target: 'reference', scenario: null, component: 'static inventory (one fresh seal per request)', transform: (s) => once(s, '      envelope = await seal(copy(p.selectorBytes));', '      envelope = globalThis.__lastEnvelope ?? await seal(copy(p.selectorBytes)); globalThis.__lastEnvelope = envelope;') },
  'dynamic-import': { target: 'reference', scenario: null, component: 'static inventory (forbidden code)', transform: (s) => once(s, 'async function replaceSelector(p) {', 'async function replaceSelector(p) {\n    await import(\'/src/storage/m2/session-codec.js\');') },
  'second-writer': { target: 'reference', scenario: null, component: 'static inventory (write sites)', transform: (s) => once(s, '  async function writeHold(p) {', '  async function writeHold(p) {\n    await db.transaction([NS], async (ops) => { await ops.put(NS, \'shadow\', copy(p.hold.parentKeyedRoot)); });') },
};

// ---- HTTP server -----------------------------------------------------------------------------------------
let arm = { recorder: false, mutant: null, prng: true, lives: 0 };
let lateReports = []; let clientErrors = [];
const SERVED = path.join(out, 'served.jsonl'); fs.writeFileSync(SERVED, '');
let context = 'init';
function transformFor(file, source) {
  const t = [];
  const target = file === REF ? 'reference' : (file === VAULT ? 'vault' : (file === WORKER ? 'worker' : null));
  if (target === null) return { source, t };
  if (arm.mutant && MUTANTS[arm.mutant].target === target) { source = MUTANTS[arm.mutant].transform(source); t.push(`mutant:${arm.mutant}`); }
  if (arm.recorder && target !== 'worker') { source = RECORDER[target](source); t.push(`recorder:${target}`); }
  if (target === 'worker') {
    if (arm.recorder) { source = RECORDER.worker(source); t.push('recorder:worker'); }
    const body = (arm.recorder ? PATH_PREFIX : '') + (arm.prng ? prngPrefix(((0x9e3779b9 + Math.imul(0x6d2b79f5, arm.lives++)) >>> 0) || 1) : '');
    if (body) { source = `${body}\n${source}`; t.push('prefix'); }
  }
  return { source, t };
}
const server = http.createServer((req, res) => {
  try {
    const u = new URL(req.url, 'http://x');
    // K19: a request after the final audit of a worker life is an observer error of the scenario (Argon F5,
    // CP); every other hook is answered (no kill point in this proof).
    if (u.pathname === '/hook' && u.searchParams.get('p') === 'K19:LATE') { let d = null; try { d = JSON.parse(u.searchParams.get('d')); } catch { d = { unparsable: true }; } lateReports.push(d); return res.end('ok'); }
    if (u.pathname === '/hook') return res.end('ok');
    if (u.pathname === '/') { res.setHeader('content-type', 'text/html'); return res.end('<!doctype html><script type="module" src="/suite/page.mjs"></script>'); }
    const base = u.pathname.startsWith('/src/') ? path.join(root, 'src') : suite;
    const file = path.resolve(base, u.pathname.startsWith('/src/') ? u.pathname.slice(5) : u.pathname.slice(7));
    if (!(u.pathname.startsWith('/src/') || u.pathname.startsWith('/suite/')) || !file.startsWith(base + path.sep) || !fs.existsSync(file)) { res.statusCode = 404; return res.end(); }
    const original = fs.readFileSync(file, 'utf8');
    const { source, t } = transformFor(file, original);
    fs.appendFileSync(SERVED, `${JSON.stringify({ context, url: req.url, final: rel(file), original: sha(original), transformation: t, sha256: sha(source) })}\n`);
    res.setHeader('content-type', 'text/javascript'); res.setHeader('cache-control', 'no-store'); res.end(source);
  } catch (e) { res.statusCode = 500; res.end(String(e.stack)); }
});

// Hoisted imports of worker.mjs (instrument.mjs first) evaluate before its body; the PRNG and recorder
// prefixes run first in the body, before `init` imports the factory.
async function runScenario(browser, name, { recorder, mutant = null }) {
  arm = { recorder, mutant, prng: true, lives: 0 }; lateReports = []; clientErrors = [];
  context = `${name}|recorder=${recorder}|mutant=${mutant}`;
  const ctx = await browser.newContext(); const page = await ctx.newPage();
  const steps = [];
  // K19 (owner decision on #317 6384613341 §1): every worker life of the scenario ends with its final
  // audit, and the next one starts with the trusted reader before its initialization; the durable state
  // is reconciled with the judged requests. The K19 failures are an audit step of their own.
  const chain = lifeChain();
  const k19 = [];
  try {
    await page.goto(`http://127.0.0.1:${server.address().port}/?factory=reference`);
    await page.waitForFunction(() => window.bchrReady); await page.evaluate(() => window.bchr.start());
    const call = (op, args) => page.evaluate(([o, a]) => window.bchr.call(o, a).then((r) => JSON.stringify(r)), [op, args ?? {}]).then((t) => JSON.parse(t))
      .then((r) => { chain.absorb(r.k19); return r; });
    const closeLife = async () => { const r = await call('finalAudit'); if (r.error) k19.push({ what: `K19: final audit failed: ${JSON.stringify(r.error)}` }); k19.push(...(r.audit ?? [])); };
    const reader = async () => { const r = await call('durable'); if (r.error) k19.push({ what: `K19: trusted reader failed: ${JSON.stringify(r.error)}` }); chain.reconcile(r.value); k19.push(...chain.failures()); };
    await reader();
    await call('init', { dbName: `path-${name}` });
    let snap = null; let holdBefore = null; let opStart = -1;
    for (const [op, args, opt] of SCENARIOS[name]) {
      if (op === 'RESTART') { await closeLife(); await page.evaluate(() => window.bchr.restart()); await reader(); await call('init', { dbName: `path-${name}` }); steps.push({ op }); continue; }
      const a = op === 'delayedReplace' ? { snap } : args;
      if (recorder) { const pre = (await call('auditPath')).value; holdBefore = pre?.hold ?? null; opStart = pre?.now ?? -1; }
      const r = await call(op, a);
      if (op === 'snapshot') snap = r.value;
      const rb = op === 'arm' ? null : await call('readback', {});
      const audit = recorder && op !== 'arm' ? (await call('auditPath')).value : null;
      steps.push({ op, error: r.error ?? r.value?.error ?? null, value: r.value ?? null, audit: r.audit ?? [], rbDigest: rb?.value?.dbDigest ?? null, path: audit, expectError: opt?.error === true, same: opt?.same === true, holdBefore, opStart });
    }
    await closeLife(); await page.evaluate(() => window.bchr.restart()); await reader(); await closeLife();
    k19.push(...chain.finish());
    for (const d of lateReports) k19.push({ harnessError: true, what: `K19: request ${d?.op} attempted after the final audit of worker life ${d?.life}` });
    for (const c of clientErrors) k19.push({ harnessError: true, what: `K19: the host rejected a request before its handler (${c})` });
    steps.push({ op: 'K19', error: null, value: null, audit: k19, rbDigest: null, path: null, expectError: false, same: false, holdBefore: null, opStart: -1 });
  } finally { await ctx.close(); }
  return steps;
}
const normalize = (steps) => JSON.stringify(steps.map((s) => ({ op: s.op, error: s.error, rbDigest: s.rbDigest, value: s.value })), (k, v) => {
  if (['requestedAt', 'answeredAt', 'seq', 'txg', 'issuedSeq', 'settledSeq', 'startSeq', 'endSeq', 'gid', 'openSeq', 'terminalSeq'].includes(k)) return undefined;
  if (typeof v === 'string') return v.replace(/[0-9a-f]{16}:(request)?\d+/g, 'TOKEN');
  return v;
});

// ============================================ run ============================================
const sources = new Map();
const staticResult = staticProof(sources);
results.static = { ...staticResult, inventory: undefined };
fs.writeFileSync(path.join(out, 'inventory.json'), JSON.stringify(staticResult.inventory, null, 1));
for (const x of staticResult.failures) check(false, `static: ${x}`);
check(staticResult.inventorySha256 === FROZEN_INVENTORY_SHA256, `static: the inventory ${staticResult.inventorySha256} is the reviewed one ${FROZEN_INVENTORY_SHA256}`);

// D (static mutants): each must be rejected by the static proof.
for (const [name, m] of Object.entries(MUTANTS)) {
  const file = m.target === 'reference' ? REF : VAULT;
  const mutated = new Map([[file, m.transform(fs.readFileSync(file, 'utf8'))]]);
  const r = staticProof(mutated);
  const rejectedStatic = r.failures.length > 0 || r.inventorySha256 !== staticResult.inventorySha256;
  results.mutants.push({ name, component: m.component, static: { rejected: rejectedStatic, failures: r.failures.slice(0, 3), inventoryChanged: r.inventorySha256 !== staticResult.inventorySha256 } });
  if (m.scenario === null) check(r.failures.length > 0, `mutant ${name}: rejected by ${m.component} (a specific static failure, not only a changed hash)`);
}

// CP6: a request rejected before any handler is a harness error of the scenario running.
server.on('clientError', (err, socket) => {
  clientErrors.push(err?.code ?? String(err?.message));
  try { socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); } catch { /* gone */ }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const browser = await chromium.launch({ executablePath: process.env.BCHR_EXE, headless: true,
  args: ['--disable-gpu', '--disable-extensions', '--no-zygote', '--renderer-process-limit=1'] });
try {
  // B: the recorder arm on every scenario.
  const recorded = {};
  for (const name of Object.keys(SCENARIOS)) {
    const steps = await runScenario(browser, name, { recorder: true });
    recorded[name] = steps;
    const f = [];
    for (const s of steps) {
      if (s.op === 'RESTART') continue;
      if (s.expectError) f.push(...(s.error === null ? [`${name}/${s.op}: the operation was expected to fail`] : []));
      else if (s.error !== null && s.op !== 'arm') f.push(`${name}/${s.op}: unexpected error ${JSON.stringify(s.error)}`);
      for (const x of s.audit) f.push(`${name}/${s.op}: observer audit: ${x.what}`);
      if (s.path) f.push(...judgePath(s.path, { label: `${name}/${s.op}`, errorOp: s.same, before: s.holdBefore, opStart: s.opStart }));
    }
    // Coverage receipts: the binding transaction exists where a hold is retained.
    const sets = steps.flatMap((s) => s.path?.events ?? []).filter((e) => e.ev === 'hold-set').length;
    if (['original-INDETERMINATE', 'reconcile-INDETERMINATE'].includes(name)) f.push(...(sets >= 1 || name === 'reconcile-INDETERMINATE' ? [] : [`${name}: no hold was retained`]));
    results.dynamic.push({ name, ok: f.length === 0, failures: f, holdSets: sets, steps: steps.map((s) => ({ op: s.op, error: s.error?.code ?? null, events: s.path?.events?.length ?? 0, txs: s.path?.txs?.filter((t) => t.mode === 'readwrite').map((t) => `${t.gid}:${t.terminal}`) ?? [] })) });
    for (const x of f) check(false, x);
    console.log(JSON.stringify({ part: 'B', name, ok: f.length === 0, failures: f.slice(0, 3) }));
  }
  // C: equivalence controls (untransformed vs recorder with flags off), same deterministic random stream.
  for (const name of EQUIVALENT) {
    const plain = await runScenario(browser, name, { recorder: false });
    const a = normalize(plain); const b = normalize(recorded[name]);
    results.equivalence.push({ name, identical: a === b, plain: sha(a), recorder: sha(b) });
    check(a === b, `equivalence ${name}: results, traces and durable digests identical`);
    if (a !== b) fs.writeFileSync(path.join(out, `equivalence-${name}.json`), JSON.stringify({ plain: JSON.parse(a), recorder: JSON.parse(b) }, null, 1));
    console.log(JSON.stringify({ part: 'C', name, identical: a === b }));
  }
  // D: dynamic mutants, each rejected by its named component.
  for (const [name, m] of Object.entries(MUTANTS)) {
    if (m.scenario === null) continue;
    const steps = await runScenario(browser, m.scenario, { recorder: true, mutant: name });
    const f = [];
    for (const s of steps) if (s.path) f.push(...judgePath(s.path, { label: `${name}/${s.op}`, errorOp: s.same, before: s.holdBefore, opStart: s.opStart }));
    const entry = results.mutants.find((x) => x.name === name);
    entry.dynamic = { rejected: f.length > 0, failures: f.slice(0, 3) };
    check(f.length > 0, `mutant ${name}: rejected by ${m.component}`);
    console.log(JSON.stringify({ part: 'D', name, rejected: f.length > 0, by: f[0] }));
  }
} finally { await browser.close(); await new Promise((r) => server.close(r)); }

// Manifest of the whole chain that produces the verdict.
const chain = ['run.mjs', 'observer-regressions.mjs', 'concrete-path.test.mjs', 'suite/page.mjs', 'suite/worker.mjs', 'suite/instrument.mjs',
  'suite/expectations.mjs', 'suite/fixtures.mjs', 'suite/reference-port.mjs', 'suite/observer-cases.mjs'].map((f) => path.join(here, f));
const manifest = Object.fromEntries([...new Set([...chain, ...Object.keys(staticResult.files).map((f) => path.join(root, f))])].sort().map((f) => [rel(f), sha(fs.readFileSync(f))]));
const verdict = failures.length === 0 ? 'PASS' : 'FAIL';
fs.writeFileSync(path.join(out, 'verdict.json'), JSON.stringify({ verdict, failures, manifest, served: sha(fs.readFileSync(SERVED)), inventorySha256: staticResult.inventorySha256, counts: staticResult.counts, results }, null, 1));
console.log(JSON.stringify({ verdict, failures: failures.length, inventorySha256: staticResult.inventorySha256, counts: staticResult.counts }));
process.exitCode = verdict === 'PASS' ? 0 : 1;
