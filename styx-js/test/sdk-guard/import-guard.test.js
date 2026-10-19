// Import guard -- PROTOTYPE branch (proto/sdk-demo-2026-10).
// Follows the I-SDK contract draft (guard outside the C-SDK section 9 bound):
// scans styx-js/src/sdk/** and styx-js/test/sdk/** and fails on any import
// (static, export-from, dynamic import(), require()) of a specifier or name
// that the C-SDK section 9 table does not allow for that location, on any
// node: / bare built-in under src/sdk, on symlinks or non-.js files, and on a
// ws:// or wss:// substring under src/sdk. Prototype simplification: the
// tokenizer is a regular-expression scan, not the draft's full token rules.
import { describe, test, expect } from '@jest/globals';
import { readdirSync, lstatSync, readFileSync } from 'node:fs';

const here = decodeURIComponent(import.meta.url.replace(/^file:\/\//, ''));
const base = here.slice(0, here.lastIndexOf('/') + 1); // .../styx-js/test/sdk-guard/
const styxJs = base.slice(0, base.length - 'test/sdk-guard/'.length);
const SRC = styxJs + 'src/sdk/';
const TEST = styxJs + 'test/sdk/';
const PREVIEW = TEST + 'flegias-preview/';

const UTILS_OK = new Set(['EventEmitter', 'uuidv4', 'bytesToHex', 'hexToBytes', 'utf8Encode', 'utf8Decode', 'randomBytes',
  'constantTimeEqual', 'concatBytes', 'bytesToBase64', 'base64ToBytes', 'secureZero']);
const NODE_TEST_OK = new Set(['node:assert', 'node:events', 'node:net', 'node:http', 'node:timers', 'node:timers/promises', 'node:crypto']);
const BUILTINS = new Set(['fs', 'path', 'url', 'os', 'child_process', 'crypto', 'net', 'http', 'https', 'events', 'assert', 'util', 'stream', 'timers', 'worker_threads', 'module', 'process', 'buffer', 'tls', 'dns', 'zlib', 'vm']);

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = dir + name;
    const st = lstatSync(p);
    if (st.isSymbolicLink()) out.push({ path: p, problem: 'symlink' });
    else if (st.isDirectory()) walk(p + '/', out);
    else if (st.isFile()) out.push({ path: p, problem: /\.(c|m)?js$/.test(name) ? null : 'extension' });
  }
  return out;
}

/** Resolve a relative specifier against a file path (string operations only). */
function resolve(file, spec) {
  if (!spec.startsWith('.')) return spec;
  const parts = file.slice(0, file.lastIndexOf('/')).split('/');
  for (const seg of spec.split('/')) {
    if (seg === '..') parts.pop();
    else if (seg !== '.') parts.push(seg);
  }
  return parts.join('/');
}

/** Every import of a file: { spec, names: string[] | null (null = namespace/all/side effect) }. */
export function importsOf(text) {
  const out = [];
  const src = text.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:\\])\/\/[^\n]*/g, '$1');
  const stat = /(?:^|[;\s])(?:import|export)\s+([\s\S]*?)\s*from\s*(['"])([^'"]+)\2/g;
  let m;
  while ((m = stat.exec(src))) {
    const clause = m[1];
    let names = null;
    const braces = /\{([\s\S]*)\}/.exec(clause);
    if (braces && !/\*/.test(clause.replace(braces[0], ''))) {
      names = braces[1].split(',').map((s) => s.trim().split(/\s+as\s+/)[0].trim()).filter(Boolean);
      if (/^[A-Za-z_$][\w$]*\s*,/.test(clause.trim())) names.push('default');
    } else if (!braces && !/\*/.test(clause)) {
      names = ['default'];
    }
    out.push({ spec: m[3], names });
  }
  const bare = /(?:^|[;\s])import\s*(['"])([^'"]+)\1/g;
  while ((m = bare.exec(src))) out.push({ spec: m[2], names: null });
  const dyn = /\b(import|require)\s*\(\s*([^)]*)\)/g;
  while ((m = dyn.exec(src))) {
    const lit = /^(['"`])([^'"`]+)\1$/.exec(m[2].trim());
    out.push({ spec: lit ? lit[2] : '<non-literal>', names: null, dynamic: true });
  }
  return out;
}

function allowed(file, imp) {
  const inSrc = file.startsWith(SRC);
  const { spec, names } = imp;
  const target = resolve(file, spec);
  const all = (set) => names !== null && names.every((n) => set.has(n));
  if (spec === '<non-literal>') return false;
  if (target.startsWith(SRC)) return true; // lane modules
  if (target === styxJs + 'src/utils.js') return all(UTILS_OK);
  if (target === styxJs + 'src/transport/transport-interface.js') return all(new Set(['TransportInterface', 'TransportState', 'TransportMessage']));
  if (target === styxJs + 'src/transport/nostr-transport.js') return all(new Set(['RelayPool']));
  if (spec === '@noble/hashes/sha256') return all(new Set(['sha256']));
  if (spec === '@noble/curves/secp256k1') return all(new Set(['schnorr']));
  if (inSrc) return false;
  if (target.startsWith(TEST)) return true; // own test files
  if (spec === '@jest/globals') return all(new Set(['describe', 'test', 'it', 'expect', 'beforeAll', 'beforeEach', 'afterAll', 'afterEach', 'jest']));
  if (spec === 'ws') return all(new Set(['WebSocket', 'WebSocketServer']));
  if (NODE_TEST_OK.has(spec)) return true;
  return false;
}

const files = [...walk(SRC), ...walk(TEST)].filter((f) => !f.path.startsWith(PREVIEW));

describe('import guard (C-SDK section 9, prototype)', () => {
  test('the two trees are found and are not the guard directory', () => {
    expect(files.some((f) => f.path === SRC + 'client.js')).toBe(true);
    expect(files.some((f) => f.path === TEST + 'client.test.js')).toBe(true);
    expect(files.every((f) => !f.path.startsWith(base))).toBe(true);
  });

  test('no symlink and no non-.js file', () => {
    expect(files.filter((f) => f.problem).map((f) => `${f.problem}: ${f.path}`)).toEqual([]);
  });

  test('every import is allowed by the C-SDK section 9 table for its location', () => {
    const bad = [];
    for (const f of files) {
      const text = readFileSync(f.path, 'utf8');
      for (const imp of importsOf(text)) {
        const s = imp.spec;
        if (f.path.startsWith(SRC) && (s.startsWith('node:') || BUILTINS.has(s))) { bad.push(`${f.path}: built-in ${s}`); continue; }
        if (!allowed(f.path, imp)) bad.push(`${f.path}: ${s} {${imp.names ?? '*'}}`);
      }
    }
    expect(bad).toEqual([]);
  });

  test('no ws:// or wss:// literal under src/sdk', () => {
    const hits = files.filter((f) => f.path.startsWith(SRC) && /wss?:\/\//i.test(readFileSync(f.path, 'utf8'))).map((f) => f.path);
    expect(hits).toEqual([]);
  });

  test('the guard detects violations (self-check on synthetic text)', () => {
    const f = SRC + 'x.js';
    const v = (t) => importsOf(t).some((i) => i.spec.startsWith('node:') || BUILTINS.has(i.spec) || !allowed(f, i));
    expect(v("import { readFileSync } from 'node:fs';")).toBe(true);
    expect(v("import fs from 'fs';")).toBe(true);
    expect(v("import { uint32BE } from '../utils.js';")).toBe(true);
    expect(v("import * as u from '../utils.js';")).toBe(true);
    expect(v("const m = await import('../crypto/mls/mls-engine.js');")).toBe(true);
    expect(v("const m = require('ws');")).toBe(true);
    expect(v("export * from '../storage/x.js';")).toBe(true);
    expect(v("import { WebSocket } from 'ws';")).toBe(true); // ws is test-only
    expect(v("import { bytesToHex } from '../utils.js';\nimport { createOutbox } from './delivery/outbox.js';")).toBe(false);
  });
});
