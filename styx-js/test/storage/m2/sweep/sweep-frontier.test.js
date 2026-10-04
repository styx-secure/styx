// T-SWEEP (#317 G-SCOPE): deterministic mutation × crash-boundary sweep over the merged M2 stack.
//
// The full matrix (`engine.js`, IMPACT.md) runs in separate Node processes, one per shard
// (`shard.runner.js`), so every shard has its own heap: each simulated restart loads a fresh module
// registry, and one Jest process does not reclaim those. The outcome of every cell is compared with
// the committed frontier `frontier.json`:
//   - every cell recorded PASS must still hold every invariant;
//   - no cell may produce a hit the frontier does not record (a recorded hit may only become PASS);
//   - each EXPLAINED group is a `test.failing` that flips when its fix lands (#435 for T-COMPOSE R1-R3);
//   - UNEXPLAINED cells are excluded by recorded id and asserted nowhere.
//
// `TSWEEP_UPDATE_FRONTIER=1` rewrites `frontier.json` from the current run instead of comparing.

import { describe, expect, test, beforeAll } from '@jest/globals';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { availableParallelism, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { enumerateCells, runCell } from './engine.js';
import { enumerateMarkerCells, runMarkerCell, runPeerUpdateGuard } from './marker.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const STYX_JS = resolve(HERE, '../../../..');
const JEST = join(STYX_JS, 'node_modules/jest/bin/jest.js');
const FRONTIER_PATH = join(HERE, 'frontier.json');
const SCHEMA = 'styx-m2-t-sweep-frontier/v1';
const BASE = '8c03d8683d3f405a7542216fffe310f83929f9be';
const SHARD_SIZE = 150;
const PARALLEL = Math.max(1, Math.min(4, availableParallelism() - 1));
const UPDATE = process.env.TSWEEP_UPDATE_FRONTIER === '1';

function runShard(from, to, dir) {
  const out = join(dir, `shard-${from}.json`);
  return new Promise((resolveShard, reject) => {
    const child = spawn(process.execPath, [
      '--experimental-vm-modules', JEST, '--ci', '--runInBand', '--rootDir', STYX_JS,
      '--testMatch', '**/test/storage/m2/sweep/shard.runner.js',
    ], {
      cwd: STYX_JS,
      env: { ...process.env, TSWEEP_FROM: String(from), TSWEEP_TO: String(to), TSWEEP_OUT: out },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-8000); });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) { reject(new Error(`shard ${from}-${to} exited ${code}\n${stderr}`)); return; }
      resolveShard(JSON.parse(readFileSync(out, 'utf8')).records);
    });
  });
}

async function runMatrix(total) {
  const dir = mkdtempSync(join(tmpdir(), 'tsweep-'));
  try {
    const ranges = [];
    for (let from = 0; from < total; from += SHARD_SIZE) ranges.push([from, Math.min(total, from + SHARD_SIZE)]);
    const results = new Array(ranges.length);
    let next = 0;
    const worker = async () => {
      while (next < ranges.length) {
        const i = next;
        next += 1;
        results[i] = await runShard(ranges[i][0], ranges[i][1], dir);
      }
    };
    await Promise.all(Array.from({ length: PARALLEL }, worker));
    return results.flat();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const compact = (r) => [r.id, r.classification, r.violations];

function frontierOf(records, marker) {
  const counts = {};
  for (const r of records) counts[r.classification] = (counts[r.classification] ?? 0) + 1;
  const hits = records.filter((r) => r.classification !== 'PASS');
  return {
    schema: SCHEMA,
    base: BASE,
    cells: records.length,
    counts: Object.fromEntries(Object.entries(counts).sort()),
    unexplained: hits.filter((r) => r.classification === 'UNEXPLAINED').map((r) => r.id),
    hits: hits.map((r) => ({
      id: r.id, classification: r.classification, violations: r.violations,
      readback: r.readback, path: r.path, adapterResults: r.adapterResults, txnErrors: r.txnErrors,
      final: r.final, followUp: r.followUp, wireRefusals: r.wireRefusals,
    })),
    frontier: records.map(compact),
    marker: marker.map((r) => [r.id, r.classification, r.violations, r.final?.state ?? null]),
  };
}

const recorded = existsSync(FRONTIER_PATH)
  ? JSON.parse(readFileSync(FRONTIER_PATH, 'utf8'))
  : { schema: null, base: null, unexplained: [], frontier: [] };
const EXPLAINED_IDS = [...new Set(recorded.frontier.map(([, c]) => c).filter((c) => c.startsWith('EXPLAINED:')))].sort();

let cells;
let records;
let byId;
let marker;

beforeAll(async () => {
  cells = await enumerateCells();
  records = await runMatrix(cells.length);
  byId = new Map(records.map((r) => [r.id, r]));
  marker = [];
  for (const c of enumerateMarkerCells()) marker.push(await runMarkerCell(c));
  marker.push(await runPeerUpdateGuard());
  if (UPDATE) writeFileSync(FRONTIER_PATH, `${JSON.stringify(frontierOf(records, marker), null, 1)}\n`);
}, 1_800_000);

describe('T-SWEEP L-MARK one-way cutover × CREATE, and the APPLY_PEER_UPDATE guard', () => {
  test('every marker cell and the guard hold every invariant and match the recorded frontier', () => {
    expect(marker.map((r) => [r.id, r.classification, r.violations, r.final?.state ?? null])).toEqual(recorded.marker);
    expect(marker.filter((r) => r.violations.length > 0).map((r) => `${r.id}: ${r.violations.join(' ')}`)).toEqual([]);
  });

  test('the cutover covers every C-REC marker boundary and both session outcomes', () => {
    const ids = marker.map((r) => r.id);
    expect(ids).toContain('GUARD|APPLY_PEER_UPDATE');
    for (const b of ['BEFORE_DISTINCT_SESSION_CONFIRMATION', 'AFTER_CONFIRMATION_BEFORE_MARKER_COMMIT', 'AFTER_MARKER_COMMIT']) {
      expect(marker.some((r) => r.boundary === b && r.crashed !== null)).toBe(true);
    }
    expect(new Set(marker.filter((r) => r.final).map((r) => r.final.state))).toEqual(new Set(['LEGACY_INVALIDATED', 'PENDING_NEW_SESSION']));
  });
});

describe('T-SWEEP the matrix', () => {
  test('every cell ran exactly once, in enumeration order, and matches the recorded matrix', () => {
    expect(records.map((r) => r.id)).toEqual(cells.map((c) => c.id));
    expect(new Set(records.map((r) => r.id)).size).toBe(cells.length);
    expect(recorded.schema).toBe(SCHEMA);
    expect(recorded.base).toBe(BASE);
    expect(recorded.frontier.map(([id]) => id)).toEqual(cells.map((c) => c.id));
  });

  test('every operation and both phases are covered, with every recovery fault mode', () => {
    const ops = new Set(cells.map((c) => c.op));
    expect([...ops].sort()).toEqual(['CREATE', 'JOIN_WELCOME', 'OPEN_APPLICATION', 'PROTECT_APPLICATION', 'SELF_UPDATE']);
    expect(new Set(cells.map((c) => c.phase))).toEqual(new Set(['ORIGINAL', 'RECONCILIATION']));
    expect(new Set(cells.map((c) => c.fault))).toEqual(new Set(['KILL', 'EXC_LOST', 'EXC_RETAINED']));
  });

  test('a cell replays byte-identically (fixed seed, injected clock and randomness)', async () => {
    for (const i of [0, Math.floor(cells.length / 3), cells.length - 1]) {
      const again = await runCell(cells[i]);
      expect(JSON.stringify(again)).toBe(JSON.stringify(byId.get(cells[i].id)));
    }
  }, 120_000);
});

describe('T-SWEEP invariants against the recorded frontier', () => {
  test('every cell recorded PASS holds every invariant', () => {
    const regressed = recorded.frontier
      .filter(([, c]) => c === 'PASS')
      .map(([id]) => byId.get(id))
      .filter((r) => r.violations.length > 0)
      .map((r) => `${r.id}: ${r.violations.join(' ')}`);
    expect(regressed).toEqual([]);
  });

  test('no hit outside the recorded frontier (a recorded hit may only become PASS)', () => {
    const recordedClass = new Map(recorded.frontier.map(([id, c]) => [id, c]));
    const fresh = records
      .filter((r) => r.classification !== 'PASS' && r.classification !== recordedClass.get(r.id))
      .map((r) => `${r.id}: ${r.classification} ${r.violations.join(' ')}`);
    expect(fresh).toEqual([]);
  });

  test('the recorded UNEXPLAINED cells are excluded by id and listed in the frontier', () => {
    const unexplained = recorded.frontier.filter(([, c]) => c === 'UNEXPLAINED').map(([id]) => id);
    expect(unexplained).toEqual(recorded.unexplained);
  });

  // Known-failing until the fix of each explained divergence lands; each flips to a failure then,
  // which is the signal to re-record the frontier. Never asserted as correct behaviour.
  for (const id of EXPLAINED_IDS) {
    test.failing(`${id}: every cell of the group holds every invariant`, () => {
      const group = recorded.frontier.filter(([, c]) => c === id).map(([cellId]) => byId.get(cellId));
      expect(group.length).toBeGreaterThan(0);
      expect(group.filter((r) => r.violations.length > 0).map((r) => r.id)).toEqual([]);
    });
  }
});
