// T-SWEEP shard runner. Not a `.test.js` file, so the normal suite never collects it; the frontier
// test (`sweep-frontier.test.js`) runs it in separate Node processes through an explicit
// `--testMatch`, one process per shard, so every shard gets its own heap (each restart loads a
// fresh module registry, and Jest's ESM registry is not reclaimed within one process).
//
// Environment: `TSWEEP_FROM`, `TSWEEP_TO` (cell index range), `TSWEEP_OUT` (JSON output path).

import { writeFileSync } from 'node:fs';
import { expect, test } from '@jest/globals';
import { enumerateCells, runCell } from './engine.js';

test('T-SWEEP shard', async () => {
  const cells = await enumerateCells();
  const from = Number(process.env.TSWEEP_FROM);
  const to = Number(process.env.TSWEEP_TO);
  expect(Number.isSafeInteger(from) && Number.isSafeInteger(to) && from >= 0 && to <= cells.length && from < to).toBe(true);
  const records = [];
  for (const cell of cells.slice(from, to)) records.push(await runCell(cell));
  writeFileSync(process.env.TSWEEP_OUT, JSON.stringify({ from, to, total: cells.length, records }));
}, 3_600_000);
