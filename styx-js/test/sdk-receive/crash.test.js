// M3-RECEIVE-2: real process kills of Bob's client over the reference
// receiver and the real MlsEngine, at every named step of every kind of
// snapshot rewrite and inside openCandidate. After each kill a new process
// recovers; a joint oracle then checks the durable state, the MLS state and
// the delivery log. STYX_CRASH_REPETITIONS (default 1) repeats the matrix;
// the evidence run uses 3.
import { describe, test, expect, beforeAll, afterAll, jest } from '@jest/globals';
import { spawn } from 'node:child_process';
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { WebSocket } from 'ws';
import { bytesToHex } from '../../src/utils.js';
import { WRITE_STEPS } from '../../reference/receive-state/index.js';
import {
  initWasm, tempRoot, removeTempRoots, party, loaded, invite, relay, makeClient, counted, fastClock, until, text, untext,
} from './helpers.js';

jest.setTimeout(3_600_000);
const CHILD = new URL('./crash-child.js', import.meta.url).pathname;
const REPETITIONS = Number.parseInt(process.env.STYX_CRASH_REPETITIONS ?? '1', 10);
const MESSAGES = 3;
let originalWebSocket;
let relayHandle;
beforeAll(async () => {
  originalWebSocket = globalThis.WebSocket;
  globalThis.WebSocket = WebSocket;
  await initWasm();
  relayHandle = await relay();
});
afterAll(async () => {
  await relayHandle.close();
  globalThis.WebSocket = originalWebSocket;
  removeTempRoots();
});

function child(configPath) {
  return new Promise((resolve) => {
    const proc = spawn(process.execPath, ['--experimental-vm-modules', '--no-warnings', CHILD, configPath], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    proc.stderr.on('data', (chunk) => { stderr += chunk; });
    proc.stdout.on('data', () => {});
    proc.on('exit', (exitCode, signal) => resolve({ exitCode, signal, stderr }));
  });
}

function readLog(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
}

/** One case: fresh Alice and Bob, three messages, a killed run, a recovery run, a reply run. */
async function crashCase(killAt) {
  const root = tempRoot();
  const alice = party(root, 'alice');
  const bob = party(root, 'bob');
  // Alice: an SDK client over her own reference receiver, in this process.
  const aliceReceiver = alice.instance();
  const aliceClient = makeClient({
    urls: [relayHandle.url], keys: alice.keys, ports: counted(aliceReceiver), clock: fastClock(5), receiptMode: 'RECIPIENT_RECEIPT',
    delivery: { deadlineMs: 600_000 },
  });
  expect((await aliceClient.start()).ok).toBe(true);
  try {
    // Bob's archive: created and joined in this process, then left to the child processes.
    const setup = bob.instance();
    await loaded(setup, bob.identity);
    await invite(alice, aliceReceiver, bob, setup);
    const deliveries = [];
    for (let i = 0; i < MESSAGES; i += 1) {
      const sent = await aliceClient.client.send({ recipient: bob.identity, payload: text(`m${i}`) });
      expect(sent.ok).toBe(true);
      deliveries.push(sent.value.deliveryId);
    }
    expect(await until(() => [...relayHandle.events.values()].filter((e) => e.kind === 4741
      && e.tags.some(([t, v]) => t === 'p' && v === bob.identity)).length === MESSAGES)).toBe(true);
    const expected = [...relayHandle.events.values()]
      .filter((e) => e.kind === 4741 && e.tags.some(([t, v]) => t === 'p' && v === bob.identity)).map((e) => e.id);
    const logPath = join(root, 'bob.log');
    const base = {
      directory: bob.directory, atRestKeyHex: bytesToHex(bob.atRestKey), secretHex: bytesToHex(bob.keys.secret),
      identity: bob.identity, peer: alice.identity, relays: [relayHandle.url], expected, logPath, timeoutMs: 20_000,
    };
    const configFor = (phase, kill) => {
      const path = join(root, `${phase}.json`);
      writeFileSync(path, JSON.stringify({ ...base, phase, killAt: kill }));
      return path;
    };
    const killed = await child(configFor('kill', killAt));
    const recovered = await child(configFor('verify', null));
    const replied = await child(configFor('reply', null));
    const lines = readLog(logPath);
    const of = (run, kind) => lines.filter((l) => l.run === run && l.kind === kind);
    const reached = of('kill', 'kill').length === 1;
    // --- the joint oracle ---
    const problems = [];
    if (reached && killed.signal !== 'SIGKILL') problems.push(`kill run ended with ${killed.exitCode}/${killed.signal}`);
    if (!reached && killed.exitCode !== 0) problems.push(`kill point not reached and kill run failed: ${killed.exitCode} ${killed.stderr.slice(0, 400)}`);
    if (recovered.exitCode !== 0) problems.push(`recovery run failed: ${recovered.exitCode}/${recovered.signal} ${recovered.stderr.slice(0, 400)}`);
    if (replied.exitCode !== 0) problems.push(`reply run failed: ${replied.exitCode}/${replied.signal} ${replied.stderr.slice(0, 400)}`);
    const recoveryLoad = of('verify', 'load')[0];
    if (!recoveryLoad || recoveryLoad.code !== null) problems.push(`recovery load: ${JSON.stringify(recoveryLoad)}`);
    // 1. No staged event lost: every stage that returned before the kill is in the recovered seen set.
    for (const line of of('kill', 'stage-ok')) if (!recoveryLoad?.seen?.includes(line.id)) problems.push(`staged ${line.id} lost`);
    // 2. No committed id processed by MLS again after the restart.
    const committed = new Set(of('kill', 'commit-ok').map((l) => l.id));
    for (const line of [...of('verify', 'open'), ...of('reply', 'open')]) {
      if (line.id === null || committed.has(line.id)) problems.push(`committed ${line.id} opened again`);
    }
    // 3. Every message delivered with its payload, acknowledged; nothing left pending or owed.
    const payloads = new Map(lines.filter((l) => l.kind === 'delivered').map((l) => [l.id, l.payload]));
    for (const [i, id] of expected.entries()) if (payloads.get(id) === undefined) problems.push(`message ${i} never delivered`);
    const sentOrder = expected.map((id) => payloads.get(id)).sort();
    if (JSON.stringify(sentOrder) !== JSON.stringify(['m0', 'm1', 'm2'])) problems.push(`payloads ${JSON.stringify(sentOrder)}`);
    const final = of('reply', 'final')[0];
    if (!final || final.code !== null) problems.push(`final load ${JSON.stringify(final)}`);
    else {
      if (final.pending.length !== 0 || final.ready.length !== 0 || final.receiptsDue.length !== 0) problems.push(`final not settled ${JSON.stringify(final)}`);
      if (JSON.stringify([...final.acknowledged].sort()) !== JSON.stringify([...expected].sort())) problems.push('acknowledged set');
      if (JSON.stringify([...final.seen].sort()) !== JSON.stringify([...expected].sort())) problems.push('seen set');
      if (final.cursors !== 1) problems.push('cursor');
    }
    // 4. The live MLS state was never ahead of or behind the committed one: Bob's reply (sealed
    //    from the recovered state) opens at Alice, and Alice received Bob's receipts.
    if (!(await until(() => aliceClient.messages().some((m) => untext(m.payload) === 'reply-reply'), 10_000))) {
      problems.push('Alice did not receive the reply sealed after recovery');
    }
    for (const deliveryId of deliveries) {
      if (!(await until(() => aliceClient.events.some((e) => e.deliveryId === deliveryId && e.state === 'RECIPIENT_RECEIPT_RECEIVED'), 10_000))) {
        problems.push(`no receipt for ${deliveryId}`);
      }
    }
    return { reached, problems, opens: lines.filter((l) => l.kind === 'open').length };
  } finally {
    await aliceClient.client.shutdown();
  }
}

const OPERATIONS = ['stage', 'commit', 'ack', 'receiptDone', 'commitCursor', 'seal'];
const POINTS = [];
for (let repetition = 0; repetition < REPETITIONS; repetition += 1) {
  for (const operation of OPERATIONS) {
    for (const step of WRITE_STEPS) {
      const occurrence = operation === 'seal' || operation === 'commitCursor' ? 1 : 1 + (repetition % MESSAGES);
      POINTS.push({ operation, step, occurrence, repetition });
    }
  }
  POINTS.push({ operation: 'candidate', step: 'openCandidate', occurrence: 1 + (repetition % MESSAGES), repetition });
}

describe('real process kills with the reference receiver (criterion 3, PR2)', () => {
  test.each(POINTS.map((p) => [`${p.operation}/${p.step}#${p.occurrence} (repetition ${p.repetition + 1})`, p]))(
    'kill at %s: recovery loses nothing staged, opens nothing committed, delivers everything once acknowledged',
    async (_label, point) => {
      const result = await crashCase({ operation: point.operation, step: point.step, occurrence: point.occurrence });
      expect(result.problems).toEqual([]);
      expect(result.reached).toBe(true);
    },
  );
});
