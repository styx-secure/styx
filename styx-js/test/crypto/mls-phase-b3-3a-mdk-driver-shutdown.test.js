// SPDX-License-Identifier: AGPL-3.0-or-later
// Deterministic shutdown tests for the B3.3a MDK spike driver (C-MDKDRV-SHUTDOWN). Fake peers are tiny shell
// scripts written to a private temporary directory; event-order cases use a stub ChildProcess. Real-peer cases
// use the constructor seam `drainTimeoutMs` (BOUND), so every case settles well inside Jest's default 5 s timeout.
// Every case carries its own short deadline, so at a driver without the seams it fails fast instead of hanging.
// Stub phase cases run on Jest's fake clock (nextTick, setImmediate and microtasks stay real) and step across each
// boundary (acknowledgement B, kill plus drain 2 x B, live plus drain near 3 x B), so host load cannot make them
// fail; the real-peer cases are smoke tests with an upper bound and a generous scheduling slack.
import { spawn as spawnProcess } from 'node:child_process';
import { EventEmitter, once } from 'node:events';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';

import { jest } from '@jest/globals';

import { B33A_ERROR } from '../../spikes/marmot-phase-b3-3a/b3-3a-canonical.mjs';
import { MdkB33aProcess } from '../../spikes/marmot-phase-b3-3a/b3-3a-mdk-driver.mjs';

const ACK = '{"id":1,"ok":true,"result":{"checkpointed":true}}';
const QUARANTINED = '{"id":1,"ok":false,"error":{"code":"mdk_peer_quarantined","details":null,'
  + '"message":"quarantined"}}';
const BOUND = 300; // real-peer cases
const BS = 200; // stub phase cases
const SLACK = 700; // scheduling slack for the real-peer upper bounds (smoke tests)
// Real timers, captured before any test fakes the clock: deadlines and sleeps never depend on the fake clock.
const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
const FAKE_CLOCK = { doNotFake: ['nextTick', 'setImmediate', 'queueMicrotask'] };
const ACK_RESPONSE = { id: 1, ok: true, result: { checkpointed: true } };
const FAKES = {
  'ack-exit0': `read line\nprintf '%s\\n' '${ACK}'\nexit 0`,
  'ack-exit3': `read line\nprintf '%s\\n' '${ACK}'\nexit 3`,
  'ack-holder': `read line\n(exec sleep 3) &\necho $! > "$0.pid.tmp" && mv "$0.pid.tmp" "$0.pid"\n`
    + `printf '%s\\n' '${ACK}'\nexit 0`,
  'ack-live': `read line\nprintf '%s\\n' '${ACK}'\nexec sleep 3`,
  dead: 'exit 0',
  'quarantine-closed-stdin': `read line\nexec 0<&-\nprintf '%s\\n' '${QUARANTINED}'\nsleep 0.2\nexit 0`,
  silent: 'read line\nexit 0',
  'silent-live': 'read line\nexec sleep 3',
};

let fakes;
let uncaught = [];
const onUncaught = (error) => { uncaught.push(error); };
const onUnhandled = (reason) => { uncaught.push(reason instanceof Error ? reason : new Error(`unhandled: ${reason}`)); };
const sleep = (ms) => new Promise((resolve) => { realSetTimeout(resolve, ms); });
const flush = async () => { for (let i = 0; i < 5; i += 1) await new Promise((r) => { setImmediate(r); }); };

beforeAll(() => {
  fakes = mkdtempSync(join(tmpdir(), 'mdkdrv-fakes-'));
  for (const [name, body] of Object.entries(FAKES)) {
    writeFileSync(join(fakes, `${name}.sh`), `#!/bin/sh\n${body}\n`);
    chmodSync(join(fakes, `${name}.sh`), 0o700);
  }
  process.on('uncaughtException', onUncaught);
  process.on('unhandledRejection', onUnhandled);
});
afterAll(() => {
  process.off('uncaughtException', onUncaught);
  process.off('unhandledRejection', onUnhandled);
  rmSync(fakes, { recursive: true, force: true });
});
beforeEach(() => { uncaught = []; });
afterEach(async () => {
  await sleep(50);
  expect(uncaught.map((error) => error.message)).toEqual([]);
});

// Real fake peer; the injected spawn records the real ChildProcess so the test can wait for it to close.
function realPeer(name) {
  const handle = {};
  handle.peer = new MdkB33aProcess(join(fakes, `${name}.sh`), {
    drainTimeoutMs: BOUND,
    spawn: (...args) => { handle.child = spawnProcess(...args); return handle.child; },
  });
  return handle;
}
async function waitClosed(handle) {
  if (!handle.child) throw new Error('driver did not use the injected spawn');
  if (handle.child.exitCode === null && handle.child.signalCode === null) await once(handle.child, 'close');
  await flush();
}
function rejection(promise) {
  return promise.then(() => { throw new Error('resolved, expected a rejection'); }, (error) => error);
}
function withDeadline(promise, ms) {
  let timer;
  return Promise.race([
    promise.finally(() => realClearTimeout(timer)),
    new Promise((_, reject) => {
      timer = realSetTimeout(() => reject(new Error(`HUNG: not settled in ${ms} ms`)), ms);
    }),
  ]);
}
// Advance the fake clock by ms, letting microtasks, nextTick and setImmediate callbacks run, then settle I/O.
async function advance(ms) {
  await jest.advanceTimersByTimeAsync(ms);
  await flush();
}
async function withFakeClock(body) {
  jest.useFakeTimers(FAKE_CLOCK);
  try { await body(); } finally { jest.useRealTimers(); }
}
// Kill the holder's descendant: only a validated pid (decimal digits, safe integer > 1) is ever signalled.
function killHolder(pidFile) {
  if (!existsSync(pidFile)) throw new Error('holder cleanup: pid file missing');
  const text = readFileSync(pidFile, 'utf8').trim();
  rmSync(pidFile, { force: true });
  const pid = /^[0-9]{1,10}$/.test(text) ? Number(text) : Number.NaN;
  if (!Number.isSafeInteger(pid) || pid <= 1) throw new Error(`holder cleanup: invalid pid ${JSON.stringify(text)}`);
  try { process.kill(pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
}
async function state(promise) {
  let result = 'pending';
  promise.then(() => { result = 'resolved'; }, () => { result = 'rejected'; });
  await flush();
  return result;
}

class StubChild extends EventEmitter {
  constructor() {
    super();
    this.pid = 4242;
    this.exitCode = null;
    this.signalCode = null;
    this.killed = [];
    this.written = [];
    this.stdin = new PassThrough();
    this.stdout = new PassThrough();
    this.stderr = new PassThrough();
    this.stdin.setEncoding('utf8');
    this.stdin.on('data', (chunk) => {
      for (const line of chunk.split('\n').filter(Boolean)) this.written.push(JSON.parse(line));
    });
  }

  kill(signal) {
    this.killed.push(signal);
    if (this.killError) this.emit('error', this.killError);
    return !this.killError;
  }

  respond(value) { this.stdout.write(`${JSON.stringify(value)}\n`); }

  exit(code, signal) {
    this.exitCode = code;
    this.signalCode = signal;
    this.emit('exit', code, signal);
  }

  async closeStdio(code, signal) {
    this.stdout.end();
    this.stderr.end();
    await flush();
    this.emit('close', code, signal);
    await flush();
  }
}
function stubPeer(options = {}) {
  const stub = new StubChild();
  let used = false;
  const peer = new MdkB33aProcess('stub-mdk-peer', { ...options, spawn: () => { used = true; return stub; } });
  if (!used) throw new Error('driver did not use the injected spawn');
  return { peer, stub };
}

describe('B3.3a MDK driver shutdown (C-MDKDRV-SHUTDOWN)', () => {
  test('ack then exit 0: close() resolves', async () => {
    await expect(withDeadline(realPeer('ack-exit0').peer.close(), 4000)).resolves.toBeUndefined();
  });

  test('exit 0 without ack: close() rejects as an exit', async () => {
    const error = await rejection(withDeadline(realPeer('silent').peer.close(), 4000));
    expect(error.message).toMatch(/^MDK peer exited code=0 signal=null/);
    expect(error.code).toBe('mdk_peer_exited');
  });

  test('ack then exit 3: close() rejects', async () => {
    const error = await rejection(withDeadline(realPeer('ack-exit3').peer.close(), 4000));
    expect(error.message).toMatch(/^MDK peer exited code=3 signal=null after acknowledging shutdown/);
    expect(error.code).toBe('mdk_peer_exited');
  });

  test('dead before close and never announced: close() rejects without writing', async () => {
    const handle = realPeer('dead');
    await waitClosed(handle);
    const writes = [];
    const write = handle.child.stdin.write.bind(handle.child.stdin);
    handle.child.stdin.write = (...args) => { writes.push(args[0]); return write(...args); };
    const error = await rejection(withDeadline(handle.peer.close(), 4000));
    expect(error.message).toMatch(/^MDK peer exited code=0 signal=null without acknowledging shutdown/);
    expect(error.code).toBe('mdk_peer_exited');
    expect(writes).toEqual([]);
  });

  test('request() on a dead peer: typed rejection, nothing written', async () => {
    const handle = realPeer('dead');
    await waitClosed(handle);
    const writes = [];
    const write = handle.child.stdin.write.bind(handle.child.stdin);
    handle.child.stdin.write = (...args) => { writes.push(args[0]); return write(...args); };
    const error = await rejection(handle.peer.request('hello'));
    expect(error.message).toMatch(/^MDK peer is not running/);
    expect(error.code).toBe('mdk_peer_not_running');
    expect(writes).toEqual([]);
  });

  test('terminating error, peer closed its stdin: close() resolves, no EPIPE', async () => {
    const { peer } = realPeer('quarantine-closed-stdin');
    const first = await rejection(peer.request('ingest_group_message'));
    expect(first.code).toBe('mdk_peer_quarantined');
    expect(first.message).toBe('quarantined');
    await expect(withDeadline(peer.close(), 4000)).resolves.toBeUndefined();
  });

  test('ack then exit 0, a descendant holds stdout open: close() rejects at the drain bound after exit', async () => {
    const started = Date.now();
    const holderPid = join(fakes, 'ack-holder.sh.pid');
    try {
      const error = await rejection(withDeadline(realPeer('ack-holder').peer.close(), 3 * BOUND + 500));
      expect(error.message).toMatch(/^MDK peer did not finish shutdown \(exit and stdio close\) within 300 ms/);
      expect(error.code).toBe('mdk_peer_shutdown_timeout');
      const elapsed = Date.now() - started;
      expect(elapsed).toBeGreaterThanOrEqual(BOUND - 20);
      expect(elapsed).toBeLessThan(BOUND + SLACK);
    } finally {
      killHolder(holderPid);
    }
  });

  test('ack but the peer stays alive: killed after the live bound, close() rejects (smoke, bound 3 x B)', async () => {
    const handle = realPeer('ack-live');
    const started = Date.now();
    const error = await rejection(withDeadline(handle.peer.close(), 3 * BOUND + 500));
    expect(error.message).toMatch(/^MDK peer did not finish shutdown \(exit and stdio close\) within 300 ms/);
    expect(error.code).toBe('mdk_peer_shutdown_timeout');
    expect(handle.child.signalCode).toBe('SIGKILL');
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(BOUND - 20);
    expect(elapsed).toBeLessThan(2 * BOUND + SLACK); // immediate ack: live bound, then a prompt exit after SIGKILL
  });

  test('live peer never acknowledges: killed after the bound, close() rejects (smoke, bound 2 x B)', async () => {
    const handle = realPeer('silent-live');
    const started = Date.now();
    const error = await rejection(withDeadline(handle.peer.close(), 3 * BOUND + 500));
    expect(error.message).toMatch(/^MDK peer did not acknowledge checkpoint_and_exit within 300 ms/);
    expect(error.code).toBe('mdk_peer_shutdown_timeout');
    expect(handle.child.signalCode).toBe('SIGKILL');
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(BOUND - 20);
    expect(elapsed).toBeLessThan(2 * BOUND + SLACK);
  });

  test('stub child: exit before the ack is read does not reject; close() resolves after stdio closes', async () => {
    const { peer, stub } = stubPeer();
    const closing = peer.close();
    await flush();
    expect(stub.written).toEqual([{ id: 1, op: 'checkpoint_and_exit' }]);
    stub.exit(0, null);
    await flush();
    expect(await state(closing)).toBe('pending');
    stub.respond({ id: 1, ok: true, result: { checkpointed: true } });
    await flush();
    expect(await state(closing)).toBe('pending');
    await stub.closeStdio(0, null);
    await expect(closing).resolves.toBeUndefined();
    expect(stub.killed).toEqual([]);
  });

  test('stub child: signaled termination rejects the pending request and close()', async () => {
    const { peer, stub } = stubPeer();
    const pending = rejection(peer.request('public_projection'));
    await flush();
    stub.exit(null, 'SIGKILL');
    await stub.closeStdio(null, 'SIGKILL');
    const error = await pending;
    expect(error.message).toMatch(/^MDK peer exited code=null signal=SIGKILL/);
    expect(error.code).toBe('mdk_peer_exited');
    const closeError = await rejection(withDeadline(peer.close(), 1000));
    expect(closeError.message).toMatch(/^MDK peer exited code=null signal=SIGKILL without acknowledging/);
    expect(closeError.code).toBe('mdk_peer_exited');

    const acked = stubPeer();
    const closing = rejection(acked.peer.close());
    await flush();
    acked.stub.respond({ id: 1, ok: true, result: { checkpointed: true } });
    await flush();
    acked.stub.exit(null, 'SIGTERM');
    await acked.stub.closeStdio(null, 'SIGTERM');
    const ackedError = await closing;
    expect(ackedError.message).toMatch(/^MDK peer exited code=null signal=SIGTERM after acknowledging/);
    expect(ackedError.code).toBe('mdk_peer_exited');
  });

  test('spawn failure: request() and close() reject with the spawn error, nothing uncaught', async () => {
    const missing = join(fakes, 'missing-peer');
    const early = new MdkB33aProcess(missing);
    const earlyError = await rejection(withDeadline(early.close(), 4000));
    expect(earlyError.code).toBe('ENOENT');
    expect(earlyError.message).toMatch(/^spawn .*missing-peer ENOENT$/);

    const late = new MdkB33aProcess(missing);
    await sleep(100);
    const requestError = await rejection(late.request('hello'));
    expect(requestError.code).toBe('ENOENT');
    const lateError = await rejection(withDeadline(late.close(), 4000));
    expect(lateError.code).toBe('ENOENT');
  });

  test('stub child: a normal RPC outstanding at an unexpected exit is rejected after the drain', async () => {
    const { peer, stub } = stubPeer();
    const pending = rejection(peer.request('public_projection'));
    await flush();
    expect(stub.written).toEqual([{ id: 1, op: 'public_projection' }]);
    stub.exit(0, null);
    await flush();
    expect(await state(pending)).toBe('pending');
    await stub.closeStdio(0, null);
    const error = await pending;
    expect(error.message).toMatch(/^MDK peer exited code=0 signal=null; stderr=$/);
    expect(error.code).toBe('mdk_peer_exited');
    const notRunning = await rejection(peer.request('hello'));
    expect(notRunning.code).toBe('mdk_peer_not_running');
  });

  test('stub child: an error answer on a live peer kills it at once; close() rejects with that error', async () => {
    const { peer, stub } = stubPeer();
    const closing = rejection(peer.close());
    await flush();
    expect(stub.written).toEqual([{ id: 1, op: 'checkpoint_and_exit' }]);
    stub.respond({ id: 1, ok: false, error: { code: 'engine_busy', details: null, message: 'busy' } });
    await flush();
    expect(stub.killed).toEqual(['SIGKILL']);
    stub.exit(null, 'SIGKILL');
    await stub.closeStdio(null, 'SIGKILL');
    const error = await withDeadline(closing, 1000);
    expect(error.code).toBe('engine_busy');
    expect(error.message).toBe('busy');
  });

  test('stub child: close() is idempotent: one write, one promise, the same outcome', async () => {
    const ok = stubPeer();
    const first = ok.peer.close();
    const second = ok.peer.close();
    expect(second).toBe(first);
    await flush();
    ok.stub.respond({ id: 1, ok: true, result: { checkpointed: true } });
    ok.stub.exit(0, null);
    await ok.stub.closeStdio(0, null);
    await expect(withDeadline(first, 1000)).resolves.toBeUndefined();
    await expect(ok.peer.close()).resolves.toBeUndefined();
    expect(ok.stub.written).toEqual([{ id: 1, op: 'checkpoint_and_exit' }]);

    const bad = stubPeer();
    const firstBad = rejection(bad.peer.close());
    await flush();
    bad.stub.exit(0, null);
    await bad.stub.closeStdio(0, null);
    const error = await withDeadline(firstBad, 1000);
    expect(error.code).toBe('mdk_peer_exited');
    const again = await rejection(withDeadline(bad.peer.close(), 1000));
    expect(again).toBe(error);
    expect(bad.stub.written).toEqual([{ id: 1, op: 'checkpoint_and_exit' }]);
  });

  test('constructor seam: drainTimeoutMs must be a positive safe integer', () => {
    const spawn = () => { throw new Error('must validate before spawning'); };
    for (const drainTimeoutMs of [0, -1, 1.5, '300', Number.NaN]) {
      expect(() => new MdkB33aProcess('stub-mdk-peer', { spawn, drainTimeoutMs })).toThrow(TypeError);
    }
  });
  test('stub phases: no acknowledgement and SIGKILL ignored: ack timeout at B, drain expiry at 2 x B', async () => {
    await withFakeClock(async () => {
      const { peer, stub } = stubPeer({ drainTimeoutMs: BS });
      const closing = rejection(peer.close());
      await flush();
      await advance(BS - 1);
      expect(stub.killed).toEqual([]);
      expect(await state(closing)).toBe('pending');
      await advance(1); // acknowledgement bound: kill, drain starts
      expect(stub.killed).toEqual(['SIGKILL']);
      expect(await state(closing)).toBe('pending');
      await advance(BS - 1);
      expect(await state(closing)).toBe('pending');
      await advance(1); // drain bound: 2 x B
      expect(await state(closing)).toBe('resolved');
      const error = await withDeadline(closing, 1000);
      expect(error.message).toMatch(/^MDK peer did not acknowledge checkpoint_and_exit within 200 ms/);
      expect(error.code).toBe('mdk_peer_shutdown_timeout');
      // A late acknowledgement and a late stream closure keep the rejection; close() returns the same promise.
      stub.respond(ACK_RESPONSE);
      stub.exit(null, 'SIGKILL');
      await stub.closeStdio(null, 'SIGKILL');
      expect(await rejection(peer.close())).toBe(error);
      expect(stub.killed).toEqual(['SIGKILL']);
      expect(stub.written).toEqual([{ id: 1, op: 'checkpoint_and_exit' }]);
    });
  });

  test('stub phases: acknowledgement near B, then live and drain expiry near 3 x B', async () => {
    await withFakeClock(async () => {
      const { peer, stub } = stubPeer({ drainTimeoutMs: BS });
      const closing = rejection(peer.close());
      await flush();
      await advance(BS - 40);
      stub.respond(ACK_RESPONSE); // acknowledged at B - 40: the live bound runs to 2 x B - 40
      await flush();
      await advance(BS - 1);
      expect(stub.killed).toEqual([]);
      expect(await state(closing)).toBe('pending');
      await advance(1);
      expect(stub.killed).toEqual(['SIGKILL']);
      expect(await state(closing)).toBe('pending');
      await advance(BS - 1);
      expect(await state(closing)).toBe('pending');
      await advance(1); // drain bound after the kill: 3 x B - 40
      expect(await state(closing)).toBe('resolved');
      const error = await withDeadline(closing, 1000);
      expect(error.message).toMatch(/^MDK peer did not finish shutdown \(exit and stdio close\) within 200 ms/);
      expect(error.code).toBe('mdk_peer_shutdown_timeout');
      stub.exit(null, 'SIGKILL');
      await stub.closeStdio(null, 'SIGKILL');
      expect(await rejection(peer.close())).toBe(error);
      expect(stub.killed).toEqual(['SIGKILL']);
    });
  });

  test('stub child: a late acknowledgement after its bound is ignored; a concurrent request gets the exit', async () => {
    await withFakeClock(async () => {
      const { peer, stub } = stubPeer({ drainTimeoutMs: BS });
      const other = rejection(peer.request('public_projection'));
      const closing = rejection(peer.close());
      await flush();
      expect(stub.written).toEqual([{ id: 1, op: 'public_projection' }, { id: 2, op: 'checkpoint_and_exit' }]);
      await advance(BS);
      expect(stub.killed).toEqual(['SIGKILL']);
      stub.respond({ id: 2, ok: true, result: { checkpointed: true } });
      await flush();
      expect(await state(other)).toBe('pending');
      expect(await state(closing)).toBe('pending');
      stub.exit(null, 'SIGKILL');
      await stub.closeStdio(null, 'SIGKILL');
      const otherError = await withDeadline(other, 1000);
      expect(otherError.code).toBe('mdk_peer_exited');
      const error = await withDeadline(closing, 1000);
      expect(error.message).toMatch(/^MDK peer did not acknowledge checkpoint_and_exit within 200 ms/);
    });
  });

  test('stub child: an error on a live child during close(): killed once, close() rejects with it at B', async () => {
    await withFakeClock(async () => {
      const { peer, stub } = stubPeer({ drainTimeoutMs: BS });
      const closing = rejection(peer.close());
      await flush();
      const eperm = Object.assign(new Error('kill EPERM'), { code: 'EPERM' });
      stub.emit('error', eperm);
      expect(stub.killed).toEqual(['SIGKILL']);
      await advance(BS - 1);
      expect(await state(closing)).toBe('pending');
      await advance(1);
      expect(await state(closing)).toBe('resolved');
      expect(await withDeadline(closing, 1000)).toBe(eperm);
      expect(stub.killed).toEqual(['SIGKILL']);
      expect(await rejection(peer.request('hello'))).toBe(eperm);
      expect(stub.written).toEqual([{ id: 1, op: 'checkpoint_and_exit' }]);
    });
  });

  test('stub child: an error on a live child before close(), kill also fails: no write, no recursion, bounded', async () => {
    await withFakeClock(async () => {
      const { peer, stub } = stubPeer({ drainTimeoutMs: BS });
      stub.killError = Object.assign(new Error('kill EPERM again'), { code: 'EPERM' });
      const first = Object.assign(new Error('child EPERM'), { code: 'EPERM' });
      stub.emit('error', first);
      expect(stub.killed).toEqual(['SIGKILL']);
      const closing = rejection(peer.close());
      await advance(BS - 1);
      expect(await state(closing)).toBe('pending');
      await advance(1);
      expect(await withDeadline(closing, 1000)).toBe(first);
      expect(stub.killed).toEqual(['SIGKILL']);
      expect(stub.written).toEqual([]);
    });
  });

  test('stub child: failed spawn and no close event: close() rejects with the spawn error at the bound', async () => {
    await withFakeClock(async () => {
      const stub = new StubChild();
      stub.pid = undefined;
      const peer = new MdkB33aProcess('stub-mdk-peer', { spawn: () => stub, drainTimeoutMs: BS });
      const enoent = Object.assign(new Error('spawn stub-mdk-peer ENOENT'), { code: 'ENOENT' });
      stub.emit('error', enoent);
      const closing = rejection(peer.close());
      await advance(BS - 1);
      expect(await state(closing)).toBe('pending');
      await advance(1);
      expect(await withDeadline(closing, 1000)).toBe(enoent);
      expect(stub.written).toEqual([]);
      expect(stub.killed).toEqual([]);
    });
  });

  test('stub child: an invalid answer to checkpoint_and_exit on a live peer kills it; close() rejects invalid', async () => {
    for (const raw of ['not-json', JSON.stringify({ id: 1, ok: true })]) {
      const { peer, stub } = stubPeer({ drainTimeoutMs: BS });
      const closing = rejection(peer.close());
      await flush();
      stub.stdout.write(`${raw}\n`);
      await flush();
      expect(stub.killed).toEqual(['SIGKILL']);
      stub.exit(null, 'SIGKILL');
      await stub.closeStdio(null, 'SIGKILL');
      const error = await withDeadline(closing, 1000);
      expect(error.code).toBe(B33A_ERROR.INVALID);
    }
  });

  test('stub child: a write failure on a live peer kills it; close() rejects with the write error', async () => {
    const { peer, stub } = stubPeer({ drainTimeoutMs: BS });
    const epipe = Object.assign(new Error('write EPIPE'), { code: 'EPIPE' });
    stub.stdin.write = (chunk, callback) => {
      process.nextTick(() => { callback(epipe); stub.stdin.emit('error', epipe); });
      return false;
    };
    const closing = rejection(peer.close());
    await flush();
    expect(stub.killed).toEqual(['SIGKILL']);
    stub.exit(null, 'SIGKILL');
    await stub.closeStdio(null, 'SIGKILL');
    const error = await withDeadline(closing, 1000);
    expect(error).toBe(epipe);
  });
});
