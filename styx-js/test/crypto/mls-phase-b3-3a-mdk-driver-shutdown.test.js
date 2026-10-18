// SPDX-License-Identifier: AGPL-3.0-or-later
// Deterministic shutdown tests for the B3.3a MDK spike driver (C-MDKDRV-SHUTDOWN). Fake peers are tiny shell
// scripts written to a private temporary directory; event-order cases use a stub ChildProcess. Real-peer cases
// use the constructor seam `drainTimeoutMs` (BOUND), so every case settles well inside Jest's default 5 s timeout.
// Every case carries its own short deadline, so at a driver without the seams it fails fast instead of hanging.
import { spawn as spawnProcess } from 'node:child_process';
import { EventEmitter, once } from 'node:events';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';

import { MdkB33aProcess } from '../../spikes/marmot-phase-b3-3a/b3-3a-mdk-driver.mjs';

const ACK = '{"id":1,"ok":true,"result":{"checkpointed":true}}';
const QUARANTINED = '{"id":1,"ok":false,"error":{"code":"mdk_peer_quarantined","details":null,'
  + '"message":"quarantined"}}';
const BOUND = 300;
const FAKES = {
  'ack-exit0': `read line\nprintf '%s\\n' '${ACK}'\nexit 0`,
  'ack-exit3': `read line\nprintf '%s\\n' '${ACK}'\nexit 3`,
  'ack-holder': `read line\nprintf '%s\\n' '${ACK}'\n(sleep 3) &\nexit 0`,
  'ack-live': `read line\nprintf '%s\\n' '${ACK}'\nexec sleep 3`,
  dead: 'exit 0',
  'quarantine-closed-stdin': `read line\nexec 0<&-\nprintf '%s\\n' '${QUARANTINED}'\nsleep 0.2\nexit 0`,
  silent: 'read line\nexit 0',
  'silent-live': 'read line\nexec sleep 3',
};

let fakes;
let uncaught = [];
const onUncaught = (error) => { uncaught.push(error); };
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });
const flush = async () => { for (let i = 0; i < 5; i += 1) await new Promise((r) => { setImmediate(r); }); };

beforeAll(() => {
  fakes = mkdtempSync(join(tmpdir(), 'mdkdrv-fakes-'));
  for (const [name, body] of Object.entries(FAKES)) {
    writeFileSync(join(fakes, `${name}.sh`), `#!/bin/sh\n${body}\n`);
    chmodSync(join(fakes, `${name}.sh`), 0o700);
  }
  process.on('uncaughtException', onUncaught);
});
afterAll(() => {
  process.off('uncaughtException', onUncaught);
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
    promise.finally(() => clearTimeout(timer)),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`HUNG: not settled in ${ms} ms`)), ms); }),
  ]);
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

  kill(signal) { this.killed.push(signal); return true; }

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
function stubPeer() {
  const stub = new StubChild();
  let used = false;
  const peer = new MdkB33aProcess('stub-mdk-peer', { spawn: () => { used = true; return stub; } });
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

  test('ack then exit 0, a descendant holds stdout open: close() rejects within the drain bound', async () => {
    const started = Date.now();
    const error = await rejection(withDeadline(realPeer('ack-holder').peer.close(), 2000));
    expect(error.message).toMatch(/^MDK peer did not finish shutdown \(exit and stdio close\) within 300 ms/);
    expect(error.code).toBe('mdk_peer_shutdown_timeout');
    expect(Date.now() - started).toBeGreaterThanOrEqual(BOUND - 20);
  });

  test('ack but the peer stays alive: it is killed and close() rejects within 2 x the bound', async () => {
    const handle = realPeer('ack-live');
    const started = Date.now();
    const error = await rejection(withDeadline(handle.peer.close(), 2500));
    expect(error.message).toMatch(/^MDK peer did not finish shutdown \(exit and stdio close\) within 300 ms/);
    expect(error.code).toBe('mdk_peer_shutdown_timeout');
    expect(handle.child.signalCode).toBe('SIGKILL');
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(BOUND - 20);
    expect(elapsed).toBeLessThan(3 * BOUND + 1000);
  });

  test('live peer never acknowledges: killed after the bound, close() rejects within 3 x the bound', async () => {
    const handle = realPeer('silent-live');
    const started = Date.now();
    const error = await rejection(withDeadline(handle.peer.close(), 2500));
    expect(error.message).toMatch(/^MDK peer did not acknowledge checkpoint_and_exit within 300 ms/);
    expect(error.code).toBe('mdk_peer_shutdown_timeout');
    expect(handle.child.signalCode).toBe('SIGKILL');
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(BOUND - 20);
    expect(elapsed).toBeLessThan(3 * BOUND + 1000);
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
});
