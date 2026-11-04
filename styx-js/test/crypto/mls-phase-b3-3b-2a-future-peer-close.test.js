// SPDX-License-Identifier: AGPL-3.0-or-later

import { spawn } from 'node:child_process';
import {
  chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { withRestoredMdk }
  from '../../spikes/marmot-phase-b3-3b-2a/retained-window-probe.mjs';

const PROBE = fileURLToPath(
  new URL('../../spikes/marmot-phase-b3-3b-2a/retained-window-probe.mjs', import.meta.url),
);
const MALFORMED = 'open durable storage: backend corruption: database disk image is malformed';
const FIELDS = Object.freeze({
  databaseKeyPath: '/nonexistent/key',
  databasePath: '/nonexistent/future-account.sqlite3',
  expectedRevision: 'synthetic-revision',
  identityHex: '00'.repeat(32),
  secretPath: '/nonexistent/secret',
});
const EXIT_BOUND_MS = 20_000;

// Scripted stand-in for the peer's stdio contract only (no MLS). Like the real
// peer, it answers every request in order, stays alive after an ordinary
// request error (mdk_peer_error is not a quarantine), and exits only after
// acknowledging checkpoint_and_exit or at end of stdin. It records its pid.
function peerScript(failingOp) {
  return `#!/bin/sh
echo "$$" >> "$0.pids"
while IFS= read -r request; do
  id=$(printf '%s' "$request" | sed -n 's/.*"id":\\([0-9]*\\).*/\\1/p')
  op=$(printf '%s' "$request" | sed -n 's/.*"op":"\\([a-z_]*\\)".*/\\1/p')
  if [ "$op" = "${failingOp}" ]; then
    printf '{"id":%s,"ok":false,"error":{"code":"mdk_peer_error","details":null,"message":"%s"}}\\n' "$id" '${MALFORMED}'
    continue
  fi
  case "$op" in
    hello) printf '{"id":%s,"ok":true,"result":{"mdk_revision":"synthetic-revision"}}\\n' "$id" ;;
    checkpoint_and_exit) printf '{"id":%s,"ok":true,"result":{"checkpointed":true}}\\n' "$id"; exit 0 ;;
    *) printf '{"id":%s,"ok":true,"result":{"op":"%s"}}\\n' "$id" "$op" ;;
  esac
done
exit 0
`;
}

function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error.code === 'ESRCH') return false;
    throw error;
  }
}

describe('Phase B3.3b-2a retained-window probe: fresh MDK peer cleanup', () => {
  let directory;
  const started = [];
  const script = (name, failingOp) => {
    const path = join(directory, name);
    writeFileSync(path, peerScript(failingOp));
    chmodSync(path, 0o700);
    return path;
  };
  const pids = (path) => {
    if (!existsSync(`${path}.pids`)) return [];
    const recorded = readFileSync(`${path}.pids`, 'utf8').trim().split('\n').map(Number);
    started.push(...recorded);
    return recorded;
  };

  beforeAll(() => { directory = mkdtempSync(join(tmpdir(), 'styx-b33b2a-future-peer-')); });
  afterAll(() => {
    // Only a failing run leaves a peer behind; kill it so the failure is reported instead of a hang.
    for (const pid of started) if (isAlive(pid)) process.kill(pid, 'SIGKILL');
    rmSync(directory, { recursive: true, force: true });
  });

  test.each(['initialize', 'restore_group'])(
    'a fresh peer whose %s fails is closed before the failure propagates',
    async (failingOp) => {
      const path = script(`fail-${failingOp}.sh`, failingOp);
      let used = false;
      await expect(withRestoredMdk(path, FIELDS, 'aa', () => { used = true; }))
        .rejects.toMatchObject({ code: 'mdk_peer_error', message: MALFORMED });
      expect(used).toBe(false);
      const recorded = pids(path);
      expect(recorded).toHaveLength(1);
      expect(recorded.filter(isAlive)).toEqual([]);
    },
  );

  test('a failure of the work closes the peer and propagates unchanged', async () => {
    const path = script('fail-work.sh', 'public_projection');
    await expect(withRestoredMdk(path, FIELDS, 'aa', (peer) => peer.request('public_projection')))
      .rejects.toMatchObject({ code: 'mdk_peer_error', message: MALFORMED });
    const recorded = pids(path);
    expect(recorded).toHaveLength(1);
    expect(recorded.filter(isAlive)).toEqual([]);
  });

  test('successful work returns its result after the peer exited', async () => {
    const path = script('succeed.sh', 'none');
    await expect(withRestoredMdk(path, FIELDS, 'aa', (peer) => peer.request('public_projection')))
      .resolves.toEqual({ op: 'public_projection' });
    const recorded = pids(path);
    expect(recorded).toHaveLength(1);
    expect(recorded.filter(isAlive)).toEqual([]);
  });

  test('a Node process whose fresh peer initialize fails exits by itself', async () => {
    const path = script('fail-initialize-process.sh', 'initialize');
    const program = `
      const { withRestoredMdk } = await import(process.argv[1]);
      try {
        await withRestoredMdk(process.argv[2], JSON.parse(process.argv[3]), 'aa', () => {});
        process.stdout.write('{"resolved":true}');
      } catch (error) {
        process.stdout.write(JSON.stringify({ code: error.code, message: error.message }));
        process.exitCode = 1;
      }
    `;
    const child = spawn(process.execPath, [
      '--input-type=module', '-e', program,
      pathToFileURL(PROBE).href, path, JSON.stringify(FIELDS),
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
    child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
    let timer;
    const outcome = await Promise.race([
      new Promise((resolveExit) => child.once('exit', (code, signal) => resolveExit({ code, signal }))),
      new Promise((resolveTimeout) => {
        timer = setTimeout(() => resolveTimeout({ timedOut: true }), EXIT_BOUND_MS);
      }),
    ]);
    clearTimeout(timer);
    if (outcome.timedOut) {
      child.kill('SIGKILL');
      await new Promise((resolveExit) => child.once('exit', resolveExit));
    }
    const recorded = pids(path);
    // On a mismatch the child's stderr is part of the reported difference.
    expect({ ...outcome, stderr: outcome.code === 1 ? '' : stderr })
      .toEqual({ code: 1, signal: null, stderr: '' });
    expect(JSON.parse(stdout)).toEqual({ code: 'mdk_peer_error', message: MALFORMED });
    expect(recorded).toHaveLength(1);
    expect(recorded.filter(isAlive)).toEqual([]);
  }, EXIT_BOUND_MS + 10_000);
});
