// PROTOTYPE end-to-end: two separate Node processes (proto/demo-member.mjs),
// two loopback relays started here, invitation over Nostr, SDK client only.
import { describe, test, expect, afterAll } from '@jest/globals';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startRelay } from './support/relay.js';
import { createFileIdentity } from '../../proto/identity.js';

const DEMO = new URL('../../proto/demo-member.mjs', import.meta.url).pathname;
const dir = mkdtempSync(join(process.env.TMPDIR || tmpdir(), 'styx-2p-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

function run(role, env) {
  return new Promise((resolve) => {
    const out = [];
    const p = spawn(process.execPath, ['--no-warnings', DEMO], { env: { ...process.env, ROLE: role, ...env } });
    p.stdout.on('data', (d) => out.push(String(d)));
    p.stderr.on('data', (d) => out.push(String(d)));
    p.on('exit', (code) => resolve({ code, log: out.join('') }));
  });
}

describe('two local processes', () => {
  test('invitee + inviter: invite over Nostr, 2 messages each way, all RECIPIENT_RECEIPT_RECEIVED', async () => {
    const relays = [await startRelay(), await startRelay()];
    try {
      const RELAYS = relays.map((r) => r.url).join(',');
      const PASS = 'synthetic-two-process-pass';
      const idB = join(dir, 'bob.json');
      const bobPk = createFileIdentity({ path: idB, passphrase: PASS }).getPublicKey();
      const common = { RELAYS, IDENTITY_PASSPHRASE: PASS, MESSAGES: '2' };
      const bob = run('invitee', { ...common, IDENTITY_FILE: idB, OUT: join(dir, 'bob-out.json') });
      // the inviter starts once the KeyPackage is on the relay
      const t0 = Date.now();
      while (!relays[0].events.some((e) => e.kind === 4743 && e.pubkey === bobPk)) {
        if (Date.now() - t0 > 60000) throw new Error('no KeyPackage');
        await new Promise((r) => setTimeout(r, 200));
      }
      const alice = run('inviter', { ...common, IDENTITY_FILE: join(dir, 'alice.json'), INVITEE: bobPk, OUT: join(dir, 'alice-out.json') });
      const [a, b] = await Promise.all([alice, bob]);
      if (a.code !== 0 || b.code !== 0) console.log(a.log, '\n----\n', b.log);
      expect(a.code).toBe(0);
      expect(b.code).toBe(0);
      const ra = JSON.parse(readFileSync(join(dir, 'alice-out.json'), 'utf8'));
      const rb = JSON.parse(readFileSync(join(dir, 'bob-out.json'), 'utf8'));
      expect(ra.groupCheck).toBe(rb.groupCheck);
      expect(ra.peer).toBe(rb.self);
      expect(rb.peer).toBe(ra.self);
      expect(ra.deliveries.map((d) => d.state)).toEqual(['RECIPIENT_RECEIPT_RECEIVED', 'RECIPIENT_RECEIPT_RECEIVED']);
      expect(rb.deliveries.map((d) => d.state)).toEqual(['RECIPIENT_RECEIPT_RECEIVED', 'RECIPIENT_RECEIPT_RECEIVED']);
      expect(rb.received.map((m) => m.sha)).toEqual(ra.deliveries.map((d) => d.sha));
      expect(ra.received.map((m) => m.sha)).toEqual(rb.deliveries.map((d) => d.sha));
      // no secret in logs or result files: the passphrase never appears
      for (const t of [a.log, b.log, JSON.stringify(ra), JSON.stringify(rb)]) expect(t).not.toContain(PASS);
      // no file exchange: the only shared input was Bob's public key
      expect(existsSync(join(dir, 'keypackage.json'))).toBe(false);
      // the Welcome went through the relay as a kind-1059 gift wrap
      expect(relays[0].events.some((e) => e.kind === 1059)).toBe(true);
    } finally {
      for (const r of relays) await r.close();
    }
  }, 240000);
});
