// test/registry.test.js — the registry is the bridge's only state: pubkey →
// [subscription]. It must dedupe by endpoint and survive a restart (reload).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Registry } from '../src/registry.js';

function tmpFile() {
  const dir = mkdtempSync(join(tmpdir(), 'styx-reg-'));
  return { path: join(dir, 'reg.json'), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const subA = { endpoint: 'https://push/a', keys: { p256dh: 'x', auth: 'y' } };
const subB = { endpoint: 'https://push/b', keys: { p256dh: 'x', auth: 'y' } };

test('add stores a subscription and get returns it', async () => {
  const { path, cleanup } = tmpFile();
  try {
    const r = new Registry({ filePath: path });
    await r.load();
    assert.equal(r.add('pk1', subA), true);
    assert.deepEqual(r.get('pk1'), [subA]);
    assert.deepEqual(r.pubkeys(), ['pk1']);
  } finally { cleanup(); }
});

test('add is idempotent per endpoint (dedupe)', async () => {
  const { path, cleanup } = tmpFile();
  try {
    const r = new Registry({ filePath: path });
    await r.load();
    r.add('pk1', subA);
    assert.equal(r.add('pk1', subA), false); // same endpoint → no change
    r.add('pk1', subB);
    assert.equal(r.get('pk1').length, 2);
  } finally { cleanup(); }
});

test('remove drops one subscription by endpoint and forgets an empty pubkey', async () => {
  const { path, cleanup } = tmpFile();
  try {
    const r = new Registry({ filePath: path });
    await r.load();
    r.add('pk1', subA); r.add('pk1', subB);
    assert.equal(r.remove('pk1', subA.endpoint), true);
    assert.deepEqual(r.get('pk1'), [subB]);
    r.remove('pk1', subB.endpoint);
    assert.deepEqual(r.pubkeys(), []); // pubkey with no subs is forgotten
  } finally { cleanup(); }
});

test('state survives a reload from disk', async () => {
  const { path, cleanup } = tmpFile();
  try {
    const r1 = new Registry({ filePath: path });
    await r1.load();
    r1.add('pk1', subA);
    const r2 = new Registry({ filePath: path });
    await r2.load();
    assert.deepEqual(r2.get('pk1'), [subA]);
  } finally { cleanup(); }
});
