// test/chat/styx-chat-envelope.test.js — StyxChat.init through the envelope codec:
// legacy state migrates in place, bad state fails closed (never a silent fresh engine),
// and persistence writes envelopes. Real identity, real MLS, real transport (dev).
import { describe, test, expect, beforeAll, afterEach } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import {
  MLS_STATE_KEY,
  MLS_MIGRATION_PENDING_KEY,
  MLS_MIGRATION_BACKUP_KEY,
  MLS_MIGRATION_VERSION_KEY,
} from '../../src/storage/mls-state-migration.js';
import {
  MLS_STATE_FORMAT,
  detectMlsStateFormat,
} from '../../src/storage/mls-state-envelope.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

/** Faithful to LocalStorageBackend: every value goes through a JSON round-trip. */
function jsonBackend() {
  const m = new Map();
  return {
    m,
    async get(k) { return m.has(k) ? JSON.parse(m.get(k)) : null; },
    async set(k, v) { m.set(k, JSON.stringify(v)); },
    async delete(k) { m.delete(k); },
    async clear() { m.clear(); },
  };
}
const flush = async () => { for (let i = 0; i < 6; i++) await new Promise((r) => setTimeout(r, 5)); };

const live = [];
afterEach(() => { live.splice(0).forEach((c) => c.destroy()); });

async function realPeer({ backend, channelName, alias, password = 'pw' }) {
  const chat = new StyxChat();
  await chat.init({ password, backend, channelName, alias, allowInsecureTransport: true });
  live.push(chat);
  return chat;
}

/** Pair two peers (bob on `backend`), send one message, tear bob down. */
async function pairedBobBackend(channelName) {
  const backend = jsonBackend();
  const alice = await realPeer({ backend: jsonBackend(), channelName, alias: 'Alice' });
  const bob = await realPeer({ backend, channelName, alias: 'Bob' });
  const { qr } = await bob.createQrInvite();
  const { contactPubkey } = await alice.acceptQrInvite(qr);
  await alice.confirmPairing({ contactPubkey, alias: 'Bob' });
  await flush();
  await bob.confirmPairing({ contactPubkey: alice.me.pubkey, alias: 'Alice' });
  await alice.sendText(bob.me.pubkey, 'prima del reload');
  await flush();
  return { backend, alice, bobPubkey: bob.me.pubkey };
}

describe('StyxChat + MLS state envelope', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('persistence writes an envelope, not a bare string', async () => {
    const { backend } = await pairedBobBackend('env-persist');
    const stored = await backend.get(MLS_STATE_KEY);
    expect(detectMlsStateFormat(stored)).toBe('envelope');
    expect(stored.format).toBe(MLS_STATE_FORMAT);
  });

  test('legacy state migrates on init and the restored session still decrypts', async () => {
    const { backend, alice, bobPubkey } = await pairedBobBackend('env-legacy');
    // Rewrite bob's stored state to the PRE-envelope format: the bare base64 payload.
    const envelope = await backend.get(MLS_STATE_KEY);
    await backend.set(MLS_STATE_KEY, envelope.payload);
    expect(detectMlsStateFormat(await backend.get(MLS_STATE_KEY))).toBe('legacy-base64');

    // Reload bob from the legacy backend: init must migrate, then restore.
    const bob = new StyxChat();
    await bob.init({ password: 'pw', backend, channelName: 'env-legacy', allowInsecureTransport: true });
    live.push(bob);
    expect(bob.me.pubkey).toBe(bobPubkey);

    // Storage converged to a clean envelope, no leftover migration keys.
    expect(detectMlsStateFormat(await backend.get(MLS_STATE_KEY))).toBe('envelope');
    expect(await backend.get(MLS_MIGRATION_VERSION_KEY)).toBe(1);
    expect(await backend.get(MLS_MIGRATION_PENDING_KEY)).toBeNull();
    expect(await backend.get(MLS_MIGRATION_BACKUP_KEY)).toBeNull();

    // The migrated-and-restored MLS session actually works.
    const got = new Promise((res) => bob.onMessage((m) => res(m)));
    await alice.sendText(bobPubkey, 'dopo la migrazione');
    const msg = await Promise.race([
      got,
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 6000)),
    ]);
    expect(msg.text).toBe('dopo la migrazione');
  });

  test('a corrupted envelope fails init closed: no fresh engine, storage untouched', async () => {
    const { backend } = await pairedBobBackend('env-corrupt');
    const envelope = await backend.get(MLS_STATE_KEY);
    const corrupted = { ...envelope, payloadSha256: '0'.repeat(64) };
    await backend.set(MLS_STATE_KEY, corrupted);
    const before = new Map(backend.m);

    const bob = new StyxChat();
    await expect(bob.init({ password: 'pw', backend, channelName: 'env-corrupt', allowInsecureTransport: true }))
      .rejects.toThrow(/MLS_STATE_CORRUPTED/);
    // Fail-closed: nothing was repaired, deleted or re-created.
    expect(backend.m).toEqual(before);
  });

  test('state from an unvalidated OpenMLS revision is refused explicitly', async () => {
    const { backend } = await pairedBobBackend('env-revision');
    const envelope = await backend.get(MLS_STATE_KEY);
    await backend.set(MLS_STATE_KEY, { ...envelope, openMlsRevision: 'a'.repeat(40) });

    const bob = new StyxChat();
    await expect(bob.init({ password: 'pw', backend, channelName: 'env-revision', allowInsecureTransport: true }))
      .rejects.toThrow(/MLS_STATE_OPENMLS_INCOMPATIBLE/);
  });

  test('a future envelope version is refused without modifying the data', async () => {
    const { backend } = await pairedBobBackend('env-future');
    const envelope = await backend.get(MLS_STATE_KEY);
    await backend.set(MLS_STATE_KEY, { ...envelope, envelopeVersion: 2 });
    const before = new Map(backend.m);

    const bob = new StyxChat();
    await expect(bob.init({ password: 'pw', backend, channelName: 'env-future', allowInsecureTransport: true }))
      .rejects.toThrow(/MLS_STATE_VERSION_UNSUPPORTED/);
    expect(backend.m).toEqual(before);
  });

  test('unrecognized state shape and missing idpk both fail closed', async () => {
    const { backend } = await pairedBobBackend('env-shape');
    await backend.set(MLS_STATE_KEY, 42);
    const bob1 = new StyxChat();
    await expect(bob1.init({ password: 'pw', backend, channelName: 'env-shape', allowInsecureTransport: true }))
      .rejects.toThrow(/MLS_STATE_INVALID/);

    const { backend: backend2 } = await pairedBobBackend('env-noidpk');
    await backend2.delete('mls:idpk');
    const bob2 = new StyxChat();
    await expect(bob2.init({ password: 'pw', backend: backend2, channelName: 'env-noidpk', allowInsecureTransport: true }))
      .rejects.toThrow(/MLS_STATE_INVALID/);
  });

  test('wipe after a partial migration leaves no MLS keys behind', async () => {
    const { backend } = await pairedBobBackend('env-wipe');
    // Fake an interrupted migration: leftover markers next to the state.
    await backend.set(MLS_MIGRATION_PENDING_KEY, { toVersion: 1 });
    await backend.set(MLS_MIGRATION_BACKUP_KEY, 'AAAA');
    const bob = new StyxChat();
    await bob.init({ password: 'pw', backend, channelName: 'env-wipe', allowInsecureTransport: true });
    await bob.wipe();
    expect(backend.m.size).toBe(0);
  });
});
