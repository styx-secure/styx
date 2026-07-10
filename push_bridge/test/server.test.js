// test/server.test.js — the HTTP API: hands out the VAPID key, accepts a
// correctly-signed register/unregister, and rejects a bad signature with 401.
// Verify + registry are injected; no real relays or push involved.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import { registrationDigest } from '../../styx-js/src/push/registration-digest.js';
import { createServer } from '../src/server.js';

function memRegistry() {
  const m = new Map();
  return {
    add: (pk, sub) => { m.set(pk, [...(m.get(pk) || []), sub]); return true; },
    remove: (pk) => { m.delete(pk); return true; },
    get: (pk) => m.get(pk) || [],
    pubkeys: () => [...m.keys()],
    _m: m,
  };
}
function keypair() {
  const sk = schnorr.utils.randomPrivateKey();
  return { sk, pk: bytesToHex(schnorr.getPublicKey(sk)) };
}
async function listen(server) {
  await new Promise((r) => server.listen(0, r));
  return `http://127.0.0.1:${server.address().port}`;
}

test('GET /vapidPublicKey returns the configured key', async () => {
  const server = createServer({ registry: memRegistry(), vapidPublicKey: 'VKEY', verify: () => true, onRegister: () => {} });
  const base = await listen(server);
  after(() => server.close());
  const res = await fetch(`${base}/vapidPublicKey`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { key: 'VKEY' });
});

test('POST /register stores a validly-signed subscription and watches the pubkey', async () => {
  const registry = memRegistry();
  const watched = [];
  const server = createServer({
    registry, vapidPublicKey: 'V',
    verify: ({ pubkey, action, endpoint, sig }) => {
      try { return schnorr.verify(sig, registrationDigest(action, pubkey, endpoint), pubkey); } catch { return false; }
    },
    onRegister: (pk) => watched.push(pk),
  });
  const base = await listen(server);
  after(() => server.close());

  const { sk, pk } = keypair();
  const endpoint = 'https://push/abc';
  const sig = bytesToHex(schnorr.sign(registrationDigest('register', pk, endpoint), sk));
  const res = await fetch(`${base}/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ pubkey: pk, subscription: { endpoint, keys: {} }, sig }),
  });
  assert.equal(res.status, 200);
  assert.deepEqual(registry.get(pk), [{ endpoint, keys: {} }]);
  assert.deepEqual(watched, [pk]);
});

test('POST /register with a bad signature is rejected 401 and stores nothing', async () => {
  const registry = memRegistry();
  const server = createServer({ registry, vapidPublicKey: 'V', verify: () => false, onRegister: () => {} });
  const base = await listen(server);
  after(() => server.close());
  const res = await fetch(`${base}/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ pubkey: 'pk', subscription: { endpoint: 'e', keys: {} }, sig: 'bad' }),
  });
  assert.equal(res.status, 401);
  assert.deepEqual(registry.pubkeys(), []);
});

test('POST /unregister removes a validly-signed subscription', async () => {
  const registry = memRegistry();
  registry.add('pk', { endpoint: 'e', keys: {} });
  const server = createServer({ registry, vapidPublicKey: 'V', verify: () => true, onRegister: () => {} });
  const base = await listen(server);
  after(() => server.close());
  const res = await fetch(`${base}/unregister`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ pubkey: 'pk', endpoint: 'e', sig: 'ok' }),
  });
  assert.equal(res.status, 200);
  assert.deepEqual(registry.pubkeys(), []);
});
