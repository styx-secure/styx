// PROTOTYPE — DO NOT MERGE. Caller-owned encrypted state, no SDK private API.
import { mkdirSync, chmodSync, readFileSync, existsSync, openSync, writeFileSync, fsyncSync, closeSync, renameSync } from 'node:fs';
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { identity } from './ports.mjs';
const b64 = (v) => Buffer.from(v).toString('base64');
const bytes = (v) => new Uint8Array(Buffer.from(v, 'base64'));
export function stateFile(dir, keyHex) {
  if (!/^[0-9a-f]{64}$/.test(keyHex ?? '')) throw Error('DEMO_STATE_KEY must be 32 random bytes in hex');
  mkdirSync(dir, { recursive: true, mode: 0o700 }); chmodSync(dir, 0o700);
  const key = Buffer.from(keyHex, 'hex'), file = dir + '/state.aesgcm';
  let data = {};
  if (existsSync(file)) {
    const blob = readFileSync(file), decipher = createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
    decipher.setAAD(Buffer.from('styx-demo-persistence-v1')); decipher.setAuthTag(blob.subarray(12, 28));
    data = JSON.parse(Buffer.concat([decipher.update(blob.subarray(28)), decipher.final()]).toString(),
      (_key, value) => value && typeof value === 'object' && Object.keys(value).length === 1 && typeof value.__demoBytes === 'string' ? bytes(value.__demoBytes) : value);
  }
  function save() {
    const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(Buffer.from('styx-demo-persistence-v1'));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(data, (_key, value) => value instanceof Uint8Array ? { __demoBytes: b64(value) } : value)), cipher.final()]);
    const fd = openSync(file + '.new', 'w', 0o600);
    try { writeFileSync(fd, Buffer.concat([nonce, cipher.getAuthTag(), ciphertext])); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(file + '.new', file);
    const directory = openSync(dir, 'r'); try { fsyncSync(directory); } finally { closeSync(directory); }
  }
  if (!data.seed) { data.seed = randomBytes(32).toString('hex'); save(); }
  return { data, save, identity: identity(data.seed), destroy: () => key.fill(0) };
}
export async function persistentSession(store) {
  await MlsEngine.initWasm({ wasmBytes: readFileSync(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)) });
  const pk = store.identity.getPublicKey(), saved = store.data.mls;
  const engine = saved ? await MlsEngine.restore({ name: pk, stateBytes: bytes(saved.state), identityPubKey: bytes(saved.identity) }) : await MlsEngine.create({ name: pk });
  const groups = saved?.groups ?? {};
  for (const [peer, groupId] of Object.entries(groups)) {
    if (!engine.loadSession(peer, groupId) || engine.peerIdentity(peer) !== peer) throw Error('restore binding failed');
  }
  function persist() {
    store.data.mls = { state: b64(engine.serializeState()), identity: b64(engine.identityPublicKey()), groups };
    store.save();
  }
  function assertNew(peer) { if (engine.session(peer)) throw Error('existing session'); }
  const port = {
    createKeyPackage: () => { const result = engine.keyPackageBytes(); persist(); return result; },
    startSession: async ({ peer, keyPackage }) => {
      assertNew(peer);
      const probe = await MlsEngine.create({ name: pk }); probe.startSession(peer, keyPackage);
      if (probe.peerIdentity(peer) !== peer) throw Error('wrong KeyPackage credential');
      const result = engine.startSession(peer, keyPackage); groups[peer] = result.groupId; persist();
      return { welcome: result.welcome, ratchetTree: result.ratchetTree };
    },
    joinSession: async ({ peer, welcome, ratchetTree }) => {
      assertNew(peer);
      const clone = await MlsEngine.restore({ name: pk, stateBytes: engine.serializeState(), identityPubKey: engine.identityPublicKey() });
      clone.joinSession(peer, welcome, ratchetTree);
      if (clone.peerIdentity(peer) !== peer) throw Error('wrong Welcome credential');
      engine.joinSession(peer, welcome, ratchetTree); persist(); return true;
    },
    seal: ({ recipient, plaintext }) => { const ciphertext = engine.session(recipient).encrypt(plaintext); persist(); return { ciphertext }; },
    open: ({ sender, ciphertext }) => {
      const result = engine.session(sender).decrypt(ciphertext);
      if (result.kind !== 'application') throw Error('not application data');
      persist(); return { plaintext: result.plaintext };
    },
  };
  persist();
  return { port, groupId: (peer) => groups[peer],
    bindGroup: (peer, groupId) => {
      // groupId arrives in an authenticated application payload, not from provider internals.
      if (groups[peer] && groups[peer] !== groupId) throw Error('group changed');
      if (!engine.loadSession(peer, groupId) || engine.peerIdentity(peer) !== peer) throw Error('invalid group binding');
      groups[peer] = groupId; persist();
    },
    fingerprint: (peer) => createHash('sha256').update(engine.session(peer).exportSecret('styx-demo-nov-check', new Uint8Array(), 32)).digest('hex') };
}
export function persistentOutbox(store) {
  // Each SDK process gets an explicitly separate namespace. SDK v0.3 cannot
  // hydrate an old one. Archive EVERYTHING; never conceal old records via list().
  const old = store.data.outboxes ?? [];
  const recovered = old.flatMap((run, namespace) => Object.values(run.records).filter((r) => !['RECIPIENT_RECEIPT_RECEIVED','RELAY_ACCEPTED','FAILED_NOT_ACCEPTED','FAILED_NO_RECEIPT','CANCELLED','LOST_ON_SHUTDOWN'].includes(r.state)).map((r) => ({ namespace, deliveryId: r.deliveryId, previousState: r.state, applicationOutcome: 'FAILED_AFTER_RESTART_UNKNOWN_OUTCOME', retried: false })));
  store.data.recovery ??= [];
  for (const r of recovered) if (!store.data.recovery.some((x) => x.namespace === r.namespace && x.deliveryId === r.deliveryId)) store.data.recovery.push(r);
  const run = { records: {} }; old.push(run); store.data.outboxes = old; store.save();
  const clone = (r) => structuredClone(r);
  return { recovered: store.data.recovery,
    port: {
      put: (r) => { run.records[r.deliveryId] = clone(r); store.save(); return true; },
      get: (id) => run.records[id] ? clone(run.records[id]) : null,
      update: (id, r) => { if (!(id in run.records)) return false; run.records[id] = clone(r); store.save(); return true; },
      remove: (id) => { const had = id in run.records; delete run.records[id]; store.save(); return had; },
      list: () => Object.values(run.records).map(clone),
    } };
}
