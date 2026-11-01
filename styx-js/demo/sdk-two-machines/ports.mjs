// PROTOTYPE — DO NOT MERGE. Caller-owned ports; no SDK/crypto modifications.
import { readFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1';
import { wrapEvent, unwrapEvent } from 'nostr-tools/nip59';
import { verifyEvent } from 'nostr-tools/pure';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';

export function identity(seed) {
  // The seed is a high-entropy secret passed in the environment, never logged.
  if (seed !== undefined && (typeof seed !== 'string' || seed.length < 32)) throw Error('seed too short');
  const key = seed === undefined ? randomBytes(32) : createHash('sha256').update('styx-sdk-demo-nov:').update(seed).digest();
  const pk = Buffer.from(schnorr.getPublicKey(key)).toString('hex');
  return {
    getPublicKey: () => pk,
    sign: ({ digest }) => schnorr.sign(digest, key),
    giftWrap: ({ rumor, recipient }) => {
      // Strip nostr-tools' cached-verification Symbol: SDK accepts closed plain events.
      return JSON.parse(JSON.stringify(wrapEvent(rumor, key, recipient)));
    },
    unwrapGift: ({ event }) => {
      // NIP-59 helper verifies the seal and binds its signer to the rumor author.
      if (!verifyEvent(event)) throw Error('bad outer signature');
      const unpacked = unwrapEvent(event, key);
      const { pubkey, created_at, kind, tags, content } = unpacked;
      return { rumor: { pubkey, created_at, kind, tags, content }, sealSigner: pubkey };
    },
    destroy: () => key.fill(0),
  };
}

export async function session(identityPort) {
  await MlsEngine.initWasm({ wasmBytes: readFileSync(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)) });
  const pk = identityPort.getPublicKey();
  const engine = await MlsEngine.create({ name: pk });
  const bindings = new Set();
  const port = {
    createKeyPackage: () => engine.keyPackageBytes(),
    startSession: async ({ peer, keyPackage }) => {
      if (bindings.has(peer)) throw Error('existing session');
      const probe = await MlsEngine.create({ name: pk });
      probe.startSession(peer, keyPackage);
      if (probe.peerIdentity(peer) !== peer) throw Error('wrong KeyPackage credential');
      const result = engine.startSession(peer, keyPackage);
      bindings.add(peer);
      return { welcome: result.welcome, ratchetTree: result.ratchetTree };
    },
    joinSession: async ({ peer, welcome, ratchetTree }) => {
      if (bindings.has(peer)) throw Error('existing session');
      const clone = await MlsEngine.restore({ name: pk, stateBytes: engine.serializeState(), identityPubKey: engine.identityPublicKey() });
      clone.joinSession(peer, welcome, ratchetTree);
      if (clone.peerIdentity(peer) !== peer) throw Error('wrong Welcome credential');
      engine.joinSession(peer, welcome, ratchetTree);
      bindings.add(peer);
      return true;
    },
    seal: ({ recipient, plaintext }) => ({ ciphertext: engine.session(recipient).encrypt(plaintext) }),
    open: ({ sender, ciphertext }) => {
      const result = engine.session(sender).decrypt(ciphertext);
      if (result.kind !== 'application') throw Error('not application data');
      return { plaintext: result.plaintext };
    },
  };
  return { port, fingerprint: (peer) => createHash('sha256').update(engine.session(peer).exportSecret('styx-demo-nov-check', new Uint8Array(), 32)).digest('hex') };
}

export function storage() {
  const records = new Map();
  return {
    put: (r) => { records.set(r.deliveryId, r); return true; },
    get: (id) => records.get(id) ?? null,
    update: (id, r) => { records.set(id, r); return true; },
    remove: (id) => records.delete(id),
    list: () => [...records.values()],
  };
}
export const clock = { now: () => Date.now(), setTimer: (f, ms) => setTimeout(f, ms), clearTimer: (t) => clearTimeout(t) };
