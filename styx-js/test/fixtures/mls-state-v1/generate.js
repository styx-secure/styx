// generate.js — produce the mls-state-v1 regression fixture with the REAL vendored
// WASM runtime and test-only synthetic identities. See README.md in this directory.
//
// Run from styx-js/:  node test/fixtures/mls-state-v1/generate.js
//
// The blob is not byte-deterministic (key generation uses the system CSPRNG), so a
// regeneration REPLACES the regression artifact — do it only on purpose (e.g. after
// a validated crate bump) and record why in the commit message.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { MlsEngine } from '../../../src/crypto/mls/mls-engine.js';
import { encodeMlsStateEnvelope } from '../../../src/storage/mls-state-envelope.js';
import { bytesToBase64, utf8Encode, utf8Decode } from '../../../src/utils.js';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

// Synthetic, test-only credential labels (the app uses real Nostr pubkeys here).
// These hex strings were never used outside the test tree and hold no secrets.
const CREATOR = '11'.repeat(32);
const PEER = '22'.repeat(32);
const REF_PLAINTEXT = 'mls-state-v1 reference message — only a correctly restored session decrypts this';

await MlsEngine.initWasm({ wasmBytes });

const creator = await MlsEngine.create({ name: CREATOR });
const peer = await MlsEngine.create({ name: PEER });

// Pair the two synthetic identities exactly like the app does.
const { session: creatorSession, welcome, ratchetTree, groupId } = creator.startSession(PEER, peer.keyPackageBytes());
const peerSession = peer.joinSession(CREATOR, welcome, ratchetTree);

// Advance the ratchets in both directions so the snapshot is a *lived-in* state.
peerSession.decrypt(creatorSession.encrypt(utf8Encode('synthetic message creator→peer')));
creatorSession.decrypt(peerSession.encrypt(utf8Encode('synthetic message peer→creator')));

// Snapshot the creator side.
const envelope = encodeMlsStateEnvelope(creator.serializeState());
const idpk = bytesToBase64(creator.identityPublicKey());

// Reference ciphertext produced AFTER the snapshot: a restored creator must decrypt it.
const refCiphertext = bytesToBase64(peerSession.encrypt(utf8Encode(REF_PLAINTEXT)));

const context = {
  name: CREATOR,
  peer: PEER,
  groupId,
  idpk,
  groups: { [PEER]: groupId },
  refCiphertext,
  refPlaintext: REF_PLAINTEXT,
};

writeFileSync(`${HERE}envelope.json`, `${JSON.stringify(envelope, null, 2)}\n`);
writeFileSync(`${HERE}context.json`, `${JSON.stringify(context, null, 2)}\n`);

// Self-check: restore from what was just written and decrypt the reference message.
const restored = await MlsEngine.restore({
  name: CREATOR,
  stateBytes: Uint8Array.from(Buffer.from(envelope.payload, 'base64')),
  identityPubKey: Uint8Array.from(Buffer.from(idpk, 'base64')),
});
const restoredSession = restored.loadSession(PEER, groupId);
const out = restoredSession.decrypt(Uint8Array.from(Buffer.from(refCiphertext, 'base64')));
if (utf8Decode(out.plaintext) !== REF_PLAINTEXT) {
  throw new Error('self-check failed: restored session did not decrypt the reference message');
}
console.log('fixture written and self-checked: envelope.json, context.json');
