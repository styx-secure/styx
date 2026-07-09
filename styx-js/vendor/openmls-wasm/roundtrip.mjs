// Smoke test for the vendored OpenMLS-WASM engine: a full MLS 1:1 round-trip.
// Run: node vendor/openmls-wasm/roundtrip.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import initWasm, { Provider, Identity, Group, KeyPackage, RatchetTree }
  from './openmls_wasm.js';

const wasm = fileURLToPath(new URL('./openmls_wasm_bg.wasm', import.meta.url));
await initWasm({ module_or_path: readFileSync(wasm) });

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
const ok = (c, m) => { console.log((c ? 'PASS' : 'FAIL') + ' — ' + m); if (!c) process.exitCode = 1; };

// Each peer has its own sovereign, local crypto+storage Provider.
const aliceProv = new Provider();
const bobProv = new Provider();
const alice = new Identity(aliceProv, 'alice');
const bob = new Identity(bobProv, 'bob');

// Bob publishes his KeyPackage; Alice receives its bytes over the wire.
const bobKp = KeyPackage.from_bytes(bob.key_package(bobProv).to_bytes());

// Alice creates a 2-member group and adds Bob.
const aliceGroup = Group.create_new(aliceProv, alice, 'styx:1:1:alice+bob');
const add = aliceGroup.propose_and_commit_add(aliceProv, alice, bobKp);
aliceGroup.merge_pending_commit(aliceProv);
ok(add.welcome.length > 0, 'commit produced a Welcome (' + add.welcome.length + ' bytes)');

// Alice ships Welcome + ratchet tree to Bob; Bob joins.
const rt = RatchetTree.from_bytes(aliceGroup.export_ratchet_tree().to_bytes());
const bobGroup = Group.join(bobProv, add.welcome, rt);

// Bidirectional application messages.
const pt1 = dec(bobGroup.process_message(bobProv, aliceGroup.create_message(aliceProv, alice, enc('Ciao Bob 🔐'))));
ok(pt1 === 'Ciao Bob 🔐', 'bob decrypted alice: ' + JSON.stringify(pt1));
const pt2 = dec(aliceGroup.process_message(aliceProv, bobGroup.create_message(bobProv, bob, enc('Ricevuto'))));
ok(pt2 === 'Ricevuto', 'alice decrypted bob: ' + JSON.stringify(pt2));

console.log('OpenMLS-WASM 1:1 round-trip OK.');
