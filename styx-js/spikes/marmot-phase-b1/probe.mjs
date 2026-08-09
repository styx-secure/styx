import { schnorr } from '@noble/curves/secp256k1';

import {
  ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID,
  createAccountIdentityProofV2,
  verifyAccountIdentityProofV2,
} from './identity-proof-v2.js';
import { loadPhaseB1Wasm } from './wasm-loader.mjs';

const wasm = await loadPhaseB1Wasm();
const {
  Provider,
  PhaseB1Identity,
  PhaseB1KeyPackage,
  PhaseB1Group,
  PhaseB1RatchetTree,
} = wasm;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function check(condition, message) {
  if (!condition) throw new Error(`Phase B1 probe failed: ${message}`);
  console.log(`PASS — ${message}`);
}

function createPeer(provider) {
  const privateKey = Uint8Array.from(schnorr.utils.randomPrivateKey());
  const accountKey = Uint8Array.from(schnorr.getPublicKey(privateKey));
  const identity = new PhaseB1Identity(provider, accountKey);
  const proof = createAccountIdentityProofV2(
    privateKey,
    identity.leaf_signature_key(),
    Math.floor(Date.now() / 1000),
  );
  verifyAccountIdentityProofV2(proof, accountKey, identity.leaf_signature_key());
  const keyPackage = PhaseB1KeyPackage.from_framed_bytes(
    identity.key_package(provider, proof).to_framed_bytes(),
  );
  return { accountKey, identity, proof, keyPackage };
}

const aliceProvider = new Provider();
const bobProvider = new Provider();
const charlieProvider = new Provider();
const alice = createPeer(aliceProvider);
const bob = createPeer(bobProvider);
const charlie = createPeer(charlieProvider);

check(bob.keyPackage.ciphersuite_id() === 0x0001, 'framed KeyPackage uses ciphersuite 0x0001');
check(bob.keyPackage.identity_proof().length === 104, 'identity proof is exactly 104 bytes');
check(
  Array.from(bob.keyPackage.supported_component_ids()).join(',')
    === String(ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID),
  'leaf advertises component 0x8009',
);
check(!bob.keyPackage.is_last_resort(), 'KeyPackage is not last-resort');

const groupId = crypto.getRandomValues(new Uint8Array(32));
const aliceGroup = PhaseB1Group.create_new(
  aliceProvider,
  alice.identity,
  groupId,
  alice.proof,
);
const initialAdd = aliceGroup.propose_and_commit_add(
  aliceProvider,
  alice.identity,
  bob.keyPackage,
);
check(aliceGroup.epoch() === 0n, 'local Add remains pending before explicit confirm');
aliceGroup.confirm_pending_add(aliceProvider, initialAdd);
check(aliceGroup.epoch() === 1n, 'explicit local confirm advances exactly one epoch');

const bobGroup = PhaseB1Group.join(
  bobProvider,
  initialAdd.welcome(),
  PhaseB1RatchetTree.from_bytes(aliceGroup.export_ratchet_tree().to_bytes()),
);
const application = aliceGroup.create_application_message(
  aliceProvider,
  alice.identity,
  encoder.encode('phase-b1 application data'),
);
check(
  decoder.decode(bobGroup.process_application_message(bobProvider, application))
    === 'phase-b1 application data',
  'probe group decrypts application data only through the application path',
);

const pendingCharlie = bobGroup.propose_and_commit_add(
  bobProvider,
  bob.identity,
  charlie.keyPackage,
);
const stagedCharlie = aliceGroup.stage_inbound_commit(aliceProvider, pendingCharlie.commit());
const projection = stagedCharlie.projection();
check(aliceGroup.epoch() === 1n && aliceGroup.member_count() === 2, 'inbound Commit is staged without merge');
check(
  projection.add_count() === 1
    && projection.added_member_count() === 1
    && projection.prior_epoch() === 1n
    && projection.next_epoch() === 2n,
  'staged Commit exposes a bounded public projection',
);
aliceGroup.merge_staged_commit(aliceProvider, stagedCharlie);
bobGroup.confirm_pending_add(bobProvider, pendingCharlie);
check(aliceGroup.epoch() === 2n && aliceGroup.member_count() === 3, 'explicit merge applies exactly once');

console.log('Phase B1 capability probe completed. This is not a Marmot interoperability claim.');
