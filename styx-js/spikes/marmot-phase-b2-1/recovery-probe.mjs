import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import { createAccountIdentityProofV2 } from '../marmot-phase-b1/identity-proof-v2.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function check(condition, message) {
  if (!condition) throw new Error(`Phase B2.1 recovery probe failed: ${message}`);
}

function equalBytes(left, right) {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

async function loadWasm(directory, label) {
  if (!directory) throw new Error(`${label} directory is required`);
  const moduleUrl = pathToFileURL(join(directory, 'openmls_wasm.js'));
  moduleUrl.searchParams.set('phase-b2-1', label);
  const wasm = await import(moduleUrl.href);
  await wasm.default({
    module_or_path: readFileSync(join(directory, 'openmls_wasm_bg.wasm')),
  });
  return wasm;
}

function ownMemberSnapshot(owner) {
  return Object.fromEntries(Object.getOwnPropertyNames(owner).sort().map((name) => {
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if ('value' in descriptor) {
      if (name === 'length' && typeof descriptor.value === 'number') {
        return [name, `number:${descriptor.value}`];
      }
      return [
        name,
        typeof descriptor.value === 'function'
          ? `function:${descriptor.value.length}`
          : typeof descriptor.value,
      ];
    }
    return [
      name,
      `accessor:get=${descriptor.get?.length ?? '-'}:set=${descriptor.set?.length ?? '-'}`,
    ];
  }));
}

function exportedWrapperClasses(module) {
  return Object.fromEntries(Object.keys(module).sort().flatMap((name) => {
    const value = module[name];
    if (typeof value !== 'function' || !value.prototype) return [];
    const prototypeNames = Object.getOwnPropertyNames(value.prototype);
    return prototypeNames.includes('free') ? [[name, value]] : [];
  }));
}

function classSnapshot(module) {
  return Object.fromEntries(Object.entries(exportedWrapperClasses(module)).map(([name, value]) => {
    return [[name, {
      static: ownMemberSnapshot(value),
      prototype: ownMemberSnapshot(value.prototype),
    }]];
  }).flat());
}

function exactLineSet(body) {
  return new Set(body.split('\n').map((line) => line.trim()).filter(Boolean));
}

function extractDeclarationMembers(source) {
  const members = new Set();
  const classPattern = /^export class ([A-Za-z0-9_$]+) \{\n([\s\S]*?)^\}$/gm;
  for (const match of source.matchAll(classPattern)) {
    for (const line of exactLineSet(match[2])) {
      members.add(`${match[1]}.${line}`);
    }
  }
  return members;
}

function extractInitOutputMembers(source) {
  const match = source.match(/^export interface InitOutput \{\n([\s\S]*?)^\}$/m);
  check(match !== null, 'generated declarations contain InitOutput');
  return exactLineSet(match[1]);
}

function compareExactAdditions(before, after, expected, label) {
  const removals = [...before].filter((entry) => !after.has(entry)).sort();
  const additions = [...after].filter((entry) => !before.has(entry)).sort();
  const wanted = [...expected].sort();
  check(removals.length === 0, `${label} removes ${JSON.stringify(removals)}`);
  check(
    JSON.stringify(additions) === JSON.stringify(wanted),
    `${label} additions differ; observed ${JSON.stringify(additions)}`,
  );
}

function helperDescriptorShape(descriptor) {
  return {
    configurable: descriptor?.configurable,
    enumerable: descriptor?.enumerable,
    getterType: typeof descriptor?.get,
    setterType: typeof descriptor?.set,
    valueArity: typeof descriptor?.value === 'function' ? descriptor.value.length : undefined,
    valueType: typeof descriptor?.value,
    writable: descriptor?.writable,
  };
}

function assertGeneratedIdentityHelper(committed, candidate, candidateDts, candidateJs) {
  const expectedShape = {
    configurable: true,
    enumerable: false,
    getterType: 'undefined',
    setterType: 'undefined',
    valueArity: 1,
    valueType: 'function',
    writable: true,
  };
  const candidateShape = helperDescriptorShape(
    Object.getOwnPropertyDescriptor(candidate.PhaseB1Identity, '__wrap'),
  );
  check(
    JSON.stringify(candidateShape) === JSON.stringify(expectedShape),
    `PhaseB1Identity.__wrap descriptor differs: ${JSON.stringify(candidateShape)}`,
  );
  check(
    !Object.keys(candidate.PhaseB1Identity).includes('__wrap'),
    'PhaseB1Identity.__wrap is not Object.keys-enumerable',
  );
  const forInNames = [];
  for (const name in candidate.PhaseB1Identity) forInNames.push(name);
  check(!forInNames.includes('__wrap'), 'PhaseB1Identity.__wrap is not for-in enumerable');
  check(!candidateDts.includes('__wrap'), 'PhaseB1Identity.__wrap is absent from declarations');

  const committedHasMatchingHelper = Object.values(exportedWrapperClasses(committed)).some(
    (wrapper) => JSON.stringify(helperDescriptorShape(
      Object.getOwnPropertyDescriptor(wrapper, '__wrap'),
    )) === JSON.stringify(expectedShape),
  );
  check(committedHasMatchingHelper, 'a committed wrapper has the same static __wrap shape');

  const callToken = 'PhaseB1Identity.__wrap(';
  check(
    candidateJs.split(callToken).length - 1 === 1,
    'candidate JavaScript has exactly one PhaseB1Identity.__wrap call site',
  );
  const identityClass = candidateJs.match(
    /^export class PhaseB1Identity \{\n([\s\S]*?)^\}$/m,
  );
  check(identityClass !== null, 'candidate JavaScript contains PhaseB1Identity');
  check(
    identityClass[1].includes(
      'return ret[0] === 0 ? undefined : PhaseB1Identity.__wrap(ret[0]);',
    ),
    'PhaseB1Identity.load contains the exact generated __wrap return shape',
  );
}

function comparePublicSurface(
  committed,
  candidate,
  committedDts,
  candidateDts,
  candidateJs,
) {
  const committedExports = Object.keys(committed).sort();
  const candidateExports = Object.keys(candidate).sort();
  check(
    JSON.stringify(candidateExports) === JSON.stringify(committedExports),
    'the disposable module adds or removes no named module export',
  );

  const before = classSnapshot(committed);
  const after = classSnapshot(candidate);
  check(
    JSON.stringify(Object.keys(after)) === JSON.stringify(Object.keys(before)),
    'the disposable module adds or removes no exported class',
  );

  const additions = {};
  for (const className of Object.keys(before)) {
    for (const side of ['static', 'prototype']) {
      const oldMembers = before[className][side];
      const newMembers = after[className][side];
      for (const [name, signature] of Object.entries(oldMembers)) {
        check(name in newMembers, `${className}.${side}.${name} remains exported`);
        check(
          newMembers[name] === signature,
          `${className}.${side}.${name} retains its observable arity/type`,
        );
      }
      for (const name of Object.keys(newMembers)) {
        if (!(name in oldMembers)) {
          additions[`${className}.${side}.${name}`] = newMembers[name];
        }
      }
    }
  }

  const expectedRaw = {
    'PhaseB1Group.prototype.clear_pending_commit': 'function:2',
    'PhaseB1Group.prototype.confirm_pending_commit': 'function:2',
    'PhaseB1Group.prototype.group_id': 'function:0',
    'PhaseB1Group.prototype.has_pending_commit': 'function:1',
    'PhaseB1Group.prototype.matches_own_identity': 'function:2',
    'PhaseB1Group.static.load': 'function:2',
    'PhaseB1Identity.static.__wrap': 'function:1',
    'PhaseB1Identity.static.load': 'function:3',
  };
  check(
    JSON.stringify(Object.entries(additions).sort())
      === JSON.stringify(Object.entries(expectedRaw).sort()),
    `raw class delta differs; observed ${JSON.stringify(additions)}`,
  );

  const expectedDeclarations = [
    'PhaseB1Group.clear_pending_commit(provider: Provider, expected_prior_epoch: bigint): void;',
    'PhaseB1Group.confirm_pending_commit(provider: Provider, expected_prior_epoch: bigint): void;',
    'PhaseB1Group.group_id(): Uint8Array;',
    'PhaseB1Group.has_pending_commit(provider: Provider): boolean;',
    'PhaseB1Group.matches_own_identity(account_public_key: Uint8Array, leaf_signature_key: Uint8Array): boolean;',
    'PhaseB1Group.static load(provider: Provider, group_id: Uint8Array): PhaseB1Group | undefined;',
    'PhaseB1Identity.static load(provider: Provider, account_public_key: Uint8Array, leaf_signature_key: Uint8Array): PhaseB1Identity | undefined;',
  ];
  compareExactAdditions(
    extractDeclarationMembers(committedDts),
    extractDeclarationMembers(candidateDts),
    expectedDeclarations,
    'declared class surface',
  );

  const expectedInitOutput = [
    'readonly phaseb1group_clear_pending_commit: (a: number, b: number, c: bigint) => [number, number];',
    'readonly phaseb1group_confirm_pending_commit: (a: number, b: number, c: bigint) => [number, number];',
    'readonly phaseb1group_group_id: (a: number) => [number, number];',
    'readonly phaseb1group_has_pending_commit: (a: number, b: number) => [number, number, number];',
    'readonly phaseb1group_load: (a: number, b: number, c: number) => [number, number, number];',
    'readonly phaseb1group_matches_own_identity: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];',
    'readonly phaseb1identity_load: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];',
  ];
  compareExactAdditions(
    extractInitOutputMembers(committedDts),
    extractInitOutputMembers(candidateDts),
    expectedInitOutput,
    'InitOutput',
  );

  check(candidate.PhaseB1Identity.length === 2, 'PhaseB1Identity constructor arity remains 2');
  check(
    candidateDts.includes('constructor(provider: Provider, account_public_key: Uint8Array);'),
    'PhaseB1Identity keeps its exact public TypeScript constructor',
  );
  check(
    !candidateDts.includes('export class PhaseB1Identity {\n    private constructor();'),
    'PhaseB1Identity does not acquire a private TypeScript constructor',
  );

  assertGeneratedIdentityHelper(committed, candidate, candidateDts, candidateJs);
  console.log('PASS SURFACE_DELTA_EXACTLY_SEVEN');
  console.log('PASS GENERATED_HELPER_EXACTLY_PHASEB1IDENTITY_WRAP');
}

function createPeer(wasm, provider) {
  const privateKey = Uint8Array.from(schnorr.utils.randomPrivateKey());
  const accountKey = Uint8Array.from(schnorr.getPublicKey(privateKey));
  const identity = new wasm.PhaseB1Identity(provider, accountKey);
  const leafKey = identity.leaf_signature_key();
  const proof = createAccountIdentityProofV2(
    privateKey,
    leafKey,
    Math.floor(Date.now() / 1000),
  );
  const keyPackage = wasm.PhaseB1KeyPackage.from_framed_bytes(
    identity.key_package(provider, proof).to_framed_bytes(),
  );
  return { accountKey, identity, keyPackage, leafKey, proof };
}

function restoreProvider(wasm, snapshot) {
  const provider = new wasm.Provider();
  provider.restore_state(snapshot);
  return provider;
}

function loadIdentity(wasm, provider, peer) {
  const identity = wasm.PhaseB1Identity.load(provider, peer.accountKey, peer.leafKey);
  check(identity !== undefined, 'the exact persisted Phase B1 signing key reloads');
  return identity;
}

function loadGroup(wasm, provider, groupId, peer) {
  const group = wasm.PhaseB1Group.load(provider, groupId);
  check(group !== undefined, 'the exact persisted Phase B1 group reloads');
  check(equalBytes(group.group_id(), groupId), 'the restored group id is byte-exact');
  check(group.matches_own_identity(peer.accountKey, peer.leafKey), 'the restored own leaf matches the persisted identity');
  return group;
}

function assertLiveness(left, right, label) {
  const leftPlaintext = encoder.encode(`${label}:left-to-right`);
  const leftCiphertext = left.group.create_application_message(
    left.provider,
    left.identity,
    leftPlaintext,
  );
  check(
    decoder.decode(right.group.process_application_message(right.provider, leftCiphertext))
      === decoder.decode(leftPlaintext),
    `${label} remains live left-to-right`,
  );

  const rightPlaintext = encoder.encode(`${label}:right-to-left`);
  const rightCiphertext = right.group.create_application_message(
    right.provider,
    right.identity,
    rightPlaintext,
  );
  check(
    decoder.decode(left.group.process_application_message(left.provider, rightCiphertext))
      === decoder.decode(rightPlaintext),
    `${label} remains live right-to-left`,
  );
}

function groupId(label) {
  return encoder.encode(`styx-b2-1:${label}`);
}

function joinFromPending(wasm, provider, pending, confirmedGroup) {
  return wasm.PhaseB1Group.join(
    provider,
    pending.welcome(),
    wasm.PhaseB1RatchetTree.from_bytes(confirmedGroup.export_ratchet_tree().to_bytes()),
  );
}

function setupStablePair(wasm, label) {
  const aliceProvider = new wasm.Provider();
  const bobProvider = new wasm.Provider();
  const alice = createPeer(wasm, aliceProvider);
  const bob = createPeer(wasm, bobProvider);
  const id = groupId(label);
  const aliceGroup = wasm.PhaseB1Group.create_new(aliceProvider, alice.identity, id, alice.proof);
  const pending = aliceGroup.propose_and_commit_add(aliceProvider, alice.identity, bob.keyPackage);
  aliceGroup.confirm_pending_add(aliceProvider, pending);
  const bobGroup = joinFromPending(wasm, bobProvider, pending, aliceGroup);
  check(aliceGroup.epoch() === 1n && bobGroup.epoch() === 1n, `${label} starts from stable epoch 1`);
  return {
    alice: { ...alice, group: aliceGroup, provider: aliceProvider },
    bob: { ...bob, group: bobGroup, provider: bobProvider },
    groupId: id,
  };
}

function foundingAddMerge(wasm) {
  const aliceProvider = new wasm.Provider();
  const bobProvider = new wasm.Provider();
  const alice = createPeer(wasm, aliceProvider);
  const bob = createPeer(wasm, bobProvider);
  const id = groupId('founding-merge');
  const group = wasm.PhaseB1Group.create_new(aliceProvider, alice.identity, id, alice.proof);
  const pending = group.propose_and_commit_add(aliceProvider, alice.identity, bob.keyPackage);
  const snapshot = aliceProvider.serialize_state();

  const recoveredProvider = restoreProvider(wasm, snapshot);
  const recoveredIdentity = loadIdentity(wasm, recoveredProvider, alice);
  const recoveredGroup = loadGroup(wasm, recoveredProvider, id, alice);
  check(recoveredGroup.has_pending_commit(recoveredProvider), 'founding merge reloads pending state');
  recoveredGroup.confirm_pending_commit(recoveredProvider, 0n);
  check(recoveredGroup.epoch() === 1n && recoveredGroup.member_count() === 2, 'founding recovery merge advances exactly once');
  const bobGroup = joinFromPending(wasm, bobProvider, pending, recoveredGroup);
  assertLiveness(
    { group: recoveredGroup, identity: recoveredIdentity, provider: recoveredProvider },
    { group: bobGroup, identity: bob.identity, provider: bobProvider },
    'founding merge',
  );
  console.log('PASS FOUNDING_ADD_MERGE');
}

function foundingAddClear(wasm) {
  const aliceProvider = new wasm.Provider();
  const bobProvider = new wasm.Provider();
  const alice = createPeer(wasm, aliceProvider);
  const bob = createPeer(wasm, bobProvider);
  const id = groupId('founding-clear');
  const group = wasm.PhaseB1Group.create_new(aliceProvider, alice.identity, id, alice.proof);
  group.propose_and_commit_add(aliceProvider, alice.identity, bob.keyPackage);
  const pendingSnapshot = aliceProvider.serialize_state();

  const clearProvider = restoreProvider(wasm, pendingSnapshot);
  const clearGroup = loadGroup(wasm, clearProvider, id, alice);
  clearGroup.clear_pending_commit(clearProvider, 0n);
  const clearedSnapshot = clearProvider.serialize_state();
  const recoveredProvider = restoreProvider(wasm, clearedSnapshot);
  const recoveredIdentity = loadIdentity(wasm, recoveredProvider, alice);
  const recoveredGroup = loadGroup(wasm, recoveredProvider, id, alice);
  check(!recoveredGroup.has_pending_commit(recoveredProvider), 'founding clear persists across a second restore');
  check(recoveredGroup.epoch() === 0n && recoveredGroup.member_count() === 1, 'founding clear preserves epoch and membership');
  const fresh = recoveredGroup.propose_and_commit_add(recoveredProvider, recoveredIdentity, bob.keyPackage);
  recoveredGroup.confirm_pending_add(recoveredProvider, fresh);
  const bobGroup = joinFromPending(wasm, bobProvider, fresh, recoveredGroup);
  assertLiveness(
    { group: recoveredGroup, identity: recoveredIdentity, provider: recoveredProvider },
    { group: bobGroup, identity: bob.identity, provider: bobProvider },
    'founding clear fresh Add',
  );
  console.log('PASS FOUNDING_ADD_CLEAR');
}

function nonFoundingAddMerge(wasm) {
  const stable = setupStablePair(wasm, 'nonfounding-merge');
  const charlieProvider = new wasm.Provider();
  const charlie = createPeer(wasm, charlieProvider);
  const pending = stable.alice.group.propose_and_commit_add(
    stable.alice.provider,
    stable.alice.identity,
    charlie.keyPackage,
  );
  const commit = pending.commit();
  const snapshot = stable.alice.provider.serialize_state();
  const recoveredProvider = restoreProvider(wasm, snapshot);
  const recoveredIdentity = loadIdentity(wasm, recoveredProvider, stable.alice);
  const recoveredGroup = loadGroup(wasm, recoveredProvider, stable.groupId, stable.alice);
  recoveredGroup.confirm_pending_commit(recoveredProvider, 1n);
  const staged = stable.bob.group.stage_inbound_commit(stable.bob.provider, commit);
  stable.bob.group.merge_staged_commit(stable.bob.provider, staged);
  check(recoveredGroup.epoch() === 2n && recoveredGroup.member_count() === 3, 'non-founding recovery merge advances epoch 1 to 2');
  assertLiveness(
    { group: recoveredGroup, identity: recoveredIdentity, provider: recoveredProvider },
    stable.bob,
    'non-founding merge',
  );
  console.log('PASS NONFOUNDING_ADD_MERGE');
}

function nonFoundingAddClear(wasm) {
  const stable = setupStablePair(wasm, 'nonfounding-clear');
  const charlieProvider = new wasm.Provider();
  const charlie = createPeer(wasm, charlieProvider);
  stable.alice.group.propose_and_commit_add(
    stable.alice.provider,
    stable.alice.identity,
    charlie.keyPackage,
  );
  const pendingSnapshot = stable.alice.provider.serialize_state();
  const clearProvider = restoreProvider(wasm, pendingSnapshot);
  const clearGroup = loadGroup(wasm, clearProvider, stable.groupId, stable.alice);
  clearGroup.clear_pending_commit(clearProvider, 1n);
  const clearedSnapshot = clearProvider.serialize_state();
  const recoveredProvider = restoreProvider(wasm, clearedSnapshot);
  const recoveredIdentity = loadIdentity(wasm, recoveredProvider, stable.alice);
  const recoveredGroup = loadGroup(wasm, recoveredProvider, stable.groupId, stable.alice);
  check(!recoveredGroup.has_pending_commit(recoveredProvider), 'non-founding clear persists across a second restore');
  check(recoveredGroup.epoch() === 1n && recoveredGroup.member_count() === 2, 'non-founding clear preserves the stable pair');
  assertLiveness(
    { group: recoveredGroup, identity: recoveredIdentity, provider: recoveredProvider },
    stable.bob,
    'non-founding clear',
  );
  console.log('PASS NONFOUNDING_ADD_CLEAR');
}

function inboundRestageBranches(wasm) {
  const stable = setupStablePair(wasm, 'inbound-restage');
  const charlieProvider = new wasm.Provider();
  const charlie = createPeer(wasm, charlieProvider);
  const aliceStableSnapshot = stable.alice.provider.serialize_state();
  const pending = stable.bob.group.propose_and_commit_add(
    stable.bob.provider,
    stable.bob.identity,
    charlie.keyPackage,
  );
  const exactCommit = Uint8Array.from(pending.commit());
  const bobPendingSnapshot = stable.bob.provider.serialize_state();

  const mergeAliceProvider = restoreProvider(wasm, aliceStableSnapshot);
  const mergeAliceIdentity = loadIdentity(wasm, mergeAliceProvider, stable.alice);
  const mergeAliceGroup = loadGroup(wasm, mergeAliceProvider, stable.groupId, stable.alice);
  const mergeStaged = mergeAliceGroup.stage_inbound_commit(mergeAliceProvider, exactCommit);
  mergeAliceGroup.merge_staged_commit(mergeAliceProvider, mergeStaged);
  const mergeBobProvider = restoreProvider(wasm, bobPendingSnapshot);
  const mergeBobIdentity = loadIdentity(wasm, mergeBobProvider, stable.bob);
  const mergeBobGroup = loadGroup(wasm, mergeBobProvider, stable.groupId, stable.bob);
  mergeBobGroup.confirm_pending_commit(mergeBobProvider, 1n);
  check(mergeAliceGroup.epoch() === 2n && mergeAliceGroup.member_count() === 3, 'exact inbound bytes re-stage and merge after restore');
  assertLiveness(
    { group: mergeAliceGroup, identity: mergeAliceIdentity, provider: mergeAliceProvider },
    { group: mergeBobGroup, identity: mergeBobIdentity, provider: mergeBobProvider },
    'inbound re-stage merge',
  );
  console.log('PASS INBOUND_RESTAGE_MERGE');

  const discardAliceProvider = restoreProvider(wasm, aliceStableSnapshot);
  const discardAliceIdentity = loadIdentity(wasm, discardAliceProvider, stable.alice);
  const discardAliceGroup = loadGroup(wasm, discardAliceProvider, stable.groupId, stable.alice);
  const discardStaged = discardAliceGroup.stage_inbound_commit(discardAliceProvider, exactCommit);
  discardAliceGroup.discard_staged_commit(discardAliceProvider, discardStaged);
  const clearBobProvider = restoreProvider(wasm, bobPendingSnapshot);
  const clearBobIdentity = loadIdentity(wasm, clearBobProvider, stable.bob);
  const clearBobGroup = loadGroup(wasm, clearBobProvider, stable.groupId, stable.bob);
  clearBobGroup.clear_pending_commit(clearBobProvider, 1n);
  check(discardAliceGroup.epoch() === 1n && discardAliceGroup.member_count() === 2, 'exact inbound bytes re-stage and discard without state advance');
  assertLiveness(
    { group: discardAliceGroup, identity: discardAliceIdentity, provider: discardAliceProvider },
    { group: clearBobGroup, identity: clearBobIdentity, provider: clearBobProvider },
    'inbound re-stage discard',
  );
  console.log('PASS INBOUND_RESTAGE_DISCARD');
}

const committed = await loadWasm(process.env.B2_COMMITTED_WASM_DIR, 'committed');
const candidate = await loadWasm(process.env.B2_WASM_DIR, 'candidate');
const committedDts = readFileSync(
  join(process.env.B2_COMMITTED_WASM_DIR, 'openmls_wasm.d.ts'),
  'utf8',
);
const candidateDts = readFileSync(join(process.env.B2_WASM_DIR, 'openmls_wasm.d.ts'), 'utf8');
const candidateJs = readFileSync(join(process.env.B2_WASM_DIR, 'openmls_wasm.js'), 'utf8');

foundingAddMerge(candidate);
foundingAddClear(candidate);
nonFoundingAddMerge(candidate);
nonFoundingAddClear(candidate);
inboundRestageBranches(candidate);
comparePublicSurface(committed, candidate, committedDts, candidateDts, candidateJs);

console.log('Phase B2.1 recovery probe completed. This is capability evidence, not a Marmot interoperability claim.');
