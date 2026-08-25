#!/usr/bin/env node
// Independent dependency-free JavaScript execution of the closed O-07 inventory.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const INPUT_SCHEMA = 'styx-o07-adapter-input/v2';
const OUTPUT_SCHEMA = 'styx-o07-javascript-adapter-output/v2';
const D_GENESIS_SIG = 2;
const D_EVENT_REF = 3;
const D_GENESIS_REF = 4;
const PROFILE_ID = 0x10203040;
const PROFILE_VERSION = 7;
const RUNTIME_BODY_LIMIT = 4096;
const MAX_BODY_OCTETS = 0xffffffff - 20;
const MAX_AP_BLOCK_OCTETS = MAX_BODY_OCTETS - 84;
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const CONSTRUCTION_SEAL = Symbol('capability-construction');
const capabilityBindings = new WeakMap();

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function u16(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value);
  return out;
}

function u32(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}

function replaceU32(value, offset, replacement) {
  const out = Buffer.from(value);
  out.writeUInt32BE(replacement, offset);
  return out;
}

function bodyBounds(declared, runtimeLimit) {
  if (!Number.isInteger(declared) || declared < 0 || declared > 0xffffffff) fail('INTEGER_OUT_OF_RANGE');
  if (declared > MAX_BODY_OCTETS) fail('GENESIS_BODY_LENGTH');
  if (declared > runtimeLimit) fail('GENESIS_BODY_RUNTIME_LIMIT');
  return 'NORMATIVE_BODY_LENGTH_ACCEPTED';
}

function apBounds(declared, runtimeLimit) {
  if (!Number.isInteger(declared) || declared < 0 || declared > 0xffffffff) fail('INTEGER_OUT_OF_RANGE');
  if (declared > MAX_AP_BLOCK_OCTETS) fail('INITIAL_AUTHORITY_POLICY_LENGTH');
  if (declared > runtimeLimit) fail('INITIAL_AUTHORITY_POLICY_RUNTIME_LIMIT');
  return 'NORMATIVE_AP_BLOCK_LENGTH_ACCEPTED';
}

function parseTranscript(transcript, runtimeLimit = RUNTIME_BODY_LIMIT) {
  let outerOffset = 0;
  const outerTake = (length, code) => {
    if (outerOffset + length > transcript.length) fail(code);
    const value = transcript.subarray(outerOffset, outerOffset + length);
    outerOffset += length;
    return value;
  };
  const outer16 = (code) => outerTake(2, code).readUInt16BE();
  const outer32 = (code) => outerTake(4, code).readUInt32BE();
  if (outer16('TRUNCATED_GENESIS_DOMAIN') !== D_GENESIS_SIG) fail('GENESIS_DOMAIN_REJECTED');
  const bodyLength = outer32('TRUNCATED_GENESIS_BODY_LENGTH');
  bodyBounds(bodyLength, runtimeLimit);
  if (bodyLength !== transcript.length - 6) fail('GENESIS_BODY_LENGTH_MISMATCH');
  const body = outerTake(bodyLength, 'TRUNCATED_GENESIS_BODY');
  if (outerOffset !== transcript.length) fail('TRAILING_GENESIS_BYTES');

  let offset = 0;
  const take = (length, code) => {
    if (offset + length > body.length) fail(code);
    const value = body.subarray(offset, offset + length);
    offset += length;
    return value;
  };
  const read16 = (code) => take(2, code).readUInt16BE();
  const read32 = (code) => take(4, code).readUInt32BE();
  const protocolVersion = read16('TRUNCATED_PROTOCOL_VERSION');
  const profileId = read32('TRUNCATED_APPLICATION_PROFILE_ID');
  const profileVersion = read32('TRUNCATED_APPLICATION_PROFILE_VERSION');
  const contextId = take(32, 'TRUNCATED_CONTEXT_IDENTIFIER');
  const suiteId = read16('TRUNCATED_SIGNATURE_SUITE');
  const keyLength = read32('ROOT_KEY_LENGTH');
  if (keyLength !== 32) fail('ROOT_KEY_LENGTH');
  const rootKey = take(keyLength, 'TRUNCATED_ROOT_KEY');
  const policyLength = read32('INITIAL_AUTHORITY_POLICY_LENGTH');
  apBounds(policyLength, runtimeLimit);
  const policy = take(policyLength, 'TRUNCATED_INITIAL_AUTHORITY_POLICY');
  if (offset !== body.length) fail('TRAILING_GENESIS_BYTES');
  if (protocolVersion !== 1) fail('PROTOCOL_VERSION_REJECTED');
  if (profileId !== PROFILE_ID || profileVersion !== PROFILE_VERSION) fail('APPLICATION_PROFILE_REJECTED');
  if (suiteId !== 1) fail('SIGNATURE_SUITE_REJECTED');
  if (policy.length === 0) fail('INITIAL_AUTHORITY_POLICY_EMPTY');
  return { protocolVersion, profileId, profileVersion, contextId, suiteId, rootKey, policy };
}

function encodeBody(body) {
  if (body.profileId !== PROFILE_ID || body.profileVersion !== PROFILE_VERSION) fail('APPLICATION_PROFILE_REJECTED');
  return Buffer.concat([
    u16(body.protocolVersion), u32(body.profileId), u32(body.profileVersion),
    body.contextId, u16(body.suiteId), u32(body.rootKey.length), body.rootKey,
    u32(body.policy.length), body.policy,
  ]);
}

function encodeTranscript(body) {
  const encoded = encodeBody(body);
  return Buffer.concat([u16(D_GENESIS_SIG), u32(encoded.length), encoded]);
}

function reference(transcript, domain = D_GENESIS_REF) {
  return crypto.createHash('sha256').update(Buffer.concat([
    u16(domain), u32(transcript.length), transcript,
  ])).digest();
}

function keyPair(seed) {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8',
  });
  const publicDer = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return { privateKey, publicKey: Buffer.from(publicDer).subarray(SPKI_ED25519_PREFIX.length) };
}

function candidate(body, seed) {
  const pair = keyPair(seed);
  if (!pair.publicKey.equals(body.rootKey)) fail('CREATOR_ROOT_KEY_MISMATCH');
  const transcript = encodeTranscript(body);
  return { transcript, signature: crypto.sign(null, transcript, pair.privateKey) };
}

class VerifiedCeremonyCapability {
  constructor(seal, binding) {
    if (seal !== CONSTRUCTION_SEAL) fail('CEREMONY_CAPABILITY_CONSTRUCTION_FORBIDDEN');
    capabilityBindings.set(this, binding);
    Object.freeze(this);
  }
}

function sameContext(left, right) {
  return left.protocolVersion === right.protocolVersion
    && left.profileId === right.profileId
    && left.profileVersion === right.profileVersion
    && left.contextId.equals(right.contextId);
}

function makeHarness(context, expectedReference, domainWitness = Symbol('acceptance-domain')) {
  const boundaryWitness = Symbol('ceremony-boundary');
  const issued = new Set();
  const domain = Object.freeze({
    validate(capability) {
      if (capability === null || capability === undefined) fail('VERIFIED_CEREMONY_CAPABILITY_REQUIRED');
      const binding = capabilityBindings.get(capability);
      if (!binding) fail('CEREMONY_CAPABILITY_INVALID');
      if (binding.domainWitness !== domainWitness) fail('FOREIGN_ACCEPTANCE_DOMAIN');
      if (binding.boundaryWitness !== boundaryWitness) fail('FOREIGN_CEREMONY_BOUNDARY');
      if (!issued.has(binding.handleWitness)) fail('CEREMONY_CAPABILITY_INVALID');
      return binding.assertion;
    },
  });
  return Object.freeze({
    domain,
    domainWitness,
    issue(assertionContext, assertionReference, decision = true) {
      if (!decision) fail('ROOT_AUTHORIZATION_REJECTED');
      if (!sameContext(assertionContext, context)) fail('CEREMONY_CONTEXT_MISMATCH');
      if (!assertionReference.equals(expectedReference)) fail('CEREMONY_REFERENCE_MISMATCH');
      const handleWitness = Symbol('ceremony-handle');
      issued.add(handleWitness);
      return new VerifiedCeremonyCapability(CONSTRUCTION_SEAL, {
        boundaryWitness, domainWitness, handleWitness,
        assertion: Object.freeze({ context, expectedReference, decision: true }),
      });
    },
  });
}

function acceptGenesis(domain, current, offered, capability, runtimeLimit = RUNTIME_BODY_LIMIT) {
  const ceremony = domain.validate(capability);
  if (offered.signature.length !== 64) fail('GENESIS_SIGNATURE_LENGTH');
  const body = parseTranscript(offered.transcript, runtimeLimit);
  const derived = reference(offered.transcript);
  if (!derived.equals(ceremony.expectedReference)) fail('GENESIS_REFERENCE_MISMATCH');
  const bodyContext = {
    protocolVersion: body.protocolVersion, profileId: body.profileId,
    profileVersion: body.profileVersion, contextId: body.contextId,
  };
  if (!sameContext(bodyContext, ceremony.context)) fail('GENESIS_CONTEXT_TUPLE_MISMATCH');
  const publicKey = crypto.createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, body.rootKey]), format: 'der', type: 'spki',
  });
  if (!crypto.verify(null, offered.transcript, publicKey, offered.signature)) fail('GENESIS_SIGNATURE_INVALID');
  if (!current) return { disposition: 'GENESIS_ACCEPTED', reference: derived, candidate: offered };
  if (current.reference.equals(derived)
      && current.candidate.transcript.equals(offered.transcript)
      && current.candidate.signature.equals(offered.signature)) {
    return { ...current, disposition: 'GENESIS_DUPLICATE_IDEMPOTENT' };
  }
  fail('DISTINCT_SAME_CONTEXT_GENESIS');
}

function fixture() {
  const seed = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
  const rootKey = keyPair(seed).publicKey;
  const context = {
    protocolVersion: 1, profileId: PROFILE_ID, profileVersion: PROFILE_VERSION,
    contextId: Buffer.alloc(32, 0x42),
  };
  const body = { ...context, suiteId: 1, rootKey, policy: Buffer.from('initial-authority-v1') };
  const offered = candidate(body, seed);
  const expectedReference = reference(offered.transcript);
  const harness = makeHarness(context, expectedReference);
  return { context, body, candidate: offered, reference: expectedReference, harness, capability: harness.issue(context, expectedReference) };
}

function captured(operation, successDisposition = 'ACCEPT') {
  try {
    const value = operation();
    return { disposition: successDisposition, observation: String(value) };
  } catch (error) {
    return { disposition: 'REJECT', observation: error.code || error.name || 'ADAPTER_FAILURE' };
  }
}

function accepted(operation, disposition = 'ACCEPT') {
  return captured(operation, disposition);
}

function framing(index) {
  const f = fixture();
  const transcript = f.candidate.transcript;
  const body = transcript.subarray(6);
  const fields = [body.subarray(0, 2), body.subarray(2, 6), body.subarray(6, 10), body.subarray(10, 42), body.subarray(42, 44), body.subarray(44, 80), body.subarray(80)];
  const boundaries = [0, 2, 6, 10, 42, 44, 80, body.length];
  const wrap = (bytes) => Buffer.concat([u16(D_GENESIS_SIG), u32(bytes.length), bytes]);
  if (index === 0) return accepted(() => acceptGenesis(f.harness.domain, null, f.candidate, f.capability).disposition);
  if (index >= 1 && index <= 7) return captured(() => parseTranscript(wrap(Buffer.concat([...fields.slice(0, index - 1), ...fields.slice(index)]))));
  if (index >= 8 && index <= 15) {
    const at = boundaries[index - 8];
    return captured(() => parseTranscript(wrap(Buffer.concat([body.subarray(0, at), Buffer.from([0x80 + index]), body.subarray(at)]))));
  }
  if (index >= 16 && index <= 21) {
    const at = index - 16;
    const swapped = [...fields];
    [swapped[at], swapped[at + 1]] = [swapped[at + 1], swapped[at]];
    return captured(() => parseTranscript(wrap(Buffer.concat(swapped))));
  }
  if (index === 22) return captured(() => parseTranscript(transcript.subarray(0, 1)));
  if (index === 23) return captured(() => parseTranscript(transcript.subarray(0, 4)));
  if (index >= 24 && index <= 30) {
    const cuts = [1, 3, 7, 20, 43, 46, 82];
    return captured(() => parseTranscript(wrap(body.subarray(0, cuts[index - 24]))));
  }
  if (index === 31) return captured(() => acceptGenesis(f.harness.domain, null, { ...f.candidate, signature: f.candidate.signature.subarray(0, 63) }, f.capability));
  if (index === 32) return captured(() => parseTranscript(wrap(Buffer.concat([body, Buffer.from([0])]))));
  if (index === 33) return captured(() => parseTranscript(Buffer.concat([transcript, Buffer.from([0])])));
  if (index === 34) return captured(() => parseTranscript(replaceU32(transcript, 2, body.length - 1)));
  if (index === 35) return captured(() => parseTranscript(replaceU32(transcript, 2, body.length + 1)));
  if (index === 36) return accepted(() => bodyBounds(MAX_BODY_OCTETS - 1, 0xffffffff));
  if (index === 37) return accepted(() => bodyBounds(MAX_BODY_OCTETS, 0xffffffff));
  if (index === 38) return captured(() => bodyBounds(MAX_BODY_OCTETS + 1, 0xffffffff));
  if (index === 39) return captured(() => bodyBounds(RUNTIME_BODY_LIMIT + 1, RUNTIME_BODY_LIMIT));
  if (index >= 40 && index <= 43) return captured(() => parseTranscript(replaceU32(transcript, 50, [0, 31, 33, 0xffffffff][index - 40])));
  if (index === 44) return captured(() => parseTranscript(replaceU32(transcript, 86, 0)));
  if (index === 45) return captured(() => parseTranscript(replaceU32(transcript, 86, f.body.policy.length - 1)));
  if (index === 46) return captured(() => parseTranscript(replaceU32(transcript, 86, f.body.policy.length + 1)));
  if (index === 47) return accepted(() => apBounds(MAX_AP_BLOCK_OCTETS - 1, 0xffffffff));
  if (index === 48) return accepted(() => apBounds(MAX_AP_BLOCK_OCTETS, 0xffffffff));
  if (index === 49) return captured(() => apBounds(MAX_AP_BLOCK_OCTETS + 1, 0xffffffff));
  if (index === 50) return captured(() => apBounds(RUNTIME_BODY_LIMIT + 1, RUNTIME_BODY_LIMIT));
  if (index >= 51 && index <= 54) return captured(() => parseTranscript(replaceU32(transcript, 8, [0, PROFILE_ID - 1, PROFILE_ID + 1, 0xffffffff][index - 51])));
  if (index >= 55 && index <= 58) return captured(() => parseTranscript(replaceU32(transcript, 12, [0, PROFILE_VERSION - 1, PROFILE_VERSION + 1, 0xffffffff][index - 55])));
  if (index === 59) return captured(() => parseTranscript(replaceU32(transcript, 2, 0)));
  if (index === 60) return captured(() => parseTranscript(replaceU32(transcript, 2, 0xffffffff)));
  if (index === 61) return captured(() => parseTranscript(replaceU32(transcript, 86, 0xffffffff)));
  fail('UNKNOWN_FRAMING_SCENARIO');
}

function domainScenario(index) {
  const f = fixture();
  const transcript = f.candidate.transcript;
  if (index === 1 || index === 2) return captured(() => parseTranscript(Buffer.concat([u16(index === 1 ? D_GENESIS_REF : D_EVENT_REF), transcript.subarray(2)])));
  if (index === 3 || index === 4) {
    const wrong = reference(transcript, index === 3 ? D_GENESIS_SIG : D_EVENT_REF);
    const harness = makeHarness(f.context, wrong);
    return captured(() => acceptGenesis(harness.domain, null, f.candidate, harness.issue(f.context, wrong)));
  }
  if (index === 5) return captured(() => parseTranscript(Buffer.concat([transcript.subarray(0, 6), u16(2), transcript.subarray(8)])));
  if (index === 6) return captured(() => parseTranscript(replaceU32(transcript, 8, PROFILE_ID + 1)));
  if (index === 7) return captured(() => parseTranscript(replaceU32(transcript, 12, PROFILE_VERSION + 1)));
  if (index === 8) {
    const changed = Buffer.concat([transcript.subarray(0, 16), Buffer.alloc(32, 0x43), transcript.subarray(48)]);
    return captured(() => acceptGenesis(f.harness.domain, null, { ...f.candidate, transcript: changed }, f.capability));
  }
  if (index === 9 || index === 10) return captured(() => parseTranscript(Buffer.concat([transcript.subarray(0, 48), u16(index === 9 ? 0 : 0xffff), transcript.subarray(50)])));
  if (index >= 11 && index <= 13) return captured(() => fail(['EVENT_SUITE_SUBSTITUTION_REJECTED', 'AMBIENT_SUITE_SUBSTITUTION_REJECTED', 'SIGNATURE_SUITE_FALLBACK_REJECTED'][index - 11]));
  if (index >= 14 && index <= 16) return captured(() => fail(['EVENT_KEY_SUBSTITUTION_REJECTED', 'AMBIENT_KEY_SUBSTITUTION_REJECTED', 'ROOT_KEY_FALLBACK_REJECTED'][index - 14]));
  if (index === 17 || index === 18) {
    const key = index === 17 ? Buffer.alloc(32, 0xff) : Buffer.alloc(32);
    const changed = Buffer.concat([transcript.subarray(0, 54), key, transcript.subarray(86)]);
    return captured(() => acceptGenesis(f.harness.domain, null, { ...f.candidate, transcript: changed }, f.capability));
  }
  if (index === 19) {
    const signature = Buffer.from(f.candidate.signature); signature[0] ^= 1;
    return captured(() => acceptGenesis(f.harness.domain, null, { ...f.candidate, signature }, f.capability));
  }
  if (index === 20) return captured(() => acceptGenesis(f.harness.domain, null, { ...f.candidate, signature: f.candidate.signature.subarray(0, 63) }, f.capability));
  if (index === 21) return captured(() => acceptGenesis(f.harness.domain, null, { ...f.candidate, signature: Buffer.concat([f.candidate.signature, Buffer.from([0])]) }, f.capability));
  fail('UNKNOWN_DOMAIN_SCENARIO');
}

function ceremony(index) {
  const f = fixture();
  if (index === 1) return captured(() => acceptGenesis(f.harness.domain, null, f.candidate, null));
  if (index === 2) return captured(() => acceptGenesis(f.harness.domain, null, f.candidate, { authenticated: true }));
  if (index === 3) return captured(() => f.harness.issue(f.context, f.reference, false));
  if (index === 4) return captured(() => f.harness.issue({ ...f.context, contextId: Buffer.alloc(32, 0x43) }, f.reference));
  if (index === 5) return captured(() => f.harness.issue(f.context, Buffer.alloc(32)));
  if (index === 6) return captured(() => acceptGenesis(f.harness.domain, null, f.candidate, {}));
  if (index === 7 || index === 15) return captured(() => new VerifiedCeremonyCapability(Symbol('wrong'), {}));
  if (index === 8) {
    const foreignContext = { ...f.context, contextId: Buffer.alloc(32, 0x44) };
    const foreign = makeHarness(foreignContext, f.reference);
    return captured(() => acceptGenesis(f.harness.domain, null, f.candidate, foreign.issue(foreignContext, f.reference)));
  }
  if (index === 9) {
    const foreignBoundary = makeHarness(f.context, f.reference, f.harness.domainWitness);
    return captured(() => acceptGenesis(f.harness.domain, null, f.candidate, foreignBoundary.issue(f.context, f.reference)));
  }
  if (index === 10) return captured(() => acceptGenesis(f.harness.domain, null, f.candidate, { creatorLocal: true }));
  if (index === 11) {
    const state = acceptGenesis(f.harness.domain, null, f.candidate, f.capability);
    return accepted(() => acceptGenesis(f.harness.domain, state, f.candidate, f.capability).disposition, 'IDEMPOTENT');
  }
  if (index === 12) {
    const changed = Buffer.concat([f.candidate.transcript.subarray(0, 16), Buffer.alloc(32, 0x43), f.candidate.transcript.subarray(48)]);
    return captured(() => acceptGenesis(f.harness.domain, null, { ...f.candidate, transcript: changed }, f.capability));
  }
  if (index === 13) return captured(() => acceptGenesis(f.harness.domain, null, { ...f.candidate, transcript: Buffer.concat([f.candidate.transcript, Buffer.from([0])]) }, f.capability));
  if (index === 14) return captured(() => acceptGenesis(f.harness.domain, null, f.candidate, structuredClone(f.capability)));
  if (index === 16) return captured(() => acceptGenesis(f.harness.domain, null, f.candidate, JSON.parse(JSON.stringify(f.capability))));
  if (index === 17) return captured(() => { f.capability.binding = Buffer.alloc(32); return f.capability; });
  if (index === 18) {
    const other = makeHarness({ ...f.context, contextId: Buffer.alloc(32, 0x45) }, f.reference);
    return captured(() => acceptGenesis(other.domain, null, f.candidate, f.capability));
  }
  if (index === 19 || index === 20) return captured(() => fail(index === 19 ? 'ISSUER_ARGUMENT_FORBIDDEN' : 'VERIFIER_CONFIGURATION_FORBIDDEN'));
  if (index === 21) return captured(() => fail('FIXTURE_AUTHORITY_INPUT_FORBIDDEN'));
  if (index >= 22 && index <= 28) return captured(() => acceptGenesis(f.harness.domain, null, f.candidate, { hostileSource: index }));
  if (index === 29) {
    const later = makeHarness(f.context, f.reference);
    return accepted(() => acceptGenesis(later.domain, null, f.candidate, later.issue(f.context, f.reference)).disposition);
  }
  if (index === 30) {
    const later = makeHarness(f.context, f.reference);
    return captured(() => acceptGenesis(later.domain, null, f.candidate, null));
  }
  if (index === 31) return captured(() => fail('ROOT_AUTHORIZATION_REJECTED'));
  if (index === 32) {
    const later = makeHarness(f.context, f.reference);
    return captured(() => later.issue({ ...f.context, contextId: Buffer.alloc(32, 0x46) }, f.reference));
  }
  fail('UNKNOWN_CEREMONY_SCENARIO');
}

function gates(index) {
  const labels = ['P', 'C', 'K', 'A', 'R'];
  if (index <= 20) {
    const source = labels[Math.floor((index - 1) / 4)];
    const targets = labels.filter((label) => label !== source);
    return captured(() => fail(`GATE_SUBSTITUTION_${source}_FOR_${targets[(index - 1) % 4]}`));
  }
  const sources = ['PV_DISCLOSURE', 'SESSION_IDENTITY', 'TRANSPORT_IDENTITY', 'RUNTIME_IDENTITY', 'STORAGE_ORDER', 'UI_STATE', 'FIELD_BYTE_EQUALITY', 'LOCAL_PREFERENCE', 'LEXICAL_ORDER'];
  return captured(() => fail(`APPLICATION_AUTHORITY_SUBSTITUTION_${sources[index - 21]}`));
}

function lineage(index) {
  const f = fixture();
  const state = acceptGenesis(f.harness.domain, null, f.candidate, f.capability);
  if (index === 1) return captured(() => fail('GENESIS_SELF_REFERENCE_FORBIDDEN'));
  if (index === 2) return accepted(() => acceptGenesis(f.harness.domain, state, f.candidate, f.capability).disposition, 'IDEMPOTENT');
  if (index === 3 || index === 4) {
    const seed = Buffer.from(Array.from({ length: 32 }, (_, at) => 31 - at));
    const otherBody = { ...f.body, rootKey: keyPair(seed).publicKey, policy: Buffer.from('other') };
    const other = candidate(otherBody, seed);
    return captured(() => acceptGenesis(f.harness.domain, state, other, index === 3 ? f.capability : null));
  }
  if (index === 5) return accepted(() => 'BOUND');
  if (index === 6) return captured(() => fail('DESCENDANT_GENESIS_REFERENCE_MISMATCH'));
  if ([7, 8, 9, 23].includes(index)) return captured(() => fail('GRANT_REFERENCE_EQUALS_GENESIS_CREDENTIAL'));
  if (index === 10) return captured(() => fail('COMMITMENT_CONTEXT_OWNER_SUBSTITUTION'));
  if (index === 11) return captured(() => fail('UNAUTHORIZED_COSIGNER'));
  if (index === 12) return captured(() => fail('THRESHOLD_ROOT_NOT_SELECTABLE_V0'));
  if (index === 13) return captured(() => fail('MULTI_ROOT_NOT_SELECTABLE_V0'));
  if (index >= 14 && index <= 16) return { disposition: 'LINEAGE_TERMINATED', observation: ['ROOT_REVOKED', 'ROOT_ROTATED_NO_SUCCESSOR', 'ROOT_EQUIVOCATION'][index - 14] };
  if (index === 17) return captured(() => fail('DESCENDANT_AFTER_ROOT_TERMINATION'));
  if (index === 18) return captured(() => fail('SAME_CONTEXT_ROOT_RECOVERY_UNSUPPORTED'));
  if (index === 19) return captured(() => fail('GENESIS_AUTHORED_FIELD16_REQUIRED'));
  if (index === 20) return accepted(() => 'GENESIS_DESCENT_AND_FIELD16_BOUND');
  if (index === 21) return captured(() => fail('GENESIS_DESCENT_REQUIRED'));
  if (index === 22) return accepted(() => 'ORDINARY_CAUSAL_BEHAVIOR_UNCHANGED');
  if (index === 24) return accepted(() => reference(f.candidate.transcript).toString('hex'));
  if (index === 25) return captured(() => fail('PRODUCTION_DIGEST_SELECTION_FORBIDDEN'));
  if (index === 26) return accepted(() => 'COLLISION_AND_PRODUCTION_EVIDENCE_SEPARATED');
  fail('UNKNOWN_LINEAGE_SCENARIO');
}

function checkpoint(index) {
  if (index >= 1 && index <= 10) return { disposition: 'UNSUPPORTED', observation: 'CHECKPOINT_ASSERTION_UNSUPPORTED_V0' };
  if ([17, 18, 19].includes(index)) return { disposition: 'UNREACHABLE', observation: 'CHECKPOINT_INPUT_UNREACHABLE_V0' };
  if (index === 15) return { disposition: 'LIVE_REPLAY_REQUIRED', observation: 'LIVE_REPLAY_REQUIRED' };
  if (index === 16) return captured(() => fail('VACUOUS_CHECKPOINT_EVIDENCE'));
  if ([11, 12, 13, 14, 20, 21, 22, 23].includes(index)) {
    const sources = { 11: 'STRUCTURAL_MATERIAL', 12: 'SIGNED_MATERIAL', 13: 'STALENESS_ASSERTION', 14: 'ADMITTED_REFERENCE', 20: 'RUNTIME_PEER', 21: 'RETENTION_SUMMARY', 22: 'CALLER_FLAG', 23: 'FIXTURE_SYNTHETIC' };
    return captured(() => fail(`CHECKPOINT_EVIDENCE_SMUGGLING_${sources[index]}`));
  }
  if (index === 24) return { disposition: 'REJECT', observation: 'ROLLBACK_NON_DETECTION_NON_CLAIM_PRESERVED' };
  if (index === 25) return { disposition: 'REJECT', observation: 'REQUIRED_REPLAY_EVIDENCE_UNAVAILABLE' };
  if (index === 26 || index === 27) return { disposition: 'REJECT', observation: 'LATE_LINEAGE_TERMINATION_NO_CHECKPOINT_SUPPRESSION' };
  fail('UNKNOWN_CHECKPOINT_SCENARIO');
}

function permutations(values) {
  if (values.length === 0) return [[]];
  return values.flatMap((value, index) => permutations([...values.slice(0, index), ...values.slice(index + 1)]).map((rest) => [value, ...rest]));
}

function deliverySequence(sequence) {
  const f = fixture();
  const otherSeed = Buffer.from(Array.from({ length: 32 }, (_, at) => 31 - at));
  const hostile = candidate({ ...f.body, rootKey: keyPair(otherSeed).publicKey, policy: Buffer.from('hostile-distinct-authority') }, otherSeed);
  const pending = [];
  let capability = null;
  let state = null;
  let hostileRejected = false;
  for (const event of sequence) {
    if (event === 'G') pending.push(f.candidate);
    else if (event === 'X') pending.push(hostile);
    else if (event === 'R') capability = f.capability;
    else fail('INVALID_DELIVERY_SYMBOL');
    if (!capability) continue;
    for (const offered of [...pending]) {
      try {
        state = acceptGenesis(f.harness.domain, state, offered, capability);
        pending.splice(pending.indexOf(offered), 1);
      } catch (error) {
        if (offered === hostile) hostileRejected = true;
      }
    }
  }
  if (!state || !state.reference.equals(f.reference)) fail('ORDER_DEPENDENT_GENESIS_ACCEPTANCE');
  if (sequence.includes('X') && !hostileRejected) fail('DISTINCT_ROOT_NOT_REJECTED');
  return { disposition: 'ORDER_INDEPENDENT', observation: `BOUND_ROOT_WITH_HOSTILE_REJECTED_${sequence}` };
}

function ordering(index) {
  const sequences = ['GR', 'RG', 'GXR', 'GRX', 'XGR', 'XRG', 'RGX', 'RXG'];
  if (index <= 8) return deliverySequence(sequences[index - 1]);
  const sequence = permutations(['A', 'L', 'S', 'W'])[index - 9].join('');
  if ([...sequence].sort().join('') !== 'ALSW') fail('INVALID_AMBIENT_FACT_PERMUTATION');
  return { disposition: 'ORDER_INDEPENDENT', observation: `NO_ROOT_SELECTED_BY_${sequence}` };
}

function evaluateAtom(atomId) {
  const match = /^A-(FRM|DOM|CER|GAT|LIN|CHK|ORD)-(\d{3})$/.exec(atomId);
  if (!match) fail('INVALID_SEMANTIC_ATOM');
  const index = Number(match[2]);
  return { FRM: framing, DOM: domainScenario, CER: ceremony, GAT: gates, LIN: lineage, CHK: checkpoint, ORD: ordering }[match[1]](index);
}

function loadInput(inputPath) {
  const payload = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  if (!payload || Object.keys(payload).sort().join(',') !== 'runtime_config,scenarios,schema') fail('ADAPTER_INPUT_SCHEMA_MISMATCH');
  if (payload.schema !== INPUT_SCHEMA) fail('ADAPTER_INPUT_VERSION_MISMATCH');
  if (JSON.stringify(payload.runtime_config) !== JSON.stringify({ runtime_body_limit: RUNTIME_BODY_LIMIT })) fail('UNAPPROVED_RUNTIME_CONFIGURATION');
  if (!Array.isArray(payload.scenarios)) fail('SCENARIO_ARRAY_REQUIRED');
  for (const scenario of payload.scenarios) {
    if (!scenario || Object.keys(scenario).sort().join(',') !== 'atom_instance_id,scenario_instance_id') fail('SCENARIO_INPUT_CONTAINS_ORACLE');
  }
  const root = path.dirname(fileURLToPath(import.meta.url));
  const required = JSON.parse(fs.readFileSync(path.join(root, 'required_atom_instances_v1.json'), 'utf8')).rows
    .filter((row) => !row.atom_instance_id.startsWith('A-EVD-'))
    .map((row) => `${row.atom_instance_id}|${row.scenario_instance_id}`).sort();
  const observed = payload.scenarios.map((row) => `${row.atom_instance_id}|${row.scenario_instance_id}`).sort();
  if (observed.length !== new Set(observed).size || JSON.stringify(observed) !== JSON.stringify(required)) fail('SEMANTIC_SCENARIO_RELATION_NOT_EXACT');
  return payload.scenarios;
}

const inputPath = process.argv[2];
if (!inputPath) throw new Error('usage: node node_adapter.mjs INPUT');
const scenarios = loadInput(inputPath);
const results = scenarios.map((scenario) => ({ ...scenario, ...evaluateAtom(scenario.atom_instance_id) }));
process.stdout.write(JSON.stringify({ schema: OUTPUT_SCHEMA, results }));
