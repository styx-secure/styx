#!/usr/bin/env node
/** Independent Node.js reader/replayer for the transcript-only C0.3 corpus. */

import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const DOMAINS = Object.freeze({
  application: Buffer.from("53545958000100010000000000000000", "hex"),
  genesisSignature: Buffer.from("53545958000100020000000000000000", "hex"),
  eventReference: Buffer.from("53545958000100030000000000000000", "hex"),
  genesisReference: Buffer.from("53545958000100040000000000000000", "hex"),
  commitment: Buffer.from("53545958000100050000000000000000", "hex"),
  leaf: Buffer.from("53545958000100060000000000000000", "hex"),
  node: Buffer.from("53545958000100070000000000000000", "hex"),
});
const MAX_U32 = 0xffff_ffffn;
const MAX_BODY = MAX_U32 - 20n;
const BASE_SHA = "7768c32d3ddba230bd60f8b5db1b34d4bcb8ec3b";
const O08_LIMITS = Object.freeze({
  AP_TRANSITION_BLOCK_OCTETS: 4096,
  CHUNKS_PER_CONTENT: 64,
  CONTENT_EXACT_OCTETS: 262144,
  FRAMING_OBJECT_OCTETS: 8192,
  GENESIS_BODY_OCTETS: 8192,
  GENESIS_POLICY_OCTETS: 4096,
  PARENTS_PER_EVENT: 8,
  SEQUENCE_VALUE: 4095,
});
const O08_CHUNK_OCTETS = new Set([4096, 16384]);

class ProtocolError extends Error {
  constructor(message, stage = "S3_KERNEL_STRUCTURAL") { super(message); this.stage = stage; }
}
const require = (ok, message) => { if (!ok) throw new ProtocolError(message); };
const hash = (...parts) => createHash("sha256").update(Buffer.concat(parts)).digest();
const hex = value => Buffer.from(value).toString("hex");

function uint(value, width, label) {
  const number = BigInt(value);
  require(number >= 0n && number < (1n << BigInt(width * 8)), `${label}_OUT_OF_RANGE`);
  const output = Buffer.alloc(width);
  for (let index = width - 1, rest = number; index >= 0; index -= 1, rest >>= 8n) {
    output[index] = Number(rest & 0xffn);
  }
  return output;
}

function opaque(value, label) {
  const bytes = Buffer.from(value);
  require(bytes.length <= Number(MAX_U32), `${label}_LENGTH_INVALID`);
  return Buffer.concat([uint(bytes.length, 4, `${label}_length`), bytes]);
}

function fixed(value, width, label) {
  const bytes = Buffer.from(value);
  require(bytes.length === width, `${label}_WIDTH_INVALID`);
  return bytes;
}

function framedHash(domain, body) {
  return hash(domain, uint(body.length, 4, "preimage"), body);
}

class Reader {
  constructor(data) { this.data = Buffer.from(data); this.offset = 0; }
  take(count, label) {
    require(Number.isInteger(count) && count >= 0 && count <= this.data.length - this.offset, `TRUNCATED_${label.toUpperCase()}`);
    const result = this.data.subarray(this.offset, this.offset + count);
    this.offset += count;
    return result;
  }
  integer(width, label) {
    let value = 0n;
    for (const octet of this.take(width, label)) value = (value << 8n) | BigInt(octet);
    require(value <= BigInt(Number.MAX_SAFE_INTEGER), `${label}_UNSAFE_INTEGER`);
    return Number(value);
  }
  opaque(label) { return this.take(this.integer(4, `${label}_length`), label); }
  finish(label) { require(this.offset === this.data.length, `TRAILING_${label.toUpperCase()}`); }
}

function encodeGenesis(fields) {
  const policy = Buffer.from(fields.initialAuthorityPolicyHex, "hex");
  const key = Buffer.from(fields.rootVerificationKeyHex, "hex");
  require(policy.length > 0 && key.length === 32, "GENESIS_FIELDS_INVALID");
  const body = Buffer.concat([
    uint(1, 2, "protocol_version"), uint(fields.applicationProfileId, 4, "profile_id"),
    uint(fields.applicationProfileVersion, 4, "profile_version"),
    fixed(Buffer.from(fields.contextIdentifierHex, "hex"), 32, "context"), uint(1, 2, "signature_suite"),
    opaque(key, "root_key"), opaque(policy, "initial_authority_policy"),
  ]);
  require(BigInt(body.length) <= MAX_BODY, "GENESIS_BODY_LIMIT");
  return Buffer.concat([DOMAINS.genesisSignature, uint(body.length, 4, "body_length"), body]);
}

function parseGenesis(transcript) {
  const outer = new Reader(transcript);
  require(outer.take(16, "domain").equals(DOMAINS.genesisSignature), "WRONG_DOMAIN");
  const bodyLength = outer.integer(4, "body_length");
  require(BigInt(bodyLength) <= MAX_BODY, "GENESIS_BODY_LIMIT");
  require(bodyLength <= O08_LIMITS.GENESIS_BODY_OCTETS, "GENESIS_BODY_OCTETS_LIMIT");
  const body = new Reader(outer.take(bodyLength, "body")); outer.finish("transcript");
  const protocol = body.integer(2, "protocol");
  const profile = body.integer(4, "profile"); const version = body.integer(4, "profile_version");
  const context = body.take(32, "context"); const suite = body.integer(2, "signature_suite");
  const key = body.opaque("root_key"); const policy = body.opaque("initial_authority_policy"); body.finish("body");
  require(policy.length <= O08_LIMITS.GENESIS_POLICY_OCTETS, "GENESIS_POLICY_OCTETS_LIMIT");
  require(protocol === 1 && profile === 1 && version === 1 && suite === 1 && key.length === 32 && policy.length > 0, "GENESIS_FIELDS_INVALID");
  const fields = { applicationProfileId: profile, applicationProfileVersion: version,
    contextIdentifierHex: hex(context), initialAuthorityPolicyHex: hex(policy), rootVerificationKeyHex: hex(key) };
  require(encodeGenesis(fields).equals(transcript), "NONCANONICAL_REENCODING");
  return fields;
}

function encodeEvent(fields) {
  const content = fields.content;
  const parents = fields.causalParents.map(value => Buffer.from(value, "hex"));
  require(parents.every((value, index) => index === 0 || Buffer.compare(parents[index - 1], value) < 0), "CAUSAL_FRONTIER_NONCANONICAL");
  const predecessor = fields.directPredecessorHex === null ? null : Buffer.from(fields.directPredecessorHex, "hex");
  require((fields.authorSequence === 0) !== (predecessor !== null), "SEQUENCE_PREDECESSOR_MISMATCH");
  require(predecessor === null || !parents.some(parent => parent.equals(predecessor)), "PREDECESSOR_DUPLICATED_IN_FRONTIER");
  const contentClass = ({ NONE: 0, REQUIRED: 1, DETACHABLE: 2 })[content.class];
  require(contentClass !== undefined, "CONTENT_CLASS_UNKNOWN");
  let descriptor = Buffer.concat([uint(contentClass, 1, "content_class"), uint(content.exactLength, 8, "content_length")]);
  if (contentClass === 0) {
    require(content.exactLength === 0 && Object.keys(content).sort().join(",") === "class,exactLength", "NONE_DESCRIPTOR_INVALID");
  } else {
    const commitment = Buffer.from(content.commitmentHex, "hex"); const shape = ({ SINGLE: 0, TREE: 1 })[content.shape];
    require(shape !== undefined && commitment.length === 32 && content.contentType > 0, "CONTENT_DESCRIPTOR_INVALID");
    const geometry = content.geometry ?? null;
    require(!(shape === 0 && geometry !== null) && !(shape === 1 && geometry === null), "CONTENT_GEOMETRY_INVALID");
    descriptor = Buffer.concat([descriptor, uint(content.contentType, 4, "content_type"), uint(1, 2, "suite"),
      uint(shape, 1, "shape"), opaque(commitment, "commitment"), uint(geometry === null ? 0 : 1, 1, "geometry_presence")]);
    if (geometry !== null) descriptor = Buffer.concat([descriptor, opaque(Buffer.concat([
      uint(geometry.chunkSize, 4, "chunk_size"), uint(geometry.chunkCount, 8, "chunk_count"),
      uint(geometry.finalChunkLength, 4, "final_chunk_length")]), "geometry")]);
  }
  let roleCode; let tail = Buffer.alloc(0);
  if (fields.eventRole === "ORDINARY") { roleCode = 0; require(fields.tail === undefined, "ORDINARY_TAIL_FORBIDDEN"); }
  else if (fields.eventRole === "REMOVAL") {
    roleCode = 1; require(contentClass === 0, "CONTROL_CONTENT_FORBIDDEN");
    tail = Buffer.concat([fixed(Buffer.from(fields.tail.targetEventReferenceHex, "hex"), 32, "target_event"),
      opaque(fixed(Buffer.from(fields.tail.targetCommitmentHex, "hex"), 32, "target_commitment"), "target_commitment")]);
  } else if (fields.eventRole === "CREDENTIAL") {
    roleCode = 2; require(contentClass === 0, "CONTROL_CONTENT_FORBIDDEN");
    const kind = ({ GRANT: 1, REVOKE: 2, ROTATE: 3, RECOVER: 4, POLICY: 5, CLOSURE: 6 })[fields.tail.kind];
    require(kind !== undefined, "CONTROL_KIND_UNKNOWN"); tail = uint(kind, 1, "control_kind");
    if (kind === 1) tail = Buffer.concat([tail, uint(1, 2, "grantee_suite"), opaque(Buffer.from(fields.tail.granteeVerificationKeyHex, "hex"), "grantee_key")]);
    if (kind === 2) tail = Buffer.concat([tail, fixed(Buffer.from(fields.tail.targetCredentialHex, "hex"), 32, "target_credential")]);
    if (kind === 3) tail = Buffer.concat([tail, fixed(Buffer.from(fields.tail.retiringCredentialHex, "hex"), 32, "retiring_credential"), fixed(Buffer.from(fields.tail.replacementGrantHex, "hex"), 32, "replacement_grant")]);
    if (kind === 4) tail = Buffer.concat([tail, fixed(Buffer.from(fields.tail.retiredCredentialHex, "hex"), 32, "retired_credential"), fixed(Buffer.from(fields.tail.recoveryGrantHex, "hex"), 32, "recovery_grant")]);
  } else throw new ProtocolError("EVENT_ROLE_UNKNOWN");
  const body = Buffer.concat([
    uint(1, 2, "protocol_version"), uint(fields.applicationProfileId, 4, "profile_id"), uint(fields.applicationProfileVersion, 4, "profile_version"),
    fixed(Buffer.from(fields.contextIdentifierHex, "hex"), 32, "context"), uint(1, 2, "object_kind"), uint(roleCode, 1, "event_role"),
    uint(fields.eventTypeId, 4, "event_type"), uint(fields.schemaId, 4, "schema_id"), uint(fields.schemaVersion, 4, "schema_version"),
    opaque(Buffer.from(fields.transitionBlockHex, "hex"), "transition_block"), fixed(Buffer.from(fields.credentialIdentifierHex, "hex"), 32, "credential"),
    uint(fields.authorSequence, 8, "author_sequence"), uint(predecessor === null ? 0 : 1, 1, "predecessor_presence"), predecessor ?? Buffer.alloc(0),
    uint(parents.length, 4, "parent_count"), ...parents, fixed(Buffer.from(fields.genesisReferenceHex, "hex"), 32, "genesis_reference"), descriptor, tail,
  ]);
  require(BigInt(body.length) <= MAX_BODY, "FRAMING_OBJECT_LIMIT");
  return Buffer.concat([DOMAINS.application, uint(body.length, 4, "body_length"), body]);
}

function parseEvent(transcript) {
  const outer = new Reader(transcript); require(outer.take(16, "domain").equals(DOMAINS.application), "WRONG_DOMAIN");
  const bodyLength = outer.integer(4, "body_length"); require(BigInt(bodyLength) <= MAX_BODY, "FRAMING_OBJECT_LIMIT");
  require(bodyLength <= O08_LIMITS.FRAMING_OBJECT_OCTETS, "FRAMING_OBJECT_OCTETS_LIMIT");
  const body = new Reader(outer.take(bodyLength, "body")); outer.finish("transcript");
  const protocol = body.integer(2, "protocol"), profile = body.integer(4, "profile"), version = body.integer(4, "profile_version");
  const context = body.take(32, "context"), objectKind = body.integer(2, "object_kind"), roleCode = body.integer(1, "role");
  const eventType = body.integer(4, "event_type"), schemaId = body.integer(4, "schema"), schemaVersion = body.integer(4, "schema_version");
  const transition = body.opaque("transition_block"); require(transition.length <= O08_LIMITS.AP_TRANSITION_BLOCK_OCTETS, "AP_TRANSITION_BLOCK_OCTETS_LIMIT");
  const credential = body.take(32, "credential"), sequence = body.integer(8, "sequence"); require(sequence <= O08_LIMITS.SEQUENCE_VALUE, "SEQUENCE_VALUE_LIMIT");
  const presence = body.integer(1, "predecessor_presence"); require([0, 1].includes(presence), "PREDECESSOR_PRESENCE_INVALID");
  const predecessor = presence ? body.take(32, "predecessor") : null; const parentCount = body.integer(4, "parent_count");
  if (parentCount > O08_LIMITS.PARENTS_PER_EVENT) throw new ProtocolError("PARENTS_PER_EVENT_LIMIT", "S4_GRAPH_ADMISSION");
  const parents = Array.from({ length: parentCount }, () => body.take(32, "parent"));
  const genesis = body.take(32, "genesis"), contentClass = body.integer(1, "content_class"), exactLength = body.integer(8, "content_length");
  require(exactLength <= O08_LIMITS.CONTENT_EXACT_OCTETS, "CONTENT_EXACT_OCTETS_LIMIT");
  const className = ({ 0: "NONE", 1: "REQUIRED", 2: "DETACHABLE" })[contentClass]; require(className !== undefined, "CONTENT_CLASS_UNKNOWN");
  const content = { class: className, exactLength };
  if (contentClass === 0) require(exactLength === 0, "NONE_DESCRIPTOR_INVALID");
  else {
    const contentType = body.integer(4, "content_type"), suite = body.integer(2, "suite"), shapeCode = body.integer(1, "shape");
    const commitment = body.opaque("commitment"), geometryPresence = body.integer(1, "geometry_presence");
    require(suite === 1 && commitment.length === 32 && [0, 1].includes(geometryPresence), "CONTENT_DESCRIPTOR_INVALID");
    let geometry = null;
    if (geometryPresence) {
      const encoded = new Reader(body.opaque("geometry")); geometry = { chunkSize: encoded.integer(4, "chunk_size"), chunkCount: encoded.integer(8, "chunk_count"), finalChunkLength: encoded.integer(4, "final_chunk_length") }; encoded.finish("geometry");
      require(O08_CHUNK_OCTETS.has(geometry.chunkSize), "CHUNK_OCTETS_LIMIT");
      require(geometry.chunkCount <= O08_LIMITS.CHUNKS_PER_CONTENT, "CHUNKS_PER_CONTENT_LIMIT");
      require(geometry.finalChunkLength > 0 && geometry.finalChunkLength <= geometry.chunkSize, "FINAL_CHUNK_LENGTH_LIMIT");
    }
    const shape = ({ 0: "SINGLE", 1: "TREE" })[shapeCode]; require(shape !== undefined && ((shape === "SINGLE") !== (geometry !== null)), "CONTENT_GEOMETRY_INVALID");
    Object.assign(content, { commitmentHex: hex(commitment), contentType, shape }); if (geometry !== null) content.geometry = geometry;
  }
  const role = ({ 0: "ORDINARY", 1: "REMOVAL", 2: "CREDENTIAL" })[roleCode];
  const fields = { applicationProfileId: profile, applicationProfileVersion: version, authorSequence: sequence, causalParents: parents.map(hex), content,
    contextIdentifierHex: hex(context), credentialIdentifierHex: hex(credential), directPredecessorHex: predecessor ? hex(predecessor) : null,
    eventRole: role, eventTypeId: eventType, genesisReferenceHex: hex(genesis), schemaId, schemaVersion, transitionBlockHex: hex(transition) };
  require(protocol === 1 && profile === 1 && version === 1 && objectKind === 1 && Math.min(eventType, schemaId, schemaVersion) > 0, "UNSUPPORTED_PROFILE_OR_REGISTRY");
  if (role === "REMOVAL") { const target = body.take(32, "target_event"); fields.tail = { targetCommitmentHex: hex(body.opaque("target_commitment")), targetEventReferenceHex: hex(target) }; }
  else if (role === "CREDENTIAL") {
    const kindCode = body.integer(1, "control_kind"), kind = ({ 1: "GRANT", 2: "REVOKE", 3: "ROTATE", 4: "RECOVER", 5: "POLICY", 6: "CLOSURE" })[kindCode];
    require(kind !== undefined, "CONTROL_KIND_UNKNOWN"); const tail = { kind };
    if (kind === "GRANT") { require(body.integer(2, "grantee_suite") === 1, "GRANTEE_SUITE_UNSUPPORTED"); tail.granteeVerificationKeyHex = hex(body.opaque("grantee_key")); }
    if (kind === "REVOKE") tail.targetCredentialHex = hex(body.take(32, "target_credential"));
    if (kind === "ROTATE") { tail.retiringCredentialHex = hex(body.take(32, "retiring_credential")); tail.replacementGrantHex = hex(body.take(32, "replacement_grant")); }
    if (kind === "RECOVER") { tail.retiredCredentialHex = hex(body.take(32, "retired_credential")); tail.recoveryGrantHex = hex(body.take(32, "recovery_grant")); }
    fields.tail = tail;
  } else require(role === "ORDINARY", "EVENT_ROLE_UNKNOWN");
  body.finish("body"); require(encodeEvent(fields).equals(transcript), "NONCANONICAL_REENCODING"); return fields;
}

function commitment(fields, supplied, randomizer, chunkSize) {
  const context = Buffer.from(fields.contextIdentifierHex, "hex"), credential = Buffer.from(fields.credentialIdentifierHex, "hex");
  const contextBytes = Buffer.concat([uint(1, 2, "commitment_suite"), uint(1, 2, "protocol_version"), uint(fields.applicationProfileId, 4, "profile_id"),
    uint(fields.applicationProfileVersion, 4, "profile_version"), fixed(context, 32, "context"), fixed(credential, 32, "credential"), uint(fields.authorSequence, 8, "sequence")]);
  const chunks = chunkSize === undefined ? [supplied] : Array.from({ length: Math.ceil(supplied.length / chunkSize) }, (_, index) => supplied.subarray(index * chunkSize, (index + 1) * chunkSize));
  const leaves = chunks.map((chunk, index) => framedHash(DOMAINS.leaf, Buffer.concat([contextBytes, uint(fields.content.contentType, 4, "content_type"), uint(index, 8, "leaf_ordinal"), uint(chunk.length, 4, "leaf_length"), randomizer, chunk])));
  const tree = values => { if (values.length === 1) return values[0]; const split = 2 ** Math.floor(Math.log2(values.length - 1)); const left = tree(values.slice(0, split)), right = tree(values.slice(split)); return framedHash(DOMAINS.node, Buffer.concat([uint(1, 2, "suite"), uint(values.length, 8, "subtree"), left, right])); };
  const root = tree(leaves), shape = chunkSize === undefined ? 0 : 1;
  const geometry = chunkSize === undefined ? Buffer.alloc(0) : Buffer.concat([uint(chunkSize, 4, "chunk_size"), uint(chunks.length, 8, "chunk_count"), uint(chunks.at(-1).length, 4, "final_chunk_length")]);
  return {
    commitmentHex: hex(framedHash(DOMAINS.commitment, Buffer.concat([contextBytes, uint(fields.content.contentType, 4, "content_type"), uint(supplied.length, 8, "content_length"), uint(shape, 1, "shape"), geometry, root, randomizer]))),
    leafDigests: leaves.map(hex),
    rootHex: hex(root),
  };
}

function ed25519Verify(publicKey, signature, message) {
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return verifySignature(null, message, createPublicKey({ key: Buffer.concat([prefix, publicKey]), format: "der", type: "spki" }), signature);
}

function evaluate(record) {
  const transcript = Buffer.from(record.transcriptHex, "hex"), state = hex(hash(Buffer.from("styx-c03/evaluation/initial")));
  const result = { commitmentVerification: "NOT_PRESENT", externalEffects: [], localOutcome: "APPLIED", postStateDigest: null, preStateDigest: state,
    remoteClass: "APPLIED", signatureVerification: "NOT_EVALUATED", stage: "FINAL_AFTER_S6", transcriptVerification: "VALID" };
  const reject = (outcome, stage, transcriptStatus = "VALID") => Object.assign(result, { localOutcome: outcome, postStateDigest: state, remoteClass: "OPAQUE_REMOTE_FAILURE", stage, transcriptVerification: transcriptStatus });
  let fields, reference, expected;
  try {
    if (record.kind === "GENESIS") { fields = parseGenesis(transcript); reference = hex(framedHash(DOMAINS.genesisReference, transcript)); expected = record.genesisReferenceHex; }
    else if (record.kind === "APPLICATION_EVENT") { fields = parseEvent(transcript); reference = hex(framedHash(DOMAINS.eventReference, transcript)); expected = record.eventReferenceHex; }
    else throw new ProtocolError("OBJECT_KIND_UNKNOWN");
  } catch (error) {
    if (error instanceof ProtocolError && error.message.endsWith("_LIMIT")) return reject("CURRENT_OBJECT_OUT_OF_PROFILE", error.stage, "REJECTED");
    return reject("STRUCTURAL_REJECTION", error instanceof ProtocolError ? error.stage : "S3_KERNEL_STRUCTURAL", "REJECTED");
  }
  if (reference !== expected) return reject("REFERENCE_COLLISION_UNSUPPORTED", "S3_KERNEL_STRUCTURAL");
  try { if (!ed25519Verify(Buffer.from(record.binding.verificationKeyHex, "hex"), Buffer.from(record.signatureHex, "hex"), transcript)) { result.signatureVerification = "REJECTED"; return reject("INVALID", "S3_KERNEL_STRUCTURAL"); } } catch { result.signatureVerification = "REJECTED"; return reject("INVALID", "S3_KERNEL_STRUCTURAL"); }
  result.signatureVerification = "VALID";
  if (record.kind === "APPLICATION_EVENT") {
    if (record.binding.contextIdentifierHex !== fields.contextIdentifierHex || record.binding.credentialIdentifierHex !== fields.credentialIdentifierHex) return reject("CREDENTIAL_BINDING_MISMATCH", "S3_KERNEL_STRUCTURAL");
    if (fields.content.class !== "NONE") {
      if (record.opening === undefined) { result.commitmentVerification = "PENDING"; return reject("OPENING_MISSING", "EVENT_LOCAL"); }
      const supplied = Buffer.from(record.opening.contentHex, "hex"), randomizer = Buffer.from(record.opening.randomizerHex, "hex");
      const computed = commitment(fields, supplied, randomizer, fields.content.geometry?.chunkSize);
      if (supplied.length !== fields.content.exactLength || computed.commitmentHex !== fields.content.commitmentHex) { result.commitmentVerification = "REJECTED"; return reject("COMMITMENT_MISMATCH", "S3_KERNEL_STRUCTURAL"); }
      result.commitmentVerification = "VALID";
    }
  }
  const rules = [["duplicate", "DUPLICATE", "S3_KERNEL_STRUCTURAL"],
    ["missingDependency", "PENDING_ANCESTOR", "S4_GRAPH_ADMISSION"], ["fork", "FORK_EVIDENCE", "EVENT_LOCAL"], ["postRevocation", "POST_REVOCATION", "EVENT_LOCAL"]];
  for (const [key, outcome, stage] of rules) if (record.conditions?.[key]) return reject(outcome, stage);
  if (record.conditions?.authorized === false) return reject("AUTHENTIC_BUT_UNAUTHORIZED", "EVENT_LOCAL");
  result.postStateDigest = hex(hash(Buffer.from(state, "hex"), Buffer.from(reference, "hex"))); return result;
}

function stateDigest(value) { return hex(hash(Buffer.from(value, "utf8"))); }

function computeTrace(scenario, vectors, transitions) {
  const steps = scenario.steps.map((step, index) => {
    const vector = vectors.get(step.inputVectorId); require(vector !== undefined, `unknown vector:${step.inputVectorId}`);
    const executed = step.executed ?? true, observed = executed ? evaluate(vector) : null;
    const preStateDigest = stateDigest(`styx-c03/state/${scenario.id}/${step.preState}`);
    let localOutcome, stage, postState;
    if (!executed) {
      require(scenario.modelId === "flow", `non-flow boundary:${scenario.id}`);
      localOutcome = scenario.id === "scenario-flow-transport_publish" ? "TRANSPORT_PROFILE_REQUIRED" : "SESSION_PROFILE_REQUIRED";
      stage = "BOUNDARY_NOT_EXECUTED"; postState = "UNCHANGED";
    } else if (step.transitionId !== null) {
      const transition = transitions.get(`${scenario.modelId}:${step.transitionId}`);
      require(transition !== undefined && transition.from.includes(step.preState), `transition mismatch:${scenario.id}:${index}`);
      localOutcome = transition.outcome; stage = "MODEL_TRANSITION"; postState = transition.to;
    } else {
      localOutcome = observed.localOutcome; stage = observed.stage;
      postState = observed.preStateDigest === observed.postStateDigest ? "UNCHANGED" : "APPLIED";
    }
    const postStateDigest = postState === "UNCHANGED" || !executed
      ? preStateDigest : stateDigest(`styx-c03/state/${scenario.id}/${postState}`);
    return {
      apAuthorityResult: executed ? "MODEL_SELECTED" : "NOT_EVALUATED",
      causalClassification: step.transitionId ?? "FLOW_OR_COUNTEREXAMPLE",
      commitmentVerification: observed === null ? "NOT_PRESENT" : observed.commitmentVerification,
      dependencyStatus: step.requiredPriorEvidence.length === 0 ? "SATISFIED" : "REQUIRED",
      externalEffects: [], inputDigest: hex(hash(Buffer.from(vector.transcriptHex, "hex"))),
      kBindingAdmission: executed ? "MODEL_SELECTED" : "NOT_EVALUATED", localOutcome,
      postStateDigest, preStateDigest, remoteClass: localOutcome === "APPLIED" ? "APPLIED" : "OPAQUE_REMOTE_FAILURE",
      signatureVerification: observed === null ? "NOT_EVALUATED" : observed.signatureVerification,
      stage, step: index, transcriptVerification: observed === null ? "NOT_EVALUATED" : observed.transcriptVerification,
    };
  });
  return { id: `trace-${scenario.id}`, scenarioId: scenario.id, steps };
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalValue(value[key])]));
  if (typeof value === "number") require(Number.isInteger(value) && Number.isFinite(value), "NONCANONICAL_NUMBER");
  return value;
}
const canonical = value => `${JSON.stringify(canonicalValue(value))}\n`;
function loadCanonical(path) { const bytes = readFileSync(path, "utf8"); const value = JSON.parse(bytes); require(canonical(value) === bytes, `NONCANONICAL_JSON:${path}`); return value; }
function setEqual(left, right) { return left.size === right.size && [...left].every(value => right.has(value)); }
function parseArgs() { const args = process.argv.slice(2), values = {}; for (let i = 0; i < args.length; i += 2) values[args[i]] = args[i + 1]; for (const key of ["--repo-root", "--corpus", "--output"]) require(values[key], `missing ${key}`); return values; }

function baseJson(repoRoot, path) {
  return JSON.parse(execFileSync("git", ["show", `${BASE_SHA}:${path}`], { cwd: repoRoot, encoding: "utf8" }));
}

function mutationReport(args, corpus, valid, invalid, scenarios, expected, model) {
  const registry = loadCanonical(resolve(corpus, "adversarial-mutations.json")).records;
  const manifest = loadCanonical(resolve(corpus, "manifest.json"));
  const vectors = new Map([...valid, ...invalid].map(record => [record.id, record]));
  const expectedById = new Map(expected.map(record => [record.id, record]));
  const scenarioByTrace = new Map(scenarios.map(record => [`trace-${record.id}`, record]));
  const transitions = new Map(model.state_models.flatMap(machine => machine.transitions.map(transition => [`${machine.id}:${transition.id}`, transition])));
  const o07 = new Set(baseJson(resolve(args["--repo-root"]), "tools/causal-flow-simulator/o07/required_atom_instances_v1.json").rows.map(row => row.atom_instance_id));
  const envelope = baseJson(resolve(args["--repo-root"]), "tools/causal-flow-simulator/o08/resource-envelope.candidate.json");
  const o08 = new Set(Object.entries(envelope.entries).filter(([, entry]) => ["C03_SEMANTIC_LIMIT", "C03_ACTIVATION_CAPABILITY_INPUT", "C03_EXPLICIT_ZERO_OR_UNSUPPORTED"].includes(entry.role)).map(([id]) => id));
  const o10 = new Set(baseJson(resolve(args["--repo-root"]), "tools/causal-flow-simulator/o10/source-inventory.json").rows.map(row => row.row_id));
  const manifestFiles = new Map(manifest.files.map(row => [row.path, row]));
  const killed = [];
  for (const mutation of registry) {
    let detected = false;
    if (mutation.detector === "INDEPENDENT_REPLAY_EXPECTATION_MISMATCH") {
      const record = vectors.get(mutation.generatedTargetId), observed = evaluate(record);
      detected = observed.localOutcome === mutation.expectedOutcome && observed.stage === mutation.expectedStage;
    } else if (mutation.detector === "INDEPENDENT_EXPECTED_STAGE_MISMATCH") {
      const corrupted = structuredClone(vectors.get(mutation.generatedTargetId));
      corrupted.expected.firstFailingStage = "CORRUPTED_EXPECTED_STAGE";
      detected = evaluate(corrupted).stage !== corrupted.expected.firstFailingStage;
    } else if (mutation.detector === "INDEPENDENT_EXPECTED_OUTCOME_MISMATCH") {
      const corrupted = structuredClone(vectors.get(mutation.generatedTargetId));
      corrupted.expected.localOutcome = "CORRUPTED_EXPECTED_OUTCOME";
      detected = evaluate(corrupted).localOutcome !== corrupted.expected.localOutcome;
    } else if (mutation.detector === "INDEPENDENT_EXPECTED_TRACE_MISMATCH") {
      const scenario = scenarioByTrace.get(mutation.generatedTargetId), computed = computeTrace(scenario, vectors, transitions);
      const corrupted = structuredClone(expectedById.get(mutation.generatedTargetId));
      corrupted.steps[0].localOutcome = "CORRUPTED_EXPECTED_OUTCOME";
      detected = JSON.stringify(canonicalValue(computed)) !== JSON.stringify(canonicalValue(corrupted));
    } else if (mutation.detector === "MANIFEST_DIGEST_MISMATCH") {
      const row = structuredClone(manifestFiles.get(mutation.generatedTargetId));
      row.sha256 = "0".repeat(64);
      detected = row.sha256 !== hex(hash(readFileSync(resolve(corpus, row.path))));
    } else if (mutation.detector === "O07_EXACT_RELATION_SET") {
      const target = mutation.generatedTargetId, original = new Set(manifest.coverage.o07.coveredRelationIds), mutated = new Set([...original].filter(value => value !== target));
      detected = original.has(target) && o07.has(target) && !setEqual(mutated, o07);
    } else if (mutation.detector === "O08_EXACT_DIMENSION_SET") {
      const target = mutation.generatedTargetId, original = new Set(manifest.coverage.o08.participatingDimensions), mutated = new Set([...original].filter(value => value !== target));
      detected = original.has(target) && o08.has(target) && !setEqual(mutated, o08);
    } else if (mutation.detector === "O10_EXACT_SOURCE_ROW_SET") {
      const target = mutation.generatedTargetId, original = new Set(manifest.coverage.o10.coveredSourceRowIds), mutated = new Set([...original].filter(value => value !== target));
      detected = original.has(target) && o10.has(target) && !setEqual(mutated, o10);
    }
    require(detected, `surviving mutation:${mutation.id}`); killed.push(mutation.id);
  }
  killed.sort();
  return { killDigest: hex(hash(Buffer.from(`${killed.join("\n")}\n`, "utf8"))), killed: killed.length, result: "PASS" };
}

function main() {
  const args = parseArgs(), corpus = resolve(args["--corpus"]);
  const valid = loadCanonical(resolve(corpus, "valid-transcript-vectors.json")).records;
  const invalid = loadCanonical(resolve(corpus, "invalid-transcript-vectors.json")).records;
  for (const record of valid) { const observed = evaluate(record); require(observed.localOutcome === "APPLIED", `valid vector rejected:${record.id}:${observed.localOutcome}:${observed.stage}:${observed.commitmentVerification}`); }
  for (const record of invalid) { const observed = evaluate(record); require(observed.localOutcome === record.expected.localOutcome && observed.stage === record.expected.firstFailingStage, `invalid mismatch:${record.id}`); require(observed.preStateDigest === observed.postStateDigest && observed.externalEffects.length === 0, `invalid side effect:${record.id}`); }
  const scenarios = loadCanonical(resolve(corpus, "state-machine-scenarios.json")).records;
  const expected = loadCanonical(resolve(corpus, "expected-traces.json")).records;
  const model = baseJson(resolve(args["--repo-root"]), "docs/protocol/review/styx-app-kernel-v0-review-model.json");
  if (args["--mode"] === "mutations") {
    writeFileSync(resolve(args["--output"]), canonical(mutationReport(args, corpus, valid, invalid, scenarios, expected, model)), { flag: "wx" });
    return;
  }
  const transitions = new Map(model.state_models.flatMap(machine => machine.transitions.map(transition => [`${machine.id}:${transition.id}`, transition])));
  const vectors = new Map([...valid, ...invalid].map(record => [record.id, record]));
  const expectedByScenario = new Map(expected.map(record => [record.scenarioId, record]));
  for (const scenario of scenarios) {
    const computed = computeTrace(scenario, vectors, transitions), oracle = expectedByScenario.get(scenario.id);
    require(JSON.stringify(canonicalValue(computed)) === JSON.stringify(canonicalValue(oracle)), `trace mismatch:${scenario.id}`);
  }
  require(scenarios.length === expected.length, "unexpected expected trace");
  const names = ["adversarial-mutations.json", "expected-traces.json", "invalid-transcript-vectors.json", "manifest.json", "state-machine-scenarios.json", "valid-transcript-vectors.json"];
  const corpusDigest = hex(hash(...names.map(name => readFileSync(resolve(corpus, name)))));
  const report = { corpusDigest, invalidVectors: invalid.length, result: "PASS", scenarios: scenarios.length,
    traceDigest: hex(hash(readFileSync(resolve(corpus, "expected-traces.json")))), validVectors: valid.length };
  writeFileSync(resolve(args["--output"]), canonical(report), { flag: "wx" });
}

try { main(); } catch (error) { process.stderr.write(`c03_node_failure=${error.message}\n`); process.exitCode = 2; }
