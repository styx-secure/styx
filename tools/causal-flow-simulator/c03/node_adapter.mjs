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
const BASE_SHA = "0fbba871130e4e100558030837e03dd609128976";
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
const PRODUCED_K_PRIMARIES = new Set(["COMMITMENT_MISMATCH", "CONTEXT_CAPACITY_EXHAUSTED", "CREDENTIAL_BINDING_MISMATCH", "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED", "CURRENT_OBJECT_OUT_OF_PROFILE", "DEPENDENCY_DEFERRED", "DUPLICATE", "FORK_EVIDENCE", "INVALID", "LENGTH_MISMATCH", "OPENING_MISSING", "PENDING_ANCESTOR", "PENDING_OPENING", "REFERENCE_COLLISION_UNSUPPORTED", "STRUCTURAL_REJECTION", "UNRESOLVED_CREDENTIAL_BINDING"]);
const AP_OWNED_EXCLUSIONS = new Set(["APPLIED", "AUTHENTIC_BUT_UNAUTHORIZED", "AUTHORITY_PROJECTION_UNAVAILABLE", "LINEAGE_QUARANTINED", "POST_REVOCATION"]);
const TRANSCRIPT_PROFILE_UNREACHABLE = new Set(["PROFILE_ACTIVATION_UNSUPPORTED", "REMOVAL_INAPPLICABLE", "STALE_EVIDENCE", "UNRESOLVABLE_CREDENTIAL"]);
const O10_TAXONOMY = JSON.parse(readFileSync(new URL("../o10/outcome-taxonomy.json", import.meta.url), "utf8"));
const O10_BY_ID = new Map(O10_TAXONOMY.primaries.map(row => [row.id, row]));

class ProtocolError extends Error {
  constructor(message, stage = "S3_KERNEL_STRUCTURAL", observations = {}) {
    super(message); this.stage = stage; this.observations = observations;
  }
}
const require = (ok, message) => { if (!ok) throw new ProtocolError(message); };
const hash = (...parts) => createHash("sha256").update(Buffer.concat(parts)).digest();
const hex = value => Buffer.from(value).toString("hex");
function o10Result(primary, stage = undefined) {
  const row = O10_BY_ID.get(primary);
  require(row?.owner === "K", `non-K or unknown O-10 primary:${primary}`);
  const stages = row.stage.split("|");
  const selected = stage ?? stages[0];
  require(stages.includes(selected), `O-10 stage mismatch:${primary}:${selected}`);
  return { localOutcome: primary, remoteClass: O10_TAXONOMY.remote_collapse, stage: selected };
}
function selectO10Result(candidates) {
  require(Array.isArray(candidates) && candidates.length > 0, "empty O-10 candidate set");
  const normalized = [...new Map(candidates.map(([primary, stage]) => [`${primary}:${stage}`, [primary, stage]])).values()]
    .sort((left, right) => `${left[0]}:${left[1]}`.localeCompare(`${right[0]}:${right[1]}`));
  const results = normalized.map(([primary, stage]) => o10Result(primary, stage));
  if (results.length === 1) return results[0];
  const identifiers = new Set(results.map(row => row.localOutcome));
  for (const key of ["k_precedence", "event_precedence"]) {
    const precedence = O10_TAXONOMY[key];
    if (Array.isArray(precedence) && [...identifiers].every(identifier => precedence.includes(identifier))) {
      return results.toSorted((left, right) => precedence.indexOf(left.localOutcome) - precedence.indexOf(right.localOutcome))[0];
    }
  }
  throw new ProtocolError(`O-10 candidates lack one closed precedence relation:${[...identifiers].sort().join(",")}`);
}

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

function geometryObservations() {
  return Object.fromEntries(Array.from({ length: 7 }, (_, index) => [`geometryPredicate${index + 1}`, "NOT_EVALUATED"]));
}

function validateGeometryPredicates(exactLength, shape, geometry) {
  const observations = geometryObservations();
  const fail = (index, code = "CHUNK_GEOMETRY_INVALID") => {
    observations[`geometryPredicate${index}`] = "FAIL";
    throw new ProtocolError(code, "S3_KERNEL_STRUCTURAL", observations);
  };
  if (shape === "SINGLE") {
    observations.geometryPredicate1 = "PASS";
    if (exactLength > Number(MAX_U32 - 132n)) fail(2, "CONTENT_GEOMETRY_INVALID");
    observations.geometryPredicate2 = "PASS";
    for (let index = 3; index <= 7; index += 1) observations[`geometryPredicate${index}`] = "NOT_APPLICABLE";
    return observations;
  }
  if (shape !== "TREE" || geometry === null) fail(1, "CONTENT_GEOMETRY_INVALID");
  if (exactLength === 0) fail(1);
  observations.geometryPredicate1 = "PASS";
  observations.geometryPredicate2 = "NOT_APPLICABLE";
  const { chunkSize, chunkCount, finalChunkLength } = geometry;
  if (!(chunkSize >= 1 && chunkSize <= Number(MAX_U32 - 132n))) fail(3);
  observations.geometryPredicate3 = "PASS";
  if (chunkSize >= exactLength || chunkCount < 2) fail(4);
  observations.geometryPredicate4 = "PASS";
  const expectedCount = 1 + Math.floor((exactLength - 1) / chunkSize);
  if (chunkCount !== expectedCount) fail(5);
  observations.geometryPredicate5 = "PASS";
  const consumed = chunkSize * (chunkCount - 1);
  if (!Number.isSafeInteger(consumed) || consumed >= exactLength || finalChunkLength !== exactLength - consumed) fail(6);
  observations.geometryPredicate6 = "PASS";
  if (!(finalChunkLength > 0 && finalChunkLength <= chunkSize)) fail(7);
  observations.geometryPredicate7 = "PASS";
  return observations;
}

function geometryPredicateMutantIsKilled(number) {
  const cases = new Map([
    [1, [0, "TREE", { chunkSize: 1, chunkCount: 2, finalChunkLength: 1 }, "FAIL"]],
    [2, [Number(MAX_U32 - 131n), "SINGLE", null, "FAIL"]],
    [3, [8, "TREE", { chunkSize: 0, chunkCount: 2, finalChunkLength: 8 }, "FAIL"]],
    [4, [8, "TREE", { chunkSize: 8, chunkCount: 2, finalChunkLength: 1 }, "FAIL"]],
    [5, [9, "TREE", { chunkSize: 4, chunkCount: 2, finalChunkLength: 5 }, "FAIL"]],
    [6, [9, "TREE", { chunkSize: 4, chunkCount: 3, finalChunkLength: 2 }, "FAIL"]],
    [7, [8, "TREE", { chunkSize: 4, chunkCount: 2, finalChunkLength: 4 }, "PASS"]],
  ]);
  const [exactLength, shape, geometry, expected] = cases.get(number);
  let observations;
  try { observations = validateGeometryPredicates(exactLength, shape, geometry); }
  catch (error) {
    if (!(error instanceof ProtocolError)) throw error;
    observations = error.observations;
  }
  return observations[`geometryPredicate${number}`] === expected;
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
    }
    const shape = ({ 0: "SINGLE", 1: "TREE" })[shapeCode]; require(shape !== undefined && ((shape === "SINGLE") !== (geometry !== null)), "CONTENT_GEOMETRY_INVALID");
    const predicateResults = validateGeometryPredicates(exactLength, shape, geometry);
    if (geometry !== null && !O08_CHUNK_OCTETS.has(geometry.chunkSize)) throw new ProtocolError("CHUNK_OCTETS_LIMIT", "S3_KERNEL_STRUCTURAL", predicateResults);
    if (geometry !== null && geometry.chunkCount > O08_LIMITS.CHUNKS_PER_CONTENT) throw new ProtocolError("CHUNKS_PER_CONTENT_LIMIT", "S3_KERNEL_STRUCTURAL", predicateResults);
    if (exactLength > O08_LIMITS.CONTENT_EXACT_OCTETS) throw new ProtocolError("CONTENT_EXACT_OCTETS_LIMIT", "S3_KERNEL_STRUCTURAL", predicateResults);
    Object.assign(content, { commitmentHex: hex(commitment), contentType, geometryPredicateResults: predicateResults, shape }); if (geometry !== null) content.geometry = geometry;
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
  const result = { apAuthorityResult: "AP_FOLD_NOT_EXECUTED", commitmentMatchVerification: "NOT_EVALUATED", commitmentVerification: "NOT_PRESENT", externalEffects: [], ...geometryObservations(),
    kBindingAdmission: "ADMITTED", outcomeEvaluated: false, postStateDigest: null, preStateDigest: state,
    signatureVerification: "NOT_EVALUATED", stage: "FINAL_AFTER_S6", suppliedLengthVerification: "NOT_EVALUATED", transcriptVerification: "VALID" };
  const reject = (outcome, stage, transcriptStatus = "VALID", admitted = false) => Object.assign(result, selectO10Result(
    Array.isArray(outcome) ? outcome : [[outcome, stage ?? O10_BY_ID.get(outcome)?.stage.split("|")[0]]],
  ), {
    apAuthorityResult: admitted ? "REJECTED_OR_DEFERRED" : "NOT_REACHED",
    kBindingAdmission: admitted ? "ADMITTED" : "REJECTED", outcomeEvaluated: true,
    postStateDigest: state, transcriptVerification: transcriptStatus,
  });
  let fields, reference, expected;
  try {
    if (record.kind === "GENESIS") { fields = parseGenesis(transcript); reference = hex(framedHash(DOMAINS.genesisReference, transcript)); expected = record.genesisReferenceHex; }
    else if (record.kind === "APPLICATION_EVENT") { fields = parseEvent(transcript); reference = hex(framedHash(DOMAINS.eventReference, transcript)); expected = record.eventReferenceHex; }
    else throw new ProtocolError("OBJECT_KIND_UNKNOWN");
  } catch (error) {
    if (error instanceof ProtocolError) Object.assign(result, error.observations);
    if (error instanceof ProtocolError && error.message === "PARENTS_PER_EVENT_LIMIT") return reject("CONTEXT_CAPACITY_EXHAUSTED", error.stage, "REJECTED");
    if (error instanceof ProtocolError && error.message.endsWith("_LIMIT")) return reject("CURRENT_OBJECT_OUT_OF_PROFILE", error.stage, "REJECTED");
    return reject("STRUCTURAL_REJECTION", error instanceof ProtocolError ? error.stage : "S3_KERNEL_STRUCTURAL", "REJECTED");
  }
  if (reference !== expected) return reject("REFERENCE_COLLISION_UNSUPPORTED", "S3_KERNEL_STRUCTURAL");
  const admission = record.admissionContext ?? {};
  if (admission === null || Array.isArray(admission) || typeof admission !== "object") return reject("STRUCTURAL_REJECTION", "S3_KERNEL_STRUCTURAL");
  if ((admission.checkpointEvidenceReferences ?? []).length > 0) return reject("CURRENT_OBJECT_OUT_OF_PROFILE", "S3_KERNEL_STRUCTURAL");
  try { if (!ed25519Verify(Buffer.from(record.binding.verificationKeyHex, "hex"), Buffer.from(record.signatureHex, "hex"), transcript)) { result.signatureVerification = "REJECTED"; return reject("INVALID", "S3_KERNEL_STRUCTURAL"); } } catch { result.signatureVerification = "REJECTED"; return reject("INVALID", "S3_KERNEL_STRUCTURAL"); }
  result.signatureVerification = "VALID";
  if (record.kind === "APPLICATION_EVENT") {
    if (record.binding.contextIdentifierHex !== fields.contextIdentifierHex || record.binding.credentialIdentifierHex !== fields.credentialIdentifierHex) return reject("CREDENTIAL_BINDING_MISMATCH", "S3_KERNEL_STRUCTURAL");
    if (fields.content.class === "NONE") {
      for (let index = 1; index <= 7; index += 1) result[`geometryPredicate${index}`] = "NOT_APPLICABLE";
      result.suppliedLengthVerification = "NOT_APPLICABLE";
      result.commitmentMatchVerification = "NOT_APPLICABLE";
    }
    if (fields.content.class !== "NONE") {
      Object.assign(result, fields.content.geometryPredicateResults);
      if (record.opening === undefined) {
        result.commitmentVerification = "PENDING";
        result.suppliedLengthVerification = "NOT_EVALUATED";
        result.commitmentMatchVerification = "NOT_EVALUATED";
        return fields.content.class === "REQUIRED"
          ? reject("PENDING_OPENING", "EVENT_LOCAL", "VALID", true)
          : reject("OPENING_MISSING", "S3_KERNEL_STRUCTURAL");
      }
      const supplied = Buffer.from(record.opening.contentHex, "hex"), randomizer = Buffer.from(record.opening.randomizerHex, "hex");
      const computed = commitment(fields, supplied, randomizer, fields.content.geometry?.chunkSize);
      const failures = [];
      if (supplied.length !== fields.content.exactLength) {
        result.commitmentVerification = "REJECTED";
        result.suppliedLengthVerification = "REJECTED";
        failures.push(["LENGTH_MISMATCH", "S3_KERNEL_STRUCTURAL"]);
      } else result.suppliedLengthVerification = "VALID";
      if (computed.commitmentHex !== fields.content.commitmentHex) {
        result.commitmentVerification = "REJECTED";
        result.commitmentMatchVerification = "REJECTED";
        failures.push(["COMMITMENT_MISMATCH", "S3_KERNEL_STRUCTURAL"]);
      } else result.commitmentMatchVerification = "VALID";
      if (failures.length > 0) return reject(failures);
      result.commitmentVerification = "VALID";
      result.commitmentMatchVerification = "VALID";
    }
  } else {
    for (let index = 1; index <= 7; index += 1) result[`geometryPredicate${index}`] = "NOT_APPLICABLE";
    result.suppliedLengthVerification = "NOT_APPLICABLE";
    result.commitmentMatchVerification = "NOT_APPLICABLE";
  }
  if ((admission.seenEventReferences ?? []).includes(reference)) return reject("DUPLICATE", "S3_KERNEL_STRUCTURAL", "VALID", true);
  if ((admission.sameAuthorSequenceReferences ?? []).some(candidate => candidate !== reference)) return reject("FORK_EVIDENCE", "EVENT_LOCAL", "VALID", true);
  if (record.kind === "APPLICATION_EVENT") {
    const dependencies = new Set(fields.causalParents);
    if (fields.directPredecessorHex !== null) dependencies.add(fields.directPredecessorHex);
    const available = new Set(admission.availableDependencyReferences ?? [...dependencies]);
    const missing = [...dependencies].filter(candidate => !available.has(candidate));
    if (missing.length > 0) {
      const pending = new Set([...(admission.knownPendingOpeningRoots ?? []), ...(admission.pendingOpeningDescendantReferences ?? [])]);
      const classifiedPending = missing.every(candidate => pending.has(candidate));
      return classifiedPending
        ? reject("PENDING_ANCESTOR", "EVENT_LOCAL", "VALID", true)
        : reject("DEPENDENCY_DEFERRED", "S4_GRAPH_ADMISSION", "VALID", true);
    }
    if (admission.credentialIdentifierCollision === true) return reject("CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED", "S3_KERNEL_STRUCTURAL");
    if (!(fields.eventRole === "CREDENTIAL" && fields.tail?.kind === "GRANT")
        && admission.credentialBindingMatchCount !== undefined
        && admission.credentialBindingMatchCount !== 1) return reject("UNRESOLVED_CREDENTIAL_BINDING", "S3_KERNEL_STRUCTURAL");
  }
  result.postStateDigest = hex(hash(Buffer.from(state, "hex"), Buffer.from(reference, "hex"))); return result;
}

function stateDigest(value) { return hex(hash(Buffer.from(value, "utf8"))); }
const SEMANTIC_OBSERVATION_FIELDS = Object.freeze([
  "apAuthorityResult", "commitmentMatchVerification", "commitmentVerification", "dependencyStatus", "executed",
  "externalEffects", "inputDigest", "kBindingAdmission", "outcomeEvaluated",
  "geometryPredicate1", "geometryPredicate2", "geometryPredicate3", "geometryPredicate4",
  "geometryPredicate5", "geometryPredicate6", "geometryPredicate7", "signatureVerification",
  "stage", "suppliedLengthVerification", "transcriptVerification",
]);
const OPTIONAL_SEMANTIC_OBSERVATION_FIELDS = Object.freeze(["localOutcome", "remoteClass"]);
const NONSEMANTIC_VECTOR_FIELDS = new Set([
  "citations", "expected", "id", "mutation", "sourceVectorId", "synthetic", "testOnly",
]);
function semanticInputDigest(vector) {
  const projection = Object.fromEntries(Object.entries(vector).filter(([key]) => !NONSEMANTIC_VECTOR_FIELDS.has(key)));
  return hex(hash(Buffer.from(canonical(projection), "utf8")));
}
function semanticObservationDigest(steps) {
  const projection = steps.map(step => {
    const observation = Object.fromEntries(SEMANTIC_OBSERVATION_FIELDS.map(field => [field, step[field]]));
    for (const field of OPTIONAL_SEMANTIC_OBSERVATION_FIELDS) {
      const present = Object.hasOwn(step, field);
      observation[`${field}Present`] = present;
      if (present) observation[field] = step[field];
    }
    return observation;
  });
  return hex(hash(Buffer.from(canonical(projection), "utf8")));
}
function transitionInputIsCompatible(observed) {
  return observed?.kBindingAdmission === "ADMITTED"
    && observed?.apAuthorityResult === "AP_FOLD_NOT_EXECUTED"
    && observed?.outcomeEvaluated === false
    && !Object.hasOwn(observed ?? {}, "localOutcome")
    && !Object.hasOwn(observed ?? {}, "remoteClass")
    && observed?.transcriptVerification === "VALID" && observed?.signatureVerification === "VALID";
}

function computeTrace(scenario, vectors, transitions) {
  const availableEvidence = new Set();
  const steps = scenario.steps.map((step, index) => {
    const vector = vectors.get(step.inputVectorId); require(vector !== undefined, `unknown vector:${step.inputVectorId}`);
    const executed = step.executed ?? true, observed = executed ? evaluate(vector) : null;
    const preStateDigest = stateDigest(`styx-c03/state/${scenario.id}/${step.preState}`);
    let observation, postState;
    if (!executed) {
      require(["flow", "ap_projection"].includes(scenario.modelId), `invalid boundary:${scenario.id}`);
      const localOutcome = scenario.modelId === "ap_projection" ? "NOT_EVALUATED"
        : scenario.id === "scenario-flow-transport_publish" ? "TRANSPORT_PROFILE_REQUIRED" : "SESSION_PROFILE_REQUIRED";
      observation = { apAuthorityResult: "NOT_EVALUATED", commitmentMatchVerification: "NOT_EVALUATED", commitmentVerification: "NOT_PRESENT", externalEffects: [], ...geometryObservations(),
        kBindingAdmission: "NOT_EVALUATED", localOutcome, outcomeEvaluated: false, remoteClass: "OPAQUE_REMOTE_FAILURE",
        signatureVerification: "NOT_EVALUATED", stage: "BOUNDARY_NOT_EXECUTED", suppliedLengthVerification: "NOT_EVALUATED", transcriptVerification: "NOT_EVALUATED" };
      postState = "UNCHANGED";
    } else if (step.transitionId !== null) {
      const transition = transitions.get(`${scenario.modelId}:${step.transitionId}`);
      require(transition !== undefined && transition.from.includes(step.preState), `transition mismatch:${scenario.id}:${index}`);
      if (transition.result_layer === "K_ADMISSION_ONLY") {
        require(transitionInputIsCompatible(observed), `incompatible positive K transition:${scenario.id}:${index}`);
      } else {
        require(observed?.outcomeEvaluated === true && observed?.localOutcome === transition.outcome,
          `incompatible negative K transition:${scenario.id}:${index}`);
      }
      observation = Object.fromEntries(Object.entries(observed).filter(([key]) => !["preStateDigest", "postStateDigest"].includes(key)));
      postState = transition.to;
    } else {
      observation = Object.fromEntries(Object.entries(observed).filter(([key]) => !["preStateDigest", "postStateDigest"].includes(key)));
      postState = observed.preStateDigest === observed.postStateDigest ? "UNCHANGED" : "READY_FOR_AP_FOLD";
    }
    const postStateDigest = postState === "UNCHANGED" || !executed
      ? preStateDigest : stateDigest(`styx-c03/state/${scenario.id}/${postState}`);
    const requirements = new Set(step.requiredPriorEvidence);
    const dependencyStatus = [...requirements].every(value => availableEvidence.has(value)) ? "SATISFIED" : "MISSING";
    require(dependencyStatus === step.expectedDependencyStatus, `dependency status mismatch:${scenario.id}:${index}`);
    const result = {
      actionDigest: hex(hash(Buffer.from(step.candidateAction, "utf8"))),
      causalClassification: step.transitionId ?? `VECTOR:${vector.id}`,
      dependencyStatus,
      evidenceConsumed: [...requirements].sort(),
      evidenceProduced: step.providedEvidence ?? null,
      executed,
      inputDigest: semanticInputDigest(vector), postStateDigest, preStateDigest, step: index,
    };
    Object.assign(result, observation);
    if (Object.hasOwn(step, "apExpectationOnly")) result.apExpectationOnly = step.apExpectationOnly;
    if (step.providedEvidence !== null && step.providedEvidence !== undefined) availableEvidence.add(step.providedEvidence);
    return result;
  });
  return {
    id: `trace-${scenario.id}`,
    observationDigest: hex(hash(Buffer.from(canonical({ scenarioId: scenario.id, steps }), "utf8"))),
    scenarioId: scenario.id,
    semanticObservationDigest: semanticObservationDigest(steps),
    steps,
  };
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
function validateSourceCoverage(coverage, o07, o08, excludedO08, o10) {
  require(coverage.o07.relationCount === o07.size && coverage.o07.coveredRelationIds.length === o07.size && setEqual(new Set(coverage.o07.coveredRelationIds), o07), "O-07 coverage mismatch");
  require(coverage.o08.participatingDimensions.length === o08.size && setEqual(new Set(coverage.o08.participatingDimensions), o08), "O-08 participating coverage mismatch");
  require(coverage.o08.excludedDimensions.length === excludedO08.size && setEqual(new Set(coverage.o08.excludedDimensions), excludedO08), "O-08 excluded coverage mismatch");
  require(coverage.o10.coveredSourceRowIds.length === o10.size && setEqual(new Set(coverage.o10.coveredSourceRowIds), o10), "O-10 source coverage mismatch");
}
function validateFileManifest(corpus, manifest) {
  const names = ["adversarial-mutations.json", "expected-traces.json", "invalid-transcript-vectors.json", "state-machine-scenarios.json", "valid-transcript-vectors.json"];
  const expected = names.map(path => ({ path, recordCount: loadCanonical(resolve(corpus, path)).records.length, sha256: hex(hash(readFileSync(resolve(corpus, path)))) }));
  require(JSON.stringify(canonicalValue(manifest.files)) === JSON.stringify(canonicalValue(expected)), "manifest file digests/counts mismatch");
}
function validateCorpusRelations(repoRoot, manifest, model, scenarios, traces, mutations, valid, invalid, apExpectations) {
  const coverage = manifest.coverage;
  const inventory = JSON.parse(readFileSync(resolve(repoRoot, "tools/causal-flow-simulator/c03/corpus-inventory.json"), "utf8"));
  const nonExecutableInvariants = new Set(["INV_C0_3_NO_GO", "INV_SOURCE_AUTHORITY"]);
  const executableInvariantIds = new Set(model.invariants.map(row => row.id).filter(id => !nonExecutableInvariants.has(id)));
  const inventoriedInvariantIds = new Set(Object.keys(inventory.invariant_witness_vectors ?? {}));
  require(setEqual(executableInvariantIds, inventoriedInvariantIds), "invariant witness inventory mismatch");
  require(new Set(Object.values(inventory.invariant_witness_vectors)).size === executableInvariantIds.size, "shared inventoried invariant witness vector");
  const scenarioIds = new Set(scenarios.map(row => row.id));
  const vectorIds = new Set([...valid, ...invalid, ...apExpectations].map(row => row.id));
  const usedVectorIds = new Set();
  for (const scenario of scenarios) {
    const available = new Set();
    require(Array.isArray(scenario.steps) && scenario.steps.length > 0, `empty scenario:${scenario.id}`);
    for (const step of scenario.steps) {
      require(vectorIds.has(step.inputVectorId), `unknown vector:${scenario.id}:${step.inputVectorId}`);
      usedVectorIds.add(step.inputVectorId);
      const dependencyStatus = step.requiredPriorEvidence.every(value => available.has(value)) ? "SATISFIED" : "MISSING";
      require(step.expectedDependencyStatus === dependencyStatus, `dependency expectation mismatch:${scenario.id}`);
      require(typeof step.providedEvidence === "string" && step.providedEvidence.length > 0 && !available.has(step.providedEvidence), `invalid produced evidence:${scenario.id}`);
      available.add(step.providedEvidence);
    }
  }
  require(setEqual(usedVectorIds, vectorIds), "vector execution coverage mismatch");

  for (const trace of traces) {
    require(
      trace.observationDigest === hex(hash(Buffer.from(canonical({ scenarioId: trace.scenarioId, steps: trace.steps }), "utf8"))),
      `trace observation mismatch:${trace.id}`,
    );
    require(trace.semanticObservationDigest === semanticObservationDigest(trace.steps), `semantic observation mismatch:${trace.id}`);
  }

  const counterexamples = new Map(model.counterexamples.map(row => [row.id, row]));
  const counterexampleScenarios = scenarios.filter(row => row.counterexampleId !== undefined);
  require(counterexampleScenarios.length === counterexamples.size && counterexampleScenarios.every(row => counterexamples.has(row.counterexampleId)), "counterexample scenario coverage mismatch");
  for (const scenario of counterexampleScenarios) {
    require(scenario.steps.length === 3 && scenario.steps.every(step => step.executed !== false), `counterexample execution mismatch:${scenario.counterexampleId}`);
    require(JSON.stringify(scenario.steps.map(step => step.candidateAction)) === JSON.stringify(counterexamples.get(scenario.counterexampleId).steps), `counterexample program mismatch:${scenario.counterexampleId}`);
  }
  const traceByScenario = new Map(traces.map(row => [row.scenarioId, row]));
  const observations = counterexampleScenarios.map(row => traceByScenario.get(row.id).semanticObservationDigest);
  require(new Set(observations).size === observations.length, "counterexample observation collision");

  const expectedCounterexamples = model.counterexamples.map(row => ({ id: row.id, scenarioId: `scenario-counterexample-${row.id.toLowerCase()}` }));
  require(JSON.stringify(canonicalValue(coverage.counterexamples)) === JSON.stringify(canonicalValue(expectedCounterexamples)), "counterexample coverage relation mismatch");
  const excludedFlows = new Set(["secure_session_receive", "secure_session_send", "transport_publish"]);
  const expectedFlows = model.flows.map(row => ({ branch: excludedFlows.has(row.id) ? "BOUNDARY_NOT_EXECUTED" : "EXECUTED", id: row.id, scenarioId: `scenario-flow-${row.id}` }));
  require(JSON.stringify(canonicalValue(coverage.flows)) === JSON.stringify(canonicalValue(expectedFlows)), "flow coverage relation mismatch");

  const mutationById = new Map(mutations.map(row => [row.id, row]));
  const expectedSourceMutationIds = new Set([
    "mutation-source-checkpoint-after-protected-work",
    "mutation-source-o10-applicability",
    "mutation-source-o10-class-membership",
    "mutation-source-o10-precedence",
    "mutation-source-r5-flatten-k-admission",
    "mutation-source-r6-classification",
    ...Array.from({ length: 7 }, (_, index) => `mutation-source-geometry-predicate-${index + 1}`),
  ]);
  const sourceMutations = mutations.filter(row => row.mutationClass === "SOURCE_ANCHORED_SECURITY");
  require(setEqual(new Set(sourceMutations.map(row => row.id)), expectedSourceMutationIds), "source-anchored mutation set mismatch");
  const sourceRowIds = new Set(baseJson(repoRoot, "tools/causal-flow-simulator/o10/source-inventory.json").rows.map(row => row.row_id));
  for (const mutation of sourceMutations) {
    require(typeof mutation.sourcePath === "string" && typeof mutation.sourceAnchor === "string" && mutation.sourceAnchor.length > 0, `invalid source mutation anchor:${mutation.id}`);
    require(baseText(repoRoot, mutation.sourcePath).includes(mutation.sourceAnchor), `stale source mutation anchor:${mutation.id}`);
    require(Array.isArray(mutation.sourceRowIds) && mutation.sourceRowIds.length > 0
      && new Set(mutation.sourceRowIds).size === mutation.sourceRowIds.length
      && mutation.sourceRowIds.every(row => sourceRowIds.has(row)), `invalid source mutation rows:${mutation.id}`);
  }
  const expectedNonExecutable = nonExecutableInvariants;
  const invariantRows = new Map(coverage.invariants.map(row => [row.id, row]));
  require(invariantRows.size === model.invariants.length && model.invariants.every(row => invariantRows.has(row.id)), "invariant coverage mismatch");
  const witnesses = new Set(), hostileMutations = new Set(), witnessVectors = new Set(), witnessObservations = new Set();
  for (const invariant of model.invariants) {
    const row = invariantRows.get(invariant.id);
    if (expectedNonExecutable.has(invariant.id)) {
      require(row.branch === "NON_EXECUTABLE_NON_CLAIM" && Array.isArray(row.citations) && row.citations.length > 0 && typeof row.reason === "string" && row.reason.length > 0, `invalid non-executable invariant:${invariant.id}`);
      continue;
    }
    require(row.branch === "EXECUTABLE_WITNESS" && row.witnessScenarioIds.length === 1 && row.hostileMutationIds.length === 1, `non-atomic invariant evidence:${invariant.id}`);
    const witnessId = row.witnessScenarioIds[0], mutationId = row.hostileMutationIds[0];
    require(!witnesses.has(witnessId) && !hostileMutations.has(mutationId), `shared sole invariant evidence:${invariant.id}`);
    witnesses.add(witnessId); hostileMutations.add(mutationId);
    const witness = scenarios.find(item => item.id === witnessId), mutation = mutationById.get(mutationId);
    require(witness?.exercisedInvariantIds?.length === 1 && witness.exercisedInvariantIds[0] === invariant.id, `invariant witness semantic mismatch:${invariant.id}`);
    const witnessVector = witness.steps[0].inputVectorId;
    require(witnessVector === inventory.invariant_witness_vectors[invariant.id], `invariant witness-vector mismatch:${invariant.id}`);
    require(!witnessVectors.has(witnessVector), `shared invariant witness vector:${invariant.id}`);
    witnessVectors.add(witnessVector);
    const witnessObservation = traceByScenario.get(witnessId)?.semanticObservationDigest;
    require(typeof witnessObservation === "string" && !witnessObservations.has(witnessObservation), `shared invariant semantic observation:${invariant.id}`);
    witnessObservations.add(witnessObservation);
    require(mutation?.mutationClass === "SEMANTIC_INVARIANT" && mutation.violatedInvariant === invariant.id && mutation.sourceRecordId === witnessId && mutation.generatedTargetId === `trace-${witnessId}`, `invariant mutation semantic mismatch:${invariant.id}`);
  }
  require(!mutations.some(row => row.mutationClass?.startsWith("SEMANTIC") && expectedNonExecutable.has(row.violatedInvariant)), "non-executable invariant claimed by mutation");

  const expectedStates = model.state_models.flatMap(machine => machine.states.map(state => `${machine.id}:${state}`)).sort();
  const expectedTerminal = model.state_models.flatMap(machine => (machine.terminal_states ?? []).map(state => `${machine.id}:${state}`)).sort();
  const expectedTransitions = model.state_models.flatMap(machine => machine.transitions.map(transition => {
    const matches = scenarios.filter(scenario => scenario.modelId === machine.id && scenario.steps.some(step => step.transitionId === transition.id));
    require(matches.length === 1, `transition witness cardinality:${machine.id}:${transition.id}`);
    return { id: `${machine.id}:${transition.id}`, scenarioId: matches[0].id };
  })).sort((a, b) => a.id.localeCompare(b.id));
  require(JSON.stringify(coverage.states) === JSON.stringify(expectedStates), "state coverage relation mismatch");
  require(JSON.stringify(coverage.terminalStates) === JSON.stringify(expectedTerminal), "terminal-state coverage relation mismatch");
  require(JSON.stringify(canonicalValue(coverage.transitions)) === JSON.stringify(canonicalValue(expectedTransitions)), "transition coverage relation mismatch");

  require(JSON.stringify(canonicalValue(coverage.o10.alias)) === JSON.stringify(canonicalValue(inventory.o10_alias)), "O-10 alias mismatch");
  const expectedOutcomes = inventory.o10_primaries.map(outcome => {
    let branch, matching;
    if (PRODUCED_K_PRIMARIES.has(outcome)) {
      branch = "PRODUCED";
      matching = scenarios.filter(scenario => scenario.steps.some(step => step.expectedOutcome === outcome)).map(row => row.id);
    } else if (AP_OWNED_EXCLUSIONS.has(outcome)) {
      branch = "AP_OWNED_EXCLUDED";
      matching = scenarios.filter(scenario => scenario.steps.some(step => step.apExpectationOnly === outcome)).map(row => row.id);
    } else {
      require(TRANSCRIPT_PROFILE_UNREACHABLE.has(outcome), `unpartitioned O-10 primary:${outcome}`);
      branch = "TRANSCRIPT_PROFILE_UNREACHABLE"; matching = [];
    }
    return { branch, citations: [{ anchor: "## Primary registry", path: "docs/protocol/styx-app-kernel-v0-outcome-taxonomy.md" }], id: outcome, scenarioIds: matching };
  });
  expectedOutcomes.push(...inventory.o10_post_c03_markers.map(marker => ({ branch: "UNREACHABLE_IN_TRANSCRIPT_ONLY_PROFILE", citations: [{ anchor: "## Closed cardinalities", path: "docs/protocol/styx-app-kernel-v0-outcome-taxonomy.md" }], id: marker, scenarioIds: [] })));
  require(JSON.stringify(canonicalValue(coverage.o10.outcomes)) === JSON.stringify(canonicalValue(expectedOutcomes)), "O-10 outcome coverage mismatch");
  const sourceInventory = baseJson(repoRoot, "tools/causal-flow-simulator/o10/source-inventory.json");
  const sourceById = new Map(sourceInventory.rows.map(row => [row.row_id, row]));
  const vectorById = new Map([...valid, ...invalid, ...apExpectations].map(row => [row.id, row]));
  const producedWitnesses = inventory.o10_produced_source_row_witnesses;
  require(producedWitnesses && typeof producedWitnesses === "object" && !Array.isArray(producedWitnesses)
    && Object.keys(producedWitnesses).length > 0, "O-10 produced-row witness map missing");
  for (const [rowId, witnesses] of Object.entries(producedWitnesses)) {
    const source = sourceById.get(rowId);
    require(source !== undefined, `O-10 produced-row witness references unknown row:${rowId}`);
    require(source.mapping !== undefined, `produced forbidden O-10 row:${rowId}`);
    const primary = inventory.o10_primaries.includes(source.mapping.primary)
      ? source.mapping.primary : undefined;
    require(primary !== undefined && !AP_OWNED_EXCLUSIONS.has(primary), `produced non-K O-10 row:${rowId}`);
    require(Array.isArray(witnesses) && witnesses.length > 0, `empty O-10 row witness set:${rowId}`);
    const seenInputs = new Set();
    for (const witness of witnesses) {
      require(witness && typeof witness === "object" && !Array.isArray(witness)
        && JSON.stringify(Object.keys(witness).sort()) === JSON.stringify(["inputId", "jointSourceRowIds"]),
      `malformed O-10 row witness:${rowId}`);
      require(typeof witness.inputId === "string" && witness.inputId.length > 0
        && !seenInputs.has(witness.inputId), `invalid O-10 row witness relation:${rowId}`);
      seenInputs.add(witness.inputId);
      require(Array.isArray(witness.jointSourceRowIds) && witness.jointSourceRowIds.length > 0
        && witness.jointSourceRowIds.includes(rowId)
        && JSON.stringify(witness.jointSourceRowIds) === JSON.stringify([...new Set(witness.jointSourceRowIds)].sort())
        && witness.jointSourceRowIds.every(identifier => sourceById.has(identifier)),
      `invalid O-10 row witness relation:${rowId}`);
    }
  }
  const expectedSourceRows = sourceInventory.rows.map(row => {
    let disposition, primary, rowWitnesses = [];
    if (Object.hasOwn(producedWitnesses, row.row_id)) {
      disposition = "PRODUCED"; primary = row.mapping.primary;
      rowWitnesses = producedWitnesses[row.row_id].map(witness => {
        const scenarioId = `scenario-vector-${witness.inputId}`;
        const scenario = scenarios.find(item => item.id === scenarioId);
        require(scenario?.steps.some(step => step.inputVectorId === witness.inputId), `missing O-10 row scenario:${row.row_id}:${witness.inputId}`);
        const observed = evaluate(vectorById.get(witness.inputId));
        require(observed.localOutcome === primary && observed.stage === row.mapping.stage, `O-10 row witness result mismatch:${row.row_id}:${witness.inputId}`);
        require(Array.isArray(witness.jointSourceRowIds) && witness.jointSourceRowIds.length > 0
          && witness.jointSourceRowIds.includes(row.row_id)
          && JSON.stringify(witness.jointSourceRowIds) === JSON.stringify([...new Set(witness.jointSourceRowIds)].sort()), `invalid O-10 joint witness:${row.row_id}`);
        for (const jointId of witness.jointSourceRowIds) {
          const joint = sourceById.get(jointId)?.mapping;
          require(joint?.primary === row.mapping.primary && joint?.stage === row.mapping.stage, `incompatible O-10 joint witness:${row.row_id}:${jointId}`);
        }
        return { ...witness, scenarioId };
      });
    } else if (row.mapping !== undefined && AP_OWNED_EXCLUSIONS.has(row.mapping.primary)) {
      disposition = "AP_OWNED_EXCLUDED"; primary = row.mapping.primary;
    } else if (row.mapping !== undefined) {
      disposition = "TRANSCRIPT_PROFILE_UNREACHABLE"; primary = row.mapping.primary;
    } else {
      disposition = "TRANSCRIPT_PROFILE_UNREACHABLE"; primary = row.forbidden_identifier;
    }
    return { disposition, primary, rowId: row.row_id, witnesses: rowWitnesses };
  });
  require(JSON.stringify(canonicalValue(coverage.o10.sourceRows)) === JSON.stringify(canonicalValue(expectedSourceRows)), "O-10 source-row partition mismatch");
}
function parseArgs() { const args = process.argv.slice(2), values = {}; for (let i = 0; i < args.length; i += 2) values[args[i]] = args[i + 1]; for (const key of ["--repo-root", "--corpus", "--output"]) require(values[key], `missing ${key}`); return values; }

function baseJson(repoRoot, path) {
  return JSON.parse(execFileSync("git", ["show", `${BASE_SHA}:${path}`], { cwd: repoRoot, encoding: "utf8" }));
}
function baseText(repoRoot, path) {
  require(typeof path === "string" && !path.startsWith("/") && !path.split(/[\\/]/).includes(".."), `unsafe Base path:${path}`);
  return execFileSync("git", ["show", `${BASE_SHA}:${path}`], { cwd: repoRoot, encoding: "utf8" });
}

function mutationReport(args, corpus, valid, invalid, apExpectations, scenarios, expected, model) {
  const registry = loadCanonical(resolve(corpus, "adversarial-mutations.json")).records;
  const manifest = loadCanonical(resolve(corpus, "manifest.json"));
  const vectors = new Map([...valid, ...invalid, ...apExpectations].map(record => [record.id, record]));
  const expectedById = new Map(expected.map(record => [record.id, record]));
  const scenarioByTrace = new Map(scenarios.map(record => [`trace-${record.id}`, record]));
  const transitions = new Map(model.state_models.flatMap(machine => machine.transitions.map(transition => [`${machine.id}:${transition.id}`, transition])));
  const o07 = new Set(baseJson(resolve(args["--repo-root"]), "tools/causal-flow-simulator/o07/required_atom_instances_v1.json").rows.map(row => row.atom_instance_id));
  const envelope = baseJson(resolve(args["--repo-root"]), "tools/causal-flow-simulator/o08/resource-envelope.candidate.json");
  const o08 = new Set(Object.entries(envelope.entries).filter(([, entry]) => ["C03_SEMANTIC_LIMIT", "C03_ACTIVATION_CAPABILITY_INPUT", "C03_EXPLICIT_ZERO_OR_UNSUPPORTED"].includes(entry.role)).map(([id]) => id));
  const excludedO08 = new Set(Object.entries(envelope.entries).filter(([, entry]) => ["POST_C03_LAYER_PROFILE", "EVIDENCE_ONLY"].includes(entry.role)).map(([id]) => id));
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
      corrupted.expected.firstFailingStage = "FINAL_AFTER_S6";
      detected = evaluate(corrupted).stage !== corrupted.expected.firstFailingStage;
    } else if (mutation.detector === "INDEPENDENT_EXPECTED_OUTCOME_MISMATCH") {
      const corrupted = structuredClone(vectors.get(mutation.generatedTargetId));
      corrupted.expected.localOutcome = "APPLIED";
      detected = evaluate(corrupted).localOutcome !== corrupted.expected.localOutcome;
    } else if (mutation.detector === "INDEPENDENT_EXPECTED_TRACE_MISMATCH") {
      const scenario = scenarioByTrace.get(mutation.generatedTargetId), computed = computeTrace(scenario, vectors, transitions);
      const corrupted = structuredClone(expectedById.get(mutation.generatedTargetId));
      corrupted.steps[0].localOutcome = "INVALID";
      detected = JSON.stringify(canonicalValue(computed)) !== JSON.stringify(canonicalValue(corrupted));
    } else if (mutation.detector === "INDEPENDENT_EXPECTED_DEPENDENCY_STATUS_MISMATCH") {
      const scenario = scenarioByTrace.get(mutation.generatedTargetId), computed = computeTrace(scenario, vectors, transitions);
      const corrupted = structuredClone(expectedById.get(mutation.generatedTargetId));
      corrupted.steps[0].dependencyStatus = "SATISFIED";
      detected = JSON.stringify(canonicalValue(computed)) !== JSON.stringify(canonicalValue(corrupted));
    } else if (mutation.detector === "INVARIANT_WITNESS_TRACE_MISMATCH") {
      const scenario = structuredClone(scenarioByTrace.get(mutation.generatedTargetId));
      scenario.steps[0].inputVectorId = mutation.replacementVectorId;
      detected = JSON.stringify(canonicalValue(computeTrace(scenario, vectors, transitions))) !== JSON.stringify(canonicalValue(expectedById.get(mutation.generatedTargetId)));
    } else if (mutation.detector === "MANIFEST_DIGEST_MISMATCH") {
      const mutated = structuredClone(manifest), row = mutated.files.find(item => item.path === mutation.generatedTargetId);
      row.sha256 = mutated.files.find(item => item.path !== row.path).sha256;
      try { validateFileManifest(corpus, mutated); } catch { detected = true; }
    } else if (mutation.detector === "O07_EXACT_RELATION_SET") {
      const target = mutation.generatedTargetId, mutated = structuredClone(manifest);
      mutated.coverage.o07.coveredRelationIds = mutated.coverage.o07.coveredRelationIds.filter(value => value !== target);
      try { validateSourceCoverage(mutated.coverage, o07, o08, excludedO08, o10); } catch { detected = o07.has(target); }
    } else if (mutation.detector === "O08_EXACT_DIMENSION_SET") {
      const target = mutation.generatedTargetId, mutated = structuredClone(manifest);
      mutated.coverage.o08.participatingDimensions = mutated.coverage.o08.participatingDimensions.filter(value => value !== target);
      try { validateSourceCoverage(mutated.coverage, o07, o08, excludedO08, o10); } catch { detected = o08.has(target); }
    } else if (mutation.detector === "O10_EXACT_SOURCE_ROW_SET") {
      const target = mutation.generatedTargetId, mutated = structuredClone(manifest);
      mutated.coverage.o10.coveredSourceRowIds = mutated.coverage.o10.coveredSourceRowIds.filter(value => value !== target);
      try { validateSourceCoverage(mutated.coverage, o07, o08, excludedO08, o10); } catch { detected = o10.has(target); }
    } else if (mutation.detector === "SOURCE_O10_CLASS_MEMBERSHIP") {
      try { o10Result("APPLIED", "FINAL_AFTER_S6"); } catch { detected = true; }
    } else if (mutation.detector === "SOURCE_O10_APPLICABILITY") {
      try { o10Result("LENGTH_MISMATCH", "EVENT_LOCAL"); } catch { detected = true; }
    } else if (mutation.detector === "SOURCE_O10_PRECEDENCE") {
      detected = selectO10Result([
        ["COMMITMENT_MISMATCH", "S3_KERNEL_STRUCTURAL"],
        ["LENGTH_MISMATCH", "S3_KERNEL_STRUCTURAL"],
      ]).localOutcome === "LENGTH_MISMATCH";
    } else if (mutation.detector === "SOURCE_CHECKPOINT_BEFORE_PROTECTED_WORK") {
      const corrupted = structuredClone(vectors.get(mutation.generatedTargetId));
      corrupted.admissionContext ??= {};
      corrupted.admissionContext.checkpointEvidenceReferences = ["00".repeat(32)];
      const observed = evaluate(corrupted);
      detected = observed.localOutcome === "CURRENT_OBJECT_OUT_OF_PROFILE"
        && observed.signatureVerification === "NOT_EVALUATED"
        && observed.commitmentVerification === "NOT_PRESENT";
    } else if (mutation.detector === "SOURCE_GEOMETRY_PREDICATE") {
      detected = geometryPredicateMutantIsKilled(mutation.predicateNumber);
    } else if (mutation.detector === "SOURCE_R6_CLASSIFICATION") {
      const observed = evaluate(vectors.get(mutation.generatedTargetId));
      detected = observed.localOutcome === "CURRENT_OBJECT_OUT_OF_PROFILE"
        && observed.stage === "S3_KERNEL_STRUCTURAL"
        && observed.signatureVerification === "NOT_EVALUATED"
        && [1, 3, 4, 5, 6, 7].every(number => observed[`geometryPredicate${number}`] === "PASS");
    } else if (mutation.detector === "SOURCE_R5_LAYERING") {
      const observed = evaluate(vectors.get(mutation.generatedTargetId));
      detected = transitionInputIsCompatible(observed)
        && observed.apAuthorityResult === "AP_FOLD_NOT_EXECUTED"
        && observed.outcomeEvaluated === false
        && !Object.hasOwn(observed, "localOutcome")
        && !Object.hasOwn(observed, "remoteClass");
    }
    require(detected, `surviving mutation:${mutation.id}`); killed.push(mutation.id);
  }
  killed.sort();
  return { killDigest: hex(hash(Buffer.from(`${killed.join("\n")}\n`, "utf8"))), killed: killed.length, result: "PASS" };
}

function main() {
  const args = parseArgs(), corpus = resolve(args["--corpus"]);
  const valid = loadCanonical(resolve(corpus, "valid-transcript-vectors.json")).records;
  const invalidDocument = loadCanonical(resolve(corpus, "invalid-transcript-vectors.json"));
  const invalid = invalidDocument.records, apExpectations = invalidDocument.apExpectationOnlyRecords;
  for (const record of valid) { const observed = evaluate(record); require(transitionInputIsCompatible(observed), `valid vector rejected:${record.id}:${observed.localOutcome}:${observed.stage}:${observed.commitmentVerification}`); }
  for (const record of invalid) { const observed = evaluate(record); require(observed.localOutcome === record.expected.localOutcome && observed.stage === record.expected.firstFailingStage, `invalid mismatch:${record.id}`); require(observed.preStateDigest === observed.postStateDigest && observed.externalEffects.length === 0, `invalid side effect:${record.id}`); }
  for (const record of apExpectations) require(transitionInputIsCompatible(evaluate(record)), `AP-only vector rejected:${record.id}`);
  const scenarios = loadCanonical(resolve(corpus, "state-machine-scenarios.json")).records;
  const expected = loadCanonical(resolve(corpus, "expected-traces.json")).records;
  const manifest = loadCanonical(resolve(corpus, "manifest.json"));
  const mutations = loadCanonical(resolve(corpus, "adversarial-mutations.json")).records;
  const model = JSON.parse(readFileSync(resolve(args["--repo-root"], "docs/protocol/review/styx-app-kernel-v0-review-model.json"), "utf8"));
  validateCorpusRelations(resolve(args["--repo-root"]), manifest, model, scenarios, expected, mutations, valid, invalid, apExpectations);
  if (args["--mode"] === "mutations") {
    writeFileSync(resolve(args["--output"]), canonical(mutationReport(args, corpus, valid, invalid, apExpectations, scenarios, expected, model)), { flag: "wx" });
    return;
  }
  const transitions = new Map(model.state_models.flatMap(machine => machine.transitions.map(transition => [`${machine.id}:${transition.id}`, transition])));
  const vectors = new Map([...valid, ...invalid, ...apExpectations].map(record => [record.id, record]));
  const expectedByScenario = new Map(expected.map(record => [record.scenarioId, record]));
  const computedTraces = [];
  for (const scenario of scenarios) {
    const computed = computeTrace(scenario, vectors, transitions), oracle = expectedByScenario.get(scenario.id);
    require(JSON.stringify(canonicalValue(computed)) === JSON.stringify(canonicalValue(oracle)), `trace mismatch:${scenario.id}`);
    computedTraces.push(computed);
  }
  require(scenarios.length === expected.length, "unexpected expected trace");
  const o07 = new Set(baseJson(resolve(args["--repo-root"]), "tools/causal-flow-simulator/o07/required_atom_instances_v1.json").rows.map(row => row.atom_instance_id));
  const envelope = baseJson(resolve(args["--repo-root"]), "tools/causal-flow-simulator/o08/resource-envelope.candidate.json");
  const o08 = new Set(Object.entries(envelope.entries).filter(([, entry]) => ["C03_SEMANTIC_LIMIT", "C03_ACTIVATION_CAPABILITY_INPUT", "C03_EXPLICIT_ZERO_OR_UNSUPPORTED"].includes(entry.role)).map(([id]) => id));
  const excludedO08 = new Set(Object.entries(envelope.entries).filter(([, entry]) => ["POST_C03_LAYER_PROFILE", "EVIDENCE_ONLY"].includes(entry.role)).map(([id]) => id));
  const o10 = new Set(baseJson(resolve(args["--repo-root"]), "tools/causal-flow-simulator/o10/source-inventory.json").rows.map(row => row.row_id));
  validateSourceCoverage(manifest.coverage, o07, o08, excludedO08, o10);
  validateFileManifest(corpus, manifest);
  const names = ["adversarial-mutations.json", "expected-traces.json", "invalid-transcript-vectors.json", "manifest.json", "state-machine-scenarios.json", "valid-transcript-vectors.json"];
  const corpusDigest = hex(hash(...names.map(name => readFileSync(resolve(corpus, name)))));
  const observations = computedTraces.flatMap(trace => trace.steps.map(step => {
    const observation = { id: `${trace.scenarioId}:${step.step}`,
      ...Object.fromEntries(SEMANTIC_OBSERVATION_FIELDS.map(field => [field, step[field]])) };
    for (const field of OPTIONAL_SEMANTIC_OBSERVATION_FIELDS) {
      const present = Object.hasOwn(step, field);
      observation[`${field}Present`] = present;
      if (present) observation[field] = step[field];
    }
    return observation;
  })).sort((left, right) => left.id.localeCompare(right.id));
  const report = { corpusDigest, invalidVectors: invalid.length, observations, result: "PASS", scenarios: scenarios.length,
    traceDigest: hex(hash(readFileSync(resolve(corpus, "expected-traces.json")))), validVectors: valid.length };
  writeFileSync(resolve(args["--output"]), canonical(report), { flag: "wx" });
}

try { main(); } catch (error) { process.stderr.write(`c03_node_failure=${error.message}\n`); process.exitCode = 2; }
