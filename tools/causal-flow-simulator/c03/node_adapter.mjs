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
const ED_P = (1n << 255n) - 19n;
const ED_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const ED_D = ((-121665n * modPow(121666n, ED_P - 2n, ED_P)) % ED_P + ED_P) % ED_P;
const ED_SQRT_M1 = modPow(2n, (ED_P - 1n) / 4n, ED_P);
const BASE_SHA = "a4fa1286b57b2ee79b3c580fdce0d1fb3bf9cd40";
const O08_LIMITS = Object.freeze({
  AP_TRANSITION_BLOCK_OCTETS: 4096,
  CHUNKS_PER_CONTENT: 64,
  CONTENT_EXACT_OCTETS: 262144,
  FRAMING_OBJECT_OCTETS: 8192,
  GENESIS_BODY_OCTETS: 8192,
  GENESIS_POLICY_OCTETS: 4096,
  PARENTS_PER_EVENT: 8,
  SEQUENCE_VALUE: 4095,
  VERIFICATION_KEY_OCTETS: 32,
});
const O08_CHUNK_OCTETS = new Set([4096, 16384]);
const PRODUCED_K_PRIMARIES = new Set(["COMMITMENT_MISMATCH", "CONTEXT_CAPACITY_EXHAUSTED", "CREDENTIAL_BINDING_MISMATCH", "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED", "CURRENT_OBJECT_OUT_OF_PROFILE", "DEPENDENCY_DEFERRED", "DUPLICATE", "FORK_EVIDENCE", "INVALID", "LENGTH_MISMATCH", "OPENING_MISSING", "PENDING_ANCESTOR", "PENDING_OPENING", "REFERENCE_COLLISION_UNSUPPORTED", "STRUCTURAL_REJECTION", "UNRESOLVABLE_CREDENTIAL", "UNRESOLVED_CREDENTIAL_BINDING"]);
const AP_OWNED_EXCLUSIONS = new Set(["APPLIED", "AUTHENTIC_BUT_UNAUTHORIZED", "AUTHORITY_PROJECTION_UNAVAILABLE", "LINEAGE_QUARANTINED", "POST_REVOCATION"]);
const TRANSCRIPT_PROFILE_UNREACHABLE = new Set(["PROFILE_ACTIVATION_UNSUPPORTED", "REMOVAL_INAPPLICABLE", "STALE_EVIDENCE"]);
const O10_TAXONOMY = JSON.parse(readFileSync(new URL("../o10/outcome-taxonomy.json", import.meta.url), "utf8"));
const O10_BY_ID = new Map(O10_TAXONOMY.primaries.map(row => [row.id, row]));

class ProtocolError extends Error {
  constructor(message, stage = "S3_KERNEL_STRUCTURAL", observations = {}, admitted = false) {
    super(message); this.admitted = admitted; this.stage = stage; this.observations = observations;
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
  const body = new Reader(outer.take(bodyLength, "body")); outer.finish("transcript");
  const protocol = body.integer(2, "protocol");
  const profile = body.integer(4, "profile"); const version = body.integer(4, "profile_version");
  const context = body.take(32, "context"); const suite = body.integer(2, "signature_suite");
  const key = body.opaque("root_key"); const policy = body.opaque("initial_authority_policy"); body.finish("body");
  require(protocol === 1 && profile === 1 && version === 1 && suite === 1 && key.length === 32 && policy.length > 0, "GENESIS_FIELDS_INVALID");
  const fields = { applicationProfileId: profile, applicationProfileVersion: version,
    contextIdentifierHex: hex(context), initialAuthorityPolicyHex: hex(policy), rootVerificationKeyHex: hex(key) };
  require(encodeGenesis(fields).equals(transcript), "NONCANONICAL_REENCODING");
  return fields;
}

function genesisProfileFailure(transcript, fields) {
  const bodyLength = transcript.readUInt32BE(16);
  if (bodyLength > O08_LIMITS.GENESIS_BODY_OCTETS) return new ProtocolError("GENESIS_BODY_OCTETS_LIMIT");
  if (Buffer.from(fields.initialAuthorityPolicyHex, "hex").length > O08_LIMITS.GENESIS_POLICY_OCTETS) return new ProtocolError("GENESIS_POLICY_OCTETS_LIMIT");
  return null;
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
  const body = new Reader(outer.take(bodyLength, "body")); outer.finish("transcript");
  const protocol = body.integer(2, "protocol"), profile = body.integer(4, "profile"), version = body.integer(4, "profile_version");
  const context = body.take(32, "context"), objectKind = body.integer(2, "object_kind"), roleCode = body.integer(1, "role");
  const eventType = body.integer(4, "event_type"), schemaId = body.integer(4, "schema"), schemaVersion = body.integer(4, "schema_version");
  const transition = body.opaque("transition_block");
  const credential = body.take(32, "credential"), sequence = body.integer(8, "sequence");
  const presence = body.integer(1, "predecessor_presence"); require([0, 1].includes(presence), "PREDECESSOR_PRESENCE_INVALID");
  const predecessor = presence ? body.take(32, "predecessor") : null; const parentCount = body.integer(4, "parent_count");
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
    Object.assign(content, { commitmentHex: hex(commitment), contentType, geometryPredicateResults: predicateResults, shape }); if (geometry !== null) content.geometry = geometry;
  }
  const role = ({ 0: "ORDINARY", 1: "REMOVAL", 2: "CREDENTIAL" })[roleCode];
  const fields = { applicationProfileId: profile, applicationProfileVersion: version, authorSequence: sequence, causalParents: parents.map(hex), content,
    contextIdentifierHex: hex(context), credentialIdentifierHex: hex(credential), directPredecessorHex: predecessor ? hex(predecessor) : null,
    eventRole: role, eventTypeId: eventType, genesisReferenceHex: hex(genesis), schemaId, schemaVersion, transitionBlockHex: hex(transition) };
  // Parsing proves canonical framing. A non-zero AP tuple that differs from
  // the receiver-selected tuple is classified by eventProfileFailures rather
  // than being rewritten as malformed transcript bytes.
  require(protocol === 1 && profile > 0 && version > 0 && objectKind === 1 && Math.min(eventType, schemaId, schemaVersion) > 0, "UNSUPPORTED_PROFILE_OR_REGISTRY");
  if (role === "REMOVAL") { const target = body.take(32, "target_event"); fields.tail = { targetCommitmentHex: hex(body.opaque("target_commitment")), targetEventReferenceHex: hex(target) }; }
  else if (role === "CREDENTIAL") {
    const kindCode = body.integer(1, "control_kind"), kind = ({ 1: "GRANT", 2: "REVOKE", 3: "ROTATE", 4: "RECOVER", 5: "POLICY", 6: "CLOSURE" })[kindCode];
    require(kind !== undefined, "CONTROL_KIND_UNKNOWN"); const tail = { kind };
    if (kind === "GRANT") {
      require(body.integer(2, "grantee_suite") === 1, "GRANTEE_SUITE_UNSUPPORTED");
      const granteeKey = body.opaque("grantee_key");
      require(granteeKey.length >= O08_LIMITS.VERIFICATION_KEY_OCTETS, "GRANTEE_KEY_LENGTH_INVALID");
      tail.granteeVerificationKeyHex = hex(granteeKey);
    }
    if (kind === "REVOKE") tail.targetCredentialHex = hex(body.take(32, "target_credential"));
    if (kind === "ROTATE") { tail.retiringCredentialHex = hex(body.take(32, "retiring_credential")); tail.replacementGrantHex = hex(body.take(32, "replacement_grant")); }
    if (kind === "RECOVER") { tail.retiredCredentialHex = hex(body.take(32, "retired_credential")); tail.recoveryGrantHex = hex(body.take(32, "recovery_grant")); }
    fields.tail = tail;
  } else require(role === "ORDINARY", "EVENT_ROLE_UNKNOWN");
  body.finish("body"); require(encodeEvent(fields).equals(transcript), "NONCANONICAL_REENCODING"); return fields;
}

function eventProfileFailures(transcript, fields) {
  if (fields.applicationProfileId !== 1 || fields.applicationProfileVersion !== 1) return [new ProtocolError("APPLICATION_PROFILE_MISMATCH"), null];
  const bodyLength = transcript.readUInt32BE(16);
  if (bodyLength > O08_LIMITS.FRAMING_OBJECT_OCTETS) return [new ProtocolError("FRAMING_OBJECT_OCTETS_LIMIT"), null];
  if (Buffer.from(fields.transitionBlockHex, "hex").length > O08_LIMITS.AP_TRANSITION_BLOCK_OCTETS) return [new ProtocolError("AP_TRANSITION_BLOCK_OCTETS_LIMIT"), null];
  if (fields.eventRole === "CREDENTIAL" && fields.tail?.kind === "GRANT" && Buffer.from(fields.tail.granteeVerificationKeyHex, "hex").length > O08_LIMITS.VERIFICATION_KEY_OCTETS) return [new ProtocolError("VERIFICATION_KEY_OCTETS_LIMIT"), null];
  if (fields.authorSequence > O08_LIMITS.SEQUENCE_VALUE) return [new ProtocolError("SEQUENCE_VALUE_LIMIT"), null];
  const content = fields.content;
  const geometry = content.geometry ?? null;
  const observations = content.geometryPredicateResults ?? {};
  if (geometry !== null && !O08_CHUNK_OCTETS.has(geometry.chunkSize)) return [new ProtocolError("CHUNK_OCTETS_LIMIT", "S3_KERNEL_STRUCTURAL", observations), null];
  if (geometry !== null && geometry.chunkCount > O08_LIMITS.CHUNKS_PER_CONTENT) return [new ProtocolError("CHUNKS_PER_CONTENT_LIMIT", "S3_KERNEL_STRUCTURAL", observations), null];
  if (content.exactLength > O08_LIMITS.CONTENT_EXACT_OCTETS) return [new ProtocolError("CONTENT_EXACT_OCTETS_LIMIT", "S3_KERNEL_STRUCTURAL", observations), null];
  if (fields.causalParents.length > O08_LIMITS.PARENTS_PER_EVENT) return [null, new ProtocolError("PARENTS_PER_EVENT_LIMIT", "S4_GRAPH_ADMISSION")];
  return [null, null];
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

function mod(value) {
  const reduced = value % ED_P;
  return reduced < 0n ? reduced + ED_P : reduced;
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let addend = ((base % modulus) + modulus) % modulus;
  let value = exponent;
  while (value > 0n) {
    if ((value & 1n) === 1n) result = (result * addend) % modulus;
    addend = (addend * addend) % modulus;
    value >>= 1n;
  }
  return result;
}

const ED_IDENTITY = Object.freeze({ x: 0n, y: 1n, z: 1n, t: 0n });
const ed25519EvidenceCounts = { boundaryInvocations: 0, equationInvocations: 0 };

function edPoint(x, y, z = 1n, t = undefined) {
  return { x: mod(x), y: mod(y), z: mod(z), t: mod(t ?? x * y) };
}

function edAdd(left, right) {
  const a = mod((left.y - left.x) * (right.y - right.x));
  const b = mod((left.y + left.x) * (right.y + right.x));
  const c = mod(2n * ED_D * left.t * right.t);
  const d = mod(2n * left.z * right.z);
  const e = mod(b - a), f = mod(d - c), g = mod(d + c), h = mod(b + a);
  return edPoint(e * f, g * h, f * g, e * h);
}

function edDouble(point) {
  const a = mod(point.x * point.x), b = mod(point.y * point.y);
  const c = mod(2n * point.z * point.z), d = mod(-a);
  const e = mod((point.x + point.y) ** 2n - a - b);
  const g = mod(d + b), f = mod(g - c), h = mod(d - b);
  return edPoint(e * f, g * h, f * g, e * h);
}

function edScalarMult(scalar, point) {
  let result = ED_IDENTITY, addend = point, value = scalar;
  while (value > 0n) {
    if ((value & 1n) === 1n) result = edAdd(result, addend);
    addend = edDouble(addend);
    value >>= 1n;
  }
  return result;
}

function edEqual(left, right) {
  return mod(left.x * right.z - right.x * left.z) === 0n
    && mod(left.y * right.z - right.y * left.z) === 0n;
}

function littleEndianInteger(bytes) {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index]);
  }
  return value;
}

function edDecode(encoded, enforceCanonical = true) {
  if (encoded.length !== 32) throw new ProtocolError("SIGNATURE_POINT_LENGTH");
  const raw = littleEndianInteger(encoded);
  const sign = raw >> 255n;
  const y = raw & ((1n << 255n) - 1n);
  if (enforceCanonical && y >= ED_P) throw new ProtocolError("SIGNATURE_POINT_NONCANONICAL");
  const y2 = mod(y * y);
  const value = mod((y2 - 1n) * modPow(ED_D * y2 + 1n, ED_P - 2n, ED_P));
  let x = modPow(value, (ED_P + 3n) / 8n, ED_P);
  if (mod(x * x) !== value) x = mod(x * ED_SQRT_M1);
  if (mod(x * x) !== value || (x === 0n && sign === 1n)) {
    throw new ProtocolError("SIGNATURE_POINT_INVALID");
  }
  if ((x & 1n) !== sign) x = mod(-x);
  return edPoint(x, y);
}

function ed25519VerifyDetailed(publicKey, signature, message) {
  if (publicKey.length !== 32) return { accepted: false, equationInvocations: 0, guardCode: "PUBLIC_KEY_LENGTH" };
  if (signature.length !== 64) return { accepted: false, equationInvocations: 0, guardCode: "SIGNATURE_LENGTH" };
  let pointA, pointR;
  try { pointA = edDecode(publicKey); }
  catch (error) {
    return { accepted: false, equationInvocations: 0, guardCode: error.message === "SIGNATURE_POINT_NONCANONICAL" ? "NON_CANONICAL_POINT" : "OFF_CURVE_POINT" };
  }
  try { pointR = edDecode(signature.subarray(0, 32)); }
  catch (error) {
    return { accepted: false, equationInvocations: 0, guardCode: error.message === "SIGNATURE_POINT_NONCANONICAL" ? "NON_CANONICAL_POINT" : "OFF_CURVE_POINT" };
  }
  const scalar = littleEndianInteger(signature.subarray(32));
  if (scalar >= ED_L) return { accepted: false, equationInvocations: 0, guardCode: "NON_CANONICAL_SCALAR" };
  if (edEqual(pointA, ED_IDENTITY) || !edEqual(edScalarMult(ED_L, pointA), ED_IDENTITY)) {
    return { accepted: false, equationInvocations: 0, guardCode: "PUBLIC_KEY_NOT_PRIME_ORDER" };
  }
  if (edEqual(pointR, ED_IDENTITY) || !edEqual(edScalarMult(ED_L, pointR), ED_IDENTITY)) {
    return { accepted: false, equationInvocations: 0, guardCode: "R_NOT_PRIME_ORDER" };
  }
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  let equationInvocations = 0;
  const selectedEquation = () => {
    equationInvocations += 1;
    return verifySignature(null, message, createPublicKey({ key: Buffer.concat([prefix, publicKey]), format: "der", type: "spki" }), signature);
  };
  try {
    const accepted = selectedEquation();
    return { accepted, equationInvocations, guardCode: "GUARD_ACCEPTED" };
  } catch {
    return { accepted: false, equationInvocations, guardCode: "GUARD_ACCEPTED" };
  }
}

function ed25519Verify(publicKey, signature, message) {
  const observed = ed25519VerifyDetailed(publicKey, signature, message);
  ed25519EvidenceCounts.boundaryInvocations += 1;
  ed25519EvidenceCounts.equationInvocations += observed.equationInvocations;
  return observed.accepted;
}

function evaluate(record) {
  const transcript = Buffer.from(record.transcriptHex, "hex"), state = hex(hash(Buffer.from("styx-c03/evaluation/initial")));
  const result = { apAuthorityResult: "AP_FOLD_NOT_EXECUTED", commitmentMatchVerification: "NOT_EVALUATED", commitmentVerification: "NOT_EVALUATED", externalEffects: [], ...geometryObservations(),
    kBindingAdmission: "ADMITTED", outcomeEvaluated: false, postStateDigest: null, preStateDigest: state,
    referenceVerification: "NOT_REACHED", signatureVerification: "NOT_EVALUATED", stage: "FINAL_AFTER_S6", suppliedLengthVerification: "NOT_EVALUATED", transcriptVerification: "VALID" };
  const reject = (outcome, stage, transcriptStatus = "VALID", admitted = false) => Object.assign(result, selectO10Result(
    Array.isArray(outcome) ? outcome : [[outcome, stage ?? O10_BY_ID.get(outcome)?.stage.split("|")[0]]],
  ), {
    apAuthorityResult: "NOT_REACHED",
    kBindingAdmission: admitted ? "ADMITTED" : "REJECTED", outcomeEvaluated: true,
    postStateDigest: state, transcriptVerification: transcriptStatus,
  });
  let fields, reference, expected, s3ProfileFailure = null, s4ProfileFailure = null;
  try {
    if (record.kind === "GENESIS") { fields = parseGenesis(transcript); reference = hex(framedHash(DOMAINS.genesisReference, transcript)); expected = record.genesisReferenceHex; s3ProfileFailure = genesisProfileFailure(transcript, fields); }
    else if (record.kind === "APPLICATION_EVENT") { fields = parseEvent(transcript); reference = hex(framedHash(DOMAINS.eventReference, transcript)); expected = record.eventReferenceHex; [s3ProfileFailure, s4ProfileFailure] = eventProfileFailures(transcript, fields); }
    else throw new ProtocolError("OBJECT_KIND_UNKNOWN");
  } catch (error) {
    if (error instanceof ProtocolError) Object.assign(result, error.observations);
    return reject("STRUCTURAL_REJECTION", error instanceof ProtocolError ? error.stage : "S3_KERNEL_STRUCTURAL", "REJECTED");
  }
  const admission = record.admissionContext ?? {};
  if (admission === null || Array.isArray(admission) || typeof admission !== "object") return reject("STRUCTURAL_REJECTION", "S3_KERNEL_STRUCTURAL");
  if (record.kind === "APPLICATION_EVENT") {
    if (fields.content.class === "NONE") {
      for (let index = 1; index <= 7; index += 1) result[`geometryPredicate${index}`] = "NOT_APPLICABLE";
      result.commitmentVerification = "NOT_PRESENT";
      result.suppliedLengthVerification = "NOT_APPLICABLE";
      result.commitmentMatchVerification = "NOT_APPLICABLE";
    } else Object.assign(result, fields.content.geometryPredicateResults);
  } else {
    for (let index = 1; index <= 7; index += 1) result[`geometryPredicate${index}`] = "NOT_APPLICABLE";
    result.commitmentVerification = "NOT_PRESENT";
    result.suppliedLengthVerification = "NOT_APPLICABLE";
    result.commitmentMatchVerification = "NOT_APPLICABLE";
  }
  if (reference !== expected) {
    result.referenceVerification = "REJECTED";
    const collision = new Set(admission.seenEventReferences ?? []).has(expected);
    return reject(collision ? "REFERENCE_COLLISION_UNSUPPORTED" : "INVALID", "S3_KERNEL_STRUCTURAL");
  }
  result.referenceVerification = "VALID";
  if ((admission.checkpointEvidenceReferences ?? []).length > 0) return reject("CURRENT_OBJECT_OUT_OF_PROFILE", "S3_KERNEL_STRUCTURAL");
  if (s3ProfileFailure !== null) { Object.assign(result, s3ProfileFailure.observations); return reject("CURRENT_OBJECT_OUT_OF_PROFILE", s3ProfileFailure.stage); }
  try { if (!ed25519Verify(Buffer.from(record.binding.verificationKeyHex, "hex"), Buffer.from(record.signatureHex, "hex"), transcript)) { result.signatureVerification = "REJECTED"; return reject("INVALID", "S3_KERNEL_STRUCTURAL"); } } catch { result.signatureVerification = "REJECTED"; return reject("INVALID", "S3_KERNEL_STRUCTURAL"); }
  result.signatureVerification = "VALID";
  if (record.kind === "APPLICATION_EVENT") {
    if (record.binding.contextIdentifierHex !== fields.contextIdentifierHex || record.binding.credentialIdentifierHex !== fields.credentialIdentifierHex) return reject("CREDENTIAL_BINDING_MISMATCH", "S3_KERNEL_STRUCTURAL");
    if (fields.content.class !== "NONE") {
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
  }
  if ((admission.admittedEventReferences ?? []).includes(reference)) return reject("DUPLICATE", "S3_KERNEL_STRUCTURAL", "VALID", true);
  if (s4ProfileFailure !== null) return reject("CONTEXT_CAPACITY_EXHAUSTED", s4ProfileFailure.stage);
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
  if (s4ProfileFailure !== null) return reject("CONTEXT_CAPACITY_EXHAUSTED", s4ProfileFailure.stage);
  result.postStateDigest = hex(hash(Buffer.from(state, "hex"), Buffer.from(reference, "hex"))); return result;
}

function evaluateKAdmissionScenario(genesisRecord, records, knownForkReferences = new Set()) {
  require(genesisRecord?.kind === "GENESIS", "PREACCEPTED_GENESIS_KIND_INVALID");
  const genesisTranscript = Buffer.from(genesisRecord.transcriptHex, "hex");
  const genesisFields = parseGenesis(genesisTranscript);
  const genesisReference = hex(framedHash(DOMAINS.genesisReference, genesisTranscript));
  require(genesisReference === genesisRecord.genesisReferenceHex, "PREACCEPTED_GENESIS_REFERENCE_INVALID");
  const genesisKey = Buffer.from(genesisFields.rootVerificationKeyHex, "hex");
  require(ed25519Verify(genesisKey, Buffer.from(genesisRecord.signatureHex, "hex"), genesisTranscript), "PREACCEPTED_GENESIS_SIGNATURE_INVALID");

  const context = genesisFields.contextIdentifierHex;
  const admitted = new Map();
  const bindings = new Map([[genesisReference, {
    grantReferenceHex: null,
    issuerCredentialHex: null,
    verificationKeyHex: genesisFields.rootVerificationKeyHex,
  }]]);
  const observations = [];
  const ancestors = reference => {
    const values = new Set(), frontier = [reference];
    while (frontier.length > 0) {
      const current = frontier.pop();
      if (values.has(current)) continue;
      values.add(current);
      const event = admitted.get(current);
      if (event === undefined) continue;
      if (event.fields.directPredecessorHex !== null) frontier.push(event.fields.directPredecessorHex);
      frontier.push(...event.fields.causalParents);
    }
    values.delete(reference);
    return values;
  };

  for (const record of records) {
    require(record?.kind === "APPLICATION_EVENT", "SCENARIO_EVENT_KIND_INVALID");
    const transcript = Buffer.from(record.transcriptHex, "hex");
    const fields = parseEvent(transcript);
    const reference = hex(framedHash(DOMAINS.eventReference, transcript));
    require(reference === record.eventReferenceHex, "SCENARIO_EVENT_REFERENCE_INVALID");
    if (fields.contextIdentifierHex !== context || fields.genesisReferenceHex !== genesisReference) {
      throw new ProtocolError("CREDENTIAL_BINDING_MISMATCH", "S3_KERNEL_STRUCTURAL");
    }

    const actor = fields.credentialIdentifierHex, binding = bindings.get(actor);
    require(binding !== undefined, "UNRESOLVED_CREDENTIAL_BINDING");
    const localRecord = structuredClone(record);
    delete localRecord.admissionContext;
    localRecord.binding = {
      contextIdentifierHex: context,
      credentialIdentifierHex: actor,
      verificationKeyHex: binding.verificationKeyHex,
    };
    const localObservation = evaluate(localRecord);
    if (!transitionInputIsCompatible(localObservation)) {
      throw new ProtocolError(
        localObservation.localOutcome ?? "INVALID",
        localObservation.stage ?? "S3_KERNEL_STRUCTURAL",
        {},
        localObservation.kBindingAdmission === "ADMITTED",
      );
    }
    const predecessor = fields.directPredecessorHex, parents = fields.causalParents;
    const sameSlotReferences = [...admitted.entries()]
      .filter(([, candidate]) => candidate.fields.credentialIdentifierHex === actor
        && candidate.fields.authorSequence === fields.authorSequence)
      .map(([admittedReference]) => admittedReference);
    if (sameSlotReferences.length > 0 && !(knownForkReferences.has(reference)
      && sameSlotReferences.every(admittedReference => knownForkReferences.has(admittedReference)))) {
      throw new ProtocolError("FORK_EVIDENCE", "EVENT_LOCAL", {}, true);
    }
    const dependencies = new Set(parents);
    if (predecessor !== null) dependencies.add(predecessor);
    if (![...dependencies].every(value => admitted.has(value))) {
      throw new ProtocolError("DEPENDENCY_DEFERRED", "S4_GRAPH_ADMISSION");
    }
    if (fields.authorSequence === 0) require(predecessor === null, "STRUCTURAL_REJECTION");
    else {
      const previous = admitted.get(predecessor);
      require(previous !== undefined
        && previous.fields.credentialIdentifierHex === actor
        && previous.fields.authorSequence + 1 === fields.authorSequence,
      "STRUCTURAL_REJECTION");
    }
    const predecessorAncestors = predecessor === null ? new Set() : ancestors(predecessor);
    require(!parents.some(parent => predecessorAncestors.has(parent)), "STRUCTURAL_REJECTION");
    for (let leftIndex = 0; leftIndex < parents.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < parents.length; rightIndex += 1) {
        require(!ancestors(parents[leftIndex]).has(parents[rightIndex])
          && !ancestors(parents[rightIndex]).has(parents[leftIndex]), "STRUCTURAL_REJECTION");
      }
    }
    const candidateAncestors = new Set(dependencies);
    for (const dependency of dependencies) for (const value of ancestors(dependency)) candidateAncestors.add(value);
    if (actor !== genesisReference) require(candidateAncestors.has(binding.grantReferenceHex), "UNRESOLVED_CREDENTIAL_BINDING");

    if (fields.eventRole === "CREDENTIAL") {
      const tail = fields.tail;
      if (tail.kind === "GRANT") {
        require(reference !== genesisReference && !bindings.has(reference), "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED");
      } else if (tail.kind === "REVOKE") {
        require(bindings.has(tail.targetCredentialHex), "UNRESOLVABLE_CREDENTIAL");
        require(tail.targetCredentialHex === genesisReference
          || candidateAncestors.has(tail.targetCredentialHex), "STRUCTURAL_REJECTION");
      } else if (tail.kind === "ROTATE") {
        require(tail.retiringCredentialHex !== actor, "STRUCTURAL_REJECTION");
        require(bindings.has(tail.retiringCredentialHex), "UNRESOLVABLE_CREDENTIAL");
        require(tail.retiringCredentialHex === genesisReference
          || candidateAncestors.has(tail.retiringCredentialHex), "STRUCTURAL_REJECTION");
        const replacement = admitted.get(tail.replacementGrantHex);
        require(replacement?.fields?.tail?.kind === "GRANT"
          && (tail.replacementGrantHex === predecessor || parents.includes(tail.replacementGrantHex)),
        "STRUCTURAL_REJECTION");
      } else if (tail.kind === "RECOVER") {
        const recovery = admitted.get(tail.recoveryGrantHex);
        require(recovery?.fields?.tail?.kind === "GRANT"
          && (tail.recoveryGrantHex === predecessor || parents.includes(tail.recoveryGrantHex)),
        "STRUCTURAL_REJECTION");
      }
    }
    admitted.set(reference, { ...record, fields });
    if (fields.eventRole === "CREDENTIAL" && fields.tail.kind === "GRANT") {
      bindings.set(reference, {
        grantReferenceHex: reference,
        issuerCredentialHex: actor,
        verificationKeyHex: fields.tail.granteeVerificationKeyHex,
      });
    }
    const detailed = Object.fromEntries(
      Object.entries(localObservation).filter(([key]) => !["preStateDigest", "postStateDigest"].includes(key)),
    );
    observations.push({ eventReferenceHex: reference, id: record.id, ...detailed, protocolErrorCode: null });
  }
  return observations;
}

function classifyReferenceIdentities(identities) {
  const transcriptsByReference = new Map();
  for (const { reference, transcriptHex } of identities) {
    if (!transcriptsByReference.has(reference)) transcriptsByReference.set(reference, new Set());
    transcriptsByReference.get(reference).add(transcriptHex);
  }
  return identities.map(({ reference, transcriptHex }) => ({
    classification: transcriptsByReference.get(reference).size > 1
      ? "REFERENCE_COLLISION_UNSUPPORTED" : "UNIQUE",
    reference,
    transcriptHex,
  }));
}

function evaluateKAdmissionGraph(genesisRecord, records, presentationEvidence = false) {
  require(genesisRecord?.kind === "GENESIS", "PREACCEPTED_GENESIS_KIND_INVALID");
  const genesisTranscript = Buffer.from(genesisRecord.transcriptHex, "hex");
  const genesisFields = parseGenesis(genesisTranscript);
  const genesisReference = hex(framedHash(DOMAINS.genesisReference, genesisTranscript));
  require(genesisReference === genesisRecord.genesisReferenceHex, "PREACCEPTED_GENESIS_REFERENCE_INVALID");
  require(ed25519Verify(
    Buffer.from(genesisFields.rootVerificationKeyHex, "hex"),
    Buffer.from(genesisRecord.signatureHex, "hex"),
    genesisTranscript,
  ), "PREACCEPTED_GENESIS_SIGNATURE_INVALID");

  const context = genesisFields.contextIdentifierHex;
  const presentations = new Map();
  const presentationRejected = new Map();
  const encodedByIdentifier = new Map();
  for (const record of records) {
    const transcript = Buffer.from(record.transcriptHex, "hex");
    const reference = hex(framedHash(DOMAINS.eventReference, transcript));
    const identifier = String(record.id);
    const encodedInput = canonical(record);
    if (encodedByIdentifier.has(identifier)) {
      if (encodedByIdentifier.get(identifier) === encodedInput) continue;
      throw new ProtocolError("STRUCTURAL_REJECTION");
    }
    encodedByIdentifier.set(identifier, encodedInput);
    presentations.set(identifier, { record, reference, transcript });
    try {
      const fields = parseEvent(transcript);
      require(reference === record.eventReferenceHex, "REFERENCE_COLLISION_UNSUPPORTED");
      require(fields.contextIdentifierHex === context, "CREDENTIAL_BINDING_MISMATCH");
      require(fields.genesisReferenceHex === genesisReference, "CREDENTIAL_BINDING_MISMATCH");
      presentations.get(identifier).fields = fields;
    } catch (error) {
      const code = ["REFERENCE_COLLISION_UNSUPPORTED", "CREDENTIAL_BINDING_MISMATCH"].includes(error.message)
        ? error.message : "STRUCTURAL_REJECTION";
      presentationRejected.set(identifier, { admitted: false, code, stage: "S3_KERNEL_STRUCTURAL" });
    }
  }

  const identities = [...presentations.entries()]
    .filter(([identifier]) => !presentationRejected.has(identifier))
    .map(([, value]) => ({ reference: value.reference, transcriptHex: hex(value.transcript) }));
  const collisionReferences = new Set(
    classifyReferenceIdentities(identities)
      .filter(value => value.classification === "REFERENCE_COLLISION_UNSUPPORTED")
      .map(value => value.reference),
  );
  const logicalGroups = new Map();
  for (const [identifier, presentation] of presentations) {
    if (presentationRejected.has(identifier)) continue;
    if (collisionReferences.has(presentation.reference)) {
      presentationRejected.set(identifier, {
        admitted: false, code: "REFERENCE_COLLISION_UNSUPPORTED", stage: "S3_KERNEL_STRUCTURAL",
      });
      continue;
    }
    if (!logicalGroups.has(presentation.reference)) {
      logicalGroups.set(presentation.reference, {
        fields: presentation.fields, presentationIds: [], transcript: presentation.transcript,
      });
    }
    logicalGroups.get(presentation.reference).presentationIds.push(identifier);
  }

  const dependencies = fields => {
    const values = new Set(fields.causalParents);
    if (fields.directPredecessorHex !== null) values.add(fields.directPredecessorHex);
    return values;
  };
  const admitted = new Map();
  const logicalRejected = new Map();
  const localResults = new Map();
  const bindings = new Map([[genesisReference, {
    grantReferenceHex: null,
    issuerCredentialHex: null,
    verificationKeyHex: genesisFields.rootVerificationKeyHex,
  }]]);
  const ancestors = reference => {
    const values = new Set(), frontier = [reference];
    while (frontier.length > 0) {
      const current = frontier.pop();
      if (values.has(current)) continue;
      values.add(current);
      const event = admitted.get(current);
      if (event !== undefined) frontier.push(...dependencies(event.fields));
    }
    values.delete(reference);
    return values;
  };

  const pending = new Set(logicalGroups.keys());
  while (pending.size > 0) {
    let progress = false;
    for (const reference of [...pending].sort()) {
      const group = logicalGroups.get(reference);
      const fields = group.fields;
      const actor = fields.credentialIdentifierHex, binding = bindings.get(actor);
      if (binding === undefined) continue;
      const required = dependencies(fields);
      const eligible = [], ready = [];
      for (const identifier of [...group.presentationIds].sort()) {
        if (!localResults.has(identifier)) {
          const localRecord = structuredClone(presentations.get(identifier).record);
          delete localRecord.admissionContext;
          localRecord.binding = {
            contextIdentifierHex: context,
            credentialIdentifierHex: actor,
            verificationKeyHex: binding.verificationKeyHex,
          };
          const local = evaluate(localRecord);
          const localPending = local.localOutcome === "PENDING_OPENING"
            && local.kBindingAdmission === "ADMITTED";
          localResults.set(identifier, { local, localPending });
          if (!transitionInputIsCompatible(local) && !localPending) {
            presentationRejected.set(identifier, {
              admitted: false,
              code: local.localOutcome ?? "INVALID",
              stage: local.stage ?? "S3_KERNEL_STRUCTURAL",
            });
          }
        }
        if (!presentationRejected.has(identifier)) {
          eligible.push(identifier);
          if (!localResults.get(identifier).localPending) ready.push(identifier);
        }
      }
      if (eligible.length === 0) {
        logicalRejected.set(reference, presentationRejected.get([...group.presentationIds].sort()[0]));
        pending.delete(reference); progress = true; continue;
      }

      const absent = [...required].some(value => !logicalGroups.has(value));
      const failed = [...required].some(value => logicalRejected.has(value));
      if (absent || failed) {
        logicalRejected.set(reference, {
          admitted: false, code: "DEPENDENCY_DEFERRED", stage: "S4_GRAPH_ADMISSION",
        });
        pending.delete(reference); progress = true; continue;
      }
      if (![...required].every(value => admitted.has(value))) continue;

      const predecessor = fields.directPredecessorHex, parents = fields.causalParents;
      try {
        if (fields.authorSequence === 0) require(predecessor === null, "STRUCTURAL_REJECTION");
        else {
          const previous = admitted.get(predecessor);
          require(previous !== undefined
            && previous.fields.credentialIdentifierHex === actor
            && previous.fields.authorSequence + 1 === fields.authorSequence,
          "STRUCTURAL_REJECTION");
        }
        const predecessorAncestors = predecessor === null ? new Set() : ancestors(predecessor);
        require(!parents.some(parent => predecessorAncestors.has(parent)), "STRUCTURAL_REJECTION");
        for (let leftIndex = 0; leftIndex < parents.length; leftIndex += 1) {
          for (let rightIndex = leftIndex + 1; rightIndex < parents.length; rightIndex += 1) {
            require(!ancestors(parents[leftIndex]).has(parents[rightIndex])
              && !ancestors(parents[rightIndex]).has(parents[leftIndex]), "STRUCTURAL_REJECTION");
          }
        }
        const candidateAncestors = new Set(required);
        for (const dependency of required) {
          for (const value of ancestors(dependency)) candidateAncestors.add(value);
        }
        if (actor !== genesisReference) {
          require(candidateAncestors.has(binding.grantReferenceHex), "UNRESOLVED_CREDENTIAL_BINDING");
        }
        if (fields.eventRole === "CREDENTIAL") {
          const tail = fields.tail;
          if (tail.kind === "GRANT") {
            require(reference !== genesisReference && !bindings.has(reference), "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED");
          } else if (tail.kind === "REVOKE") {
            require(bindings.has(tail.targetCredentialHex), "UNRESOLVABLE_CREDENTIAL");
            require(tail.targetCredentialHex === genesisReference
              || candidateAncestors.has(tail.targetCredentialHex), "STRUCTURAL_REJECTION");
          } else if (tail.kind === "ROTATE") {
            require(tail.retiringCredentialHex !== actor, "STRUCTURAL_REJECTION");
            require(bindings.has(tail.retiringCredentialHex), "UNRESOLVABLE_CREDENTIAL");
            require(tail.retiringCredentialHex === genesisReference
              || candidateAncestors.has(tail.retiringCredentialHex), "STRUCTURAL_REJECTION");
            const replacementEvent = admitted.get(tail.replacementGrantHex);
            require(replacementEvent?.fields?.tail?.kind === "GRANT"
              && (tail.replacementGrantHex === predecessor || parents.includes(tail.replacementGrantHex)),
            "STRUCTURAL_REJECTION");
          } else if (tail.kind === "RECOVER") {
            const recoveryEvent = admitted.get(tail.recoveryGrantHex);
            require(recoveryEvent?.fields?.tail?.kind === "GRANT"
              && (tail.recoveryGrantHex === predecessor || parents.includes(tail.recoveryGrantHex)),
            "STRUCTURAL_REJECTION");
          }
        }
      } catch (error) {
        logicalRejected.set(reference, {
          admitted: false, code: error.message, stage: error.stage ?? "S3_KERNEL_STRUCTURAL",
        });
        pending.delete(reference); progress = true; continue;
      }

      const dependencyPending = [...required].some(value => admitted.get(value).pendingLineage);
      admitted.set(reference, {
        fields,
        k1PresentationIds: eligible,
        localPending: ready.length === 0,
        logicalEventEffectCount: 1,
        pendingLineage: ready.length === 0 || dependencyPending,
        record: presentations.get((ready.length > 0 ? ready : eligible)[0]).record,
      });
      if (fields.eventRole === "CREDENTIAL" && fields.tail.kind === "GRANT") {
        bindings.set(reference, {
          grantReferenceHex: reference,
          issuerCredentialHex: actor,
          verificationKeyHex: fields.tail.granteeVerificationKeyHex,
        });
      }
      pending.delete(reference); progress = true;
    }
    if (progress) continue;
    for (const reference of [...pending].sort()) {
      const fields = logicalGroups.get(reference).fields;
      const unresolved = !bindings.has(fields.credentialIdentifierHex);
      logicalRejected.set(reference, {
        admitted: false,
        code: unresolved ? "UNRESOLVED_CREDENTIAL_BINDING" : "DEPENDENCY_DEFERRED",
        stage: unresolved ? "S3_KERNEL_STRUCTURAL" : "S4_GRAPH_ADMISSION",
      });
    }
    pending.clear();
  }

  const slots = new Map();
  for (const [reference, event] of admitted) {
    const fields = event.fields;
    const slot = `${fields.contextIdentifierHex}:${fields.credentialIdentifierHex}:${fields.authorSequence}`;
    if (!slots.has(slot)) slots.set(slot, []);
    slots.get(slot).push(reference);
  }
  const forcedForks = new Set(
    [...slots.values()].filter(members => members.length > 1).flat(),
  );

  const observations = [...presentations.entries()]
    .sort(([leftId, left], [rightId, right]) =>
      left.reference.localeCompare(right.reference) || leftId.localeCompare(rightId))
    .map(([identifier, presentation]) => {
      const reference = presentation.reference;
      let error = presentationRejected.get(identifier);
      const logical = admitted.get(reference);
      if (error === undefined) error = logicalRejected.get(reference);
      if (error === undefined && forcedForks.has(reference)) {
        error = { admitted: true, code: "FORK_EVIDENCE", stage: "EVENT_LOCAL" };
      } else if (error === undefined && logical.localPending) {
        error = { admitted: true, code: "PENDING_OPENING", stage: "EVENT_LOCAL" };
      } else if (error === undefined && logical.pendingLineage) {
        error = { admitted: true, code: "PENDING_ANCESTOR", stage: "EVENT_LOCAL" };
      }
      const kAdmitted = error === undefined || error.admitted === true;
      return {
        coalescedPresentationCount: kAdmitted && logical !== undefined
          ? logical.k1PresentationIds.length : 0,
        eventReferenceHex: reference,
        id: identifier,
        kBindingAdmission: kAdmitted ? "ADMITTED" : "REJECTED",
        logicalEventEffectCount: kAdmitted && logical !== undefined
          ? logical.logicalEventEffectCount : 0,
        logicalEventReferenceHex: reference,
        protocolErrorCode: error?.code ?? null,
        stage: error?.stage ?? "FINAL_AFTER_S6",
      };
    });
  if (presentationEvidence) return observations;
  return observations.map(({
    coalescedPresentationCount,
    logicalEventEffectCount,
    logicalEventReferenceHex,
    ...ordinary
  }) => ordinary);
}
function evaluateTranscriptConformance(record) {
  const observed = evaluate(record);
  const result = {
    ...observed,
    apAuthorityResult: "NOT_REACHED",
    kBindingAdmission: "NOT_EVALUATED",
  };
  if (transitionInputIsCompatible(observed)) {
    result.postStateDigest = observed.preStateDigest;
    result.stage = "TRANSCRIPT_CONFORMANCE_COMPLETE";
  }
  return result;
}

function publicTranscriptObservation(record) {
  const observed = evaluateTranscriptConformance(record);
  const result = {
    apAuthorityResult: observed.apAuthorityResult,
    commitmentMatchVerification: observed.commitmentMatchVerification,
    commitmentVerification: observed.commitmentVerification,
    ...Object.fromEntries(Array.from({ length: 7 }, (_, index) => [
      `geometryPredicate${index + 1}`, observed[`geometryPredicate${index + 1}`],
    ])),
    kBindingAdmission: observed.kBindingAdmission,
    localOutcomePresent: Object.hasOwn(observed, "localOutcome"),
    outcomeEvaluated: observed.outcomeEvaluated,
    referenceVerification: observed.referenceVerification,
    remoteClassPresent: Object.hasOwn(observed, "remoteClass"),
    signatureVerification: observed.signatureVerification,
    stage: observed.stage,
    suppliedLengthVerification: observed.suppliedLengthVerification,
    transcriptVerification: observed.transcriptVerification,
  };
  if (Object.hasOwn(observed, "localOutcome")) result.localOutcome = observed.localOutcome;
  if (Object.hasOwn(observed, "remoteClass")) result.remoteClass = observed.remoteClass;
  return result;
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
function semanticKGraphInputDigest(genesisRecord, records, targetRecordId) {
  const project = record => Object.fromEntries(
    Object.entries(record).filter(([key]) => !NONSEMANTIC_VECTOR_FIELDS.has(key)),
  );
  const projectedRecords = records.map(project).sort((left, right) =>
    left.eventReferenceHex.localeCompare(right.eventReferenceHex));
  return hex(hash(Buffer.from(canonical({
    acceptedGenesis: project(genesisRecord),
    records: projectedRecords,
    targetRecordId,
  }), "utf8")));
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

function computeTrace(scenario, vectors, transitions, kRecords = new Map(), kScenarios = new Map()) {
  const availableEvidence = new Set();
  const steps = scenario.steps.map((step, index) => {
    const vector = step.inputVectorId === undefined ? undefined : vectors.get(step.inputVectorId);
    const executed = step.executed ?? true;
    let observed = null, inputDigest, inputLabel;
    if (!executed) {
      require(vector !== undefined, `boundary step has no vector:${scenario.id}:${index}`);
      inputDigest = semanticInputDigest(vector);
      inputLabel = `VECTOR:${vector.id}`;
    } else if (step.evidenceLayer === "CONNECTED_K_ADMISSION") {
      const connected = kScenarios.get(step.inputKAdmissionScenarioId);
      require(connected !== undefined, `unknown connected K scenario:${step.inputKAdmissionScenarioId}`);
      const genesis = kRecords.get(connected.acceptedGenesisRecordId);
      const records = connected.recordIds.map(identifier => kRecords.get(identifier));
      require(genesis !== undefined && records.every(record => record !== undefined), "connected K record missing");
      const observations = evaluateKAdmissionScenario(genesis, records);
      observed = observations.find(row => row.id === step.inputKAdmissionRecordId);
      require(observed !== undefined, `unknown connected K target:${step.inputKAdmissionRecordId}`);
      inputDigest = semanticKGraphInputDigest(genesis, records, step.inputKAdmissionRecordId);
      inputLabel = `K_GRAPH:${step.inputKAdmissionScenarioId}:${step.inputKAdmissionRecordId}`;
    } else {
      require(vector !== undefined, `${step.evidenceLayer} step has no vector:${scenario.id}:${index}`);
      if (step.evidenceLayer === "TRANSCRIPT_CONFORMANCE") observed = evaluateTranscriptConformance(vector);
      else if (step.evidenceLayer === "LOCAL_NEGATIVE") observed = evaluate(vector);
      else throw new Error(`unknown evidence layer:${step.evidenceLayer}`);
      inputDigest = semanticInputDigest(vector);
      inputLabel = `VECTOR:${vector.id}`;
    }
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
      observation = Object.fromEntries(Object.entries(observed).filter(([key]) => ![
        "eventReferenceHex", "id", "preStateDigest", "postStateDigest", "protocolErrorCode",
      ].includes(key)));
      postState = transition.to;
    } else {
      observation = Object.fromEntries(Object.entries(observed).filter(([key]) => ![
        "eventReferenceHex", "id", "preStateDigest", "postStateDigest", "protocolErrorCode",
      ].includes(key)));
      postState = step.evidenceLayer === "TRANSCRIPT_CONFORMANCE"
        || observed.preStateDigest === observed.postStateDigest ? "UNCHANGED" : "READY_FOR_AP_FOLD";
    }
    const postStateDigest = postState === "UNCHANGED" || !executed
      ? preStateDigest : stateDigest(`styx-c03/state/${scenario.id}/${postState}`);
    const requirements = new Set(step.requiredPriorEvidence);
    const dependencyStatus = [...requirements].every(value => availableEvidence.has(value)) ? "SATISFIED" : "MISSING";
    require(dependencyStatus === step.expectedDependencyStatus, `dependency status mismatch:${scenario.id}:${index}`);
    const result = {
      actionDigest: hex(hash(Buffer.from(step.candidateAction, "utf8"))),
      causalClassification: step.transitionId ?? inputLabel,
      dependencyStatus,
      evidenceConsumed: [...requirements].sort(),
      evidenceProduced: step.providedEvidence ?? null,
      executed,
      inputDigest, postStateDigest, preStateDigest, step: index,
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
  const expected = names.map(path => {
    const document = loadCanonical(resolve(corpus, path));
    const row = { path, recordCount: document.records.length, sha256: hex(hash(readFileSync(resolve(corpus, path)))) };
    if (document.kAdmissionRecords !== undefined) row.kAdmissionRecordCount = document.kAdmissionRecords.length;
    else if (document.kAdmissionScenarios !== undefined) row.kAdmissionRecordCount = document.kAdmissionScenarios.length;
    return row;
  });
  require(JSON.stringify(canonicalValue(manifest.files)) === JSON.stringify(canonicalValue(expected)), "manifest file digests/counts mismatch");
}
function validateCorpusRelations(repoRoot, manifest, model, scenarios, traces, mutations, valid, invalid, apExpectations, kScenarios, kHostile) {
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
  const kScenarioById = new Map(kScenarios.map(row => [row.id, row]));
  for (const scenario of scenarios) {
    const available = new Set();
    require(Array.isArray(scenario.steps) && scenario.steps.length > 0, `empty scenario:${scenario.id}`);
    for (const step of scenario.steps) {
      if (step.evidenceLayer === "CONNECTED_K_ADMISSION") {
        const connected = kScenarioById.get(step.inputKAdmissionScenarioId);
        require(!Object.hasOwn(step, "inputVectorId") && connected !== undefined
          && typeof step.inputKAdmissionRecordId === "string"
          && connected.recordIds.includes(step.inputKAdmissionRecordId),
        `invalid connected K step input:${scenario.id}`);
      } else {
        require(["BOUNDARY_NOT_EXECUTED", "LOCAL_NEGATIVE", "TRANSCRIPT_CONFORMANCE"].includes(step.evidenceLayer)
          && vectorIds.has(step.inputVectorId)
          && !Object.hasOwn(step, "inputKAdmissionScenarioId")
          && !Object.hasOwn(step, "inputKAdmissionRecordId"),
        `invalid vector-backed step input:${scenario.id}:${step.inputVectorId}`);
        usedVectorIds.add(step.inputVectorId);
      }
      const dependencyStatus = step.requiredPriorEvidence.every(value => available.has(value)) ? "SATISFIED" : "MISSING";
      require(step.expectedDependencyStatus === dependencyStatus, `dependency expectation mismatch:${scenario.id}`);
      require(typeof step.providedEvidence === "string" && step.providedEvidence.length > 0 && !available.has(step.providedEvidence), `invalid produced evidence:${scenario.id}`);
      available.add(step.providedEvidence);
    }
  }
  require(setEqual(usedVectorIds, vectorIds), "vector execution coverage mismatch");
  const layerCounts = new Map();
  for (const scenario of scenarios) for (const step of scenario.steps) {
    layerCounts.set(step.evidenceLayer, (layerCounts.get(step.evidenceLayer) ?? 0) + 1);
    require(!(step.evidenceLayer === "TRANSCRIPT_CONFORMANCE"
      && step.expectedPostState === "READY_FOR_AP_FOLD"),
    "disconnected transcript fixture mutates K state");
  }
  require(JSON.stringify([...layerCounts].sort()) === JSON.stringify([
    ["BOUNDARY_NOT_EXECUTED", 11],
    ["CONNECTED_K_ADMISSION", 4],
    ["LOCAL_NEGATIVE", 68],
    ["TRANSCRIPT_CONFORMANCE", 81],
  ]), "scenario evidence-layer cardinality mismatch");

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
    "mutation-source-fork-descendant-dependency-rejection",
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
      matching.push(...kHostile.filter(scenario => scenario.expectedObservations.some(observation => observation.protocolErrorCode === outcome)).map(row => row.id));
      matching.sort();
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
      const keys = witness && typeof witness === "object" && !Array.isArray(witness)
        ? Object.keys(witness).sort() : [];
      const vectorWitness = JSON.stringify(keys) === JSON.stringify(["inputId", "jointSourceRowIds"]);
      const graphWitness = JSON.stringify(keys) === JSON.stringify(["inputKAdmissionRecordId", "inputKAdmissionScenarioId", "jointSourceRowIds"]);
      require(vectorWitness || graphWitness, `malformed O-10 row witness:${rowId}`);
      const inputIdentity = vectorWitness
        ? witness.inputId
        : `${witness.inputKAdmissionScenarioId}:${witness.inputKAdmissionRecordId}`;
      require(typeof inputIdentity === "string" && inputIdentity.length > 0
        && !seenInputs.has(inputIdentity), `invalid O-10 row witness relation:${rowId}`);
      seenInputs.add(inputIdentity);
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
        const vectorWitness = Object.hasOwn(witness, "inputId");
        const scenarioId = vectorWitness
          ? `scenario-vector-${witness.inputId}`
          : witness.inputKAdmissionScenarioId;
        let observed, inputId;
        if (vectorWitness) {
          inputId = witness.inputId;
          const scenario = scenarios.find(item => item.id === scenarioId);
          require(scenario?.steps.some(step => step.inputVectorId === inputId), `missing O-10 row scenario:${row.row_id}:${inputId}`);
          observed = evaluate(vectorById.get(inputId));
          require(observed.localOutcome === primary && observed.stage === row.mapping.stage, `O-10 row witness result mismatch:${row.row_id}:${inputId}`);
        } else {
          inputId = witness.inputKAdmissionRecordId;
          const scenario = kHostile.find(item => item.id === scenarioId);
          require(scenario !== undefined, `unknown connected O-10 scenario:${row.row_id}:${scenarioId}`);
          observed = evaluateKAdmissionGraph(scenario.acceptedGenesisRecord, scenario.records).find(item => item.id === inputId);
          require(observed !== undefined, `unknown connected O-10 record:${row.row_id}:${inputId}`);
          require(observed.protocolErrorCode === primary && observed.stage === row.mapping.stage, `O-10 row witness result mismatch:${row.row_id}:${inputId}`);
        }
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
function parseArgs() {
  const args = process.argv.slice(2), values = {};
  for (let i = 0; i < args.length; i += 2) values[args[i]] = args[i + 1];
  const required = values["--mode"] === "geometry-boundaries"
    ? ["--output"]
    : values["--h1-input"]
      ? ["--h1-input", "--output"]
      : values["--classify-reference-identities"]
        ? ["--classify-reference-identities", "--output"]
      : values["--c03-vector-input"]
        ? ["--c03-vector-input", "--output"]
      : values["--k-scenario-input"]
        ? ["--k-scenario-input", "--output"]
      : ["--repo-root", "--corpus", "--output"];
  for (const key of required) require(values[key], `missing ${key}`);
  return values;
}

function baseJson(repoRoot, path) {
  return JSON.parse(execFileSync("git", ["show", `${BASE_SHA}:${path}`], { cwd: repoRoot, encoding: "utf8" }));
}
function baseText(repoRoot, path) {
  require(typeof path === "string" && !path.startsWith("/") && !path.split(/[\\/]/).includes(".."), `unsafe Base path:${path}`);
  return execFileSync("git", ["show", `${BASE_SHA}:${path}`], { cwd: repoRoot, encoding: "utf8" });
}

function mutationReport(args, corpus, valid, invalid, apExpectations, scenarios, expected, model, kById, kScenarioById) {
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
      const scenario = scenarioByTrace.get(mutation.generatedTargetId), computed = computeTrace(scenario, vectors, transitions, kById, kScenarioById);
      const corrupted = structuredClone(expectedById.get(mutation.generatedTargetId));
      corrupted.steps[0].localOutcome = "INVALID";
      detected = JSON.stringify(canonicalValue(computed)) !== JSON.stringify(canonicalValue(corrupted));
    } else if (mutation.detector === "INDEPENDENT_EXPECTED_DEPENDENCY_STATUS_MISMATCH") {
      const scenario = scenarioByTrace.get(mutation.generatedTargetId), computed = computeTrace(scenario, vectors, transitions, kById, kScenarioById);
      const corrupted = structuredClone(expectedById.get(mutation.generatedTargetId));
      corrupted.steps[0].dependencyStatus = "SATISFIED";
      detected = JSON.stringify(canonicalValue(computed)) !== JSON.stringify(canonicalValue(corrupted));
    } else if (mutation.detector === "INVARIANT_WITNESS_TRACE_MISMATCH") {
      const scenario = structuredClone(scenarioByTrace.get(mutation.generatedTargetId));
      scenario.steps[0].inputVectorId = mutation.replacementVectorId;
      detected = JSON.stringify(canonicalValue(computeTrace(scenario, vectors, transitions, kById, kScenarioById))) !== JSON.stringify(canonicalValue(expectedById.get(mutation.generatedTargetId)));
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
      const observed = evaluateTranscriptConformance(vectors.get(mutation.generatedTargetId));
      detected = observed.kBindingAdmission === "NOT_EVALUATED"
        && observed.apAuthorityResult === "NOT_REACHED"
        && observed.outcomeEvaluated === false
        && !Object.hasOwn(observed, "localOutcome")
        && !Object.hasOwn(observed, "remoteClass");
    } else if (mutation.detector === "SOURCE_FORK_DESCENDANT_GRAPH_RETENTION") {
      const scenario = kScenarioById.get(mutation.generatedTargetId);
      const descendant = evaluateKAdmissionGraph(
        scenario.acceptedGenesisRecord,
        scenario.records,
      ).find(row => row.id === "k-hostile-fork-left-descendant");
      detected = descendant?.kBindingAdmission === "ADMITTED"
        && descendant.protocolErrorCode === null;
    }
    require(detected, `surviving mutation:${mutation.id}`); killed.push(mutation.id);
  }
  killed.sort();
  return { killDigest: hex(hash(Buffer.from(`${killed.join("\n")}\n`, "utf8"))), killed: killed.length, result: "PASS" };
}

function main() {
  const args = parseArgs();
  if (args["--mode"] === "geometry-boundaries") {
    const ceiling = Number(MAX_U32 - 132n);
    const rows = [ceiling - 1, ceiling, ceiling + 1].map(exactLength => {
      let result = "PASS";
      try { validateGeometryPredicates(exactLength, "SINGLE", null); }
      catch (error) {
        if (!(error instanceof ProtocolError)) throw error;
        result = error.observations.geometryPredicate2;
      }
      return { exactLength: String(exactLength), geometryPredicate2: result };
    });
    writeFileSync(resolve(args["--output"]), canonical({
      intrinsicExactLengthCeiling: String(ceiling), rows,
      schema: "styx-c03-geometry-boundaries/v1",
    }), { flag: "wx" });
    return;
  }
  if (args["--h1-input"]) {
    const input = loadCanonical(resolve(args["--h1-input"]));
    require(input?.schema === "styx-c03-h1-boundary-input/v1"
      && Array.isArray(input.records), "H1 boundary input schema mismatch");
    const observations = input.records.map(record => ({
      id: record.id,
      ...ed25519VerifyDetailed(
        Buffer.from(record.publicKeyHex, "hex"),
        Buffer.from(record.signatureHex, "hex"),
        Buffer.from(record.messageHex, "hex"),
      ),
    }));
    writeFileSync(resolve(args["--output"]), canonical({
      observations,
      result: "PASS",
      schema: "styx-c03-h1-boundary-observations/v1",
    }), { flag: "wx" });
    return;
  }
  if (args["--classify-reference-identities"]) {
    const input = loadCanonical(resolve(args["--classify-reference-identities"]));
    require(input?.schema === "styx-c03-reference-identities/v1"
      && Array.isArray(input.identities), "reference-identity input schema mismatch");
    const observations = classifyReferenceIdentities(input.identities);
    writeFileSync(resolve(args["--output"]), canonical({
      observations,
      result: "PASS",
      schema: "styx-c03-reference-classifications/v1",
    }), { flag: "wx" });
    return;
  }
  if (args["--c03-vector-input"]) {
    const input = loadCanonical(resolve(args["--c03-vector-input"]));
    require(input?.schema === "styx-c03-h1h2-vector-input/v1"
      && Array.isArray(input.records), "H1/H2 vector input schema mismatch");
    const observations = input.records.map(record => {
      ed25519EvidenceCounts.boundaryInvocations = 0;
      ed25519EvidenceCounts.equationInvocations = 0;
      return {
        id: record.id,
        observation: evaluate(record),
        verificationBoundary: { ...ed25519EvidenceCounts },
      };
    });
    writeFileSync(resolve(args["--output"]), canonical({
      observations,
      result: "PASS",
      schema: "styx-c03-h1h2-vector-observations/v1",
    }), { flag: "wx" });
    return;
  }
  if (args["--k-scenario-input"]) {
    const input = loadCanonical(resolve(args["--k-scenario-input"]));
    const evidenceMode = input.schema === "styx-c03-h1h2-connected-input/v1";
    const observations = input.scenarios.map(scenario => {
      ed25519EvidenceCounts.boundaryInvocations = 0;
      ed25519EvidenceCounts.equationInvocations = 0;
      let row;
      try {
        row = {
          id: scenario.id,
          observations: scenario.graphEvaluation
            ? evaluateKAdmissionGraph(
              scenario.acceptedGenesisRecord,
              scenario.records,
              evidenceMode,
            )
            : evaluateKAdmissionScenario(
              scenario.acceptedGenesisRecord,
              scenario.records,
            ),
        };
      } catch (error) {
        if (!evidenceMode) throw error;
        row = {
          harnessError: error.message,
          id: scenario.id,
          observations: [],
        };
      }
      if (evidenceMode) row.verificationBoundary = { ...ed25519EvidenceCounts };
      return row;
    });
    const output = { observations, result: "PASS" };
    if (evidenceMode) output.schema = "styx-c03-h1h2-connected-observations/v1";
    writeFileSync(resolve(args["--output"]), canonical(output), { flag: "wx" });
    return;
  }
  const corpus = resolve(args["--corpus"]);
  const validDocument = loadCanonical(resolve(corpus, "valid-transcript-vectors.json"));
  require(validDocument.schema === "styx-c03-valid-transcripts/v2", "valid transcript schema mismatch");
  const valid = validDocument.records;
  const invalidDocument = loadCanonical(resolve(corpus, "invalid-transcript-vectors.json"));
  require(invalidDocument.schema === "styx-c03-invalid-transcripts/v2", "invalid transcript schema mismatch");
  const invalid = invalidDocument.records, apExpectations = invalidDocument.apExpectationOnlyRecords;
  for (const record of valid) {
    const observed = evaluateTranscriptConformance(record);
    require(observed.transcriptVerification === "VALID"
      && observed.signatureVerification === "VALID"
      && observed.kBindingAdmission === "NOT_EVALUATED"
      && observed.apAuthorityResult === "NOT_REACHED"
      && observed.outcomeEvaluated === false
      && !Object.hasOwn(observed, "localOutcome")
      && !Object.hasOwn(observed, "remoteClass"),
    `valid transcript fixture rejected or overclaimed:${record.id}`);
  }
  for (const record of invalid) { const observed = evaluate(record); require(observed.localOutcome === record.expected.localOutcome && observed.stage === record.expected.firstFailingStage, `invalid mismatch:${record.id}`); require(observed.preStateDigest === observed.postStateDigest && observed.externalEffects.length === 0, `invalid side effect:${record.id}`); }
  for (const record of apExpectations) require(
    evaluateTranscriptConformance(record).kBindingAdmission === "NOT_EVALUATED",
    `AP-only vector claims disconnected K admission:${record.id}`,
  );
  const scenarioDocument = loadCanonical(resolve(corpus, "state-machine-scenarios.json"));
  require(scenarioDocument.schema === "styx-c03-state-scenarios/v2", "state scenario schema mismatch");
  const scenarios = scenarioDocument.records;
  const adversarialDocument = loadCanonical(resolve(corpus, "adversarial-mutations.json"));
  require(adversarialDocument.schema === "styx-c03-adversarial-mutations/v2", "adversarial schema mismatch");
  const kRecords = validDocument.kAdmissionRecords;
  const kScenarios = scenarioDocument.kAdmissionScenarios;
  require(Array.isArray(kRecords) && kRecords.length === 18
    && Array.isArray(kScenarios) && kScenarios.length === 3,
  "connected K-admission cardinality mismatch");
  const kById = new Map(kRecords.map(record => [record.id, record]));
  const kScenarioById = new Map(kScenarios.map(scenario => [scenario.id, scenario]));
  const usedKRecords = new Set(), kObservations = [];
  for (const scenario of kScenarios) {
    const genesis = kById.get(scenario.acceptedGenesisRecordId);
    require(genesis?.kind === "GENESIS" && Array.isArray(scenario.recordIds)
      && scenario.recordIds.length > 0 && new Set(scenario.recordIds).size === scenario.recordIds.length
      && scenario.recordIds.every(identifier => kById.has(identifier)),
    `invalid connected K scenario:${scenario.id}`);
    usedKRecords.add(scenario.acceptedGenesisRecordId);
    for (const identifier of scenario.recordIds) usedKRecords.add(identifier);
    const observations = evaluateKAdmissionGraph(
      genesis,
      [...scenario.recordIds].reverse().map(identifier => kById.get(identifier)),
    );
    require(observations.length === scenario.recordIds.length
      && observations.every(row => row.kBindingAdmission === "ADMITTED" && row.protocolErrorCode === null),
    `connected K scenario rejected:${scenario.id}`);
    kObservations.push({ id: scenario.id, observations });
  }
  require(usedKRecords.size === kById.size && [...kById].every(([identifier]) => usedKRecords.has(identifier)),
    "unexecuted connected K record");
  require(kObservations.reduce((count, row) => count + row.observations.length, 0) === 18,
    "positive connected K observation cardinality mismatch");
  const legacyById = new Map(valid.map(record => [record.id, record]));
  const legacyObservation = evaluateKAdmissionGraph(
    legacyById.get("vec-genesis"), [legacyById.get("vec-ordinary-none")],
  )[0];
  require(legacyObservation.kBindingAdmission === "REJECTED"
    && legacyObservation.protocolErrorCode === "CREDENTIAL_BINDING_MISMATCH",
  "legacy transcript fixture incorrectly proves K admission");
  const kHostile = adversarialDocument.kAdmissionScenarios;
  require(Array.isArray(kHostile) && kHostile.length === 17,
    "hostile connected K cardinality mismatch");
  const hostileObservations = [], observedErrorCodes = new Set();
  for (const scenario of kHostile) {
    require(JSON.stringify(Object.keys(scenario).sort()) === JSON.stringify([
      "acceptedGenesisRecord", "expectedObservations", "id", "records",
    ]), `invalid hostile connected K scenario:${scenario.id}`);
    require(Array.isArray(scenario.records) && scenario.records.length > 0,
      `empty hostile connected K scenario:${scenario.id}`);
    const observations = evaluateKAdmissionGraph(
      scenario.acceptedGenesisRecord, scenario.records,
    );
    require(JSON.stringify(canonicalValue(observations))
      === JSON.stringify(canonicalValue(scenario.expectedObservations)),
    `hostile connected K oracle mismatch:${scenario.id}`);
    for (const row of observations) if (row.protocolErrorCode !== null) observedErrorCodes.add(row.protocolErrorCode);
    hostileObservations.push({ id: scenario.id, observations });
  }
  require(hostileObservations.reduce((count, row) => count + row.observations.length, 0) === 66,
    "hostile connected K observation cardinality mismatch");
  for (const code of [
    "CREDENTIAL_BINDING_MISMATCH", "INVALID",
    "STRUCTURAL_REJECTION", "UNRESOLVABLE_CREDENTIAL", "UNRESOLVED_CREDENTIAL_BINDING",
  ]) require(observedErrorCodes.has(code), `hostile connected K class missing:${code}`);
  const removalObservations = hostileObservations.find(row =>
    row.id === "k-hostile-removal-target-absence-is-not-k-rejection").observations;
  require(removalObservations.every(row => row.kBindingAdmission === "ADMITTED"),
    "removal target absence incorrectly rejected by K");
  const expectedDocument = loadCanonical(resolve(corpus, "expected-traces.json"));
  require(expectedDocument.schema === "styx-c03-expected-traces/v2", "expected trace schema mismatch");
  const expected = expectedDocument.records;
  const manifest = loadCanonical(resolve(corpus, "manifest.json"));
  require(manifest.schema === "styx-c03-corpus-manifest/v2" && manifest.corpusFormatVersion === 2, "corpus manifest version mismatch");
  const mutations = adversarialDocument.records;
  const model = JSON.parse(readFileSync(resolve(args["--repo-root"], "docs/protocol/review/styx-app-kernel-v0-review-model.json"), "utf8"));
  validateCorpusRelations(resolve(args["--repo-root"]), manifest, model, scenarios, expected, mutations, valid, invalid, apExpectations, kScenarios, kHostile);
  if (args["--mode"] === "mutations") {
    writeFileSync(resolve(args["--output"]), canonical(mutationReport(
      args, corpus, valid, invalid, apExpectations, scenarios, expected, model,
      kById, new Map([...kScenarios, ...kHostile].map(scenario => [scenario.id, scenario])),
    )), { flag: "wx" });
    return;
  }
  const transitions = new Map(model.state_models.flatMap(machine => machine.transitions.map(transition => [`${machine.id}:${transition.id}`, transition])));
  const vectors = new Map([...valid, ...invalid, ...apExpectations].map(record => [record.id, record]));
  const expectedByScenario = new Map(expected.map(record => [record.scenarioId, record]));
  const computedTraces = [];
  for (const scenario of scenarios) {
    const computed = computeTrace(scenario, vectors, transitions, kById, kScenarioById), oracle = expectedByScenario.get(scenario.id);
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
  const report = {
    blindAdmissionGraphs: [...kObservations, ...hostileObservations].sort((left, right) => left.id.localeCompare(right.id)),
    blindTranscriptObservations: [...valid, ...invalid].sort((left, right) => left.id.localeCompare(right.id)).map(record => ({ id: record.id, ...publicTranscriptObservation(record) })),
    corpusDigest, invalidVectors: invalid.length,
    kAdmissionDigest: hex(hash(Buffer.from(canonical({ hostile: hostileObservations, positive: kObservations }), "utf8"))),
    kAdmissionHostileScenarios: kHostile.length,
    kAdmissionRecords: kRecords.length, kAdmissionScenarios: kScenarios.length,
    observations, result: "PASS", scenarios: scenarios.length,
    traceDigest: hex(hash(readFileSync(resolve(corpus, "expected-traces.json")))), validVectors: valid.length };
  writeFileSync(resolve(args["--output"]), canonical(report), { flag: "wx" });
}

try { main(); } catch (error) { process.stderr.write(`c03_node_failure=${error.message}\n`); process.exitCode = 2; }
