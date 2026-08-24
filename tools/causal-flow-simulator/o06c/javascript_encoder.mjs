#!/usr/bin/env node
// Independent dependency-free JavaScript encoder for O-06c cross-language evidence.
// Partial forward encoder only: not an inverse parser, rejection oracle, or product implementation.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const DOMAIN = Object.freeze({
  application: "53545958000100010000000000000000",
  event_reference: "53545958000100030000000000000000",
  commitment: "53545958000100050000000000000000",
  leaf: "53545958000100060000000000000000",
  node: "53545958000100070000000000000000",
});
const ROLE = Object.freeze({ ordinary: 0, removal: 1, credential: 2 });
const CONTENT = Object.freeze({ none: 0, required: 1, detachable: 2 });
const CONTROL = Object.freeze({ grant: 1, revoke: 2, rotate: 3, recover: 4, policy: 5, closure: 6 });
const CHUNK_SIZES = new Set([1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64]);

function fail(message) { throw new Error(message); }
function hex(value, label) {
  if (typeof value !== "string" || value.length % 2 || !/^[0-9a-f]*$/.test(value)) fail(`${label} is not canonical hexadecimal`);
  return Buffer.from(value, "hex");
}
function exact32(value, label) { const result = Buffer.isBuffer(value) ? value : hex(value, label); if (result.length !== 32) fail(`${label} width`); return result; }
function uint(value, width, label) {
  const number = typeof value === "bigint" ? value : BigInt(value);
  const maximum = (1n << BigInt(width * 8)) - 1n;
  if (number < 0n || number > maximum) fail(`${label} outside unsigned range`);
  const output = Buffer.alloc(width);
  for (let index = width - 1, remaining = number; index >= 0; index -= 1, remaining >>= 8n) output[index] = Number(remaining & 0xffn);
  return output;
}
const u8 = (v, l="u8") => uint(v, 1, l);
const u16 = (v, l="u16") => uint(v, 2, l);
const u32 = (v, l="u32") => uint(v, 4, l);
const u64 = (v, l="u64") => uint(v, 8, l);
function opaque(value, label) { return Buffer.concat([u32(value.length, `${label} length`), value]); }
function sha(value) { return createHash("sha256").update(value).digest(); }
function framedHash(domain, body) { return sha(Buffer.concat([hex(DOMAIN[domain], "domain"), u32(body.length), body])); }

function contextBytes(raw, credential) {
  const result = Buffer.concat([
    u16(1), u16(1), u32(raw.application_profile_id), u32(raw.application_profile_version),
    exact32(raw.context_identifier, "context"), exact32(credential, "credential"), u64(raw.author_sequence),
  ]);
  if (result.length !== 84) fail("context width drift");
  return result;
}

function geometryFor(contentLength, shape, chunkSize) {
  if (shape === "single") {
    if (contentLength > 4294967163) fail("single framing ceiling");
    return null;
  }
  if (shape !== "tree" || !Number.isInteger(chunkSize) || !CHUNK_SIZES.has(chunkSize)) fail("invalid tree chunk size");
  if (chunkSize >= contentLength) fail("tree requires two chunks");
  const count = Math.ceil(contentLength / chunkSize);
  const finalLength = contentLength - chunkSize * (count - 1);
  if (count < 2 || finalLength < 1 || finalLength > chunkSize) fail("invalid tree geometry");
  return { chunk_size: chunkSize, chunk_count: count, final_chunk_length: finalLength };
}

function geometryBytes(geometry) {
  return Buffer.concat([u32(geometry.chunk_size), u64(geometry.chunk_count), u32(geometry.final_chunk_length)]);
}

function leftComplete(digests, nodePreimages) {
  if (digests.length === 1) return digests[0];
  let split = 1;
  while (split * 2 < digests.length) split *= 2;
  const left = leftComplete(digests.slice(0, split), nodePreimages);
  const right = leftComplete(digests.slice(split), nodePreimages);
  const body = Buffer.concat([u16(1), u64(digests.length), left, right]);
  const preimage = Buffer.concat([hex(DOMAIN.node, "node domain"), u32(body.length), body]);
  nodePreimages.push(preimage);
  return sha(preimage);
}

function commitmentFor(rawContent, rawEvent, credential) {
  const klass = CONTENT[rawContent.class];
  if (klass === undefined) fail("unknown content class");
  if (klass === CONTENT.none) {
    if (Object.keys(rawContent).length !== 1) fail("NONE has unexpected fields");
    return { descriptor: Buffer.concat([u8(0), u64(0)]), derived: null };
  }
  const content = hex(rawContent.content, "content");
  const randomizer = exact32(rawContent.randomizer, "randomizer");
  const geometry = geometryFor(content.length, rawContent.shape, rawContent.chunk_size);
  const context = contextBytes(rawEvent, credential);
  const chunks = [];
  if (geometry === null) chunks.push(content);
  else for (let offset = 0; offset < content.length; offset += geometry.chunk_size) chunks.push(content.subarray(offset, offset + geometry.chunk_size));
  const leafPreimages = chunks.map((chunk, ordinal) => {
    const body = Buffer.concat([context, u32(rawContent.content_type_id), u64(ordinal), u32(chunk.length), randomizer, chunk]);
    return Buffer.concat([hex(DOMAIN.leaf, "leaf domain"), u32(body.length), body]);
  });
  const leafDigests = leafPreimages.map(sha);
  const nodePreimages = [];
  const root = leftComplete(leafDigests, nodePreimages);
  const shape = geometry === null ? 0 : 1;
  const commitmentBody = Buffer.concat([
    context, u32(rawContent.content_type_id), u64(content.length), u8(shape),
    ...(geometry === null ? [] : [geometryBytes(geometry)]), root, randomizer,
  ]);
  const commitmentPreimage = Buffer.concat([hex(DOMAIN.commitment, "commitment domain"), u32(commitmentBody.length), commitmentBody]);
  const commitmentValue = sha(commitmentPreimage);
  const descriptor = Buffer.concat([
    u8(klass), u64(content.length), u32(rawContent.content_type_id), u16(1), u8(shape),
    opaque(commitmentValue, "commitment value"), u8(geometry === null ? 0 : 1),
    ...(geometry === null ? [] : [opaque(geometryBytes(geometry), "geometry")]),
  ]);
  return {
    descriptor,
    derived: {
      context: context.toString("hex"), content: content.toString("hex"), randomizer: randomizer.toString("hex"),
      leaf_preimages: leafPreimages.map((v) => v.toString("hex")), leaf_digests: leafDigests.map((v) => v.toString("hex")),
      node_preimages: nodePreimages.map((v) => v.toString("hex")), root: root.toString("hex"),
      commitment_preimage: commitmentPreimage.toString("hex"), commitment_value: commitmentValue.toString("hex"), geometry,
    },
  };
}

function resolveCredential(spec, references) {
  if (spec && Object.keys(spec).length === 1 && "literal" in spec) return exact32(spec.literal, "literal credential");
  if (spec && Object.keys(spec).length === 1 && references.has(spec.grant_reference)) return references.get(spec.grant_reference);
  fail("unresolved credential selector");
}

function roleTail(raw, role) {
  if (role === ROLE.ordinary) { if (raw.tail !== null) fail("ordinary event has tail"); return Buffer.alloc(0); }
  if (!raw.tail || typeof raw.tail !== "object") fail("control event lacks tail");
  if (role === ROLE.removal) return Buffer.concat([exact32(raw.tail.target_event_reference, "target event"), opaque(exact32(raw.tail.target_commitment, "target commitment"), "target commitment")]);
  const kind = CONTROL[raw.tail.control_kind];
  if (kind === undefined) fail("unknown control kind");
  const prefix = u8(kind);
  if (kind === CONTROL.grant) return Buffer.concat([prefix, u16(raw.tail.grantee_suite_id), opaque(hex(raw.tail.grantee_verification_key, "grantee key"), "grantee key")]);
  if (kind === CONTROL.revoke) return Buffer.concat([prefix, exact32(raw.tail.target_credential_id, "target credential")]);
  if (kind === CONTROL.rotate) return Buffer.concat([prefix, exact32(raw.tail.retiring_credential_id, "retiring credential"), exact32(raw.tail.replacement_grant_reference, "replacement grant")]);
  if (kind === CONTROL.recover) return Buffer.concat([prefix, exact32(raw.tail.retired_credential_id, "retired credential"), exact32(raw.tail.recovery_grant_reference, "recovery grant")]);
  return prefix;
}

function deriveEvent(raw, references) {
  const role = ROLE[raw.event_role];
  if (role === undefined) fail("unknown role");
  const credential = resolveCredential(raw.credential_identifier, references);
  const commitment = commitmentFor(raw.content, raw, credential);
  if ((role === ROLE.removal || role === ROLE.credential) && CONTENT[raw.content.class] !== CONTENT.none) fail("control role requires NONE");
  const predecessor = raw.direct_predecessor === null ? null : exact32(raw.direct_predecessor, "predecessor");
  if ((Number(raw.author_sequence) === 0) === (predecessor !== null)) fail("sequence/predecessor mismatch");
  const parents = raw.causal_parents.map((value) => exact32(value, "causal parent"));
  const ordered = [...parents].sort(Buffer.compare);
  if (parents.some((value, index) => !value.equals(ordered[index])) || new Set(parents.map((v) => v.toString("hex"))).size !== parents.length) fail("noncanonical parents");
  const body = Buffer.concat([
    u16(1), u32(raw.application_profile_id), u32(raw.application_profile_version), exact32(raw.context_identifier, "context"),
    u16(1), u8(role), u32(raw.event_type_id), u32(raw.schema_id), u32(raw.schema_version),
    opaque(hex(raw.transition_block, "transition"), "transition"), credential, u64(raw.author_sequence),
    u8(predecessor === null ? 0 : 1), ...(predecessor === null ? [] : [predecessor]),
    u32(parents.length), ...parents, exact32(raw.genesis_reference, "genesis"), commitment.descriptor, roleTail(raw, role),
  ]);
  const transcript = Buffer.concat([hex(DOMAIN.application, "app domain"), u32(body.length), body]);
  const referencePreimage = Buffer.concat([hex(DOMAIN.event_reference, "reference domain"), u32(transcript.length), transcript]);
  return {
    id: raw.id, credential_identifier: credential.toString("hex"), content_descriptor: commitment.descriptor.toString("hex"),
    transcript: transcript.toString("hex"), reference_preimage: referencePreimage.toString("hex"),
    event_reference: sha(referencePreimage).toString("hex"), commitment: commitment.derived,
  };
}

function main() {
  const inputIndex = process.argv.indexOf("--input");
  const outputIndex = process.argv.indexOf("--output");
  if (inputIndex < 0 || outputIndex < 0) fail("usage: --input FILE --output FILE");
  const registry = JSON.parse(readFileSync(process.argv[inputIndex + 1], "utf8"));
  if (registry.format !== "styx-o06c-semantic-input-v1") fail("unknown registry format");
  const references = new Map();
  const events = [];
  for (const raw of registry.grants) {
    const result = deriveEvent(raw, references); references.set(raw.id, Buffer.from(result.event_reference, "hex")); events.push(result);
  }
  for (const raw of registry.cases) events.push(deriveEvent(raw, references));
  writeFileSync(process.argv[outputIndex + 1], `${JSON.stringify({ format: "styx-o06c-derived-v1", events })}\n`, "utf8");
}

main();
