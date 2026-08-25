#!/usr/bin/env node
// Independent JavaScript adapter for the isolated O-07 evidence package.

import fs from 'node:fs';
import crypto from 'node:crypto';

const inputPath = process.argv[2];
if (!inputPath) throw new Error('usage: node node_adapter.mjs INPUT');
const vectors = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
const D_GENESIS_SIG = 2;
const D_GENESIS_REF = 4;
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function u16(value) {
  const result = Buffer.alloc(2);
  result.writeUInt16BE(value);
  return result;
}

function u32(value) {
  const result = Buffer.alloc(4);
  result.writeUInt32BE(value);
  return result;
}

function reference(transcript) {
  return crypto.createHash('sha256').update(Buffer.concat([
    u16(D_GENESIS_REF), u32(transcript.length), transcript,
  ])).digest();
}

function reject(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function parse(transcript, runtimeLimit, allowedProfiles) {
  let offset = 0;
  const take = (length, code) => {
    if (offset + length > transcript.length) reject(code);
    const value = transcript.subarray(offset, offset + length);
    offset += length;
    return value;
  };
  const read16 = (code) => take(2, code).readUInt16BE();
  const read32 = (code) => take(4, code).readUInt32BE();
  if (read16('TRUNCATED_GENESIS_DOMAIN') !== D_GENESIS_SIG) reject('GENESIS_DOMAIN_REJECTED');
  const bodyLength = read32('TRUNCATED_GENESIS_BODY_LENGTH');
  if (bodyLength > runtimeLimit) reject('GENESIS_BODY_LENGTH');
  if (bodyLength !== transcript.length - 6) reject('GENESIS_BODY_LENGTH_MISMATCH');
  const protocolVersion = read16('TRUNCATED_PROTOCOL_VERSION');
  const profileId = read32('TRUNCATED_APPLICATION_PROFILE_ID');
  const profileVersion = read32('TRUNCATED_APPLICATION_PROFILE_VERSION');
  const contextId = take(32, 'TRUNCATED_CONTEXT_IDENTIFIER');
  const suiteId = read16('TRUNCATED_SIGNATURE_SUITE');
  const keyLength = read32('ROOT_KEY_LENGTH');
  if (keyLength !== 32) reject('ROOT_KEY_LENGTH');
  const rootKey = take(keyLength, 'TRUNCATED_ROOT_KEY');
  const policyLength = read32('INITIAL_AUTHORITY_POLICY_LENGTH');
  if (policyLength === 0 || policyLength > runtimeLimit) reject('INITIAL_AUTHORITY_POLICY_LENGTH');
  const policy = take(policyLength, 'TRUNCATED_INITIAL_AUTHORITY_POLICY');
  if (offset !== transcript.length) reject('TRAILING_GENESIS_BYTES');
  if (protocolVersion !== 1) reject('PROTOCOL_VERSION_REJECTED');
  if (!allowedProfiles.includes(profileId) || profileId === 0) reject('APPLICATION_PROFILE_REJECTED');
  if (profileVersion === 0) reject('APPLICATION_PROFILE_VERSION_REJECTED');
  if (suiteId !== 1) reject('SIGNATURE_SUITE_REJECTED');
  return { protocolVersion, profileId, profileVersion, contextId, suiteId, rootKey, policy };
}

function evaluate(vector) {
  try {
    if (!vector.ceremony_authenticated) reject('AUTHENTICATED_CEREMONY_REQUIRED');
    if (!vector.authorization_decision) reject('ROOT_AUTHORIZATION_REJECTED');
    const transcript = Buffer.from(vector.transcript_hex, 'hex');
    const signature = Buffer.from(vector.signature_hex, 'hex');
    if (signature.length !== 64) reject('GENESIS_SIGNATURE_LENGTH');
    const body = parse(transcript, vector.runtime_body_limit, vector.allowed_profiles);
    const derived = reference(transcript);
    if (!crypto.timingSafeEqual(derived, Buffer.from(vector.expected_reference_hex, 'hex'))) {
      reject('GENESIS_REFERENCE_MISMATCH');
    }
    if (body.protocolVersion !== vector.context.protocol_version
        || body.profileId !== vector.context.application_profile_id
        || body.profileVersion !== vector.context.application_profile_version
        || body.contextId.toString('hex') !== vector.context.context_identifier_hex) {
      reject('GENESIS_CONTEXT_TUPLE_MISMATCH');
    }
    const publicKey = crypto.createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, body.rootKey]),
      format: 'der',
      type: 'spki',
    });
    if (!crypto.verify(null, transcript, publicKey, signature)) reject('GENESIS_SIGNATURE_INVALID');
    return { id: vector.id, disposition: 'GENESIS_ACCEPTED', reference_hex: derived.toString('hex') };
  } catch (error) {
    return { id: vector.id, disposition: error.code || 'ADAPTER_FAILURE', reference_hex: null };
  }
}

process.stdout.write(JSON.stringify({ results: vectors.map(evaluate) }));
