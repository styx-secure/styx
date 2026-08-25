#!/usr/bin/env node
// Exact runtime adapter for O-14 evidence. Never imported by product code.

import fs from 'node:fs';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { webcrypto } from 'node:crypto';

const [vectorsPath, nobleEntry] = process.argv.slice(2);
if (!vectorsPath || !nobleEntry) throw new Error('usage: node_adapter.mjs VECTORS NOBLE_ENTRY');
const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));
const noble = await import(pathToFileURL(nobleEntry).href);

function bytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) throw new Error('invalid hex');
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

async function capture(call) {
  try {
    return { result: Boolean(await call()), error: null };
  } catch (error) {
    return { result: false, error: error?.name || 'Error' };
  }
}

function primeOrderGuard(publicKey, signature) {
  if (publicKey.length !== 32) return { ok: false, code: 'PUBLIC_KEY_LENGTH' };
  if (signature.length !== 64) return { ok: false, code: 'SIGNATURE_LENGTH' };
  const scalar = BigInt(`0x${Buffer.from(signature.slice(32)).reverse().toString('hex') || '0'}`);
  if (scalar >= noble.CURVE.n) return { ok: false, code: 'NON_CANONICAL_SCALAR' };
  try {
    const a = noble.Point.fromBytes(publicKey, false);
    const r = noble.Point.fromBytes(signature.slice(0, 32), false);
    if (a.isSmallOrder() || !a.isTorsionFree()) {
      return { ok: false, code: 'PUBLIC_KEY_NOT_PRIME_ORDER' };
    }
    if (r.isSmallOrder() || !r.isTorsionFree()) {
      return { ok: false, code: 'R_NOT_PRIME_ORDER' };
    }
  } catch (error) {
    return { ok: false, code: 'INVALID_POINT_ENCODING' };
  }
  return { ok: true, code: 'GUARD_ACCEPTED' };
}

async function nobleGuarded(signature, message, publicKey) {
  const guard = primeOrderGuard(publicKey, signature);
  if (!guard.ok) return { result: false, guard: guard.code, verifier_invocations: 0 };
  const verified = await capture(() => noble.verifyAsync(signature, message, publicKey, { zip215: false }));
  return { result: verified.result, guard: guard.code, verifier_invocations: 1, error: verified.error };
}

async function webcryptoRaw(signature, message, publicKey) {
  return capture(async () => {
    const key = await webcrypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
    return webcrypto.subtle.verify({ name: 'Ed25519' }, key, signature, message);
  });
}

async function webcryptoGuarded(signature, message, publicKey) {
  const guard = primeOrderGuard(publicKey, signature);
  if (!guard.ok) return { result: false, guard: guard.code, verifier_invocations: 0 };
  const verified = await webcryptoRaw(signature, message, publicKey);
  return { result: verified.result, guard: guard.code, verifier_invocations: 1, error: verified.error };
}

const results = [];
for (const vector of vectors) {
  const signature = bytes(vector.signature_hex);
  const message = bytes(vector.message_hex);
  const publicKey = bytes(vector.public_key_hex);
  const nobleDefault = await capture(() => noble.verifyAsync(signature, message, publicKey));
  const nobleStrict = await capture(() => noble.verifyAsync(signature, message, publicKey, { zip215: false }));
  const nobleSelected = await nobleGuarded(signature, message, publicKey);
  const webcrypto = await webcryptoRaw(signature, message, publicKey);
  const webcryptoSelected = await webcryptoGuarded(signature, message, publicKey);
  results.push({
    id: vector.id,
    expected_selected: vector.expected_selected,
    noble_default_zip215: nobleDefault,
    noble_zip215_false: nobleStrict,
    noble_prime_order_guarded: nobleSelected,
    node_webcrypto_raw: webcrypto,
    node_webcrypto_prime_order_guarded: webcryptoSelected,
  });
}

process.stdout.write(JSON.stringify({
  runtime: {
    node: process.version,
    openssl: process.versions.openssl,
    provider: `Node.js webcrypto.subtle / OpenSSL ${process.versions.openssl}`,
  },
  results,
}));
