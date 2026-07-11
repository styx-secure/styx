// test/crypto/mls-member-identity.test.js
//
// N2 — the MLS credential of a group member must be readable, so the app can check it
// against the transport identity that delivered the group. Without this, a peer can
// hand us a group built for somebody else and we would never notice.
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';

const wasmPath = fileURLToPath(
  new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url),
);
const wasmBytes = readFileSync(wasmPath);

const A = 'a'.repeat(64);
const B = 'b'.repeat(64);

async function paired() {
  const a = await MlsEngine.create({ name: A });
  const b = await MlsEngine.create({ name: B });
  const { welcome, ratchetTree } = a.startSession('b', b.keyPackageBytes());
  b.joinSession('a', welcome, ratchetTree);
  return { a, b };
}

describe('MLS member identities (N2)', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  test('memberIdentities lists both members by credential (the pubkey hex)', async () => {
    const { a, b } = await paired();

    expect(a.session('b').memberIdentities().sort()).toEqual([A, B].sort());
    // Both sides see the same membership.
    expect(b.session('a').memberIdentities().sort()).toEqual([A, B].sort());
  });

  test('peerIdentity returns the other member, never ourselves', async () => {
    const { a, b } = await paired();

    expect(a.peerIdentity('b')).toBe(B);
    expect(b.peerIdentity('a')).toBe(A);
  });

  test('peerIdentity is null for an unknown contact', async () => {
    const { a } = await paired();

    expect(a.peerIdentity('nobody')).toBeNull();
  });
});
