import { beforeAll, describe, expect, test } from '@jest/globals';
import { schnorr } from '@noble/curves/secp256k1';

import {
  ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID,
  ACCOUNT_IDENTITY_PROOF_V2_LENGTH,
  createAccountIdentityProofV2,
  verifyAccountIdentityProofV2,
} from '../../spikes/marmot-phase-b1/identity-proof-v2.js';
import { loadPhaseB1Wasm } from '../../spikes/marmot-phase-b1/wasm-loader.mjs';

let Provider;
let Identity;
let KeyPackage;

const secret = (byte) => new Uint8Array(32).fill(byte);

beforeAll(async () => {
  const wasm = await loadPhaseB1Wasm();
  Provider = wasm.Provider;
  Identity = wasm.PhaseB1Identity;
  KeyPackage = wasm.PhaseB1KeyPackage;
});

describe('Phase B1 account-identity-proof v2 harness', () => {
  test('constructs and verifies the exact 104-byte NIP-01/BIP340 binding', () => {
    const privateKey = secret(7);
    const accountKey = Uint8Array.from(schnorr.getPublicKey(privateKey));
    const leafKey = secret(19);
    const proof = createAccountIdentityProofV2(privateKey, leafKey, 1_800_000_000);

    expect(proof).toBeInstanceOf(Uint8Array);
    expect(proof).toHaveLength(ACCOUNT_IDENTITY_PROOF_V2_LENGTH);
    const result = verifyAccountIdentityProofV2(proof, accountKey, leafKey);
    expect(result.componentId).toBe(ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID);
    expect(result.createdAt).toBe(1_800_000_000);
    expect(result.accountPublicKey).toEqual(accountKey);
    expect(result.leafSignatureKey).toEqual(leafKey);
  });

  test.each([
    ['wrong account', (proof, account, leaf) => [proof, Uint8Array.from(schnorr.getPublicKey(secret(8))), leaf]],
    ['wrong leaf key', (proof, account) => [proof, account, secret(20)]],
    ['changed created_at', (proof, account, leaf) => {
      const changed = Uint8Array.from(proof);
      changed[39] ^= 1;
      return [changed, account, leaf];
    }],
    ['changed signature', (proof, account, leaf) => {
      const changed = Uint8Array.from(proof);
      changed[103] ^= 1;
      return [changed, account, leaf];
    }],
  ])('rejects %s', (_name, mutate) => {
    const privateKey = secret(7);
    const account = Uint8Array.from(schnorr.getPublicKey(privateKey));
    const leaf = secret(19);
    const proof = createAccountIdentityProofV2(privateKey, leaf, 1_800_000_000);
    expect(() => verifyAccountIdentityProofV2(...mutate(proof, account, leaf))).toThrow();
  });

  test('rejects missing/trailing bytes, accessor-backed inputs and invalid x-only keys', () => {
    const privateKey = secret(7);
    const account = Uint8Array.from(schnorr.getPublicKey(privateKey));
    const leaf = secret(19);
    const proof = createAccountIdentityProofV2(privateKey, leaf, 1_800_000_000);

    expect(() => verifyAccountIdentityProofV2(proof.slice(0, 103), account, leaf)).toThrow();
    expect(() => verifyAccountIdentityProofV2(new Uint8Array(105), account, leaf)).toThrow();
    expect(() => verifyAccountIdentityProofV2(Array.from(proof), account, leaf)).toThrow(TypeError);
    expect(() => verifyAccountIdentityProofV2(Buffer.from(proof), account, leaf)).toThrow(TypeError);
    expect(() => verifyAccountIdentityProofV2(proof, new Uint8Array(32).fill(0xff), leaf)).toThrow();
  });
});

describe('Phase B1 framed KeyPackage profile', () => {
  function createProfileKeyPackage() {
    const provider = new Provider();
    const privateKey = secret(11);
    const account = Uint8Array.from(schnorr.getPublicKey(privateKey));
    const identity = new Identity(provider, account);
    const proof = createAccountIdentityProofV2(
      privateKey,
      identity.leaf_signature_key(),
      1_800_000_000,
    );
    const framed = identity.key_package(provider, proof).to_framed_bytes();
    return { provider, privateKey, account, identity, proof, framed };
  }

  test('round-trips canonically with the frozen suite, raw identity and component', () => {
    const { account, identity, proof, framed } = createProfileKeyPackage();
    const parsed = KeyPackage.from_framed_bytes(framed);
    expect(parsed.to_framed_bytes()).toEqual(framed);
    expect(parsed.ciphersuite_id()).toBe(0x0001);
    expect(parsed.credential_identity()).toEqual(account);
    expect(parsed.leaf_signature_key()).toEqual(identity.leaf_signature_key());
    expect(parsed.identity_proof()).toEqual(proof);
    expect(Array.from(parsed.component_ids())).toEqual([1, 0x8009]);
    expect(Array.from(parsed.supported_component_ids())).toEqual([0x8009]);
    expect(parsed.lifetime_seconds()).toBeLessThanOrEqual(7_261_200n);
    expect(parsed.is_last_resort()).toBe(false);
  });

  test('rejects invalid identity/proof lengths, signer mismatch and trailing framing bytes', () => {
    const provider = new Provider();
    expect(() => new Identity(provider, new Uint8Array(31))).toThrow();
    expect(() => new Identity(provider, new Uint8Array(33))).toThrow();

    const { identity, proof, framed } = createProfileKeyPackage();
    expect(() => identity.key_package(provider, proof.slice(0, 103))).toThrow();
    expect(() => identity.key_package(provider, new Uint8Array(105))).toThrow();
    const wrongSigner = Uint8Array.from(proof);
    wrongSigner[0] ^= 1;
    expect(() => identity.key_package(provider, wrongSigner)).toThrow();

    const trailing = new Uint8Array(framed.length + 1);
    trailing.set(framed);
    expect(() => KeyPackage.from_framed_bytes(trailing)).toThrow();
  });

  test('rejects a duplicated application-component dictionary id while decoding', () => {
    const { framed } = createProfileKeyPackage();
    const duplicate = Uint8Array.from(framed);
    const marker = [0x00, 0x01, 0x03, 0x02, 0x80, 0x09, 0x80, 0x09, 0x40, 0x68];
    let offset = -1;
    for (let index = 0; index <= duplicate.length - marker.length; index += 1) {
      if (marker.every((byte, markerIndex) => duplicate[index + markerIndex] === byte)) {
        if (offset !== -1) throw new Error('synthetic component marker was not unique');
        offset = index;
      }
    }
    expect(offset).toBeGreaterThanOrEqual(0);
    // Replace component 0x8009 with a second component 0x0001. Lengths stay
    // canonical, so rejection specifically exercises duplicate dictionary ids.
    duplicate[offset + 6] = 0x00;
    duplicate[offset + 7] = 0x01;
    expect(() => KeyPackage.from_framed_bytes(duplicate)).toThrow(/malformed MLSMessage framing/);
  });
});
