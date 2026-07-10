// test/signature.test.js — the bridge only accepts a registration whose schnorr
// signature (over the shared digest) verifies against the claimed pubkey. This
// stops anyone registering a victim's pubkey to their own push endpoint.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import { registrationDigest } from '../../styx-js/src/push/registration-digest.js';
import { verifyRegistration } from '../src/signature.js';

function keypair() {
  const sk = schnorr.utils.randomPrivateKey();
  return { sk, pk: bytesToHex(schnorr.getPublicKey(sk)) };
}

test('accepts a correctly signed registration', () => {
  const { sk, pk } = keypair();
  const endpoint = 'https://push/abc';
  const sig = bytesToHex(schnorr.sign(registrationDigest('register', pk, endpoint), sk));
  assert.equal(verifyRegistration({ pubkey: pk, action: 'register', endpoint, sig }), true);
});

test('rejects a signature from a different key (forgery)', () => {
  const victim = keypair();
  const attacker = keypair();
  const endpoint = 'https://push/abc';
  // Attacker signs the victim's-pubkey digest with the attacker's key.
  const sig = bytesToHex(schnorr.sign(registrationDigest('register', victim.pk, endpoint), attacker.sk));
  assert.equal(verifyRegistration({ pubkey: victim.pk, action: 'register', endpoint, sig }), false);
});

test('rejects when the endpoint or action is tampered', () => {
  const { sk, pk } = keypair();
  const sig = bytesToHex(schnorr.sign(registrationDigest('register', pk, 'https://push/abc'), sk));
  assert.equal(verifyRegistration({ pubkey: pk, action: 'register', endpoint: 'https://push/OTHER', sig }), false);
  assert.equal(verifyRegistration({ pubkey: pk, action: 'unregister', endpoint: 'https://push/abc', sig }), false);
});

test('returns false on malformed input instead of throwing', () => {
  assert.equal(verifyRegistration({ pubkey: 'zz', action: 'register', endpoint: 'e', sig: 'nothex' }), false);
});
