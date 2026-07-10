// signature.js — verify that a registration was signed by the owner of the
// claimed pubkey, over the shared registrationDigest. Reuses the exact digest
// the client signs (imported from styx-js) so the two can never drift.
import { schnorr } from '@noble/curves/secp256k1';
import { hexToBytes } from '@noble/hashes/utils';
import { registrationDigest } from '../../styx-js/src/push/registration-digest.js';

/**
 * @param {object} r
 * @param {string} r.pubkey hex x-only Nostr pubkey
 * @param {'register'|'unregister'} r.action
 * @param {string} r.endpoint Web Push subscription endpoint
 * @param {string} r.sig schnorr signature, hex
 * @returns {boolean}
 */
export function verifyRegistration({ pubkey, action, endpoint, sig }) {
  try {
    const digest = registrationDigest(action, pubkey, endpoint);
    return schnorr.verify(hexToBytes(sig), digest, pubkey);
  } catch {
    return false;
  }
}
