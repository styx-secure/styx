// registration-digest.js — the canonical message the client signs and the bridge
// verifies for a push registration. Binding action + identity + endpoint stops a
// signature being replayed for a different action, key, or device subscription.
// Shared verbatim by the client (PushRegistrar / StyxChat) and the push_bridge.
import { sha256 } from '@noble/hashes/sha256';
import { utf8Encode } from '../utils.js';

/**
 * @param {'register'|'unregister'} action
 * @param {string} pubkey hex x-only Nostr pubkey (the identity)
 * @param {string} endpoint the Web Push subscription endpoint URL
 * @returns {Uint8Array} 32-byte digest
 */
export function registrationDigest(action, pubkey, endpoint) {
  return sha256(utf8Encode(`styx-push:${action}:${pubkey}:${endpoint}`));
}
