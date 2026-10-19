/**
 * MLS session port -- PROTOTYPE (branch proto/sdk-demo-2026-10, not for merge).
 *
 * Adapts an injected `MlsEngine` (styx-js/src/crypto/mls/, used unchanged and
 * never imported here) to the session port of C-SDK 8.2: `seal` / `open`.
 * One 2-member MLS group per peer, keyed by the peer's Nostr public key.
 *
 * Binding: the MLS credential of every member is its Nostr public key hex
 * (the engine is created with `name = <own pubkey>`). `open` accepts a
 * ciphertext only when the group's other member is exactly the Nostr key that
 * signed the event (`sender`), and `seal` only when the group's other member
 * is exactly the recipient. The same check guards `startSession` (the
 * KeyPackage credential must be the key the invite targets) and
 * `joinSession` (the group's other member must be the key that signed the
 * Welcome's seal).
 *
 * Errors are thrown as plain `Error`s; the delivery layer maps a throwing
 * session port to `E_SDK_SESSION_FAILED`.
 */

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * @param {object} opts
 * @param {object} opts.engine an MlsEngine (see src/crypto/mls/mls-engine.js)
 * @param {string} opts.selfPublicKey own Nostr key hex; must equal the engine's MLS credential
 */
export function createMlsSessionPort({ engine, selfPublicKey }) {
  if (!engine || typeof engine.session !== 'function') throw new TypeError('mls-port: engine required');
  if (!HEX64.test(selfPublicKey)) throw new TypeError('mls-port: selfPublicKey must be lowercase 64-hex');

  const boundPeer = (peer) => {
    if (!HEX64.test(peer)) return null;
    const s = engine.session(peer);
    if (!s) return null;
    const ids = s.memberIdentities();
    // exactly {self, peer}: no third member, credentials equal to Nostr keys
    if (ids.length !== 2 || !ids.includes(selfPublicKey) || !ids.includes(peer)) return null;
    return engine.peerIdentity(peer) === peer ? s : null;
  };

  const rollback = (peer) => { try { engine.removeSession(peer); } catch { /* ignore */ } };

  return Object.freeze({
    /** C-SDK 8.2 seal: MLS application message for `recipient`. */
    seal({ recipient, plaintext }) {
      const s = boundPeer(recipient);
      if (!s) throw new Error('mls-port: no bound MLS session for recipient');
      if (!(plaintext instanceof Uint8Array)) throw new Error('mls-port: plaintext must be bytes');
      return { ciphertext: s.encrypt(plaintext) };
    },

    /** C-SDK 8.2 open: only a bound group whose other member is the event signer. */
    open({ sender, ciphertext }) {
      const s = boundPeer(sender);
      if (!s) throw new Error('mls-port: MLS group member does not match event signer');
      const out = s.decrypt(ciphertext);
      if (!out || out.kind !== 'application' || !(out.plaintext instanceof Uint8Array)) {
        throw new Error('mls-port: not an application message');
      }
      return { plaintext: out.plaintext };
    },

    /** Own KeyPackage bytes (stores its private part in the engine). */
    keyPackageBytes() {
      return engine.keyPackageBytes();
    },

    /**
     * Inviter: create the 2-member group with `peer`'s KeyPackage. Rolls back
     * and throws if the KeyPackage credential is not `peer`.
     */
    startSession(peer, keyPackageBytes) {
      if (!HEX64.test(peer)) throw new Error('mls-port: peer must be lowercase 64-hex');
      const r = engine.startSession(peer, keyPackageBytes);
      if (!boundPeer(peer)) {
        rollback(peer);
        throw new Error('mls-port: KeyPackage credential does not match the invited key');
      }
      return { welcome: r.welcome, ratchetTree: r.ratchetTree, groupId: r.groupId };
    },

    /**
     * Invitee: join from a Welcome that `peer` (the seal signer) sent. Rolls
     * back and throws if the group's other member is not `peer`.
     */
    joinSession(peer, welcomeBytes, ratchetTreeBytes) {
      if (!HEX64.test(peer)) throw new Error('mls-port: peer must be lowercase 64-hex');
      engine.joinSession(peer, welcomeBytes, ratchetTreeBytes);
      if (!boundPeer(peer)) {
        rollback(peer);
        throw new Error('mls-port: Welcome group member does not match the seal signer');
      }
      return true;
    },

    hasSession(peer) {
      return boundPeer(peer) !== null;
    },

    /** Same value on both members of the same group/epoch (demo check value). */
    exportSecret(peer, label, context, length) {
      const s = boundPeer(peer);
      if (!s) throw new Error('mls-port: no bound MLS session');
      return s.exportSecret(label, context, length);
    },
  });
}
