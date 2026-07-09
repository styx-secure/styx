// mls-session.js — one MLS 2-member group = one 1:1 encrypted conversation.
//
// Wraps an OpenMLS `Group` and exposes opaque encrypt/decrypt over application
// messages. Handshake/commit messages (rekeys) come through the same decrypt
// path and are applied internally, surfaced as { kind: 'handshake' }.

export class MlsSession {
  /**
   * @param {import('./mls-engine.js').MlsEngine} engine owning engine (provider+identity)
   * @param {object} group the OpenMLS Group handle
   */
  constructor(engine, group) {
    this._engine = engine;
    this._group = group;
  }

  /**
   * Encrypt an application message for the peer.
   * @param {Uint8Array} plaintext
   * @returns {Uint8Array} serialized MLS private message (opaque wire bytes)
   */
  encrypt(plaintext) {
    return this._group.create_message(this._engine.provider, this._engine.identity, plaintext);
  }

  /**
   * Process an incoming MLS message. Application messages yield the plaintext;
   * handshake/commit messages are applied to the group state and yield no data.
   * @param {Uint8Array} wireBytes
   * @returns {{ kind: 'application'|'handshake', plaintext: Uint8Array|null }}
   */
  decrypt(wireBytes) {
    const out = this._group.process_message(this._engine.provider, wireBytes);
    if (out && out.length > 0) {
      return { kind: 'application', plaintext: out };
    }
    return { kind: 'handshake', plaintext: null };
  }
}
