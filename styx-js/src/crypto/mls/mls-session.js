// mls-session.js — one MLS 2-member group = one 1:1 encrypted conversation.
//
// Wraps an OpenMLS `Group` and exposes opaque encrypt/decrypt over application
// messages. A 1:1 session processes MLS application messages only: a proposal,
// a commit or any other non-application MLS message is rejected BEFORE it
// reaches the engine, so it never changes the group's membership or epoch. No
// Styx flow sends a handshake message once the session is set up.
//
// Every session is bound to the one peer it was registered for (the expected peer
// credential). Every use re-checks the 1:1 invariant: exactly two members, one
// carrying our own credential and the other carrying exactly that peer's
// credential.

// RFC 9420 §6: an MLSMessage starts with ProtocolVersion (uint16, mls10 = 1) and
// WireFormat (uint16). A PrivateMessage (wire format 2) then carries, in the
// clear, group_id<V>, epoch (uint64) and content_type (uint8). The content type
// is authenticated — it is part of the additional data of the encrypted content —
// so a sender cannot relabel a proposal or commit as application data.
const MLS_VERSION_10 = 1;
const WIRE_FORMAT_PRIVATE_MESSAGE = 2;
const CONTENT_TYPE_APPLICATION = 1;

/**
 * Read an RFC 9420 §2.1.2 variable-length integer (1, 2 or 4 bytes, minimal
 * encoding only). Null when the bytes are not a well-formed varint.
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @returns {{ value: number, next: number }|null}
 */
function readVarint(bytes, offset) {
  if (offset >= bytes.length) return null;
  const first = bytes[offset];
  const prefix = first >> 6;
  if (prefix === 0) return { value: first & 0x3f, next: offset + 1 };
  if (prefix === 1) {
    if (offset + 2 > bytes.length) return null;
    const value = ((first & 0x3f) << 8) | bytes[offset + 1];
    return value < 0x40 ? null : { value, next: offset + 2 };
  }
  if (prefix === 2) {
    if (offset + 4 > bytes.length) return null;
    const value = (first & 0x3f) * 0x1000000
      + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3];
    return value < 0x4000 ? null : { value, next: offset + 4 };
  }
  return null;
}

/**
 * True only for a serialized MLS 1.0 PrivateMessage whose content type is
 * application. Reads the public header only; decryption and authentication
 * stay with the engine.
 * @param {Uint8Array} bytes
 * @returns {boolean}
 */
export function isMlsApplicationMessage(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 4) return false;
  const version = (bytes[0] << 8) | bytes[1];
  const wireFormat = (bytes[2] << 8) | bytes[3];
  if (version !== MLS_VERSION_10 || wireFormat !== WIRE_FORMAT_PRIVATE_MESSAGE) return false;
  const groupIdLength = readVarint(bytes, 4);
  if (!groupIdLength) return false;
  const contentTypeOffset = groupIdLength.next + groupIdLength.value + 8; // skip group_id, then epoch
  if (contentTypeOffset >= bytes.length) return false;
  return bytes[contentTypeOffset] === CONTENT_TYPE_APPLICATION;
}

/**
 * Raised when a group cannot be bound, or stay bound, to the session it is
 * registered for: it is not exactly {us, the expected peer}, it is not the group
 * the caller declared, or it is already registered under another contact.
 */
export class MlsBindingError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'MlsBindingError';
  }
}

/**
 * The single peer credential of a group that is exactly {us, one other member},
 * or null. A group whose other member repeats our own credential has no peer.
 * @param {string[]} ids member credentials
 * @param {string} own our own credential
 * @returns {string|null}
 */
export function soleOtherMember(ids, own) {
  if (!Array.isArray(ids) || ids.length !== 2) return null;
  if (ids.filter((id) => id === own).length !== 1) return null;
  const other = ids.find((id) => id !== own);
  return typeof other === 'string' && other.length > 0 ? other : null;
}

export class MlsSession {
  /**
   * @param {import('./mls-engine.js').MlsEngine} engine owning engine (provider+identity)
   * @param {object} group the OpenMLS Group handle
   * @param {string} peer the expected peer credential this session is bound to
   */
  constructor(engine, group, peer) {
    if (typeof peer !== 'string' || peer.length === 0 || peer === engine.name) {
      throw new MlsBindingError('MlsSession: a session must be bound to one expected peer other than us');
    }
    this._engine = engine;
    this._group = group;
    this._peer = peer;
  }

  /** The expected peer credential this session is bound to. @returns {string} */
  get peer() { return this._peer; }

  /**
   * Whether this group is exactly {us, the expected peer}: two members, exactly
   * one carrying our own credential and the other carrying the peer's.
   * @returns {boolean}
   */
  isOneToOne() {
    return soleOtherMember(this.memberIdentities(), this._engine.name) === this._peer;
  }

  /** @private */
  _requireOneToOne(operation) {
    if (!this.isOneToOne()) {
      throw new MlsBindingError(
        `MlsSession.${operation}: the group is not exactly two members (us and the expected peer)`,
      );
    }
  }

  /**
   * Encrypt an application message for the peer.
   * @param {Uint8Array} plaintext non-empty
   * @returns {Uint8Array} serialized MLS private message (opaque wire bytes)
   */
  encrypt(plaintext) {
    this._requireOneToOne('encrypt');
    if (!(plaintext instanceof Uint8Array) || plaintext.length === 0) {
      throw new TypeError('MlsSession.encrypt: plaintext must be a non-empty Uint8Array');
    }
    return this._group.create_message(this._engine.provider, this._engine.identity, plaintext);
  }

  /**
   * Process an incoming MLS application message and return its plaintext.
   * Any other MLS message (a proposal, a commit, or a message that is not a
   * PrivateMessage) throws before the engine sees it, leaving the group state —
   * membership and epoch — unchanged. An application message that yields no
   * plaintext (our own message echoed back, which OpenMLS reports as
   * OwnPrivateMessage, or an empty payload no Styx flow sends) also throws: it is
   * not a message from the peer.
   *
   * The input is copied once, before the header check, and only that private
   * copy is checked and handed to the engine: the bytes that were checked are the
   * bytes that are processed, even if the caller's buffer changes meanwhile.
   * Anything that is not a genuine Uint8Array view is refused.
   * @param {Uint8Array} wireBytes
   * @returns {{ kind: 'application', plaintext: Uint8Array }}
   */
  decrypt(wireBytes) {
    this._requireOneToOne('decrypt');
    if (!ArrayBuffer.isView(wireBytes) || !(wireBytes instanceof Uint8Array)) {
      throw new Error('MlsSession.decrypt: not an MLS application message; rejected without applying it');
    }
    const bytes = new Uint8Array(wireBytes); // a fresh, private copy
    if (!isMlsApplicationMessage(bytes)) {
      throw new Error('MlsSession.decrypt: not an MLS application message; rejected without applying it');
    }
    const plaintext = this._group.process_message(this._engine.provider, bytes);
    if (!plaintext || plaintext.length === 0) {
      throw new Error('MlsSession.decrypt: no application plaintext from the peer');
    }
    return { kind: 'application', plaintext };
  }

  /**
   * Derive a secret from the group's key schedule. Every member of the same group
   * at the same epoch derives the same bytes, so this is how two peers can compare
   * a value that only a genuine shared session could produce.
   * @param {string} label domain separation
   * @param {Uint8Array} context binds the derivation to a caller-chosen context
   * @param {number} length output bytes
   * @returns {Uint8Array}
   */
  exportSecret(label, context, length) {
    this._requireOneToOne('exportSecret');
    return this._group.export_key(this._engine.provider, label, context, length);
  }

  /**
   * The MLS credential of every current group member — which Styx sets to the
   * member's Nostr pubkey hex. Lets a caller check who is actually in this group,
   * rather than trusting who claims to have sent it.
   * @returns {string[]}
   */
  memberIdentities() {
    return this._group.member_identities();
  }
}
