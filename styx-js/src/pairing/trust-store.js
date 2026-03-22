// styx-js/src/pairing/trust-store.js
// Trust store manager and pairing services

import { EventEmitter, bytesToBase64, base64ToBytes, randomBytes, bytesToHex } from '../utils.js';
import { sha256 } from '@noble/hashes/sha256';
import { StyxPublicKey } from '../crypto/identity.js';

// --- Trust Store ---

/**
 * Manages the trust store of paired peers with re-keying history.
 */
export class TrustStoreManager {
  /**
   * @param {import('../storage/store-interface.js').PeerStore} peerStore
   */
  constructor(peerStore) {
    this._peerStore = peerStore;
  }

  async addTrustedPeer(peerPublicKey, alias) {
    await this._peerStore.addPeer({
      pubkeyHex: peerPublicKey.toHex(),
      alias,
      pairedAt: new Date(),
    });
  }

  async revokePeer(peerPublicKey) {
    await this._peerStore.deactivatePeer(peerPublicKey.toHex());
  }

  async isTrusted(publicKey) {
    const peer = await this._peerStore.getPeerByPubkey(publicKey.toHex());
    return peer !== null && peer.isActive;
  }

  async getActivePeer() {
    const peers = await this._peerStore.getActivePeers();
    return peers.length > 0 ? peers[0] : null;
  }

  async updatePeerKey(oldKey, newKey) {
    await this._peerStore.updatePeerKey({
      oldPubkeyHex: oldKey.toHex(),
      newPubkeyHex: newKey.toHex(),
    });
    await this._peerStore.addRekeyEntry({
      oldKeyHex: oldKey.toHex(),
      newKeyHex: newKey.toHex(),
      timestamp: new Date(),
    });
  }

  async getRekeyHistory(currentKey) {
    return this._peerStore.getRekeyHistory(currentKey.toHex());
  }
}

// --- QR Pairing ---

const MAX_NONCES = 100;
const NONCE_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes

/**
 * QR pairing data container.
 */
export class QrPairingData {
  /**
   * @param {import('../crypto/identity.js').StyxPublicKey} publicKey
   * @param {Uint8Array} nonce - 16-byte anti-replay nonce
   * @param {string[]} [relayHints]
   */
  constructor(publicKey, nonce, relayHints) {
    this.publicKey = publicKey;
    this.nonce = nonce;
    this.relayHints = relayHints || [];
  }

  /** Serialize to JSON string for QR encoding (compatible with Dart) */
  toQrPayload() {
    const map = {
      pk: this.publicKey.toHex(),
      n: bytesToBase64(this.nonce),
    };
    if (this.relayHints.length > 0) {
      map.r = this.relayHints;
    }
    return JSON.stringify(map);
  }

  /** Deserialize from JSON QR payload */
  static fromQrPayload(payload) {
    const map = JSON.parse(payload);
    if (!map.pk || !map.n) {
      throw new Error('Invalid QR payload: missing pk or n');
    }
    const pubKey = StyxPublicKey.fromHex(map.pk);
    const nonce = base64ToBytes(map.n);
    const hints = map.r || [];
    return new QrPairingData(pubKey, nonce, hints);
  }

  get estimatedBytes() {
    return 32 + 16 + 1 + this.relayHints.join(',').length;
  }
}

/**
 * QR-based pairing protocol with nonce anti-replay.
 */
export class QrPairingService {
  /**
   * @param {TrustStoreManager} trustStore
   */
  constructor(trustStore) {
    this._trustStore = trustStore;
    this._recentNonces = []; // { nonce: Uint8Array, timestamp: number }
  }

  /**
   * Generate QR data with a fresh 16-byte nonce.
   */
  generateQrData(localPublicKey, relayHints) {
    const nonce = randomBytes(16);
    this._recentNonces.push({ nonce, timestamp: Date.now() });
    this._pruneNonces();
    return new QrPairingData(localPublicKey, nonce, relayHints);
  }

  /**
   * Validate a scanned QR payload.
   */
  processScannedQr(qrPayload, localPublicKey) {
    try {
      const data = QrPairingData.fromQrPayload(qrPayload);

      // Prevent self-pairing
      if (data.publicKey.equals(localPublicKey)) {
        return { isValid: false, errorMessage: 'Cannot pair with self' };
      }

      return {
        isValid: true,
        peerPublicKey: data.publicKey,
        relayHints: data.relayHints,
        errorMessage: null,
      };
    } catch (e) {
      return { isValid: false, errorMessage: `Invalid QR data: ${e.message}` };
    }
  }

  /**
   * Complete the pairing by persisting the peer.
   */
  async completePairing(peerPublicKey, peerAlias) {
    await this._trustStore.addTrustedPeer(peerPublicKey, peerAlias);
  }

  _pruneNonces() {
    const now = Date.now();
    this._recentNonces = this._recentNonces
      .filter((n) => now - n.timestamp < NONCE_EXPIRY_MS)
      .slice(-MAX_NONCES);
  }
}

// --- Remote Pairing ---

/** @enum {string} */
export const RemotePairingState = {
  IDLE: 'idle',
  MNEMONIC_GENERATED: 'mnemonicGenerated',
  WAITING_FOR_PEER: 'waitingForPeer',
  SPAKE2_IN_PROGRESS: 'spake2InProgress',
  DOUBLE_CHECK_PENDING: 'doubleCheckPending',
  COMPLETED: 'completed',
  FAILED: 'failed',
};

/**
 * Remote pairing service: mnemonic → SPAKE2 → Double Check → trust store.
 */
export class RemotePairingService {
  /**
   * @param {import('../crypto/spake2.js').Spake2Protocol} spake2Protocol
   * @param {import('../crypto/mnemonic.js').MnemonicGenerator} mnemonicGenerator
   * @param {import('../crypto/mnemonic.js').DoubleCheckVerifier} doubleCheckVerifier
   * @param {TrustStoreManager} trustStore
   * @param {number} [timeoutMs]
   */
  constructor({ spake2Protocol, mnemonicGenerator, doubleCheckVerifier, trustStore, timeoutMs }) {
    this._spake2Protocol = spake2Protocol;
    this._mnemonicGenerator = mnemonicGenerator;
    this._doubleCheckVerifier = doubleCheckVerifier;
    this._trustStore = trustStore;
    this._timeoutMs = timeoutMs;

    this.state = RemotePairingState.IDLE;
    this._emitter = new EventEmitter();
    this._session = null;
    this._mnemonic = null;
    this.peerPublicKey = null;
  }

  get stateStream() { return this._emitter; }

  /** Generate a mnemonic for out-of-band sharing */
  generateMnemonic(wordCount) {
    this._mnemonic = this._mnemonicGenerator.generate(wordCount);
    this._setState(RemotePairingState.MNEMONIC_GENERATED);
    return this._mnemonic;
  }

  /** Start SPAKE2 as initiator */
  startAsInitiator(mnemonic, localPublicKey) {
    this._mnemonic = mnemonic;
    const password = this._spake2Protocol.mnemonicToPassword(mnemonic);
    this._session = this._spake2Protocol.createInitiatorSession(password);
    const message = this._session.generateMessage();
    this._setState(RemotePairingState.WAITING_FOR_PEER);
    return message;
  }

  /** Start SPAKE2 as responder */
  startAsResponder(mnemonic, localPublicKey) {
    this._mnemonic = mnemonic;
    const password = this._spake2Protocol.mnemonicToPassword(mnemonic);
    this._session = this._spake2Protocol.createResponderSession(password);
    const message = this._session.generateMessage();
    this._setState(RemotePairingState.WAITING_FOR_PEER);
    return message;
  }

  /** Process the peer's SPAKE2 message */
  processPeerMessage(peerMessage) {
    this._setState(RemotePairingState.SPAKE2_IN_PROGRESS);
    const success = this._session.processMessage(peerMessage);
    if (success) {
      this._setState(RemotePairingState.DOUBLE_CHECK_PENDING);
    } else {
      this._setState(RemotePairingState.FAILED);
    }
    return success;
  }

  /** Get the 6-digit Double Check code */
  getDoubleCheckCode() {
    const sessionKey = this._session.getSessionKey();
    return this._doubleCheckVerifier.formatForDisplay(
      this._doubleCheckVerifier.generateCode(sessionKey)
    );
  }

  /** Confirm or fail pairing based on code comparison */
  async confirmDoubleCheck(codeMatches, peerPublicKey, peerAlias) {
    if (codeMatches) {
      this.peerPublicKey = peerPublicKey;
      await this._trustStore.addTrustedPeer(peerPublicKey, peerAlias);
      this._setState(RemotePairingState.COMPLETED);
    } else {
      this._setState(RemotePairingState.FAILED);
    }
  }

  /** Derive a discovery tag from the mnemonic for peer discovery */
  static deriveSharedTag(mnemonic) {
    const normalized = mnemonic.trim().toLowerCase().replace(/\s+/g, ' ');
    const hash = sha256(new TextEncoder().encode('styx-pairing-tag:' + normalized));
    return bytesToHex(hash).slice(0, 16);
  }

  cancel() {
    if (this._session) this._session.destroy();
    this._setState(RemotePairingState.FAILED);
  }

  dispose() {
    if (this._session) this._session.destroy();
    this._emitter.removeAllListeners();
  }

  _setState(newState) {
    this.state = newState;
    this._emitter.emit('stateChange', newState);
  }
}
