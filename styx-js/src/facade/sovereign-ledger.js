// styx-js/src/facade/sovereign-ledger.js
// Main entry point for the Styx JS library — orchestrates all subsystems

import { EventEmitter, bytesToHex } from '../utils.js';
import { schnorr } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { IdentityManager } from '../crypto/identity.js';
import { Hasher } from '../crypto/hasher.js';
import { Signer, Verifier } from '../crypto/signer.js';
import { KeyConverter, DiffieHellman } from '../crypto/key-exchange.js';
import { KeyDerivation } from '../crypto/key-derivation.js';
import { StyxEncryptor } from '../crypto/encryption.js';
import { Spake2Protocol } from '../crypto/spake2.js';
import { MnemonicGenerator, DoubleCheckVerifier } from '../crypto/mnemonic.js';
import { KeyBackup, ShamirShare } from '../crypto/shamir.js';

import { EventType, PruneReason } from '../ledger/event.js';
import { VectorClock } from '../ledger/vector-clock.js';
import { EventFactory } from '../ledger/event-factory.js';
import { ChainValidator } from '../ledger/chain-validator.js';
import { LedgerService } from '../ledger/ledger-service.js';
import { ForkDetector, DeterministicMerge, MergeEventFactory } from '../ledger/fork-merge.js';
import { PruneProtocol, RetentionManager } from '../ledger/pruning.js';

import { TransportState } from '../transport/transport-interface.js';
import { WebRTCTransport } from '../transport/webrtc-transport.js';
import { NostrTransport, RelayPool } from '../transport/nostr-transport.js';
import { TransportFailover, TransportPriority, OutboxWorker } from '../transport/failover.js';

import {
  TrustStoreManager,
  QrPairingService,
  RemotePairingService,
} from '../pairing/trust-store.js';

/** @enum {string} */
export const StyxState = {
  UNINITIALIZED: 'uninitialized',
  INITIALIZING: 'initializing',
  UNPAIRED: 'unpaired',
  READY: 'ready',
  DEGRADED: 'degraded',
  PAIRING: 'pairing',
  MIGRATING: 'migrating',
  ERROR: 'error',
  SHUTTING_DOWN: 'shuttingDown',
};

/** @enum {string} */
export const LogLevel = {
  NONE: 'none',
  ERROR: 'error',
  WARNING: 'warning',
  INFO: 'info',
  DEBUG: 'debug',
};

/**
 * Configuration for the Styx ledger.
 */
export class LedgerConfig {
  constructor({
    relayUrls = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.snort.social'],
    privacyProfile = 'balanced',
    retentionPeriodMs = null,
    retentionTypes = [],
    logLevel = LogLevel.INFO,
    persistence = 'memory', // 'memory' | 'indexeddb'
    dbName = 'styx-ledger',
    signalingUrl = null, // WebSocket URL for WebRTC signaling
    iceServers = null,
  } = {}) {
    this.relayUrls = relayUrls;
    this.privacyProfile = privacyProfile;
    this.retentionPeriodMs = retentionPeriodMs;
    this.retentionTypes = retentionTypes;
    this.logLevel = logLevel;
    this.persistence = persistence;
    this.dbName = dbName;
    this.signalingUrl = signalingUrl;
    this.iceServers = iceServers;
    Object.freeze(this);
  }
}

/**
 * Main entry point for the Styx library.
 * Manages identity, pairing, event exchange, privacy, and device migration.
 */
export class SovereignLedger {
  /**
   * @param {LedgerConfig} config
   * @param {import('../storage/store-interface.js').LedgerStore} ledgerStore
   * @param {import('../storage/store-interface.js').PeerStore} peerStore
   * @param {import('../storage/store-interface.js').SecureKeyStore} keyStore
   * @param {import('../storage/store-interface.js').OutboxStore} outboxStore
   */
  constructor({ config, ledgerStore, peerStore, keyStore, outboxStore }) {
    this._config = config || new LedgerConfig();
    this._ledgerStore = ledgerStore;
    this._peerStore = peerStore;
    this._keyStore = keyStore;
    this._outboxStore = outboxStore;

    this._state = StyxState.UNINITIALIZED;
    this._emitter = new EventEmitter();

    // Crypto primitives
    this._identityManager = new IdentityManager();
    this._hasher = new Hasher();
    this._signer = new Signer();
    this._verifier = new Verifier();
    this._keyConverter = new KeyConverter();
    this._dh = new DiffieHellman();
    this._keyDerivation = new KeyDerivation();
    this._spake2Protocol = new Spake2Protocol();
    this._mnemonicGenerator = new MnemonicGenerator();
    this._doubleCheckVerifier = new DoubleCheckVerifier();
    this._keyBackup = new KeyBackup();

    // These will be initialized after identity is loaded
    this._identity = null;
    this._keyPair = null;
    this._peerRole = null;
    this._ledgerService = null;
    this._eventFactory = null;
    this._chainValidator = null;
    this._transport = null;
    this._outboxWorker = null;
    this._trustStore = null;
    this._qrPairing = null;
    this._remotePairing = null;
    this._forkDetector = null;
    this._merge = null;
    this._pruneProtocol = null;
    this._retentionManager = null;
  }

  // --- Properties ---

  get state() { return this._state; }
  get identity() { return this._identity; }

  /** Event stream for reactive subscriptions */
  get eventStream() {
    return {
      onAllEvents: (cb) => this._ledgerService?.onNewEvent(cb),
      onRemoteEvents: (cb) => this._ledgerService?.onRemoteEvent(cb),
      onEventsByType: (type, cb) => {
        return this._ledgerService?.onNewEvent((event) => {
          if (event.eventType === type) cb(event);
        });
      },
    };
  }

  // --- Lifecycle ---

  /**
   * Initialize: generate/load identity, set up crypto, prepare ledger.
   */
  async initialize() {
    this._setState(StyxState.INITIALIZING);

    try {
      // Load or generate identity
      let keyPair = await this._keyStore.retrieveKeyPair('primary');
      if (!keyPair) {
        keyPair = await this._identityManager.generate();
        await this._keyStore.storeKeyPair({ keyId: 'primary', keyPair });
        this._log('info', 'Generated new identity:', keyPair.publicKey.nodeId);
      } else {
        this._log('info', 'Loaded existing identity:', keyPair.publicKey.nodeId);
      }

      this._keyPair = keyPair;
      this._identity = {
        publicKey: keyPair.publicKey,
        nodeId: keyPair.publicKey.nodeId,
        peerRole: null, // Set after pairing
      };

      // Set up ledger engine
      this._eventFactory = new EventFactory(this._signer, this._hasher);
      this._chainValidator = new ChainValidator(this._hasher, this._verifier);
      this._forkDetector = new ForkDetector();
      this._merge = new DeterministicMerge();
      this._pruneProtocol = new PruneProtocol(this._eventFactory);
      this._retentionManager = new RetentionManager();

      // Trust store
      this._trustStore = new TrustStoreManager(this._peerStore);
      this._qrPairing = new QrPairingService(this._trustStore);
      this._remotePairing = null; // Created on demand

      // Check if we have a paired peer
      const peer = await this._trustStore.getActivePeer();
      if (peer) {
        await this._setupPairedState(peer.publicKey);
      } else {
        this._setState(StyxState.UNPAIRED);
      }
    } catch (e) {
      this._log('error', 'Initialization failed:', e);
      this._setState(StyxState.ERROR);
      throw e;
    }
  }

  /**
   * Gracefully shut down all subsystems.
   */
  async shutdown() {
    this._setState(StyxState.SHUTTING_DOWN);

    if (this._outboxWorker) this._outboxWorker.stop();
    if (this._transport) await this._transport.dispose();

    this._emitter.removeAllListeners();
    this._setState(StyxState.UNINITIALIZED);
  }

  // --- Pairing ---

  /** Generate QR pairing data */
  async generatePairingQr() {
    this._assertState(StyxState.UNPAIRED);
    return this._qrPairing.generateQrData(
      this._keyPair.publicKey,
      this._config.relayUrls
    );
  }

  /** Process scanned QR payload */
  async processPairingQr(qrPayload) {
    this._assertState(StyxState.UNPAIRED);
    return this._qrPairing.processScannedQr(qrPayload, this._keyPair.publicKey);
  }

  /** Start remote pairing (generate or join with mnemonic) */
  async startRemotePairing(existingMnemonic) {
    this._assertState(StyxState.UNPAIRED);
    this._setState(StyxState.PAIRING);

    this._remotePairing = new RemotePairingService({
      spake2Protocol: this._spake2Protocol,
      mnemonicGenerator: this._mnemonicGenerator,
      doubleCheckVerifier: this._doubleCheckVerifier,
      trustStore: this._trustStore,
    });

    if (existingMnemonic) {
      // Responder
      return existingMnemonic;
    } else {
      // Initiator
      return this._remotePairing.generateMnemonic();
    }
  }

  /** Get Double Check verification code */
  async getDoubleCheckCode() {
    if (!this._remotePairing) throw new Error('No remote pairing in progress');
    return this._remotePairing.getDoubleCheckCode();
  }

  /** Confirm pairing after QR or Double Check verification */
  async confirmPairing({ peerPublicKey, peerAlias }) {
    const { StyxPublicKey } = await import('../crypto/identity.js');
    const pubKey = peerPublicKey instanceof StyxPublicKey
      ? peerPublicKey
      : StyxPublicKey.fromHex(peerPublicKey);

    await this._trustStore.addTrustedPeer(pubKey, peerAlias);
    await this._setupPairedState(pubKey.toHex());
  }

  /** Get current paired peer */
  async getPeer() {
    return this._trustStore.getActivePeer();
  }

  // --- Event Sending ---

  async sendTransaction({ payload }) {
    return this._sendEvent(EventType.TRANSACTION, payload);
  }

  async sendMessage({ payload }) {
    return this._sendEvent(EventType.MESSAGE, payload);
  }

  async sendSOS({ payload }) {
    return this._sendEvent(EventType.SOS, payload);
  }

  async sendConfig({ payload }) {
    return this._sendEvent(EventType.CONFIG, payload);
  }

  // --- History ---

  async getHistory() {
    return this._ledgerService.getHistory();
  }

  async getHistoryRange({ from, to }) {
    return this._ledgerService.getHistoryRange(from, to);
  }

  async validateChain() {
    return this._ledgerService.validateChain();
  }

  // --- Pruning ---

  async requestPrune({ targetEventId, reason }) {
    this._assertState(StyxState.READY, StyxState.DEGRADED);

    if (reason === PruneReason.GDPR_ARTICLE_17) {
      await this._pruneProtocol.executeUnilateralPrune(targetEventId, this._ledgerStore);
    } else {
      const target = await this._ledgerStore.getEventById(targetEventId);
      if (!target) throw new Error(`Event not found: ${targetEventId}`);

      const event = await this._pruneProtocol.requestPrune({
        targetEventId,
        targetEventHash: target.eventHash,
        reason,
        privateKey: this._keyPair.privateKey,
        publicKey: this._keyPair.publicKey,
        previousEvent: await this._ledgerStore.getLatestEvent(),
        currentVectorClock: await this._ledgerStore.getCurrentVectorClock(),
        localPeerRole: this._peerRole,
      });

      await this._ledgerStore.appendEvent(event);
      await this._outboxStore.addEntry(event.eventId);
    }
  }

  async setRetentionPolicy({ periodMs, types }) {
    this._config = new LedgerConfig({
      ...this._config,
      retentionPeriodMs: periodMs,
      retentionTypes: types,
    });
  }

  async getExpiredEvents() {
    if (!this._config.retentionPeriodMs) return [];
    const events = await this._ledgerStore.getAllEvents();
    return this._retentionManager.getExpiredEvents(
      events,
      this._config.retentionPeriodMs,
      this._config.retentionTypes
    );
  }

  // --- Shamir Backup ---

  async createIdentityBackup({ threshold = 2, totalShares = 3 } = {}) {
    const shares = this._keyBackup.backupPrivateKey(
      this._keyPair.privateKey,
      threshold,
      totalShares
    );
    return shares.map((s) => s.serialize());
  }

  async restoreIdentity({ shares }) {
    const shamirShares = shares.map((s) => ShamirShare.deserialize(s));
    const keyPair = await this._keyBackup.restoreFromShares(
      shamirShares,
      this._identityManager
    );
    await this._keyStore.storeKeyPair({ keyId: 'primary', keyPair });
    this._keyPair = keyPair;
    this._identity = {
      publicKey: keyPair.publicKey,
      nodeId: keyPair.publicKey.nodeId,
      peerRole: this._peerRole,
    };
  }

  // --- Re-keying ---

  async blessNewDevice({ newPublicKey }) {
    this._assertState(StyxState.READY);
    const payload = new TextEncoder().encode(
      JSON.stringify({ type: 'rekey', newPublicKey: newPublicKey.toHex() })
    );
    return this._sendEvent(EventType.REKEY, payload);
  }

  // --- State management ---

  onStateChange(callback) {
    return this._emitter.on('stateChange', callback);
  }

  // --- Private ---

  async _sendEvent(type, payload) {
    this._assertState(StyxState.READY, StyxState.DEGRADED);

    const event = await this._ledgerService.appendEvent({
      type,
      payload,
      privateKey: this._keyPair.privateKey,
      publicKey: this._keyPair.publicKey,
    });

    // Queue for outbox delivery
    await this._outboxStore.addEntry(event.eventId);

    // Attempt immediate send
    if (this._outboxWorker) {
      this._outboxWorker.processNow().catch(() => {});
    }

    return event;
  }

  async _setupPairedState(peerPubkeyHex) {
    const localHex = this._keyPair.publicKey.toHex();
    this._peerRole = localHex < peerPubkeyHex ? 'A' : 'B';
    this._identity.peerRole = this._peerRole;

    // Initialize ledger service
    this._ledgerService = new LedgerService(
      this._eventFactory,
      this._chainValidator,
      this._ledgerStore,
      this._peerRole
    );

    // Create genesis if empty chain
    const count = await this._ledgerStore.count();
    if (count === 0) {
      const genesis = await this._eventFactory.createGenesisEvent({
        privateKey: this._keyPair.privateKey,
        publicKey: this._keyPair.publicKey,
        nodeId: this._keyPair.publicKey.nodeId,
      });
      await this._ledgerStore.appendEvent(genesis);
    }

    // Set up encryption keys via X25519 DH
    const { StyxPublicKey } = await import('../crypto/identity.js');
    const peerPubKey = StyxPublicKey.fromHex(peerPubkeyHex);

    const localX25519Priv = this._keyConverter.ed25519PrivateToX25519(this._keyPair.privateKey);
    const peerX25519Pub = this._keyConverter.ed25519PublicToX25519(peerPubKey);
    const sharedSecret = this._dh.computeSharedSecret(localX25519Priv, peerX25519Pub);
    const dirKeys = this._keyDerivation.deriveDirectionalKeys(
      sharedSecret,
      this._keyPair.publicKey.bytes,
      peerPubKey.bytes
    );

    const encryptor = new StyxEncryptor(dirKeys.sendKey, dirKeys.receiveKey);

    // Derive a Nostr secp256k1 keypair from the Ed25519 private key via HKDF.
    // Used exclusively for NIP-01 event signing (schnorr) on relays.
    const nostrPrivKey = hkdf(sha256, this._keyPair.privateKey.bytes, 'styx-nostr-key', '', 32);
    const nostrPubHex = bytesToHex(schnorr.getPublicKey(nostrPrivKey));

    // Set up transports (WebRTC primary + Nostr fallback)
    // The Nostr pubkey is used as the event `pubkey` field (for signing).
    // The p-tag uses the Ed25519 hex pubkeys for subscription matching —
    // relays don't validate p-tag values, they just use them for filtering.
    const relayPool = new RelayPool(this._config.relayUrls);
    const nostrTransport = new NostrTransport(
      relayPool,
      encryptor,
      nostrPubHex,       // event pubkey (secp256k1, for signing)
      peerPubkeyHex,     // p-tag on outgoing events: peer's Ed25519 pubkey
      nostrPrivKey,      // secp256k1 private key for schnorr signing
      localHex           // subscription filter: our Ed25519 pubkey (what peers tag us with)
    );

    const transports = [
      new TransportPriority(nostrTransport, 3, 5000),
    ];

    // WebRTC transport if signaling is available
    if (this._config.signalingUrl) {
      // WebRTC signaling would be set up via the signaling WebSocket
      // For now, Nostr is the primary transport
    }

    this._transport = new TransportFailover(transports);

    // Listen for incoming messages
    this._transport.onMessage((msg) => {
      this._handleIncomingMessage(msg);
    });

    // Set up outbox
    this._outboxWorker = new OutboxWorker({
      outboxStore: this._outboxStore,
      ledgerStore: this._ledgerStore,
      transport: this._transport,
      encryptor,
      localPubkey: localHex,
      peerPubkey: peerPubkeyHex,
    });

    // Connect transport
    try {
      await this._transport.connect();
      this._setState(StyxState.READY);
    } catch (e) {
      this._log('warning', 'Transport connection degraded:', e.message);
      this._setState(StyxState.DEGRADED);
    }
  }

  async _handleIncomingMessage(msg) {
    try {
      const json = JSON.parse(new TextDecoder().decode(msg.payload));
      const { LedgerEvent } = await import('../ledger/event.js');
      const { HybridLogicalClock } = await import('../ledger/hlc.js');

      const event = LedgerEvent.fromJSON(json, HybridLogicalClock, VectorClock);

      // Detect forks
      const localHead = await this._ledgerStore.getLatestEvent();
      if (localHead) {
        const fork = this._forkDetector.detectForkOnReceive(event, localHead);

        if (fork) {
          const mergeResult = this._merge.merge(fork, this._peerRole);
          if (mergeResult.mergeEventNeeded) {
            const mergeFactory = new MergeEventFactory(this._eventFactory);
            const mergeVC = localHead.vectorClock.merge(event.vectorClock);
            const mergeEvent = await mergeFactory.createMergeEvent({
              branchAHeadHash: localHead.eventHash,
              branchBHeadHash: event.eventHash,
              ancestorHash: fork.commonAncestorHash,
              newPreviousEvent: event,
              privateKey: this._keyPair.privateKey,
              publicKey: this._keyPair.publicKey,
              mergedVectorClock: mergeVC,
              localPeerRole: this._peerRole,
            });
            await this._ledgerService.receiveRemoteEvent(event);
            await this._ledgerStore.appendEvent(mergeEvent);
            return;
          }
        }
      }

      // Handle prune requests
      if (event.eventType === EventType.PRUNE_REQUEST) {
        const data = JSON.parse(new TextDecoder().decode(event.payload));
        // Auto-acknowledge non-GDPR prune requests
        if (data.reason !== PruneReason.GDPR_ARTICLE_17) {
          const ack = await this._pruneProtocol.acknowledgePrune({
            pruneRequest: event,
            privateKey: this._keyPair.privateKey,
            publicKey: this._keyPair.publicKey,
            previousEvent: event,
            currentVectorClock: event.vectorClock,
            localPeerRole: this._peerRole,
          });
          await this._ledgerStore.appendEvent(ack);
          await this._pruneProtocol.executeBilateralPrune(
            data.targetEventId,
            this._ledgerStore
          );
        }
      }

      await this._ledgerService.receiveRemoteEvent(event);
    } catch (e) {
      this._log('error', 'Failed to process incoming message:', e);
    }
  }

  _setState(newState) {
    if (this._state !== newState) {
      this._state = newState;
      this._emitter.emit('stateChange', newState);
    }
  }

  _assertState(...validStates) {
    if (!validStates.includes(this._state)) {
      throw new Error(
        `Invalid state: ${this._state}. Expected one of: ${validStates.join(', ')}`
      );
    }
  }

  _log(level, ...args) {
    const levels = ['none', 'error', 'warning', 'info', 'debug'];
    const configLevel = levels.indexOf(this._config.logLevel);
    const msgLevel = levels.indexOf(level);
    if (msgLevel <= configLevel && msgLevel > 0) {
      const fn = level === 'error' ? console.error : level === 'warning' ? console.warn : console.log;
      fn(`[Styx:${level}]`, ...args);
    }
  }
}
