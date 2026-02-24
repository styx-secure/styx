import 'dart:async';
import 'dart:typed_data';

import 'package:styx/src/backup/shamir_backup_service.dart';
import 'package:styx/src/config/ledger_config.dart';
import 'package:styx/src/config/styx_identity.dart';
import 'package:styx/src/config/styx_state.dart';
import 'package:styx/src/migration/key_migration_service.dart';
import 'package:styx/src/migration/rekey_protocol.dart';
import 'package:styx/src/pairing/qr_pairing_data.dart';
import 'package:styx/src/pairing/qr_pairing_service.dart';
import 'package:styx/src/pairing/remote_pairing_service.dart';
import 'package:styx/src/streams/ledger_event_stream.dart';
import 'package:styx/src/trust/trust_store_manager.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/styx_ledger_engine.dart';
import 'package:styx_push_bridge_client/styx_push_bridge_client.dart';
import 'package:styx_transport/styx_transport.dart';

/// Abstract interface for ledger persistence operations.
abstract class LedgerStore {
  /// Appends an event to the chain.
  Future<LedgerEvent> appendEvent({
    required EventType type,
    required Uint8List payload,
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
  });

  /// Returns the full event history.
  Future<List<LedgerEvent>> getHistory();

  /// Validates the chain integrity.
  Future<ChainValidationError?> validateChain();

  /// Returns the latest event, or null if empty.
  Future<LedgerEvent?> getLatestEvent();

  /// Reactive stream of new events.
  Stream<LedgerEvent> watchNewEvents();
}

/// Abstract interface for push bridge registration.
abstract class PushBridgeRegistrar {
  /// Registers with the push bridge server.
  Future<void> register({
    required String pushBridgeUrl,
    required String token,
    required String pubkey,
    required PrivacyProfile profile,
    required List<String> relayUrls,
  });

  /// Unregisters from the push bridge server.
  Future<void> unregister({required String token});
}

/// Entry point for the Styx library.
///
/// Provides a unified API for all Styx operations: pairing, transactions,
/// history, privacy, pruning, and device migration.
class SovereignLedger {
  /// Creates a [SovereignLedger] with injected dependencies.
  ///
  /// Use this constructor for testing with injected dependencies.
  SovereignLedger({
    required this.identity,
    required this.config,
    required LedgerStore ledgerStore,
    required TransportInterface transport,
    required TrustStoreManager trustStore,
    required QrPairingService qrPairing,
    required RemotePairingService remotePairing,
    required ReKeyProtocol reKeyProtocol,
    required KeyMigrationService migrationService,
    required ShamirBackupService backupService,
    required RetentionManager retentionManager,
    required PruneProtocol pruneProtocol,
    StyxKeyPair? keyPair,
    PushBridgeRegistrar? pushBridge,
    LedgerEventStream? eventStream,
  })  : _ledgerStore = ledgerStore,
        _transport = transport,
        _trustStore = trustStore,
        _qrPairing = qrPairing,
        _remotePairing = remotePairing,
        _reKeyProtocol = reKeyProtocol,
        _migrationService = migrationService,
        _backupService = backupService,
        _retentionManager = retentionManager,
        _pruneProtocol = pruneProtocol,
        _keyPair = keyPair,
        _pushBridge = pushBridge,
        _eventStream = eventStream;

  /// Current identity (public key + role).
  final StyxIdentity identity;

  /// Current configuration.
  final LedgerConfig config;

  final LedgerStore _ledgerStore;
  final TransportInterface _transport;
  final TrustStoreManager _trustStore;
  final QrPairingService _qrPairing;
  final RemotePairingService _remotePairing;
  final ReKeyProtocol _reKeyProtocol;
  final KeyMigrationService _migrationService;
  final ShamirBackupService _backupService;
  final RetentionManager _retentionManager;
  final PruneProtocol _pruneProtocol;
  final PushBridgeRegistrar? _pushBridge;
  final StyxKeyPair? _keyPair;
  final LedgerEventStream? _eventStream;

  StyxState _state = StyxState.uninitialized;
  final _stateController = StreamController<StyxState>.broadcast();
  PrivacyProfile _privacyProfile = PrivacyProfile.balanced;
  Duration? _retentionPeriod;
  List<EventType> _retentionTypes = const [EventType.transaction];

  /// Current library state.
  StyxState get state => _state;

  /// Stream of state changes.
  Stream<StyxState> get stateStream => _stateController.stream;

  /// Current privacy profile.
  PrivacyProfile get privacyProfile => _privacyProfile;

  /// Stream of all events (local + remote).
  Stream<LedgerEvent> get eventStream =>
      _eventStream?.allEvents ?? const Stream.empty();

  // ---- LIFECYCLE ----

  /// Initializes the Styx library.
  ///
  /// Validates the chain, checks for a paired peer, and connects transport.
  Future<void> initialize() async {
    _setState(StyxState.initializing);

    _privacyProfile = config.privacyProfile;
    _retentionPeriod = config.retentionPeriod;
    _retentionTypes = config.retentionTypes;

    // Validate chain integrity.
    final chainError = await _ledgerStore.validateChain();
    if (chainError != null) {
      _setState(StyxState.error);
      return;
    }

    // Check if we have a paired peer.
    final peer = await _trustStore.getActivePeer();
    if (peer != null) {
      try {
        await _transport.connect();
        _setState(StyxState.ready);
      } on Object {
        _setState(StyxState.degraded);
      }
    } else {
      _setState(StyxState.unpaired);
    }
  }

  /// Shuts down the Styx library cleanly.
  Future<void> shutdown() async {
    _setState(StyxState.shuttingDown);

    try {
      await _transport.disconnect();
    } on Object {
      // Ignore disconnect errors during shutdown.
    }

    await _eventStream?.dispose();
    await _stateController.close();
  }

  // ---- PAIRING ----

  /// Generates QR code data for physical pairing.
  QrPairingData generatePairingQr({List<String>? relayHints}) {
    _setState(StyxState.pairing);
    return _qrPairing.generateQrData(
      localPublicKey: identity.publicKey,
      relayHints: relayHints ?? config.relayUrls,
    );
  }

  /// Processes a scanned QR payload from the peer.
  Future<PairingResult> processPairingQr(String qrPayload) async {
    final result = _qrPairing.processScannedQr(
      qrPayload: qrPayload,
      localPublicKey: identity.publicKey,
    );
    if (result.isValid) {
      await _qrPairing.completePairing(
        peerPublicKey: result.peerPublicKey,
        peerAlias: null,
      );
      _setState(StyxState.ready);
    }
    return result;
  }

  /// Starts remote pairing as initiator.
  ///
  /// Returns the mnemonic to communicate out-of-band.
  String startRemotePairing({int wordCount = 6}) {
    _setState(StyxState.pairing);
    return _remotePairing.generateMnemonic(wordCount: wordCount);
  }

  /// Returns the Double Check verification code.
  String? getDoubleCheckCode() {
    if (_remotePairing.state != RemotePairingState.doubleCheckPending) {
      return null;
    }
    return _remotePairing.getDoubleCheckCode();
  }

  /// Confirms the Double Check code and completes pairing.
  Future<void> confirmPairing({
    required bool codeMatches,
    String? peerAlias,
  }) async {
    await _remotePairing.confirmDoubleCheck(
      codeMatches: codeMatches,
      peerAlias: peerAlias,
    );
    if (_remotePairing.state == RemotePairingState.completed) {
      _setState(StyxState.ready);
    }
  }

  /// Returns the currently paired peer, if any.
  Future<TrustedPeer?> getPeer() => _trustStore.getActivePeer();

  // ---- TRANSACTIONS ----

  /// Records a financial transaction.
  Future<LedgerEvent> sendTransaction(Uint8List payload) =>
      _appendAndSend(EventType.transaction, payload);

  /// Sends a generic message.
  Future<LedgerEvent> sendMessage(Uint8List payload) =>
      _appendAndSend(EventType.message, payload);

  /// Sends an SOS signal (high priority).
  Future<LedgerEvent> sendSOS(Uint8List payload) =>
      _appendAndSend(EventType.sos, payload);

  /// Sends a configuration change.
  Future<LedgerEvent> sendConfig(Uint8List payload) =>
      _appendAndSend(EventType.config, payload);

  // ---- HISTORY ----

  /// Retrieves the full event history.
  Future<List<LedgerEvent>> getHistory() => _ledgerStore.getHistory();

  /// Retrieves events within a time range.
  Future<List<LedgerEvent>> getHistoryRange({
    required DateTime from,
    required DateTime to,
  }) async {
    final all = await _ledgerStore.getHistory();
    return all
        .where(
          (e) => !e.createdAt.isBefore(from) && !e.createdAt.isAfter(to),
        )
        .toList();
  }

  /// Validates the full chain integrity.
  Future<ChainValidationError?> validateChain() => _ledgerStore.validateChain();

  // ---- PRIVACY & GDPR ----

  /// Sets the privacy profile for push notifications.
  ///
  /// If a push bridge is configured, re-registers with the new profile.
  Future<void> setPrivacyProfile(PrivacyProfile profile) async {
    _privacyProfile = profile;
    final bridge = _pushBridge;
    final url = config.pushBridgeUrl;
    if (bridge != null && url != null) {
      await bridge.register(
        pushBridgeUrl: url,
        token: '',
        pubkey: identity.publicKey.toHex(),
        profile: profile,
        relayUrls: config.relayUrls,
      );
    }
  }

  /// Requests pruning of a specific event (GDPR Art. 17).
  Future<LedgerEvent> requestPrune({
    required String targetEventId,
    PruneReason reason = PruneReason.userRequest,
  }) async {
    final kp = _keyPair;
    if (kp == null) {
      throw StateError('No key pair available');
    }
    final history = await _ledgerStore.getHistory();
    final target = history.firstWhere((e) => e.eventId == targetEventId);
    final latest = await _ledgerStore.getLatestEvent();

    return _pruneProtocol.requestPrune(
      targetEventId: targetEventId,
      targetEventHash: target.eventHash,
      reason: reason,
      privateKey: kp.privateKey,
      publicKey: kp.publicKey,
      previousEvent: latest,
      currentVectorClock: latest?.vectorClock ?? const VectorClock.zero(),
      localPeerRole: identity.peerRole,
    );
  }

  /// Sets the retention policy for automatic pruning.
  Future<void> setRetentionPolicy({
    required Duration retentionPeriod,
    required List<EventType> applicableTypes,
  }) async {
    _retentionPeriod = retentionPeriod;
    _retentionTypes = applicableTypes;
  }

  /// Returns events that have expired according to the retention policy.
  List<LedgerEvent> getExpiredEvents(List<LedgerEvent> events) {
    if (_retentionPeriod == null) return [];
    return _retentionManager.getExpiredEvents(
      events: events,
      retentionPeriod: _retentionPeriod!,
      applicableTypes: _retentionTypes,
    );
  }

  // ---- DEVICE MIGRATION ----

  /// Creates an identity backup as Shamir shares.
  List<String> createIdentityBackup({
    int threshold = 2,
    int totalShares = 3,
  }) {
    final kp = _keyPair;
    if (kp == null) {
      throw StateError('No key pair available');
    }
    return _backupService.createBackup(
      privateKey: kp.privateKey,
      threshold: threshold,
      totalShares: totalShares,
    );
  }

  /// Restores identity from Shamir shares.
  static Future<StyxKeyPair> restoreIdentity(
    List<String> serializedShares,
  ) async {
    final shares = serializedShares.map(ShamirShare.deserialize).toList();
    final keyBackup = KeyBackup(
      splitter: ShamirSplitter(),
      reconstructor: ShamirReconstructor(),
    );
    return keyBackup.restoreFromShares(shares);
  }

  /// Initiates device migration by creating a blessing event.
  Future<LedgerEvent> blessNewDevice(
    StyxPublicKey newDevicePublicKey,
  ) async {
    final kp = _keyPair;
    if (kp == null) {
      throw StateError('No key pair available');
    }
    final latest = await _ledgerStore.getLatestEvent();
    return _migrationService.blessNewDevice(
      oldPrivateKey: kp.privateKey,
      oldPublicKey: kp.publicKey,
      newPublicKey: newDevicePublicKey,
      previousEvent: latest,
      currentVectorClock: latest?.vectorClock ?? const VectorClock.zero(),
      localPeerRole: identity.peerRole,
    );
  }

  /// Checks if the peer acknowledged the re-key.
  Future<bool> checkMigrationStatus(StyxPublicKey newKey) =>
      _reKeyProtocol.isReKeyAcknowledged(newKey: newKey);

  // ---- PRIVATE ----

  Future<LedgerEvent> _appendAndSend(
    EventType type,
    Uint8List payload,
  ) async {
    if (_state == StyxState.unpaired) {
      throw StateError('Must pair with a peer before sending events');
    }
    final kp = _keyPair;
    if (kp == null) {
      throw StateError('No key pair available');
    }
    return _ledgerStore.appendEvent(
      type: type,
      payload: payload,
      privateKey: kp.privateKey,
      publicKey: kp.publicKey,
    );
  }

  void _setState(StyxState newState) {
    _state = newState;
    if (!_stateController.isClosed) {
      _stateController.add(newState);
    }
  }
}
