import 'dart:async';

import 'package:styx/src/migration/rekey_protocol.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/styx_ledger_engine.dart';

/// State of the device migration process.
enum MigrationState {
  /// Not started.
  idle,

  /// New key pair has been generated.
  newKeyGenerated,

  /// Blessing event has been created.
  blessingCreated,

  /// Blessing event has been sent to the peer.
  blessingSent,

  /// Waiting for the peer to acknowledge the re-key.
  waitingPeerAck,

  /// Syncing ledger history to the new device.
  syncingHistory,

  /// Migration completed.
  completed,

  /// Migration failed.
  failed,
}

/// Abstract interface for ledger operations during migration.
abstract class MigrationLedger {
  /// Appends an event to the ledger.
  Future<void> appendEvent(LedgerEvent event);

  /// Returns the latest event in the chain.
  Future<LedgerEvent?> getLatestEvent();

  /// Returns the current vector clock.
  Future<VectorClock> getCurrentVectorClock();

  /// Returns the full event history.
  Future<List<LedgerEvent>> getHistory();
}

/// Orchestrates complete device migration.
///
/// Supports two flows:
/// 1. **With old device available:** Generate new key → Blessing → peer
///    acknowledgment → sync.
/// 2. **From Shamir backup:** Restore the original key (no re-keying needed).
class KeyMigrationService {
  /// Creates a [KeyMigrationService].
  KeyMigrationService({
    required IdentityManager identityManager,
    required ReKeyProtocol reKeyProtocol,
    required KeyBackup keyBackup,
  }) : _identityManager = identityManager,
       _reKeyProtocol = reKeyProtocol,
       _keyBackup = keyBackup;

  final IdentityManager _identityManager;
  final ReKeyProtocol _reKeyProtocol;
  final KeyBackup _keyBackup;

  MigrationState _state = MigrationState.idle;
  final _stateController = StreamController<MigrationState>.broadcast();

  /// Current migration state.
  MigrationState get state => _state;

  /// Stream of state changes.
  Stream<MigrationState> get stateStream => _stateController.stream;

  /// Step 1 (new device): Generates a new identity.
  Future<StyxKeyPair> generateNewIdentity() async {
    final keyPair = await _identityManager.generate();
    _setState(MigrationState.newKeyGenerated);
    return keyPair;
  }

  /// Step 2 (old device): Creates and returns the Blessing Event.
  ///
  /// The caller is responsible for sending the event via transport.
  Future<LedgerEvent> blessNewDevice({
    required StyxPrivateKey oldPrivateKey,
    required StyxPublicKey oldPublicKey,
    required StyxPublicKey newPublicKey,
    required LedgerEvent? previousEvent,
    required VectorClock currentVectorClock,
    required String localPeerRole,
  }) async {
    final event = await _reKeyProtocol.createBlessingEvent(
      oldPrivateKey: oldPrivateKey,
      oldPublicKey: oldPublicKey,
      newPublicKey: newPublicKey,
      previousEvent: previousEvent,
      currentVectorClock: currentVectorClock,
      localPeerRole: localPeerRole,
    );
    _setState(MigrationState.blessingCreated);
    return event;
  }

  /// Step 3 (new device): Waits for peer acknowledgment.
  ///
  /// Checks if the peer has processed the REKEY event by verifying
  /// the new key is trusted.
  Future<bool> checkPeerAcknowledgment({
    required StyxPublicKey newPublicKey,
  }) async {
    final acked = await _reKeyProtocol.isReKeyAcknowledged(
      newKey: newPublicKey,
    );
    if (acked) {
      _setState(MigrationState.completed);
    }
    return acked;
  }

  /// Restores identity from Shamir backup shares.
  ///
  /// No re-keying needed — the original key is reconstructed.
  Future<StyxKeyPair> restoreFromBackup(List<ShamirShare> shares) async {
    try {
      final keyPair = await _keyBackup.restoreFromShares(shares);
      _setState(MigrationState.completed);
      return keyPair;
    } on Object {
      _setState(MigrationState.failed);
      rethrow;
    }
  }

  /// Disposes resources.
  Future<void> dispose() async {
    await _stateController.close();
  }

  void _setState(MigrationState newState) {
    _state = newState;
    _stateController.add(newState);
  }
}
