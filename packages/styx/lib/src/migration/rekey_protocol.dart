import 'dart:convert';
import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:styx/src/trust/trust_store_manager.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/styx_ledger_engine.dart';

/// State of the re-key protocol.
enum ReKeyState {
  /// Not started.
  idle,

  /// Blessing event has been created.
  blessingCreated,

  /// Blessing event has been sent.
  blessingSent,

  /// Peer has updated their trust store.
  peerUpdated,

  /// Re-keying is complete.
  completed,
}

/// Result of processing a REKEY event.
@immutable
class ReKeyResult {
  /// Creates a [ReKeyResult].
  const ReKeyResult({
    required this.success,
    required this.oldKey,
    required this.newKey,
    this.errorMessage,
  });

  /// Whether the re-key was processed successfully.
  final bool success;

  /// The old public key.
  final StyxPublicKey oldKey;

  /// The new public key.
  final StyxPublicKey newKey;

  /// Error message if unsuccessful.
  final String? errorMessage;
}

/// Manages device re-keying via Blessing Events.
///
/// The old device signs a REKEY event containing the new device's pubkey.
/// The peer verifies the signature with the old (trusted) key and updates
/// their trust store.
class ReKeyProtocol {
  /// Creates a [ReKeyProtocol].
  ReKeyProtocol({
    required EventFactory eventFactory,
    required TrustStoreManager trustStoreManager,
    required Verifier verifier,
  }) : _eventFactory = eventFactory,
       _trustStore = trustStoreManager,
       _verifier = verifier;

  final EventFactory _eventFactory;
  final TrustStoreManager _trustStore;
  final Verifier _verifier;

  ReKeyState _state = ReKeyState.idle;

  /// Current state.
  ReKeyState get state => _state;

  /// Creates a Blessing Event: old device signs the new public key.
  ///
  /// The REKEY event is appended to the chain with payload containing
  /// both old and new public keys.
  Future<LedgerEvent> createBlessingEvent({
    required StyxPrivateKey oldPrivateKey,
    required StyxPublicKey oldPublicKey,
    required StyxPublicKey newPublicKey,
    required LedgerEvent? previousEvent,
    required VectorClock currentVectorClock,
    required String localPeerRole,
  }) async {
    final payloadMap = {
      'old_key': oldPublicKey.toHex(),
      'new_key': newPublicKey.toHex(),
    };
    final payload = utf8.encode(jsonEncode(payloadMap));

    final event = await _eventFactory.createEvent(
      type: EventType.rekey,
      payload: Uint8List.fromList(payload),
      privateKey: oldPrivateKey,
      publicKey: oldPublicKey,
      previousEvent: previousEvent,
      currentVectorClock: currentVectorClock,
      localPeerRole: localPeerRole,
    );

    _state = ReKeyState.blessingCreated;
    return event;
  }

  /// Processes a received REKEY event.
  ///
  /// 1. Verifies the signature with the old key (must be trusted).
  /// 2. Extracts the new key from the payload.
  /// 3. Updates the trust store.
  Future<ReKeyResult> processReKeyEvent({
    required LedgerEvent rekeyEvent,
  }) async {
    if (rekeyEvent.eventType != EventType.rekey) {
      return ReKeyResult(
        success: false,
        oldKey: StyxPublicKey(Uint8List(32)),
        newKey: StyxPublicKey(Uint8List(32)),
        errorMessage: 'Not a REKEY event',
      );
    }

    final senderKey = StyxPublicKey.fromHex(rekeyEvent.senderPubkey);

    // Check that sender is trusted.
    final isTrusted = await _trustStore.isTrusted(senderKey);
    if (!isTrusted) {
      return ReKeyResult(
        success: false,
        oldKey: senderKey,
        newKey: StyxPublicKey(Uint8List(32)),
        errorMessage: 'Sender key is not trusted',
      );
    }

    // Verify the signature.
    final hashBytes = _eventFactory.computeHashBytes(
      previousHash: rekeyEvent.previousHash,
      eventType: rekeyEvent.eventType,
      payload: rekeyEvent.payload,
      hlcBytes: rekeyEvent.hlc.toBytes(),
    );

    final signatureValid = await _verifier.verify(
      payload: hashBytes,
      signatureBytes: rekeyEvent.signature,
      publicKey: senderKey,
    );

    if (!signatureValid) {
      return ReKeyResult(
        success: false,
        oldKey: senderKey,
        newKey: StyxPublicKey(Uint8List(32)),
        errorMessage: 'Invalid signature',
      );
    }

    // Parse payload.
    final payloadJson =
        jsonDecode(utf8.decode(rekeyEvent.payload!)) as Map<String, dynamic>;
    final newKeyHex = payloadJson['new_key'] as String;
    final newKey = StyxPublicKey.fromHex(newKeyHex);

    // Update trust store.
    await _trustStore.updatePeerKey(oldKey: senderKey, newKey: newKey);

    _state = ReKeyState.peerUpdated;
    return ReKeyResult(
      success: true,
      oldKey: senderKey,
      newKey: newKey,
    );
  }

  /// Checks if the re-keying has been acknowledged by the peer.
  Future<bool> isReKeyAcknowledged({
    required StyxPublicKey newKey,
  }) async {
    return _trustStore.isTrusted(newKey);
  }
}
