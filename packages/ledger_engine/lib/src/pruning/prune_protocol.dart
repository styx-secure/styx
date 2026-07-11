import 'dart:convert';
import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/src/event_factory.dart';
import 'package:styx_ledger_engine/src/event_type.dart';
import 'package:styx_ledger_engine/src/ledger_event.dart';
import 'package:styx_ledger_engine/src/vector_clock.dart';
import 'package:styx_storage/styx_storage.dart';

/// State of a prune operation.
enum PruneState {
  /// No prune operation in progress.
  idle,

  /// A prune request has been sent.
  requestSent,

  /// Waiting for acknowledgement from peer.
  waitingAck,

  /// The event has been pruned bilaterally.
  pruned,

  /// The event has been pruned unilaterally (GDPR Art. 17).
  unilateralPruned,
}

/// Reason for pruning an event.
enum PruneReason {
  /// The event has exceeded its retention period.
  retentionExpired,

  /// The user explicitly requested deletion.
  userRequest,

  /// GDPR Article 17 — right to erasure.
  gdprArticle17,
}

/// Bilateral pruning protocol for GDPR compliance.
class PruneProtocol {
  /// Creates a [PruneProtocol].
  PruneProtocol({required EventFactory eventFactory})
    : _eventFactory = eventFactory;

  final EventFactory _eventFactory;

  /// Creates a PRUNE_REQUEST event.
  Future<LedgerEvent> requestPrune({
    required String targetEventId,
    required String targetEventHash,
    required PruneReason reason,
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
    required LedgerEvent? previousEvent,
    required VectorClock currentVectorClock,
    required String localPeerRole,
  }) async {
    final payload = Uint8List.fromList(
      utf8.encode(
        jsonEncode({
          'target_event_id': targetEventId,
          'target_event_hash': targetEventHash,
          'reason': reason.name,
        }),
      ),
    );

    return _eventFactory.createEvent(
      type: EventType.pruneRequest,
      payload: payload,
      privateKey: privateKey,
      publicKey: publicKey,
      previousEvent: previousEvent,
      currentVectorClock: currentVectorClock,
      localPeerRole: localPeerRole,
    );
  }

  /// Creates a PRUNE_ACK event in response to a PRUNE_REQUEST.
  Future<LedgerEvent> acknowledgePrune({
    required LedgerEvent pruneRequest,
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
    required LedgerEvent? previousEvent,
    required VectorClock currentVectorClock,
    required String localPeerRole,
  }) async {
    final requestPayload =
        jsonDecode(utf8.decode(pruneRequest.payload!)) as Map<String, dynamic>;

    final payload = Uint8List.fromList(
      utf8.encode(
        jsonEncode({
          'request_event_id': pruneRequest.eventId,
          'target_event_id': requestPayload['target_event_id'],
          'acknowledged': true,
        }),
      ),
    );

    return _eventFactory.createEvent(
      type: EventType.pruneAck,
      payload: payload,
      privateKey: privateKey,
      publicKey: publicKey,
      previousEvent: previousEvent,
      currentVectorClock: currentVectorClock,
      localPeerRole: localPeerRole,
    );
  }

  /// Executes bilateral pruning (after both REQUEST and ACK).
  Future<void> executeBilateralPrune({
    required String targetEventId,
    required EventDao eventDao,
  }) async {
    await eventDao.pruneEvent(targetEventId);
  }

  /// Executes unilateral pruning (GDPR Art. 17 — no ACK needed).
  Future<void> executeUnilateralPrune({
    required String targetEventId,
    required EventDao eventDao,
  }) async {
    await eventDao.pruneEvent(targetEventId);
  }
}
