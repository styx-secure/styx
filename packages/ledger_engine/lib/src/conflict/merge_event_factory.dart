import 'dart:convert';
import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/src/event_factory.dart';
import 'package:styx_ledger_engine/src/event_type.dart';
import 'package:styx_ledger_engine/src/ledger_event.dart';
import 'package:styx_ledger_engine/src/vector_clock.dart';

/// Creates MERGE events that reference both tips of a fork.
class MergeEventFactory {
  /// Creates a [MergeEventFactory].
  MergeEventFactory({required EventFactory eventFactory})
    : _eventFactory = eventFactory;

  final EventFactory _eventFactory;

  /// Creates a MERGE event referencing both branch tips.
  ///
  /// The payload contains the hashes of both tips and the ancestor.
  Future<LedgerEvent> createMergeEvent({
    required String branchAHeadHash,
    required String branchBHeadHash,
    required String ancestorHash,
    required LedgerEvent newPreviousEvent,
    required StyxPrivateKey privateKey,
    required StyxPublicKey publicKey,
    required VectorClock mergedVectorClock,
    required String localPeerRole,
  }) async {
    final payload = Uint8List.fromList(
      utf8.encode(
        jsonEncode({
          'type': 'merge',
          'branch_a_head': branchAHeadHash,
          'branch_b_head': branchBHeadHash,
          'ancestor': ancestorHash,
        }),
      ),
    );

    return _eventFactory.createEvent(
      type: EventType.merge,
      payload: payload,
      privateKey: privateKey,
      publicKey: publicKey,
      previousEvent: newPreviousEvent,
      currentVectorClock: mergedVectorClock,
      localPeerRole: localPeerRole,
    );
  }
}
