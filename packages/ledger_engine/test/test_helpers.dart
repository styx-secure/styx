import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/src/event_factory.dart';
import 'package:styx_ledger_engine/src/event_type.dart';
import 'package:styx_ledger_engine/src/ledger_event.dart';

/// Builds a chain of [count] events.
Future<List<LedgerEvent>> buildChain(
  EventFactory factory,
  StyxKeyPair keyPair,
  int count, {
  String localPeerRole = 'A',
}) async {
  final events = <LedgerEvent>[];
  final nodeId = keyPair.publicKey.toHex().substring(0, 8);

  final genesis = await factory.createGenesisEvent(
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    nodeId: nodeId,
  );
  events.add(genesis);

  var vc = genesis.vectorClock;
  var previous = genesis;

  for (var i = 1; i < count; i++) {
    final event = await factory.createEvent(
      type: EventType.message,
      payload: Uint8List.fromList([i & 0xFF]),
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      previousEvent: previous,
      currentVectorClock: vc,
      localPeerRole: localPeerRole,
    );
    events.add(event);
    vc = event.vectorClock;
    previous = event;
  }

  return events;
}

/// Builds a fork: a common base of [baseCount] events, then [branchACount]
/// events on branch A and [branchBCount] events on branch B.
Future<
  ({
    List<LedgerEvent> base,
    List<LedgerEvent> branchA,
    List<LedgerEvent> branchB,
  })
>
buildFork({
  required EventFactory factory,
  required StyxKeyPair keyPairA,
  required StyxKeyPair keyPairB,
  int baseCount = 3,
  int branchACount = 2,
  int branchBCount = 2,
}) async {
  // Build the common base with keyPairA.
  final base = await buildChain(factory, keyPairA, baseCount);
  final ancestor = base.last;
  var vcA = ancestor.vectorClock;
  var vcB = ancestor.vectorClock;

  // Branch A (local).
  final branchA = <LedgerEvent>[];
  var prevA = ancestor;
  for (var i = 0; i < branchACount; i++) {
    final event = await factory.createEvent(
      type: EventType.message,
      payload: Uint8List.fromList([100 + i]),
      privateKey: keyPairA.privateKey,
      publicKey: keyPairA.publicKey,
      previousEvent: prevA,
      currentVectorClock: vcA,
      localPeerRole: 'A',
    );
    branchA.add(event);
    vcA = event.vectorClock;
    prevA = event;
  }

  // Branch B (remote).
  final branchB = <LedgerEvent>[];
  var prevB = ancestor;
  for (var i = 0; i < branchBCount; i++) {
    final event = await factory.createEvent(
      type: EventType.message,
      payload: Uint8List.fromList([200 + i]),
      privateKey: keyPairB.privateKey,
      publicKey: keyPairB.publicKey,
      previousEvent: prevB,
      currentVectorClock: vcB,
      localPeerRole: 'B',
    );
    branchB.add(event);
    vcB = event.vectorClock;
    prevB = event;
  }

  return (base: base, branchA: branchA, branchB: branchB);
}
