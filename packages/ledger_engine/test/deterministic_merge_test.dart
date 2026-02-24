import 'dart:convert';
import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/src/conflict/deterministic_merge.dart';
import 'package:styx_ledger_engine/src/conflict/fork_detector.dart';
import 'package:styx_ledger_engine/src/conflict/merge_event_factory.dart';
import 'package:styx_ledger_engine/src/event_factory.dart';
import 'package:styx_ledger_engine/src/event_type.dart';
import 'package:styx_ledger_engine/src/hlc.dart';
import 'package:styx_ledger_engine/src/ledger_event.dart';
import 'package:styx_ledger_engine/src/vector_clock.dart';
import 'package:test/test.dart';

import 'test_helpers.dart';

/// Creates a minimal LedgerEvent with given VC and pubkey for ordering tests.
LedgerEvent _makeEvent({
  required int vcA,
  required int vcB,
  required String pubkey,
  String eventId = 'evt',
}) {
  return LedgerEvent(
    eventId: eventId,
    eventType: EventType.message,
    payload: null,
    previousHash: null,
    eventHash: 'hash-$eventId',
    hlc: HybridLogicalClock(
      timestamp: DateTime.utc(2025),
      counter: 0,
      nodeId: 'testnode',
    ),
    vectorClock: VectorClock(a: vcA, b: vcB),
    senderPubkey: pubkey,
    signature: Uint8List(64),
    createdAt: DateTime.utc(2025),
  );
}

void main() {
  late StyxKeyPair keyPairA;
  late StyxKeyPair keyPairB;
  late EventFactory factory;
  final merger = DeterministicMerge();

  setUpAll(() async {
    final idm = IdentityManager();
    keyPairA = await idm.generate();
    keyPairB = await idm.generate();
    factory = EventFactory(signer: Signer(), hasher: Hasher());
  });

  group('DeterministicMerge', () {
    // T6.11: Order by VC total
    test('T6.11 — orders by VC total ascending', () {
      final events = [
        _makeEvent(vcA: 3, vcB: 2, pubkey: 'aaa', eventId: 'e1'), // total=5
        _makeEvent(vcA: 1, vcB: 2, pubkey: 'bbb', eventId: 'e2'), // total=3
        _makeEvent(vcA: 4, vcB: 3, pubkey: 'ccc', eventId: 'e3'), // total=7
      ];
      final ordered = merger.orderConcurrentEvents(events);
      expect(ordered.map((e) => e.vectorClock.total), [3, 5, 7]);
    });

    // T6.12: Tiebreak by pubkey
    test('T6.12 — tiebreaks by pubkey lexicographic', () {
      final events = [
        _makeEvent(vcA: 2, vcB: 2, pubkey: 'zzz', eventId: 'e1'),
        _makeEvent(vcA: 2, vcB: 2, pubkey: 'aaa', eventId: 'e2'),
        _makeEvent(vcA: 2, vcB: 2, pubkey: 'mmm', eventId: 'e3'),
      ];
      final ordered = merger.orderConcurrentEvents(events);
      expect(ordered.map((e) => e.senderPubkey), ['aaa', 'mmm', 'zzz']);
    });

    // T6.13: Commutativity
    test('T6.13 — merge(A,B) == merge(B,A)', () async {
      final result = await buildFork(
        factory: factory,
        keyPairA: keyPairA,
        keyPairB: keyPairB,
        branchACount: 3,
        branchBCount: 2,
      );

      final forkAB = Fork(
        commonAncestorHash: result.base.last.eventHash,
        branchA: result.branchA,
        branchB: result.branchB,
      );
      final forkBA = Fork(
        commonAncestorHash: result.base.last.eventHash,
        branchA: result.branchB,
        branchB: result.branchA,
      );

      final mergeAB = merger.merge(fork: forkAB, localPeerRole: 'A');
      final mergeBA = merger.merge(fork: forkBA, localPeerRole: 'B');

      expect(
        mergeAB.orderedEvents.map((e) => e.eventId).toList(),
        mergeBA.orderedEvents.map((e) => e.eventId).toList(),
      );
    });

    // T6.14: 1000 random forks converge
    test('T6.14 — 1000 random forks converge', () {
      for (var i = 0; i < 1000; i++) {
        final events = [
          _makeEvent(
            vcA: (i * 7 + 3) % 50,
            vcB: (i * 11 + 1) % 50,
            pubkey: 'peer_a_${i.toRadixString(16)}',
            eventId: 'a$i',
          ),
          _makeEvent(
            vcA: (i * 13 + 5) % 50,
            vcB: (i * 3 + 7) % 50,
            pubkey: 'peer_b_${i.toRadixString(16)}',
            eventId: 'b$i',
          ),
        ];
        final orderAB = merger.orderConcurrentEvents(events);
        final orderBA = merger.orderConcurrentEvents(events.reversed.toList());
        expect(
          orderAB.map((e) => e.eventId).toList(),
          orderBA.map((e) => e.eventId).toList(),
          reason: 'Failed at iteration $i',
        );
      }
    });

    // T6.15: Merge produces linear sequence
    test('T6.15 — merge produces linear sequence from fork', () async {
      final result = await buildFork(
        factory: factory,
        keyPairA: keyPairA,
        keyPairB: keyPairB,
        branchACount: 3,
        branchBCount: 2,
      );

      final fork = Fork(
        commonAncestorHash: result.base.last.eventHash,
        branchA: result.branchA,
        branchB: result.branchB,
      );

      final mergeResult = merger.merge(fork: fork, localPeerRole: 'A');
      expect(mergeResult.orderedEvents.length, 5);
      expect(mergeResult.mergeEventNeeded, isTrue);
    });

    // T6.16: MERGE event references both tips
    test('T6.16 — MERGE event references both branch tips', () async {
      final result = await buildFork(
        factory: factory,
        keyPairA: keyPairA,
        keyPairB: keyPairB,
        branchACount: 2,
        branchBCount: 2,
      );

      final fork = Fork(
        commonAncestorHash: result.base.last.eventHash,
        branchA: result.branchA,
        branchB: result.branchB,
      );

      final mergeResult = merger.merge(fork: fork, localPeerRole: 'A');
      final lastOrdered = mergeResult.orderedEvents.last;

      final mergeFactory = MergeEventFactory(eventFactory: factory);
      final mergeEvent = await mergeFactory.createMergeEvent(
        branchAHeadHash: result.branchA.last.eventHash,
        branchBHeadHash: result.branchB.last.eventHash,
        ancestorHash: fork.commonAncestorHash,
        newPreviousEvent: lastOrdered,
        privateKey: keyPairA.privateKey,
        publicKey: keyPairA.publicKey,
        mergedVectorClock: lastOrdered.vectorClock,
        localPeerRole: 'A',
      );

      expect(mergeEvent.eventType, EventType.merge);
      final payload =
          jsonDecode(utf8.decode(mergeEvent.payload!)) as Map<String, dynamic>;
      expect(payload['branch_a_head'], result.branchA.last.eventHash);
      expect(payload['branch_b_head'], result.branchB.last.eventHash);
      expect(payload['ancestor'], fork.commonAncestorHash);
    });
  });
}
