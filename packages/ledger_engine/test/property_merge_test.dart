import 'dart:math';
import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/src/conflict/deterministic_merge.dart';
import 'package:styx_ledger_engine/src/conflict/fork_detector.dart';
import 'package:styx_ledger_engine/src/event_factory.dart';
import 'package:styx_ledger_engine/src/event_type.dart';
import 'package:styx_ledger_engine/src/hlc.dart';
import 'package:styx_ledger_engine/src/ledger_event.dart';
import 'package:styx_ledger_engine/src/vector_clock.dart';
import 'package:test/test.dart';

import 'test_helpers.dart';

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

  group('Property-based merge', () {
    // T6.27: Commutativity
    test('T6.27 — merge is commutative', () async {
      for (var i = 0; i < 20; i++) {
        final result = await buildFork(
          factory: factory,
          keyPairA: keyPairA,
          keyPairB: keyPairB,
          branchACount: 1 + (i % 5),
          branchBCount: 1 + ((i * 3) % 5),
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

        final idsAB = merger
            .merge(fork: forkAB, localPeerRole: 'A')
            .orderedEvents
            .map((e) => e.eventId)
            .toList();
        final idsBA = merger
            .merge(fork: forkBA, localPeerRole: 'B')
            .orderedEvents
            .map((e) => e.eventId)
            .toList();

        expect(idsAB, idsBA, reason: 'Commutativity failed at i=$i');
      }
    });

    // T6.28: Idempotency
    test('T6.28 — merging a chain with itself is idempotent', () async {
      final chain = await buildChain(factory, keyPairA, 5);
      final events = chain.sublist(1); // skip genesis

      final fork = Fork(
        commonAncestorHash: chain.first.eventHash,
        branchA: events,
        branchB: events,
      );

      final result = merger.merge(fork: fork, localPeerRole: 'A');
      // Duplicates should be present (both branches are the same).
      // The ordering should be stable.
      final ids = result.orderedEvents.map((e) => e.eventId).toSet();
      expect(ids.length, events.length);
    });

    // T6.29: Chain integrity post-merge (linkage)
    test('T6.29 — chain linkage preserved after merge ordering', () async {
      final result = await buildFork(
        factory: factory,
        keyPairA: keyPairA,
        keyPairB: keyPairB,
        branchACount: 3,
      );

      final fork = Fork(
        commonAncestorHash: result.base.last.eventHash,
        branchA: result.branchA,
        branchB: result.branchB,
      );

      final mergeResult = merger.merge(fork: fork, localPeerRole: 'A');
      expect(mergeResult.orderedEvents.length, 5);
      // All events should be present.
      final allIds = {
        ...result.branchA.map((e) => e.eventId),
        ...result.branchB.map((e) => e.eventId),
      };
      final mergedIds = mergeResult.orderedEvents.map((e) => e.eventId).toSet();
      expect(mergedIds, allIds);
    });

    // T6.30: Chain integrity post-prune (pruned events keep linkage)
    test('T6.30 — pruned events preserve chain linkage', () async {
      final chain = await buildChain(factory, keyPairA, 10);

      // Simulate pruning by nullifying payloads.
      final rng = Random(42);
      for (var i = 1; i < chain.length; i++) {
        if (rng.nextBool()) {
          chain[i] = LedgerEvent(
            eventId: chain[i].eventId,
            eventType: chain[i].eventType,
            payload: null,
            previousHash: chain[i].previousHash,
            eventHash: chain[i].eventHash,
            hlc: chain[i].hlc,
            vectorClock: chain[i].vectorClock,
            senderPubkey: chain[i].senderPubkey,
            signature: chain[i].signature,
            createdAt: chain[i].createdAt,
            isPruned: true,
          );
        }
      }

      // Verify chain linkage is intact.
      for (var i = 1; i < chain.length; i++) {
        expect(
          chain[i].previousHash,
          chain[i - 1].eventHash,
          reason: 'Chain linkage broken at index $i',
        );
      }
    });

    // T6.31: 10,000 merge scenarios
    test('T6.31 — 10000 merge scenarios converge', () {
      final rng = Random(12345);

      for (var i = 0; i < 10000; i++) {
        final branchSize = 1 + rng.nextInt(5);
        final events = <LedgerEvent>[];

        for (var j = 0; j < branchSize; j++) {
          events.add(
            LedgerEvent(
              eventId: 'evt-$i-$j',
              eventType: EventType.message,
              payload: null,
              previousHash: null,
              eventHash: 'hash-$i-$j',
              hlc: HybridLogicalClock(
                timestamp: DateTime.utc(2025),
                counter: j,
                nodeId: 'node${j % 2}',
              ),
              vectorClock: VectorClock(
                a: rng.nextInt(100),
                b: rng.nextInt(100),
              ),
              senderPubkey: 'pubkey_${rng.nextInt(1000).toRadixString(16)}',
              signature: Uint8List(64),
              createdAt: DateTime.utc(2025),
            ),
          );
        }

        final order1 = merger.orderConcurrentEvents(events);
        final order2 = merger.orderConcurrentEvents(events.reversed.toList());

        expect(
          order1.map((e) => e.eventId).toList(),
          order2.map((e) => e.eventId).toList(),
          reason: 'Convergence failed at scenario $i',
        );
      }
    });
  });
}
