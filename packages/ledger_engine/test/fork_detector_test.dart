import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/src/conflict/fork_detector.dart';
import 'package:styx_ledger_engine/src/event_factory.dart';
import 'package:styx_ledger_engine/src/event_type.dart';
import 'package:test/test.dart';

import 'test_helpers.dart';

void main() {
  late StyxKeyPair keyPairA;
  late StyxKeyPair keyPairB;
  late EventFactory factory;
  late ForkDetector detector;

  setUpAll(() async {
    final idm = IdentityManager();
    keyPairA = await idm.generate();
    keyPairB = await idm.generate();
    factory = EventFactory(signer: Signer(), hasher: Hasher());
    detector = ForkDetector();
  });

  group('ForkDetector', () {
    // T6.6: No fork in linear chain
    test('T6.6 — no fork in linear chain', () async {
      final chain = await buildChain(factory, keyPairA, 10);
      final forks = detector.detectForks(chain);
      expect(forks, isEmpty);
    });

    // T6.7: Simple fork — 2 events share same previousHash
    test('T6.7 — simple fork detected', () async {
      final result = await buildFork(
        factory: factory,
        keyPairA: keyPairA,
        keyPairB: keyPairB,
        branchACount: 1,
        branchBCount: 1,
      );

      final allEvents = [
        ...result.base,
        ...result.branchA,
        ...result.branchB,
      ];
      final forks = detector.detectForks(allEvents);
      expect(forks.length, 1);
      expect(forks.first.commonAncestorHash, result.base.last.eventHash);
    });

    // T6.8: Fork with multiple branch events
    test('T6.8 — fork with 3+2 branch events', () async {
      final result = await buildFork(
        factory: factory,
        keyPairA: keyPairA,
        keyPairB: keyPairB,
        branchACount: 3,
      );

      final allEvents = [
        ...result.base,
        ...result.branchA,
        ...result.branchB,
      ];
      final forks = detector.detectForks(allEvents);
      expect(forks.length, 1);
      expect(forks.first.branchA, isNotEmpty);
      expect(forks.first.branchB, isNotEmpty);
    });

    // T6.9: Fork on receive — concurrent remote event
    test('T6.9 — fork detected on receive', () async {
      final result = await buildFork(
        factory: factory,
        keyPairA: keyPairA,
        keyPairB: keyPairB,
        branchACount: 1,
        branchBCount: 1,
      );

      final localHead = result.branchA.first;
      final remoteEvent = result.branchB.first;

      final fork = detector.detectForkOnReceive(
        remoteEvent: remoteEvent,
        localHead: localHead,
      );

      expect(fork, isNotNull);
    });

    // T6.10: No fork on receive — causal successor
    test('T6.10 — no fork on causal successor', () async {
      final chain = await buildChain(factory, keyPairA, 5);
      // Create an event that extends the chain after localHead.
      final successor = await factory.createEvent(
        type: EventType.message,
        payload: Uint8List.fromList([42]),
        privateKey: keyPairA.privateKey,
        publicKey: keyPairA.publicKey,
        previousEvent: chain.last,
        currentVectorClock: chain.last.vectorClock,
        localPeerRole: 'A',
      );

      final fork = detector.detectForkOnReceive(
        remoteEvent: successor,
        localHead: chain.last,
      );

      expect(fork, isNull);
    });
  });
}
