import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/src/event_factory.dart';
import 'package:styx_ledger_engine/src/event_type.dart';
import 'package:test/test.dart';

void main() {
  late IdentityManager identityManager;
  late StyxKeyPair keyPair;
  late EventFactory factory;
  late Verifier verifier;

  setUpAll(() async {
    identityManager = IdentityManager();
    keyPair = await identityManager.generate();
    factory = EventFactory(signer: Signer(), hasher: Hasher());
    verifier = Verifier();
  });

  group('EventFactory', () {
    // T5.14: Create genesis event
    test('T5.14 — genesis event has null previousHash', () async {
      final genesis = await factory.createGenesisEvent(
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        nodeId: keyPair.publicKey.toHex().substring(0, 8),
      );

      expect(genesis.previousHash, isNull);
      expect(genesis.eventHash, isNotEmpty);
      expect(genesis.signature.length, 64);
      expect(genesis.eventType, EventType.config);
    });

    // T5.15: Create normal event
    test('T5.15 — normal event links to previous hash', () async {
      final genesis = await factory.createGenesisEvent(
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        nodeId: keyPair.publicKey.toHex().substring(0, 8),
      );

      final event = await factory.createEvent(
        type: EventType.message,
        payload: Uint8List.fromList([1, 2, 3]),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        previousEvent: genesis,
        currentVectorClock: genesis.vectorClock,
        localPeerRole: 'A',
      );

      expect(event.previousHash, genesis.eventHash);
    });

    // T5.16: Hash is deterministic
    test('T5.16 — same input produces same hash', () async {
      final payload = Uint8List.fromList([10, 20, 30]);
      final genesis = await factory.createGenesisEvent(
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        nodeId: 'testnode',
      );

      // Compute hash manually with same inputs.
      final hash1 = factory.computeHashBytes(
        previousHash: genesis.eventHash,
        eventType: EventType.message,
        payload: payload,
        hlcBytes: genesis.hlc.toBytes(),
      );
      final hash2 = factory.computeHashBytes(
        previousHash: genesis.eventHash,
        eventType: EventType.message,
        payload: payload,
        hlcBytes: genesis.hlc.toBytes(),
      );

      expect(hash1, hash2);
    });

    // T5.17: Different payload produces different hash
    test('T5.17 — different payloads produce different hashes', () {
      final hash1 = factory.computeHashBytes(
        previousHash: null,
        eventType: EventType.message,
        payload: Uint8List.fromList([1]),
        hlcBytes: Uint8List.fromList([0]),
      );
      final hash2 = factory.computeHashBytes(
        previousHash: null,
        eventType: EventType.message,
        payload: Uint8List.fromList([2]),
        hlcBytes: Uint8List.fromList([0]),
      );

      expect(hash1, isNot(equals(hash2)));
    });

    // T5.18: Signature is verifiable
    test('T5.18 — signature is verifiable', () async {
      final genesis = await factory.createGenesisEvent(
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        nodeId: 'testnode',
      );

      final hashBytes = factory.computeHashBytes(
        previousHash: genesis.previousHash,
        eventType: genesis.eventType,
        payload: genesis.payload,
        hlcBytes: genesis.hlc.toBytes(),
      );

      final isValid = await verifier.verify(
        payload: hashBytes,
        signatureBytes: genesis.signature,
        publicKey: keyPair.publicKey,
      );

      expect(isValid, isTrue);
    });

    // T5.19: EventId uniqueness
    test('T5.19 — 1000 events have unique eventIds', () async {
      final ids = <String>{};
      for (var i = 0; i < 1000; i++) {
        final event = await factory.createGenesisEvent(
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
          nodeId: 'testnode',
        );
        ids.add(event.eventId);
      }
      expect(ids.length, 1000);
    });

    // T5.20: HLC monotonicity
    test('T5.20 — 100 sequential events have monotone HLC', () async {
      var previous = await factory.createGenesisEvent(
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        nodeId: 'testnode',
      );
      var vc = previous.vectorClock;

      for (var i = 0; i < 99; i++) {
        final event = await factory.createEvent(
          type: EventType.message,
          payload: Uint8List.fromList([i]),
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
          previousEvent: previous,
          currentVectorClock: vc,
          localPeerRole: 'A',
        );
        expect(event.hlc.compareTo(previous.hlc), isPositive);
        vc = event.vectorClock;
        previous = event;
      }
    });
  });
}
