import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/styx_ledger_engine.dart';
import 'package:styx_transport/src/message_serializer.dart';
import 'package:test/test.dart';

Future<LedgerEvent> _createTestEvent({
  EventType type = EventType.message,
  Uint8List? payload,
  String? previousHash,
}) async {
  final identity = IdentityManager();
  final keyPair = await identity.generate();
  final signer = Signer();
  final hasher = Hasher();
  final factory = EventFactory(signer: signer, hasher: hasher);

  final nodeId = keyPair.publicKey.toHex().substring(0, 8);

  if (previousHash == null && type == EventType.message) {
    // Create genesis first, then a message event.
    final genesis = await factory.createGenesisEvent(
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      nodeId: nodeId,
    );

    return factory.createEvent(
      type: type,
      payload: payload ?? Uint8List.fromList([1, 2, 3]),
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      previousEvent: genesis,
      currentVectorClock: genesis.vectorClock,
      localPeerRole: 'A',
    );
  }

  return factory.createGenesisEvent(
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    nodeId: nodeId,
  );
}

void main() {
  final serializer = MessageSerializer();

  // T7.21 — Round-trip serialize/deserialize a single event
  test('T7.21: round-trip serialize/deserialize event', () async {
    final event = await _createTestEvent();

    final bytes = serializer.serialize(event);
    final restored = serializer.deserialize(bytes);

    expect(restored.eventId, event.eventId);
    expect(restored.eventType, event.eventType);
    expect(restored.payload, equals(event.payload));
    expect(restored.previousHash, event.previousHash);
    expect(restored.eventHash, event.eventHash);
    expect(restored.hlc.toCanonical(), event.hlc.toCanonical());
    expect(restored.vectorClock, event.vectorClock);
    expect(restored.senderPubkey, event.senderPubkey);
    expect(restored.signature, equals(event.signature));
    expect(restored.isPruned, event.isPruned);
  });

  // T7.22 — Batch of 50 events
  test('T7.22: batch serialize/deserialize 50 events', () async {
    final identity = IdentityManager();
    final keyPair = await identity.generate();
    final signer = Signer();
    final hasher = Hasher();
    final factory = EventFactory(signer: signer, hasher: hasher);
    final nodeId = keyPair.publicKey.toHex().substring(0, 8);

    final events = <LedgerEvent>[];
    final genesis = await factory.createGenesisEvent(
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      nodeId: nodeId,
    );
    events.add(genesis);

    var previous = genesis;
    var vc = genesis.vectorClock;
    for (var i = 1; i < 50; i++) {
      final event = await factory.createEvent(
        type: EventType.message,
        payload: Uint8List.fromList([i & 0xFF]),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        previousEvent: previous,
        currentVectorClock: vc,
        localPeerRole: 'A',
      );
      events.add(event);
      vc = event.vectorClock;
      previous = event;
    }

    final bytes = serializer.serializeBatch(events);
    final restored = serializer.deserializeBatch(bytes);

    expect(restored, hasLength(50));
    for (var i = 0; i < 50; i++) {
      expect(restored[i].eventId, events[i].eventId);
      expect(restored[i].eventHash, events[i].eventHash);
      expect(restored[i].vectorClock, events[i].vectorClock);
    }
  });

  // T7.23 — Pruned event round-trip
  test('T7.23: pruned event round-trip preserves isPruned', () async {
    final identity = IdentityManager();
    final keyPair = await identity.generate();
    final signer = Signer();
    final hasher = Hasher();
    final factory = EventFactory(signer: signer, hasher: hasher);
    final nodeId = keyPair.publicKey.toHex().substring(0, 8);

    final genesis = await factory.createGenesisEvent(
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      nodeId: nodeId,
    );

    // Create a pruned version (payload removed).
    final pruned = LedgerEvent(
      eventId: genesis.eventId,
      eventType: genesis.eventType,
      payload: null,
      previousHash: genesis.previousHash,
      eventHash: genesis.eventHash,
      hlc: genesis.hlc,
      vectorClock: genesis.vectorClock,
      senderPubkey: genesis.senderPubkey,
      signature: genesis.signature,
      createdAt: genesis.createdAt,
      isPruned: true,
    );

    final bytes = serializer.serialize(pruned);
    final restored = serializer.deserialize(bytes);

    expect(restored.isPruned, isTrue);
    expect(restored.payload, isNull);
    expect(restored.eventHash, genesis.eventHash);
  });

  // T7.24 — All event types serialize correctly
  test('T7.24: all event types serialize correctly', () async {
    for (final type in EventType.values) {
      if (type == EventType.config) {
        // Genesis is config type — test separately.
        final event = await _createTestEvent();
        final bytes = serializer.serialize(event);
        final restored = serializer.deserialize(bytes);
        expect(restored.eventType, event.eventType);
        continue;
      }

      final identity = IdentityManager();
      final keyPair = await identity.generate();
      final signer = Signer();
      final hasher = Hasher();
      final factory = EventFactory(signer: signer, hasher: hasher);
      final nodeId = keyPair.publicKey.toHex().substring(0, 8);

      final genesis = await factory.createGenesisEvent(
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        nodeId: nodeId,
      );

      final event = await factory.createEvent(
        type: type,
        payload: Uint8List.fromList([42]),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        previousEvent: genesis,
        currentVectorClock: genesis.vectorClock,
        localPeerRole: 'A',
      );

      final bytes = serializer.serialize(event);
      final restored = serializer.deserialize(bytes);

      expect(restored.eventType, type, reason: 'Failed for $type');
      expect(restored.eventId, event.eventId);
    }
  });
}
