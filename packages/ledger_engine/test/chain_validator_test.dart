import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/src/chain_validator.dart';
import 'package:styx_ledger_engine/src/event_factory.dart';
import 'package:styx_ledger_engine/src/event_type.dart';
import 'package:styx_ledger_engine/src/ledger_event.dart';
import 'package:test/test.dart';

/// Builds a chain of [count] events using the given [keyPair].
Future<List<LedgerEvent>> _buildChain(
  EventFactory factory,
  StyxKeyPair keyPair,
  int count,
) async {
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
      localPeerRole: 'A',
    );
    events.add(event);
    vc = event.vectorClock;
    previous = event;
  }

  return events;
}

void main() {
  late StyxKeyPair keyPair;
  late EventFactory factory;
  late ChainValidator validator;

  setUpAll(() async {
    keyPair = await IdentityManager().generate();
    factory = EventFactory(signer: Signer(), hasher: Hasher());
    validator = ChainValidator(hasher: Hasher(), verifier: Verifier());
  });

  group('ChainValidator', () {
    // T5.21: Valid chain of 10 events
    test('T5.21 — valid 10-event chain validates', () async {
      final chain = await _buildChain(factory, keyPair, 10);
      final error = await validator.validateFullChain(chain);
      expect(error, isNull);
    });

    // T5.22: Valid chain of 1000 events
    test('T5.22 — valid 1000-event chain validates', () async {
      final chain = await _buildChain(factory, keyPair, 1000);
      final error = await validator.validateFullChain(chain);
      expect(error, isNull);
    });

    // T5.23: Hash altered
    test('T5.23 — altered hash detected', () async {
      final chain = await _buildChain(factory, keyPair, 10);
      // Tamper with event #5's hash.
      final tampered = LedgerEvent(
        eventId: chain[5].eventId,
        eventType: chain[5].eventType,
        payload: chain[5].payload,
        previousHash: chain[5].previousHash,
        eventHash: 'tampered_hash_value',
        hlc: chain[5].hlc,
        vectorClock: chain[5].vectorClock,
        senderPubkey: chain[5].senderPubkey,
        signature: chain[5].signature,
        createdAt: chain[5].createdAt,
      );
      final tamperedChain = [...chain];
      tamperedChain[5] = tampered;

      final error = await validator.validateFullChain(tamperedChain);
      expect(error, isNotNull);
      expect(error!.errorType, ChainErrorType.hashMismatch);
      expect(error.eventId, chain[5].eventId);
    });

    // T5.24: Signature altered
    test('T5.24 — altered signature detected', () async {
      final chain = await _buildChain(factory, keyPair, 10);
      // Flip one byte in event #3's signature.
      final badSig = Uint8List.fromList(chain[3].signature);
      badSig[0] ^= 0xFF;
      final tampered = LedgerEvent(
        eventId: chain[3].eventId,
        eventType: chain[3].eventType,
        payload: chain[3].payload,
        previousHash: chain[3].previousHash,
        eventHash: chain[3].eventHash,
        hlc: chain[3].hlc,
        vectorClock: chain[3].vectorClock,
        senderPubkey: chain[3].senderPubkey,
        signature: badSig,
        createdAt: chain[3].createdAt,
      );
      final tamperedChain = [...chain];
      tamperedChain[3] = tampered;

      final error = await validator.validateFullChain(tamperedChain);
      expect(error, isNotNull);
      expect(error!.errorType, ChainErrorType.signatureInvalid);
      expect(error.eventId, chain[3].eventId);
    });

    // T5.25: Wrong previousHash
    test('T5.25 — wrong previousHash detected', () async {
      final chain = await _buildChain(factory, keyPair, 10);
      // Change event #7's previousHash.
      final tampered = LedgerEvent(
        eventId: chain[7].eventId,
        eventType: chain[7].eventType,
        payload: chain[7].payload,
        previousHash: 'wrong_previous_hash',
        eventHash: chain[7].eventHash,
        hlc: chain[7].hlc,
        vectorClock: chain[7].vectorClock,
        senderPubkey: chain[7].senderPubkey,
        signature: chain[7].signature,
        createdAt: chain[7].createdAt,
      );
      final tamperedChain = [...chain];
      tamperedChain[7] = tampered;

      final error = await validator.validateFullChain(tamperedChain);
      expect(error, isNotNull);
      expect(error!.errorType, ChainErrorType.previousHashMissing);
      expect(error.eventId, chain[7].eventId);
    });

    // T5.26: Genesis not in first position
    test('T5.26 — genesis violation when first event has previousHash',
        () async {
      final chain = await _buildChain(factory, keyPair, 5);
      // Replace first event with one that has a previousHash.
      final badGenesis = LedgerEvent(
        eventId: chain[0].eventId,
        eventType: chain[0].eventType,
        payload: chain[0].payload,
        previousHash: 'some_hash',
        eventHash: chain[0].eventHash,
        hlc: chain[0].hlc,
        vectorClock: chain[0].vectorClock,
        senderPubkey: chain[0].senderPubkey,
        signature: chain[0].signature,
        createdAt: chain[0].createdAt,
      );
      final tamperedChain = [badGenesis, ...chain.skip(1)];

      final error = await validator.validateFullChain(tamperedChain);
      expect(error, isNotNull);
      expect(error!.errorType, ChainErrorType.genesisViolation);
    });

    // T5.27: Empty chain is valid
    test('T5.27 — empty chain validates', () async {
      final error = await validator.validateFullChain([]);
      expect(error, isNull);
    });

    // T5.28: Single genesis event
    test('T5.28 — single genesis event validates', () async {
      final genesis = await factory.createGenesisEvent(
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        nodeId: keyPair.publicKey.toHex().substring(0, 8),
      );
      final error = await validator.validateFullChain([genesis]);
      expect(error, isNull);
    });
  });
}
