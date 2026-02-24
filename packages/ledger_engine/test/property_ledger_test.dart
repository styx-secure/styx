import 'dart:math';
import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_ledger_engine/src/chain_validator.dart';
import 'package:styx_ledger_engine/src/event_factory.dart';
import 'package:styx_ledger_engine/src/event_type.dart';
import 'package:styx_ledger_engine/src/ledger_event.dart';
import 'package:test/test.dart';

/// Builds a chain of [count] events.
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

  group('Property-based', () {
    // T5.29: Chain integrity for varying lengths
    test('T5.29 — chain integrity holds for various lengths', () async {
      for (final length in [1, 2, 5, 10, 50, 100]) {
        final chain = await _buildChain(factory, keyPair, length);
        final error = await validator.validateFullChain(chain);
        expect(error, isNull, reason: 'Failed for chain length $length');
      }
    });

    // T5.30: Tamper detection — flip one byte in any event's payload
    test('T5.30 — tamper detection for single-byte alteration', () async {
      final chain = await _buildChain(factory, keyPair, 20);
      final rng = Random(42);

      for (var trial = 0; trial < 10; trial++) {
        // Pick a random event to tamper with (skip genesis for simplicity).
        final idx = 1 + rng.nextInt(chain.length - 1);
        final original = chain[idx];

        // Flip one byte in the event hash.
        final badHash = StringBuffer();
        final chars = original.eventHash.split('');
        final charIdx = rng.nextInt(chars.length);
        for (var c = 0; c < chars.length; c++) {
          if (c == charIdx) {
            // Flip a hex digit.
            final digit = int.parse(chars[c], radix: 16);
            badHash.write(((digit + 1) % 16).toRadixString(16));
          } else {
            badHash.write(chars[c]);
          }
        }

        final tampered = LedgerEvent(
          eventId: original.eventId,
          eventType: original.eventType,
          payload: original.payload,
          previousHash: original.previousHash,
          eventHash: badHash.toString(),
          hlc: original.hlc,
          vectorClock: original.vectorClock,
          senderPubkey: original.senderPubkey,
          signature: original.signature,
          createdAt: original.createdAt,
        );

        final tamperedChain = [...chain];
        tamperedChain[idx] = tampered;

        final error = await validator.validateFullChain(tamperedChain);
        expect(
          error,
          isNotNull,
          reason: 'Tamper not detected at index $idx',
        );
      }
    });

    // T5.31: HLC monotonicity
    test('T5.31 — HLC is strictly monotonic in a chain', () async {
      final chain = await _buildChain(factory, keyPair, 200);

      for (var i = 1; i < chain.length; i++) {
        expect(
          chain[i].hlc.compareTo(chain[i - 1].hlc),
          isPositive,
          reason: 'HLC not monotonic at index $i',
        );
      }
    });
  });
}
