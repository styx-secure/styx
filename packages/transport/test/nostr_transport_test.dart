import 'dart:convert';
import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_transport/src/nostr/nostr_encryptor.dart';
import 'package:styx_transport/src/nostr/nostr_transport.dart';
import 'package:styx_transport/src/nostr/relay_pool.dart';
import 'package:styx_transport/src/transport_interface.dart';
import 'package:styx_transport/src/transport_message.dart';
import 'package:test/test.dart';

import 'relay_pool_test.dart';

/// Sets up a pair of encryptors for Alice and Bob.
Future<({NostrEncryptor alice, NostrEncryptor bob})> _setupEncryptors() async {
  final dh = DiffieHellman();
  final aliceKP = await dh.generateEphemeralKeyPair();
  final bobKP = await dh.generateEphemeralKeyPair();

  final alice = NostrEncryptor(
    localPrivateKey: aliceKP.privateKey,
    remotePublicKey: bobKP.publicKey,
  );
  final bob = NostrEncryptor(
    localPrivateKey: bobKP.privateKey,
    remotePublicKey: aliceKP.publicKey,
  );

  await alice.initialize();
  await bob.initialize();

  return (alice: alice, bob: bob);
}

void main() {
  const alicePubkey = 'alice_pub_hex_key_00000000000000000000000000000001';
  const bobPubkey = 'bob_pub_hex_key_000000000000000000000000000000002';

  // T7.14 — Send and receive a message
  test('T7.14: send and receive a message', () async {
    final enc = await _setupEncryptors();
    late FakeRelayConnection conn;

    final pool = RelayPool(
      relayUrls: ['wss://r1.test'],
      factory: (url) async => conn = FakeRelayConnection(),
    );

    final transport = NostrTransport(
      relayPool: pool,
      encryptor: enc.alice,
      localPubkey: alicePubkey,
      remotePubkey: bobPubkey,
    );

    await transport.connect();
    expect(transport.isAvailable, isTrue);

    final msg = TransportMessage(
      id: 'msg-1',
      senderPubkey: alicePubkey,
      recipientPubkey: bobPubkey,
      payload: Uint8List.fromList('hello'.codeUnits),
      timestamp: DateTime.utc(2026),
    );

    await transport.send(msg);

    // Verify the relay received something.
    expect(conn.sent, hasLength(1));
    final parsed = jsonDecode(conn.sent.first) as List;
    expect(parsed[0], 'EVENT');

    await transport.dispose();
  });

  // T7.15 — Receive message from relay stream
  test('T7.15: receive message from relay stream', () async {
    final enc = await _setupEncryptors();
    late FakeRelayConnection conn;

    final pool = RelayPool(
      relayUrls: ['wss://r1.test'],
      factory: (url) async => conn = FakeRelayConnection(),
    );

    final transport = NostrTransport(
      relayPool: pool,
      encryptor: enc.bob,
      localPubkey: bobPubkey,
      remotePubkey: alicePubkey,
    );

    await transport.connect();

    final received = <TransportMessage>[];
    final sub = transport.messages.listen(received.add);

    // Encrypt a payload as Alice would.
    final payload = Uint8List.fromList('hello bob'.codeUnits);
    final encrypted = await enc.alice.encrypt(payload);

    // Simulate relay delivering the event.
    conn.simulateIncoming(
      jsonEncode([
        'EVENT',
        'sub-1',
        {
          'id': 'msg-recv-1',
          'pubkey': alicePubkey,
          'kind': 30078,
          'tags': [
            ['p', bobPubkey],
          ],
          'content': base64Encode(encrypted),
          'created_at': 1740000000,
        },
      ]),
    );

    // Wait for async processing.
    await Future<void>.delayed(const Duration(milliseconds: 50));

    expect(received, hasLength(1));
    expect(received.first.id, 'msg-recv-1');
    expect(received.first.payload, equals(payload));
    expect(received.first.senderPubkey, alicePubkey);

    await sub.cancel();
    await transport.dispose();
  });

  // T7.16 — 100 messages throughput
  test('T7.16: handles 100 messages', () async {
    final enc = await _setupEncryptors();
    late FakeRelayConnection conn;

    final pool = RelayPool(
      relayUrls: ['wss://r1.test'],
      factory: (url) async => conn = FakeRelayConnection(),
    );

    final transport = NostrTransport(
      relayPool: pool,
      encryptor: enc.bob,
      localPubkey: bobPubkey,
      remotePubkey: alicePubkey,
    );

    await transport.connect();

    final received = <TransportMessage>[];
    final sub = transport.messages.listen(received.add);

    for (var i = 0; i < 100; i++) {
      final payload = Uint8List.fromList('msg-$i'.codeUnits);
      final encrypted = await enc.alice.encrypt(payload);

      conn.simulateIncoming(
        jsonEncode([
          'EVENT',
          'sub-1',
          {
            'id': 'batch-$i',
            'pubkey': alicePubkey,
            'kind': 30078,
            'tags': [
              ['p', bobPubkey],
            ],
            'content': base64Encode(encrypted),
            'created_at': 1740000000 + i,
          },
        ]),
      );

      // Allow async processing periodically.
      if (i % 10 == 9) {
        await Future<void>.delayed(Duration.zero);
      }
    }

    await Future<void>.delayed(const Duration(milliseconds: 100));

    expect(received, hasLength(100));
    await sub.cancel();
    await transport.dispose();
  });

  // T7.17 — Wrong recipient is ignored
  test('T7.17: messages for wrong recipient are ignored', () async {
    final enc = await _setupEncryptors();
    late FakeRelayConnection conn;

    final pool = RelayPool(
      relayUrls: ['wss://r1.test'],
      factory: (url) async => conn = FakeRelayConnection(),
    );

    final transport = NostrTransport(
      relayPool: pool,
      encryptor: enc.bob,
      localPubkey: bobPubkey,
      remotePubkey: alicePubkey,
    );

    await transport.connect();

    final received = <TransportMessage>[];
    final sub = transport.messages.listen(received.add);

    final encrypted = await enc.alice.encrypt(
      Uint8List.fromList('wrong target'.codeUnits),
    );

    conn.simulateIncoming(
      jsonEncode([
        'EVENT',
        'sub-1',
        {
          'id': 'wrong-1',
          'pubkey': alicePubkey,
          'kind': 30078,
          'tags': [
            ['p', 'some_other_key'],
          ],
          'content': base64Encode(encrypted),
          'created_at': 1740000000,
        },
      ]),
    );

    await Future<void>.delayed(const Duration(milliseconds: 50));

    expect(received, isEmpty);
    await sub.cancel();
    await transport.dispose();
  });

  // T7.18 — Deduplication
  test('T7.18: duplicate messages are deduplicated', () async {
    final enc = await _setupEncryptors();
    late FakeRelayConnection conn;

    final pool = RelayPool(
      relayUrls: ['wss://r1.test'],
      factory: (url) async => conn = FakeRelayConnection(),
    );

    final transport = NostrTransport(
      relayPool: pool,
      encryptor: enc.bob,
      localPubkey: bobPubkey,
      remotePubkey: alicePubkey,
    );

    await transport.connect();

    final received = <TransportMessage>[];
    final sub = transport.messages.listen(received.add);

    final encrypted = await enc.alice.encrypt(
      Uint8List.fromList('dedup test'.codeUnits),
    );
    final event = jsonEncode([
      'EVENT',
      'sub-1',
      {
        'id': 'dup-1',
        'pubkey': alicePubkey,
        'kind': 30078,
        'tags': [
          ['p', bobPubkey],
        ],
        'content': base64Encode(encrypted),
        'created_at': 1740000000,
      },
    ]);

    // Send the same event twice.
    conn.simulateIncoming(event);
    await Future<void>.delayed(const Duration(milliseconds: 50));
    conn.simulateIncoming(event);
    await Future<void>.delayed(const Duration(milliseconds: 50));

    expect(received, hasLength(1));
    await sub.cancel();
    await transport.dispose();
  });

  // T7.19 — isAvailable reflects connection state
  test('T7.19: isAvailable reflects state', () async {
    final enc = await _setupEncryptors();

    final pool = RelayPool(
      relayUrls: ['wss://r1.test'],
      factory: (url) async => FakeRelayConnection(),
    );

    final transport = NostrTransport(
      relayPool: pool,
      encryptor: enc.alice,
      localPubkey: alicePubkey,
      remotePubkey: bobPubkey,
    );

    expect(transport.isAvailable, isFalse);
    expect(transport.currentState, TransportState.disconnected);

    await transport.connect();
    expect(transport.isAvailable, isTrue);
    expect(transport.currentState, TransportState.connected);

    await transport.disconnect();
    expect(transport.isAvailable, isFalse);
    expect(transport.currentState, TransportState.disconnected);

    await transport.dispose();
  });

  // T7.20 — State stream emits transitions
  test('T7.20: stateChanges emits correct transitions', () async {
    final enc = await _setupEncryptors();

    final pool = RelayPool(
      relayUrls: ['wss://r1.test'],
      factory: (url) async => FakeRelayConnection(),
    );

    final transport = NostrTransport(
      relayPool: pool,
      encryptor: enc.alice,
      localPubkey: alicePubkey,
      remotePubkey: bobPubkey,
    );

    final states = <TransportState>[];
    final sub = transport.stateChanges.listen(states.add);

    await transport.connect();
    await transport.disconnect();

    // Allow stream events to be delivered.
    await Future<void>.delayed(Duration.zero);

    expect(states, [
      TransportState.connecting,
      TransportState.connected,
      TransportState.disconnected,
    ]);

    await sub.cancel();
    await transport.dispose();
  });
}
