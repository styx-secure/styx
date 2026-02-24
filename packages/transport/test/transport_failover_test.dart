import 'dart:async';
import 'dart:typed_data';

import 'package:styx_transport/src/failover/transport_failover.dart';
import 'package:styx_transport/src/transport_interface.dart';
import 'package:styx_transport/src/transport_message.dart';
import 'package:test/test.dart';

// ---------------------------------------------------------------------------
// Mock Transport
// ---------------------------------------------------------------------------

class MockTransport implements TransportInterface {
  MockTransport({
    this.failOnSend = false,
    this.hangOnSend = false,
    this.failOnConnect = false,
  });

  final bool failOnSend;
  final bool hangOnSend;
  final bool failOnConnect;
  final sent = <TransportMessage>[];
  int sendAttempts = 0;
  TransportState _state = TransportState.disconnected;
  final _stateController = StreamController<TransportState>.broadcast();
  final _messageController = StreamController<TransportMessage>.broadcast();

  @override
  TransportState get currentState => _state;

  @override
  Stream<TransportState> get stateChanges => _stateController.stream;

  @override
  Stream<TransportMessage> get messages => _messageController.stream;

  @override
  bool get isAvailable => _state == TransportState.connected;

  @override
  Future<void> connect() async {
    if (failOnConnect) throw Exception('Connection failed');
    _state = TransportState.connected;
    _stateController.add(_state);
  }

  @override
  Future<void> disconnect() async {
    _state = TransportState.disconnected;
    _stateController.add(_state);
  }

  @override
  Future<void> send(TransportMessage message) async {
    sendAttempts++;
    if (hangOnSend) {
      await Future<void>.delayed(const Duration(seconds: 60));
    }
    if (failOnSend) throw Exception('Send failed');
    sent.add(message);
  }

  void simulateIncoming(TransportMessage message) {
    _messageController.add(message);
  }

  Future<void> dispose() async {
    await _stateController.close();
    await _messageController.close();
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

TransportMessage _testMessage({String id = 'msg-1'}) => TransportMessage(
      id: id,
      senderPubkey: 'sender-key',
      recipientPubkey: 'recipient-key',
      payload: Uint8List.fromList([1, 2, 3]),
      timestamp: DateTime.utc(2026),
    );

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  // T9.6 — Nostr OK at first attempt
  test('T9.6: primary transport succeeds, fallback not tried', () async {
    final nostr = MockTransport();
    final email = MockTransport();

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: nostr,
          maxRetries: 3,
          timeout: const Duration(seconds: 5),
        ),
        TransportPriority(
          transport: email,
          maxRetries: 2,
          timeout: const Duration(seconds: 30),
        ),
      ],
    );

    await failover.connect();
    await failover.send(_testMessage());

    expect(nostr.sent, hasLength(1));
    expect(email.sendAttempts, 0);

    await failover.dispose();
    await nostr.dispose();
    await email.dispose();
  });

  // T9.7 — Nostr fail → Email OK
  test('T9.7: failover from primary to secondary', () async {
    final nostr = MockTransport(failOnSend: true);
    final email = MockTransport();

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: nostr,
          maxRetries: 1,
          timeout: const Duration(seconds: 5),
        ),
        TransportPriority(
          transport: email,
          maxRetries: 2,
          timeout: const Duration(seconds: 30),
        ),
      ],
    );

    await failover.connect();
    await failover.send(_testMessage());

    expect(nostr.sendAttempts, 1);
    expect(email.sent, hasLength(1));

    await failover.dispose();
    await nostr.dispose();
    await email.dispose();
  });

  // T9.8 — All fail
  test('T9.8: all transports fail throws exception', () async {
    final nostr = MockTransport(failOnSend: true);
    final email = MockTransport(failOnSend: true);

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: nostr,
          maxRetries: 1,
          timeout: const Duration(seconds: 5),
        ),
        TransportPriority(
          transport: email,
          maxRetries: 1,
          timeout: const Duration(seconds: 5),
        ),
      ],
    );

    await failover.connect();

    await expectLater(
      failover.send(_testMessage()),
      throwsA(isA<TransportFailoverException>()),
    );

    await failover.dispose();
    await nostr.dispose();
    await email.dispose();
  });

  // T9.9 — Retry with backoff
  test('T9.9: retry attempts match maxRetries', () async {
    final nostr = MockTransport(failOnSend: true);

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: nostr,
          maxRetries: 3,
          timeout: const Duration(seconds: 5),
        ),
      ],
    );

    await failover.connect();

    await expectLater(
      failover.send(_testMessage()),
      throwsA(isA<TransportFailoverException>()),
    );

    expect(nostr.sendAttempts, 3);

    await failover.dispose();
    await nostr.dispose();
  });

  // T9.10 — Timeout respected
  test('T9.10: timeout triggers fallback', () async {
    final nostr = MockTransport(hangOnSend: true);
    final email = MockTransport();

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: nostr,
          maxRetries: 1,
          timeout: const Duration(milliseconds: 50),
        ),
        TransportPriority(
          transport: email,
          maxRetries: 1,
          timeout: const Duration(seconds: 5),
        ),
      ],
    );

    await failover.connect();
    await failover.send(_testMessage());

    expect(email.sent, hasLength(1));

    await failover.dispose();
    await nostr.dispose();
    await email.dispose();
  });

  // T9.11 — IsAvailable: at least one up
  test('T9.11: anyAvailable true when one transport is up', () async {
    final nostr = MockTransport(failOnConnect: true);
    final email = MockTransport();

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: nostr,
          maxRetries: 3,
          timeout: const Duration(seconds: 5),
        ),
        TransportPriority(
          transport: email,
          maxRetries: 2,
          timeout: const Duration(seconds: 30),
        ),
      ],
    );

    await failover.connect();
    expect(failover.anyAvailable, isTrue);

    await failover.dispose();
    await nostr.dispose();
    await email.dispose();
  });

  // T9.12 — IsAvailable: none up
  test('T9.12: anyAvailable false when all down', () async {
    final nostr = MockTransport(failOnConnect: true);
    final email = MockTransport(failOnConnect: true);

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: nostr,
          maxRetries: 3,
          timeout: const Duration(seconds: 5),
        ),
        TransportPriority(
          transport: email,
          maxRetries: 2,
          timeout: const Duration(seconds: 30),
        ),
      ],
    );

    await failover.connect();
    expect(failover.anyAvailable, isFalse);

    await failover.dispose();
    await nostr.dispose();
    await email.dispose();
  });

  // T9.13 — Aggregated message stream
  test('T9.13: message stream aggregates all transports', () async {
    final nostr = MockTransport();
    final email = MockTransport();

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: nostr,
          maxRetries: 3,
          timeout: const Duration(seconds: 5),
        ),
        TransportPriority(
          transport: email,
          maxRetries: 2,
          timeout: const Duration(seconds: 30),
        ),
      ],
    );

    await failover.connect();

    final received = <TransportMessage>[];
    final sub = failover.messages.listen(received.add);

    // 3 from nostr.
    for (var i = 0; i < 3; i++) {
      nostr.simulateIncoming(_testMessage(id: 'nostr-$i'));
    }
    // 2 from email.
    for (var i = 0; i < 2; i++) {
      email.simulateIncoming(_testMessage(id: 'email-$i'));
    }

    await Future<void>.delayed(const Duration(milliseconds: 50));

    expect(received, hasLength(5));

    await sub.cancel();
    await failover.dispose();
    await nostr.dispose();
    await email.dispose();
  });
}
