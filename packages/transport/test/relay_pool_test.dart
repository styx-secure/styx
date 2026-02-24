import 'dart:async';
import 'dart:convert';

import 'package:styx_transport/src/nostr/relay_pool.dart';
import 'package:test/test.dart';

/// Fake WebSocket connection for testing.
class FakeRelayConnection implements RelayConnection {
  FakeRelayConnection();

  final _incomingController = StreamController<String>.broadcast();
  final sent = <String>[];
  bool _isOpen = true;

  @override
  Stream<String> get messages => _incomingController.stream;

  @override
  void send(String data) => sent.add(data);

  @override
  Future<void> close() async {
    _isOpen = false;
    await _incomingController.close();
  }

  @override
  bool get isOpen => _isOpen;

  /// Simulate receiving a message from the relay.
  void simulateIncoming(String data) {
    if (_isOpen) _incomingController.add(data);
  }
}

void main() {
  // T7.7 — Connect to relays
  test('T7.7: connectAll connects to all relays', () async {
    final connections = <String, FakeRelayConnection>{};

    final pool = RelayPool(
      relayUrls: ['wss://relay1.test', 'wss://relay2.test'],
      factory: (url) async {
        final conn = FakeRelayConnection();
        connections[url] = conn;
        return conn;
      },
    );

    final count = await pool.connectAll();
    expect(count, 2);
    expect(pool.connectedCount, 2);
    await pool.dispose();
  });

  // T7.8 — Partial connection failure
  test('T7.8: connectAll handles partial failure', () async {
    final pool = RelayPool(
      relayUrls: ['wss://good.test', 'wss://bad.test'],
      factory: (url) async {
        if (url == 'wss://bad.test') throw Exception('Connection failed');
        return FakeRelayConnection();
      },
    );

    final count = await pool.connectAll();
    expect(count, 1);
    expect(pool.connectedCount, 1);
    await pool.dispose();
  });

  // T7.9 — Publish to all connected relays
  test('T7.9: publish sends to all connected relays', () async {
    final connections = <FakeRelayConnection>[];

    final pool = RelayPool(
      relayUrls: ['wss://r1.test', 'wss://r2.test'],
      factory: (url) async {
        final conn = FakeRelayConnection();
        connections.add(conn);
        return conn;
      },
    );

    await pool.connectAll();

    final event = {'id': 'test-123', 'content': 'hello'};
    final sentCount = pool.publish(event);

    expect(sentCount, 2);
    for (final conn in connections) {
      expect(conn.sent, hasLength(1));
      final parsed = jsonDecode(conn.sent.first) as List;
      expect(parsed[0], 'EVENT');
      expect((parsed[1] as Map)['id'], 'test-123');
    }

    await pool.dispose();
  });

  // T7.10 — Subscribe with filter
  test('T7.10: subscribe sends REQ to all relays', () async {
    final connections = <FakeRelayConnection>[];

    final pool = RelayPool(
      relayUrls: ['wss://r1.test'],
      factory: (url) async {
        final conn = FakeRelayConnection();
        connections.add(conn);
        return conn;
      },
    );

    await pool.connectAll();

    pool.subscribe('sub-1', {
      'kinds': [30078],
    });

    expect(connections.first.sent, hasLength(1));
    final parsed = jsonDecode(connections.first.sent.first) as List;
    expect(parsed[0], 'REQ');
    expect(parsed[1], 'sub-1');
    expect((parsed[2] as Map)['kinds'], [30078]);

    await pool.dispose();
  });

  // T7.11 — Receive messages from relays
  test('T7.11: messages stream receives from relays', () async {
    late FakeRelayConnection conn;

    final pool = RelayPool(
      relayUrls: ['wss://r1.test'],
      factory: (url) async => conn = FakeRelayConnection(),
    );

    await pool.connectAll();

    final received = <String>[];
    final sub = pool.messages.listen(received.add);

    conn.simulateIncoming('test-message');
    await Future<void>.delayed(Duration.zero);

    expect(received, ['test-message']);
    await sub.cancel();
    await pool.dispose();
  });

  // T7.12 — Health check
  test('T7.12: healthCheck reports relay status', () async {
    final pool = RelayPool(
      relayUrls: ['wss://good.test', 'wss://bad.test'],
      factory: (url) async {
        if (url == 'wss://bad.test') throw Exception('fail');
        return FakeRelayConnection();
      },
    );

    await pool.connectAll();
    final health = pool.healthCheck();

    expect(health, hasLength(2));
    expect(health[0].url, 'wss://good.test');
    expect(health[0].isConnected, isTrue);
    expect(health[1].url, 'wss://bad.test');
    expect(health[1].isConnected, isFalse);

    await pool.dispose();
  });

  // T7.13 — Add and remove relays
  test('T7.13: addRelay and removeRelay manage relay list', () async {
    final pool = RelayPool(
      relayUrls: ['wss://r1.test'],
      factory: (url) async => FakeRelayConnection(),
    );

    expect(pool.relayUrls, hasLength(1));

    pool.addRelay('wss://r2.test');
    expect(pool.relayUrls, hasLength(2));

    // Adding a duplicate is a no-op.
    pool.addRelay('wss://r2.test');
    expect(pool.relayUrls, hasLength(2));

    await pool.connectAll();
    await pool.removeRelay('wss://r1.test');
    expect(pool.relayUrls, hasLength(1));
    expect(pool.relayUrls.first, 'wss://r2.test');

    await pool.dispose();
  });
}
