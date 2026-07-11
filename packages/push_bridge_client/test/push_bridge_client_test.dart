import 'dart:async';
import 'dart:typed_data';

import 'package:styx_push_bridge_client/styx_push_bridge_client.dart';
import 'package:styx_transport/styx_transport.dart';
import 'package:test/test.dart';

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

class FakeBridgeHttpClient implements BridgeHttpClient {
  final requests = <({String path, Map<String, dynamic> body})>[];

  @override
  Future<int> post(String path, Map<String, dynamic> body) async {
    requests.add((path: path, body: body));
    return 200;
  }

  @override
  Future<String> get(String path) async => '{"status":"ok"}';
}

class FakeTransport implements TransportInterface {
  TransportState _state = TransportState.disconnected;
  final _stateController = StreamController<TransportState>.broadcast();
  final _messageController = StreamController<TransportMessage>.broadcast();
  int connectCalls = 0;
  int disconnectCalls = 0;

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
    connectCalls++;
    _state = TransportState.connected;
    _stateController.add(_state);
  }

  @override
  Future<void> disconnect() async {
    disconnectCalls++;
    _state = TransportState.disconnected;
    _stateController.add(_state);
  }

  @override
  Future<void> send(TransportMessage message) async {}

  void simulateIncoming(TransportMessage message) {
    _messageController.add(message);
  }

  Future<void> dispose() async {
    await _stateController.close();
    await _messageController.close();
  }
}

class FakeLedger implements LedgerOperations {
  final inserted = <TransportMessage>[];

  @override
  Future<int> insertEvents(List<TransportMessage> events) async {
    inserted.addAll(events);
    return events.length;
  }

  @override
  Future<String?> lastKnownTimestamp() async => null;
}

class FakeOutbox implements OutboxProcessor {
  int pendingToProcess = 0;

  @override
  Future<int> processPending() async {
    final count = pendingToProcess;
    pendingToProcess = 0;
    return count;
  }

  @override
  Future<int> pendingCount() async => pendingToProcess;
}

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
  // T10.9 — DummyDetector with flag "d":"1"
  test('T10.9: isDummy returns true when d=1', () {
    const detector = DummyDetector();

    expect(detector.isDummy({'styx': 'wake', 'd': '1', 'ts': '123'}), isTrue);
  });

  // T10.10 — DummyDetector without flag
  test('T10.10: isDummy returns false without d flag', () {
    const detector = DummyDetector();

    expect(detector.isDummy({'styx': 'wake', 'ts': '123'}), isFalse);
    expect(detector.isDummy({}), isFalse);
  });

  // T10.11 — Balanced profile: no dummy, real push triggers wake-up
  test('T10.11: balanced profile wakes up on real push', () async {
    var wakeUpCalled = false;
    var connectRelayCalled = false;

    final handler = PushHandler(
      profile: PrivacyProfile.balanced,
      onWakeUp: () async {
        wakeUpCalled = true;
      },
      onConnectRelay: () async {
        connectRelayCalled = true;
      },
    );

    // Real push.
    await handler.handleMessage({'styx': 'wake', 'ts': '123'});

    expect(wakeUpCalled, isTrue);
    expect(connectRelayCalled, isFalse);
    expect(handler.realCount, 1);
    expect(handler.dummyCount, 0);
    expect(handler.connectCount, 1);
  });

  // T10.12 — Private profile: dummy push → sleep (zero network)
  test('T10.12: private profile drops dummy (zero network)', () async {
    var wakeUpCalled = false;
    var connectRelayCalled = false;

    final handler = PushHandler(
      profile: PrivacyProfile.private,
      onWakeUp: () async {
        wakeUpCalled = true;
      },
      onConnectRelay: () async {
        connectRelayCalled = true;
      },
    );

    // Dummy push.
    await handler.handleMessage({'styx': 'wake', 'd': '1', 'ts': '123'});

    expect(wakeUpCalled, isFalse);
    expect(connectRelayCalled, isFalse);
    expect(handler.dummyCount, 1);
    expect(handler.realCount, 0);
    expect(handler.connectCount, 0);
  });

  // T10.13 — Paranoid profile: dummy push → connect relay
  test('T10.13: paranoid profile connects relay on dummy', () async {
    var wakeUpCalled = false;
    var connectRelayCalled = false;

    final handler = PushHandler(
      profile: PrivacyProfile.paranoid,
      onWakeUp: () async {
        wakeUpCalled = true;
      },
      onConnectRelay: () async {
        connectRelayCalled = true;
      },
    );

    // Dummy push.
    await handler.handleMessage({'styx': 'wake', 'd': '1', 'ts': '123'});

    expect(wakeUpCalled, isFalse);
    expect(connectRelayCalled, isTrue);
    expect(handler.dummyCount, 1);
    expect(handler.connectCount, 1);
  });

  // T10.14 — WakeUpOrchestrator flow: 5 events
  test(
    'T10.14: orchestrator downloads, inserts, and processes outbox',
    () async {
      final transport = FakeTransport();
      final ledger = FakeLedger();
      final outbox = FakeOutbox()..pendingToProcess = 2;

      final orchestrator = WakeUpOrchestrator(
        transport: transport,
        ledger: ledger,
        outbox: outbox,
        downloadTimeout: const Duration(milliseconds: 50),
      );

      // Simulate incoming messages shortly after connect.
      Future<void>.delayed(const Duration(milliseconds: 10), () {
        for (var i = 0; i < 5; i++) {
          transport.simulateIncoming(_testMessage(id: 'ev-$i'));
        }
      });

      final total = await orchestrator.handleWakeUp();

      expect(total, 7); // 5 downloaded + 2 outbox
      expect(orchestrator.lastDownloadCount, 5);
      expect(orchestrator.lastOutboxCount, 2);
      expect(transport.connectCalls, 1);
      expect(transport.disconnectCalls, 1);
      expect(ledger.inserted, hasLength(5));
      expect(orchestrator.isRunning, isFalse);

      await transport.dispose();
    },
  );

  // T10.15 — FCM token refresh → auto re-register
  test('T10.15: token refresh triggers re-register', () async {
    final httpClient = FakeBridgeHttpClient();
    final client = PushBridgeClient(
      bridgeUrl: 'https://bridge.example.com',
      httpClient: httpClient,
    );

    String? refreshedToken;

    final handler = PushHandler(
      profile: PrivacyProfile.balanced,
      onWakeUp: () async {},
      onConnectRelay: () async {},
      onTokenRefresh: (newToken) async {
        refreshedToken = newToken;
        await client.register(
          fcmToken: newToken,
          nostrPubkey: 'my-pubkey',
          profile: PrivacyProfile.balanced,
        );
      },
    );

    await handler.handleTokenRefresh('new-token-xyz');

    expect(refreshedToken, 'new-token-xyz');
    expect(httpClient.requests, hasLength(1));
    expect(httpClient.requests.first.path, '/register');
    expect(httpClient.requests.first.body['fcm_token'], 'new-token-xyz');
  });

  // Additional tests for PushBridgeClient
  group('PushBridgeClient', () {
    test('register sends correct payload', () async {
      final httpClient = FakeBridgeHttpClient();
      final client = PushBridgeClient(
        bridgeUrl: 'https://bridge.example.com',
        httpClient: httpClient,
      );

      await client.register(
        fcmToken: 'token-abc',
        nostrPubkey: 'pubkey-123',
        profile: PrivacyProfile.private,
      );

      expect(httpClient.requests, hasLength(1));
      final req = httpClient.requests.first;
      expect(req.path, '/register');
      expect(req.body['fcm_token'], 'token-abc');
      expect(req.body['nostr_pubkey'], 'pubkey-123');
      expect(req.body['privacy_profile'], 'private');
      expect(req.body['platform'], 'android');
    });

    test('unregister sends correct payload', () async {
      final httpClient = FakeBridgeHttpClient();
      final client = PushBridgeClient(
        bridgeUrl: 'https://bridge.example.com',
        httpClient: httpClient,
      );

      await client.unregister(fcmToken: 'token-abc');

      expect(httpClient.requests, hasLength(1));
      final req = httpClient.requests.first;
      expect(req.path, '/unregister');
      expect(req.body['fcm_token'], 'token-abc');
    });
  });

  // PrivacyProfile tests
  group('PrivacyProfile', () {
    test('fromString parses valid profiles', () {
      expect(PrivacyProfile.fromString('balanced'), PrivacyProfile.balanced);
      expect(PrivacyProfile.fromString('private'), PrivacyProfile.private);
      expect(PrivacyProfile.fromString('paranoid'), PrivacyProfile.paranoid);
    });

    test('fromString defaults to balanced for unknown', () {
      expect(PrivacyProfile.fromString('unknown'), PrivacyProfile.balanced);
    });
  });
}
