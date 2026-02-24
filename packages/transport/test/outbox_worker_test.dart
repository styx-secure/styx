import 'dart:math';
import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:styx_transport/src/failover/outbox_worker.dart';
import 'package:styx_transport/src/failover/transport_failover.dart';
import 'package:styx_transport/src/nostr/nostr_encryptor.dart';
import 'package:styx_transport/src/transport_interface.dart';
import 'package:styx_transport/src/transport_message.dart';
import 'package:test/test.dart';

// ---------------------------------------------------------------------------
// Mock OutboxStore
// ---------------------------------------------------------------------------

class FakeOutboxStore implements OutboxStore {
  final entries = <String, OutboxEntry>{};
  final sentEntries = <String, String>{};
  final failedEntries = <String>[];

  void addEntry(OutboxEntry entry) {
    entries[entry.eventId] = entry;
  }

  @override
  Future<List<OutboxEntry>> getReadyToSend() async {
    return entries.values
        .where((e) => e.status == 'pending' || e.status == 'failed')
        .toList();
  }

  @override
  Future<void> markSent({
    required String eventId,
    required String transport,
  }) async {
    sentEntries[eventId] = transport;
    entries.remove(eventId);
  }

  @override
  Future<void> markFailed({required String eventId}) async {
    failedEntries.add(eventId);
    final entry = entries[eventId];
    if (entry != null) {
      entries[eventId] = OutboxEntry(
        eventId: entry.eventId,
        status: 'failed',
        retryCount: entry.retryCount + 1,
        createdAt: entry.createdAt,
        nextRetryAt: DateTime.now().add(const Duration(seconds: 5)),
      );
    }
  }

  @override
  Future<int> pendingCount() async =>
      entries.values.where((e) => e.status == 'pending').length;
}

// ---------------------------------------------------------------------------
// Mock EventStore
// ---------------------------------------------------------------------------

class FakeEventStore implements EventStore {
  final events = <String, StoredEvent>{};

  void addEvent(StoredEvent event) {
    events[event.eventId] = event;
  }

  @override
  Future<StoredEvent?> getEvent(String eventId) async => events[eventId];

  @override
  Future<List<StoredEvent>> getEventsByIds(List<String> eventIds) async =>
      eventIds.map((id) => events[id]).whereType<StoredEvent>().toList();
}

// ---------------------------------------------------------------------------
// Mock Transport for failover
// ---------------------------------------------------------------------------

class _MockTransport implements TransportInterface {
  _MockTransport({this.failOnSend = false});

  final bool failOnSend;
  final sent = <TransportMessage>[];
  final _sendOrder = <String>[];

  List<String> get sendOrder => List.unmodifiable(_sendOrder);

  @override
  TransportState get currentState => TransportState.connected;

  @override
  Stream<TransportState> get stateChanges => const Stream.empty();

  @override
  Stream<TransportMessage> get messages => const Stream.empty();

  @override
  bool get isAvailable => true;

  @override
  Future<void> connect() async {}

  @override
  Future<void> disconnect() async {}

  @override
  Future<void> send(TransportMessage message) async {
    if (failOnSend) throw Exception('Send failed');
    sent.add(message);
    _sendOrder.add(message.id);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

Future<({NostrEncryptor encryptor, String localPub, String remotePub})>
    _setupEncryptor() async {
  final dh = DiffieHellman();
  final localKP = await dh.generateEphemeralKeyPair();
  final remoteKP = await dh.generateEphemeralKeyPair();

  final encryptor = NostrEncryptor(
    localPrivateKey: localKP.privateKey,
    remotePublicKey: remoteKP.publicKey,
  );
  await encryptor.initialize();

  // Use hex-like strings for pubkeys.
  final localPub =
      localKP.publicKey.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  final remotePub =
      remoteKP.publicKey.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  return (encryptor: encryptor, localPub: localPub, remotePub: remotePub);
}

StoredEvent _makeStoredEvent({
  required String eventId,
  required String hlcTimestamp,
  int hlcCounter = 0,
}) {
  return StoredEvent(
    eventId: eventId,
    senderPubkey: 'sender-pubkey',
    serializedBytes: Uint8List.fromList(
      List.generate(32, (i) => Random().nextInt(256)),
    ),
    hlcTimestamp: hlcTimestamp,
    hlcCounter: hlcCounter,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  // T9.14 — ProcessBatch 5 events
  test('T9.14: processBatch sends 5 events', () async {
    final enc = await _setupEncryptor();
    final outbox = FakeOutboxStore();
    final eventStore = FakeEventStore();
    final mockTransport = _MockTransport();

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: mockTransport,
          maxRetries: 1,
          timeout: const Duration(seconds: 5),
        ),
      ],
    );

    for (var i = 0; i < 5; i++) {
      final eventId = 'event-$i';
      outbox.addEntry(
        OutboxEntry(
          eventId: eventId,
          status: 'pending',
          retryCount: 0,
          createdAt: DateTime.utc(2026, 1, 1, 0, 0, i),
        ),
      );
      eventStore.addEvent(
        _makeStoredEvent(
          eventId: eventId,
          hlcTimestamp: '2026-01-01T00:00:0$i.000Z',
        ),
      );
    }

    final worker = OutboxWorker(
      outboxStore: outbox,
      eventStore: eventStore,
      transport: failover,
      encryptor: enc.encryptor,
      localPubkey: enc.localPub,
      peerPubkey: enc.remotePub,
    );

    final processed = await worker.processBatch();

    expect(processed, 5);
    expect(worker.sentCount, 5);
    expect(outbox.sentEntries, hasLength(5));
    expect(outbox.entries, isEmpty);
  });

  // T9.15 — Causal order (HLC)
  test('T9.15: events sent in HLC order', () async {
    final enc = await _setupEncryptor();
    final outbox = FakeOutboxStore();
    final eventStore = FakeEventStore();
    final mockTransport = _MockTransport();

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: mockTransport,
          maxRetries: 1,
          timeout: const Duration(seconds: 5),
        ),
      ],
    );

    // Add events in reverse order.
    final timestamps = [
      '2026-01-01T00:00:05.000Z',
      '2026-01-01T00:00:01.000Z',
      '2026-01-01T00:00:03.000Z',
      '2026-01-01T00:00:02.000Z',
      '2026-01-01T00:00:04.000Z',
    ];

    for (var i = 0; i < 5; i++) {
      final eventId = 'event-$i';
      outbox.addEntry(
        OutboxEntry(
          eventId: eventId,
          status: 'pending',
          retryCount: 0,
          createdAt: DateTime.utc(2026, 1, 1, 0, 0, i),
        ),
      );
      eventStore.addEvent(
        _makeStoredEvent(
          eventId: eventId,
          hlcTimestamp: timestamps[i],
        ),
      );
    }

    final worker = OutboxWorker(
      outboxStore: outbox,
      eventStore: eventStore,
      transport: failover,
      encryptor: enc.encryptor,
      localPubkey: enc.localPub,
      peerPubkey: enc.remotePub,
    );

    await worker.processBatch();

    // Verify send order matches HLC order.
    expect(
      mockTransport.sendOrder,
      ['event-1', 'event-3', 'event-2', 'event-4', 'event-0'],
    );
  });

  // T9.16 — Partial failure
  test('T9.16: partial failure marks correctly', () async {
    final enc = await _setupEncryptor();
    final outbox = FakeOutboxStore();
    final eventStore = FakeEventStore();

    // We'll use a custom transport that fails on specific events.
    final failingTransport = _SelectiveFailTransport(
      failEventIds: {'event-3', 'event-4'},
    );

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: failingTransport,
          maxRetries: 1,
          timeout: const Duration(seconds: 5),
        ),
      ],
    );

    for (var i = 0; i < 5; i++) {
      final eventId = 'event-$i';
      outbox.addEntry(
        OutboxEntry(
          eventId: eventId,
          status: 'pending',
          retryCount: 0,
          createdAt: DateTime.utc(2026, 1, 1, 0, 0, i),
        ),
      );
      eventStore.addEvent(
        _makeStoredEvent(
          eventId: eventId,
          hlcTimestamp: '2026-01-01T00:00:0$i.000Z',
        ),
      );
    }

    final worker = OutboxWorker(
      outboxStore: outbox,
      eventStore: eventStore,
      transport: failover,
      encryptor: enc.encryptor,
      localPubkey: enc.localPub,
      peerPubkey: enc.remotePub,
    );

    final processed = await worker.processBatch();

    expect(processed, 5);
    expect(worker.sentCount, 3);
    expect(worker.failedCount, 2);
    expect(outbox.sentEntries, hasLength(3));
    expect(outbox.failedEntries, hasLength(2));
  });

  // T9.17 — Backoff on failure
  test('T9.17: failed entries get incremented retryCount', () async {
    final enc = await _setupEncryptor();
    final outbox = FakeOutboxStore();
    final eventStore = FakeEventStore();

    final failingTransport = _MockTransport(failOnSend: true);

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: failingTransport,
          maxRetries: 1,
          timeout: const Duration(seconds: 5),
        ),
      ],
    );

    outbox.addEntry(
      OutboxEntry(
        eventId: 'event-retry',
        status: 'pending',
        retryCount: 0,
        createdAt: DateTime.utc(2026),
      ),
    );
    eventStore.addEvent(
      _makeStoredEvent(
        eventId: 'event-retry',
        hlcTimestamp: '2026-01-01T00:00:00.000Z',
      ),
    );

    final worker = OutboxWorker(
      outboxStore: outbox,
      eventStore: eventStore,
      transport: failover,
      encryptor: enc.encryptor,
      localPubkey: enc.localPub,
      peerPubkey: enc.remotePub,
    );

    await worker.processBatch();

    expect(worker.failedCount, 1);
    expect(outbox.failedEntries, contains('event-retry'));

    final entry = outbox.entries['event-retry'];
    expect(entry, isNotNull);
    expect(entry!.retryCount, 1);
    expect(entry.status, 'failed');
    expect(entry.nextRetryAt, isNotNull);
  });

  // T9.18 — ProcessNow
  test('T9.18: processNow processes batch immediately', () async {
    final enc = await _setupEncryptor();
    final outbox = FakeOutboxStore();
    final eventStore = FakeEventStore();
    final mockTransport = _MockTransport();

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: mockTransport,
          maxRetries: 1,
          timeout: const Duration(seconds: 5),
        ),
      ],
    );

    outbox.addEntry(
      OutboxEntry(
        eventId: 'event-now',
        status: 'pending',
        retryCount: 0,
        createdAt: DateTime.utc(2026),
      ),
    );
    eventStore.addEvent(
      _makeStoredEvent(
        eventId: 'event-now',
        hlcTimestamp: '2026-01-01T00:00:00.000Z',
      ),
    );

    final worker = OutboxWorker(
      outboxStore: outbox,
      eventStore: eventStore,
      transport: failover,
      encryptor: enc.encryptor,
      localPubkey: enc.localPub,
      peerPubkey: enc.remotePub,
    );

    expect(worker.isRunning, isFalse);

    final processed = await worker.processNow();

    expect(processed, 1);
    expect(worker.sentCount, 1);
  });

  // T9.19 — Start/stop lifecycle
  test('T9.19: start processes then stops cleanly', () async {
    final enc = await _setupEncryptor();
    final outbox = FakeOutboxStore();
    final eventStore = FakeEventStore();
    final mockTransport = _MockTransport();

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: mockTransport,
          maxRetries: 1,
          timeout: const Duration(seconds: 5),
        ),
      ],
    );

    for (var i = 0; i < 3; i++) {
      final eventId = 'event-$i';
      outbox.addEntry(
        OutboxEntry(
          eventId: eventId,
          status: 'pending',
          retryCount: 0,
          createdAt: DateTime.utc(2026, 1, 1, 0, 0, i),
        ),
      );
      eventStore.addEvent(
        _makeStoredEvent(
          eventId: eventId,
          hlcTimestamp: '2026-01-01T00:00:0$i.000Z',
        ),
      );
    }

    final worker = OutboxWorker(
      outboxStore: outbox,
      eventStore: eventStore,
      transport: failover,
      encryptor: enc.encryptor,
      localPubkey: enc.localPub,
      peerPubkey: enc.remotePub,
    );

    await worker.start();

    // After start completes (outbox drained), worker stops.
    expect(worker.isRunning, isFalse);
    expect(worker.sentCount, 3);
  });

  // T9.20 — Empty outbox
  test('T9.20: empty outbox returns 0', () async {
    final enc = await _setupEncryptor();
    final outbox = FakeOutboxStore();
    final eventStore = FakeEventStore();
    final mockTransport = _MockTransport();

    final failover = TransportFailover(
      transports: [
        TransportPriority(
          transport: mockTransport,
          maxRetries: 1,
          timeout: const Duration(seconds: 5),
        ),
      ],
    );

    final worker = OutboxWorker(
      outboxStore: outbox,
      eventStore: eventStore,
      transport: failover,
      encryptor: enc.encryptor,
      localPubkey: enc.localPub,
      peerPubkey: enc.remotePub,
    );

    final processed = await worker.processBatch();

    expect(processed, 0);
    expect(worker.sentCount, 0);
    expect(worker.failedCount, 0);
  });
}

// ---------------------------------------------------------------------------
// Selective-fail transport for T9.16
// ---------------------------------------------------------------------------

class _SelectiveFailTransport implements TransportInterface {
  _SelectiveFailTransport({required this.failEventIds});

  final Set<String> failEventIds;

  @override
  TransportState get currentState => TransportState.connected;

  @override
  Stream<TransportState> get stateChanges => const Stream.empty();

  @override
  Stream<TransportMessage> get messages => const Stream.empty();

  @override
  bool get isAvailable => true;

  @override
  Future<void> connect() async {}

  @override
  Future<void> disconnect() async {}

  @override
  Future<void> send(TransportMessage message) async {
    if (failEventIds.contains(message.id)) {
      throw Exception('Selective send failure for ${message.id}');
    }
  }
}
