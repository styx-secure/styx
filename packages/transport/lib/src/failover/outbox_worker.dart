import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:styx_transport/src/failover/transport_failover.dart';
import 'package:styx_transport/src/nostr/nostr_encryptor.dart';
import 'package:styx_transport/src/transport_message.dart';

/// An outbox entry ready to be sent.
@immutable
class OutboxEntry {
  /// Creates an [OutboxEntry].
  const OutboxEntry({
    required this.eventId,
    required this.status,
    required this.retryCount,
    required this.createdAt,
    this.nextRetryAt,
  });

  /// The event ID to send.
  final String eventId;

  /// Current status: pending, failed, sent, abandoned.
  final String status;

  /// Number of retries so far.
  final int retryCount;

  /// When the entry was created.
  final DateTime createdAt;

  /// When to retry next (for failed entries).
  final DateTime? nextRetryAt;
}

/// Serialized event data retrieved from the event store.
@immutable
class StoredEvent {
  /// Creates a [StoredEvent].
  const StoredEvent({
    required this.eventId,
    required this.senderPubkey,
    required this.serializedBytes,
    required this.hlcTimestamp,
    required this.hlcCounter,
  });

  /// The event ID.
  final String eventId;

  /// Hex-encoded sender public key.
  final String senderPubkey;

  /// Pre-serialized event bytes.
  final Uint8List serializedBytes;

  /// HLC timestamp for causal ordering.
  final String hlcTimestamp;

  /// HLC counter for causal ordering.
  final int hlcCounter;
}

/// Abstract interface for outbox storage operations.
abstract class OutboxStore {
  /// Returns entries ready to send (pending or failed with expired retry).
  Future<List<OutboxEntry>> getReadyToSend();

  /// Marks an entry as successfully sent.
  Future<void> markSent({
    required String eventId,
    required String transport,
  });

  /// Marks an entry as failed with exponential backoff.
  Future<void> markFailed({required String eventId});

  /// Returns the count of pending entries.
  Future<int> pendingCount();
}

/// Abstract interface for event storage operations.
abstract class EventStore {
  /// Retrieves a stored event by its ID.
  Future<StoredEvent?> getEvent(String eventId);

  /// Retrieves multiple events by their IDs.
  Future<List<StoredEvent>> getEventsByIds(List<String> eventIds);
}

/// Processes the outbox queue in causal (HLC) order.
///
/// The worker is not a persistent background service — it activates,
/// processes a batch, and can be stopped.
class OutboxWorker {
  /// Creates an [OutboxWorker].
  OutboxWorker({
    required OutboxStore outboxStore,
    required EventStore eventStore,
    required TransportFailover transport,
    required NostrEncryptor encryptor,
    required this.localPubkey,
    required this.peerPubkey,
  })  : _outboxStore = outboxStore,
        _eventStore = eventStore,
        _transport = transport,
        _encryptor = encryptor;

  final OutboxStore _outboxStore;
  final EventStore _eventStore;
  final TransportFailover _transport;
  final NostrEncryptor _encryptor;

  /// Hex-encoded local public key.
  final String localPubkey;

  /// Hex-encoded peer public key.
  final String peerPubkey;

  bool _running = false;
  int _sentCount = 0;
  int _failedCount = 0;

  /// Whether the worker is currently running.
  bool get isRunning => _running;

  /// Total events successfully sent since creation.
  int get sentCount => _sentCount;

  /// Total events that failed since creation.
  int get failedCount => _failedCount;

  /// Returns the current pending count from the outbox.
  Future<int> get pendingCount => _outboxStore.pendingCount();

  /// Starts the worker loop.
  ///
  /// Processes batches until [stop] is called or the outbox is empty.
  Future<void> start() async {
    _running = true;
    while (_running) {
      final processed = await processBatch();
      if (processed == 0) break;
    }
    _running = false;
  }

  /// Stops the worker.
  void stop() {
    _running = false;
  }

  /// Forces immediate processing of a single batch.
  Future<int> processNow() => processBatch();

  /// Processes one batch of ready-to-send events.
  ///
  /// Events are sorted by HLC (causal order) before sending.
  /// Returns the number of events processed.
  Future<int> processBatch() async {
    final entries = await _outboxStore.getReadyToSend();
    if (entries.isEmpty) return 0;

    // Retrieve and sort events by HLC (causal order).
    final eventEntries = <(OutboxEntry, StoredEvent)>[];
    for (final entry in entries) {
      final event = await _eventStore.getEvent(entry.eventId);
      if (event != null) {
        eventEntries.add((entry, event));
      }
    }

    // Sort by HLC timestamp, then counter.
    eventEntries.sort((a, b) {
      final tsCmp = a.$2.hlcTimestamp.compareTo(b.$2.hlcTimestamp);
      if (tsCmp != 0) return tsCmp;
      return a.$2.hlcCounter.compareTo(b.$2.hlcCounter);
    });

    var processed = 0;
    for (final (entry, event) in eventEntries) {
      try {
        final encrypted = await _encryptor.encrypt(event.serializedBytes);

        final message = TransportMessage(
          id: event.eventId,
          senderPubkey: localPubkey,
          recipientPubkey: peerPubkey,
          payload: encrypted,
          timestamp: DateTime.now().toUtc(),
        );

        await _transport.send(message);

        await _outboxStore.markSent(
          eventId: entry.eventId,
          transport: 'failover',
        );
        _sentCount++;
      } on Object {
        await _outboxStore.markFailed(eventId: entry.eventId);
        _failedCount++;
      }
      processed++;
    }

    return processed;
  }
}
