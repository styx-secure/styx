import 'package:styx_transport/styx_transport.dart';

/// Abstract interface for ledger operations during wake-up.
///
/// In production, this wraps `LedgerService`. For testing, use a fake.
abstract class LedgerOperations {
  /// Validates and inserts downloaded events into the local ledger.
  /// Returns the number of events successfully inserted.
  Future<int> insertEvents(List<TransportMessage> events);

  /// Returns the HLC timestamp of the last known event.
  Future<String?> lastKnownTimestamp();
}

/// Abstract interface for outbox processing during wake-up.
abstract class OutboxProcessor {
  /// Processes any pending outbox entries. Returns the count of events sent.
  Future<int> processPending();

  /// Returns the number of pending entries in the outbox.
  Future<int> pendingCount();
}

/// Orchestrates the wake-up flow when a real push notification arrives.
///
/// 1. Connect to transport (relay).
/// 2. Download new events.
/// 3. Validate and insert into local ledger.
/// 4. Process outbox (send pending events).
/// 5. Disconnect.
class WakeUpOrchestrator {
  /// Creates a [WakeUpOrchestrator].
  WakeUpOrchestrator({
    required TransportInterface transport,
    required LedgerOperations ledger,
    required OutboxProcessor outbox,
    this.downloadTimeout = const Duration(seconds: 10),
  }) : _transport = transport,
       _ledger = ledger,
       _outbox = outbox;

  final TransportInterface _transport;
  final LedgerOperations _ledger;
  final OutboxProcessor _outbox;

  /// Timeout for the download phase.
  final Duration downloadTimeout;

  bool _isRunning = false;
  int _lastDownloadCount = 0;
  int _lastOutboxCount = 0;

  /// Whether a wake-up is currently in progress.
  bool get isRunning => _isRunning;

  /// Number of events downloaded in the last wake-up.
  int get lastDownloadCount => _lastDownloadCount;

  /// Number of outbox events sent in the last wake-up.
  int get lastOutboxCount => _lastOutboxCount;

  /// Handles a wake-up from a push notification.
  ///
  /// Returns the total number of events processed (downloaded + sent).
  Future<int> handleWakeUp() async {
    if (_isRunning) return 0;
    _isRunning = true;

    try {
      // 1. Connect.
      await _transport.connect();

      // 2. Download new events.
      final downloaded = <TransportMessage>[];
      final subscription = _transport.messages.listen(downloaded.add);

      await Future<void>.delayed(downloadTimeout);
      await subscription.cancel();

      // 3. Validate and insert.
      var insertedCount = 0;
      if (downloaded.isNotEmpty) {
        insertedCount = await _ledger.insertEvents(downloaded);
      }
      _lastDownloadCount = insertedCount;

      // 4. Process outbox.
      _lastOutboxCount = await _outbox.processPending();

      // 5. Disconnect.
      await _transport.disconnect();

      return insertedCount + _lastOutboxCount;
    } finally {
      _isRunning = false;
    }
  }
}
