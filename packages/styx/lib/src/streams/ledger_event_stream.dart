import 'dart:async';

import 'package:styx_ledger_engine/styx_ledger_engine.dart';

/// Unified stream of ledger events from local and remote sources.
class LedgerEventStream {
  /// Creates a [LedgerEventStream].
  LedgerEventStream({
    required Stream<LedgerEvent> localEventSource,
    required Stream<LedgerEvent> remoteEventSource,
  })  : _localSource = localEventSource,
        _remoteSource = remoteEventSource;

  final Stream<LedgerEvent> _localSource;
  final Stream<LedgerEvent> _remoteSource;

  StreamController<LedgerEvent>? _allController;
  final _subscriptions = <StreamSubscription<LedgerEvent>>[];

  /// Stream of all events (local + remote).
  Stream<LedgerEvent> get allEvents {
    _allController ??= _buildMergedController();
    return _allController!.stream;
  }

  /// Stream of locally created events.
  Stream<LedgerEvent> get localEvents => _localSource;

  /// Stream of events received from the peer.
  Stream<LedgerEvent> get remoteEvents => _remoteSource;

  /// Stream of events filtered by type.
  Stream<LedgerEvent> eventsByType(EventType type) =>
      allEvents.where((e) => e.eventType == type);

  /// Stream of events created after a given time.
  Stream<LedgerEvent> eventsAfter(DateTime after) =>
      allEvents.where((e) => e.createdAt.isAfter(after));

  /// Disposes the stream and its subscriptions.
  Future<void> dispose() async {
    for (final sub in _subscriptions) {
      await sub.cancel();
    }
    _subscriptions.clear();
    await _allController?.close();
  }

  StreamController<LedgerEvent> _buildMergedController() {
    final controller = StreamController<LedgerEvent>.broadcast();
    _subscriptions
      ..add(_localSource.listen(controller.add))
      ..add(_remoteSource.listen(controller.add));
    return controller;
  }
}
