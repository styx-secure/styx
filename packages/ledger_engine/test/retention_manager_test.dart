import 'dart:typed_data';

import 'package:styx_ledger_engine/src/event_type.dart';
import 'package:styx_ledger_engine/src/hlc.dart';
import 'package:styx_ledger_engine/src/ledger_event.dart';
import 'package:styx_ledger_engine/src/pruning/retention_manager.dart';
import 'package:styx_ledger_engine/src/vector_clock.dart';
import 'package:test/test.dart';

LedgerEvent _makeEvent({
  required String eventId,
  required DateTime createdAt,
  EventType eventType = EventType.transaction,
  bool isPruned = false,
}) {
  return LedgerEvent(
    eventId: eventId,
    eventType: eventType,
    payload: Uint8List.fromList([1]),
    previousHash: null,
    eventHash: 'hash-$eventId',
    hlc: HybridLogicalClock(
      timestamp: createdAt.toUtc(),
      counter: 0,
      nodeId: 'testnode',
    ),
    vectorClock: const VectorClock.zero(),
    senderPubkey: 'pubkey',
    signature: Uint8List(64),
    createdAt: createdAt,
    isPruned: isPruned,
  );
}

void main() {
  final manager = RetentionManager();

  group('RetentionManager', () {
    // T6.24: GetExpired with 30-day retention
    test('T6.24 — returns events older than retention period', () {
      final now = DateTime.now();
      final events = [
        // 5 old events (45 days ago).
        for (var i = 0; i < 5; i++)
          _makeEvent(
            eventId: 'old-$i',
            createdAt: now.subtract(const Duration(days: 45)),
          ),
        // 5 recent events.
        for (var i = 0; i < 5; i++)
          _makeEvent(
            eventId: 'new-$i',
            createdAt: now.subtract(const Duration(days: 5)),
          ),
      ];

      final expired = manager.getExpiredEvents(
        events: events,
        retentionPeriod: const Duration(days: 30),
        applicableTypes: [EventType.transaction],
      );

      expect(expired.length, 5);
      expect(expired.every((e) => e.eventId.startsWith('old-')), isTrue);
    });

    // T6.25: GetExpired filters by type
    test('T6.25 — filters by applicable types', () {
      final now = DateTime.now();
      final events = [
        _makeEvent(
          eventId: 'tx-old',
          createdAt: now.subtract(const Duration(days: 45)),
        ),
        _makeEvent(
          eventId: 'msg-old',
          createdAt: now.subtract(const Duration(days: 45)),
          eventType: EventType.message,
        ),
        _makeEvent(
          eventId: 'sos-old',
          createdAt: now.subtract(const Duration(days: 45)),
          eventType: EventType.sos,
        ),
      ];

      final expired = manager.getExpiredEvents(
        events: events,
        retentionPeriod: const Duration(days: 30),
        applicableTypes: [EventType.transaction],
      );

      expect(expired.length, 1);
      expect(expired.first.eventId, 'tx-old');
    });

    // T6.26: No expired events
    test('T6.26 — returns empty when all events are recent', () {
      final now = DateTime.now();
      final events = [
        for (var i = 0; i < 10; i++)
          _makeEvent(
            eventId: 'recent-$i',
            createdAt: now.subtract(const Duration(hours: 1)),
          ),
      ];

      final expired = manager.getExpiredEvents(
        events: events,
        retentionPeriod: const Duration(days: 30),
        applicableTypes: [EventType.transaction],
      );

      expect(expired, isEmpty);
    });

    test('excludes already-pruned events', () {
      final now = DateTime.now();
      final events = [
        _makeEvent(
          eventId: 'pruned',
          createdAt: now.subtract(const Duration(days: 45)),
          isPruned: true,
        ),
        _makeEvent(
          eventId: 'not-pruned',
          createdAt: now.subtract(const Duration(days: 45)),
        ),
      ];

      final expired = manager.getExpiredEvents(
        events: events,
        retentionPeriod: const Duration(days: 30),
        applicableTypes: [EventType.transaction],
      );

      expect(expired.length, 1);
      expect(expired.first.eventId, 'not-pruned');
    });
  });
}
