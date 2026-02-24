import 'package:drift/drift.dart' hide isNotNull, isNull;
import 'package:styx_storage/src/styx_database.dart';
import 'package:test/test.dart';

/// Inserts a minimal event into the DB and returns its eventId.
Future<String> _insertEvent(StyxDatabase db, String eventId) async {
  await db.eventDao.insertEvent(
    EventsCompanion.insert(
      eventId: eventId,
      eventType: 'MESSAGE',
      eventHash: 'hash-$eventId',
      hlcTimestamp: '2025-01-01T00:00:00Z',
      hlcNodeId: 'node-a',
      hlcCounter: 0,
      senderPubkey: 'abc123',
      signature: Uint8List(64),
      createdAt: DateTime.now(),
    ),
  );
  return eventId;
}

void main() {
  late StyxDatabase db;

  setUp(() {
    db = StyxDatabase.inMemory();
  });

  tearDown(() => db.close());

  group('OutboxDao', () {
    // T4.17: Enqueue + dequeueNext
    test('T4.17 — enqueue and dequeueNext', () async {
      final eid = await _insertEvent(db, 'out-001');
      await db.outboxDao.enqueue(eid);

      final next = await db.outboxDao.dequeueNext();
      expect(next, isNotNull);
      expect(next!.eventId, eid);
      expect(next.status, 'pending');
    });

    // T4.18: FIFO order
    test('T4.18 — dequeueNext respects FIFO order', () async {
      for (final id in ['a', 'b', 'c']) {
        final eid = await _insertEvent(db, 'out-$id');
        await db.outboxDao.enqueue(eid);
        // Small delay to ensure different createdAt.
        await Future<void>.delayed(const Duration(milliseconds: 10));
      }

      final first = await db.outboxDao.dequeueNext();
      expect(first!.eventId, 'out-a');
    });

    // T4.19: MarkSent
    test('T4.19 — markSent updates status and sentAt', () async {
      final eid = await _insertEvent(db, 'out-sent');
      await db.outboxDao.enqueue(eid);

      await db.outboxDao.markSent(eventId: eid, transport: 'nostr');

      // After marking sent, dequeueNext should not return it.
      final next = await db.outboxDao.dequeueNext();
      expect(next, isNull);
    });

    // T4.20: MarkFailed with exponential backoff
    test('T4.20 — markFailed applies exponential backoff', () async {
      final eid = await _insertEvent(db, 'out-fail');
      await db.outboxDao.enqueue(eid);

      DateTime? previousRetry;
      for (var i = 0; i < 3; i++) {
        await db.outboxDao.markFailed(eventId: eid);
        final entry = await (db.select(db.outbox)
              ..where((o) => o.eventId.equals(eid)))
            .getSingle();

        expect(entry.retryCount, i + 1);
        expect(entry.status, 'failed');
        if (previousRetry != null) {
          // Each retry should be further in the future.
          expect(
            entry.nextRetryAt!.isAfter(previousRetry),
            isTrue,
          );
        }
        previousRetry = entry.nextRetryAt;
      }
    });

    // T4.21: GetReadyToSend includes pending and expired failed
    test('T4.21 — getReadyToSend returns pending and expired failed', () async {
      // 3 pending events.
      for (var i = 0; i < 3; i++) {
        final eid = await _insertEvent(db, 'ready-$i');
        await db.outboxDao.enqueue(eid);
      }

      // 2 failed events with expired retry (nextRetryAt in the past).
      for (var i = 3; i < 5; i++) {
        final eid = await _insertEvent(db, 'ready-$i');
        await db.outboxDao.enqueue(eid);
        // Mark failed, then set nextRetryAt to the past.
        await db.outboxDao.markFailed(eventId: eid);
        await (db.update(db.outbox)..where((o) => o.eventId.equals(eid))).write(
          OutboxCompanion(
            nextRetryAt: Value(
              DateTime.now().subtract(const Duration(hours: 1)),
            ),
          ),
        );
      }

      final ready = await db.outboxDao.getReadyToSend();
      expect(ready.length, 5);
    });

    // T4.22: GetReadyToSend excludes non-expired failed
    test('T4.22 — getReadyToSend excludes non-expired failed', () async {
      final eid = await _insertEvent(db, 'not-ready');
      await db.outboxDao.enqueue(eid);
      await db.outboxDao.markFailed(eventId: eid);
      // nextRetryAt is already in the future from markFailed.

      final ready = await db.outboxDao.getReadyToSend();
      // Should not include the failed event with future retry.
      final hasNotReady = ready.any((e) => e.eventId == eid);
      expect(hasNotReady, isFalse);
    });

    // T4.23: PendingCount
    test('T4.23 — pendingCount returns correct count', () async {
      for (var i = 0; i < 7; i++) {
        final eid = await _insertEvent(db, 'count-$i');
        await db.outboxDao.enqueue(eid);
      }

      final count = await db.outboxDao.pendingCount();
      expect(count, 7);
    });

    // Remove entry
    test('remove deletes outbox entry', () async {
      final eid = await _insertEvent(db, 'out-rm');
      await db.outboxDao.enqueue(eid);
      await db.outboxDao.remove(eid);

      final next = await db.outboxDao.dequeueNext();
      expect(next, isNull);
    });
  });
}
