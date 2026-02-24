import 'package:drift/drift.dart' hide isNotNull, isNull;
import 'package:styx_storage/src/styx_database.dart';
import 'package:test/test.dart';

void main() {
  group('Performance', () {
    // T4.29: Bulk insert 10,000 events
    test('T4.29 — bulk insert 10k events completes in < 5s', () async {
      final db = StyxDatabase.inMemory();
      addTearDown(db.close);

      final sw = Stopwatch()..start();

      await db.batch((batch) {
        for (var i = 0; i < 10000; i++) {
          batch.insert(
            db.events,
            EventsCompanion.insert(
              eventId: 'evt-$i',
              eventType: 'MESSAGE',
              eventHash: 'hash-$i',
              hlcTimestamp: '2025-01-01T00:00:00Z',
              hlcNodeId: 'node-a',
              hlcCounter: i,
              senderPubkey: 'abc123',
              signature: Uint8List(64),
              createdAt: DateTime.now(),
            ),
          );
        }
      });

      sw.stop();
      expect(sw.elapsed.inSeconds, lessThan(5));
    });

    // T4.30: Chain verification 10,000 events
    test('T4.30 — chain verification 10k events completes in < 3s', () async {
      final db = StyxDatabase.inMemory();
      addTearDown(db.close);

      // Insert 10k events with valid chain.
      await db.batch((batch) {
        String? prevHash;
        for (var i = 0; i < 10000; i++) {
          final hash = 'hash-$i';
          batch.insert(
            db.events,
            EventsCompanion.insert(
              eventId: 'evt-$i',
              eventType: 'MESSAGE',
              previousHash: Value(prevHash),
              eventHash: hash,
              hlcTimestamp: '2025-01-01T00:00:00Z',
              hlcNodeId: 'node-a',
              hlcCounter: i,
              senderPubkey: 'abc123',
              signature: Uint8List(64),
              createdAt: DateTime.now(),
            ),
          );
          prevHash = hash;
        }
      });

      final sw = Stopwatch()..start();
      final result = await db.eventDao.verifyChainIntegrity();
      sw.stop();

      expect(result, isNull);
      expect(sw.elapsed.inSeconds, lessThan(3));
    });

    // T4.31: Concurrent read/write
    test('T4.31 — concurrent read and write without deadlock', () async {
      final db = StyxDatabase.inMemory();
      addTearDown(db.close);

      // Insert some initial data.
      await db.batch((batch) {
        for (var i = 0; i < 100; i++) {
          batch.insert(
            db.events,
            EventsCompanion.insert(
              eventId: 'evt-$i',
              eventType: 'MESSAGE',
              eventHash: 'hash-$i',
              hlcTimestamp: '2025-01-01T00:00:00Z',
              hlcNodeId: 'node-a',
              hlcCounter: i,
              senderPubkey: 'abc123',
              signature: Uint8List(64),
              createdAt: DateTime.now(),
            ),
          );
        }
      });

      // Concurrent reads and writes.
      final futures = <Future<void>>[];
      for (var i = 100; i < 200; i++) {
        futures
          ..add(
            db.eventDao.insertEvent(
              EventsCompanion.insert(
                eventId: 'evt-$i',
                eventType: 'MESSAGE',
                eventHash: 'hash-$i',
                hlcTimestamp: '2025-01-01T00:00:00Z',
                hlcNodeId: 'node-a',
                hlcCounter: i,
                senderPubkey: 'abc123',
                signature: Uint8List(64),
                createdAt: DateTime.now(),
              ),
            ),
          )
          ..add(db.eventDao.countEvents())
          ..add(db.eventDao.getAllEventsOrdered());
      }

      // Should complete without deadlock.
      await Future.wait<void>(futures);

      final count = await db.eventDao.countEvents();
      expect(count, 200);
    });
  });
}
