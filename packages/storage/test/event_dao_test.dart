import 'dart:math';

import 'package:drift/drift.dart' hide isNotNull, isNull;
import 'package:styx_storage/src/styx_database.dart';
import 'package:test/test.dart';

/// Creates a valid [EventsCompanion] for testing.
EventsCompanion _makeEvent({
  required String eventId,
  required String eventHash,
  String? previousHash,
  String eventType = 'MESSAGE',
  String hlcTimestamp = '2025-01-01T00:00:00Z',
  String hlcNodeId = 'node-a',
  int hlcCounter = 0,
  String senderPubkey = 'abc123',
}) {
  return EventsCompanion.insert(
    eventId: eventId,
    eventType: eventType,
    payloadEncrypted: Value(Uint8List.fromList([1, 2, 3])),
    previousHash: Value(previousHash),
    eventHash: eventHash,
    hlcTimestamp: hlcTimestamp,
    hlcNodeId: hlcNodeId,
    hlcCounter: hlcCounter,
    senderPubkey: senderPubkey,
    signature: Uint8List(64),
    createdAt: DateTime.now(),
  );
}

void main() {
  late StyxDatabase db;

  setUp(() {
    db = StyxDatabase.inMemory();
  });

  tearDown(() => db.close());

  group('EventDao', () {
    // T4.5: Insert + getByEventId
    test('T4.5 — insert and retrieve by eventId', () async {
      final companion = _makeEvent(
        eventId: 'evt-001',
        eventHash: 'hash-001',
      );
      await db.eventDao.insertEvent(companion);

      final event = await db.eventDao.getByEventId('evt-001');
      expect(event, isNotNull);
      expect(event!.eventId, 'evt-001');
      expect(event.eventHash, 'hash-001');
      expect(event.eventType, 'MESSAGE');
      expect(event.senderPubkey, 'abc123');
    });

    // T4.6: Insert duplicate eventId
    test('T4.6 — duplicate eventId throws', () async {
      await db.eventDao.insertEvent(
        _makeEvent(eventId: 'evt-dup', eventHash: 'hash-a'),
      );
      expect(
        () => db.eventDao.insertEvent(
          _makeEvent(eventId: 'evt-dup', eventHash: 'hash-b'),
        ),
        throwsA(isA<Exception>()),
      );
    });

    // T4.7: GetLatestEvent on empty DB
    test('T4.7 — getLatestEvent on empty DB returns null', () async {
      final event = await db.eventDao.getLatestEvent();
      expect(event, isNull);
    });

    // T4.8: GetLatestEvent after 10 inserts
    test('T4.8 — getLatestEvent after 10 inserts', () async {
      for (var i = 0; i < 10; i++) {
        await db.eventDao.insertEvent(
          _makeEvent(eventId: 'evt-$i', eventHash: 'hash-$i'),
        );
      }
      final latest = await db.eventDao.getLatestEvent();
      expect(latest, isNotNull);
      expect(latest!.eventId, 'evt-9');
    });

    // T4.9: GetAllEventsOrdered
    test('T4.9 — getAllEventsOrdered sorts by HLC', () async {
      final rng = Random(42);
      final timestamps = List.generate(100, (i) {
        final hour = rng.nextInt(24).toString().padLeft(2, '0');
        final minute = rng.nextInt(60).toString().padLeft(2, '0');
        final second = rng.nextInt(60).toString().padLeft(2, '0');
        return '2025-01-01T$hour:$minute:${second}Z';
      });

      for (var i = 0; i < 100; i++) {
        await db.eventDao.insertEvent(
          _makeEvent(
            eventId: 'evt-$i',
            eventHash: 'hash-$i',
            hlcTimestamp: timestamps[i],
            hlcCounter: i,
          ),
        );
      }

      final ordered = await db.eventDao.getAllEventsOrdered();
      expect(ordered.length, 100);

      for (var i = 1; i < ordered.length; i++) {
        final prev = ordered[i - 1];
        final curr = ordered[i];
        final cmp = prev.hlcTimestamp.compareTo(curr.hlcTimestamp);
        if (cmp == 0) {
          expect(prev.hlcCounter, lessThanOrEqualTo(curr.hlcCounter));
        } else {
          expect(cmp, isNegative);
        }
      }
    });

    // T4.10: GetEventsInRange
    test('T4.10 — getEventsInRange returns events in range', () async {
      for (var i = 0; i < 100; i++) {
        final ts = '2025-01-${(i ~/ 24 + 1).toString().padLeft(2, '0')}'
            'T${(i % 24).toString().padLeft(2, '0')}:00:00Z';
        await db.eventDao.insertEvent(
          _makeEvent(
            eventId: 'evt-$i',
            eventHash: 'hash-$i',
            hlcTimestamp: ts,
          ),
        );
      }

      final result = await db.eventDao.getEventsInRange(
        fromHlc: '2025-01-02T00:00:00Z',
        toHlc: '2025-01-03T00:00:00Z',
      );

      for (final event in result) {
        expect(
          event.hlcTimestamp.compareTo('2025-01-02T00:00:00Z'),
          greaterThanOrEqualTo(0),
        );
        expect(
          event.hlcTimestamp.compareTo('2025-01-03T00:00:00Z'),
          lessThanOrEqualTo(0),
        );
      }
      expect(result, isNotEmpty);
    });

    // T4.11: PruneEvent
    test('T4.11 — pruneEvent removes payload, preserves hash', () async {
      await db.eventDao.insertEvent(
        _makeEvent(eventId: 'evt-prune', eventHash: 'hash-prune'),
      );

      await db.eventDao.pruneEvent('evt-prune');
      final pruned = await db.eventDao.getByEventId('evt-prune');

      expect(pruned, isNotNull);
      expect(pruned!.isPruned, isTrue);
      expect(pruned.payloadEncrypted, isNull);
      expect(pruned.eventHash, 'hash-prune');
    });

    // T4.12: VerifyChainIntegrity OK
    test('T4.12 — verifyChainIntegrity returns null for valid chain', () async {
      String? prevHash;
      for (var i = 0; i < 100; i++) {
        final hash = 'hash-$i';
        await db.eventDao.insertEvent(
          _makeEvent(
            eventId: 'evt-$i',
            eventHash: hash,
            previousHash: prevHash,
          ),
        );
        prevHash = hash;
      }

      final result = await db.eventDao.verifyChainIntegrity();
      expect(result, isNull);
    });

    // T4.13: VerifyChainIntegrity FAIL
    test('T4.13 — verifyChainIntegrity detects broken chain', () async {
      // Insert 3 events with valid chain.
      await db.eventDao.insertEvent(
        _makeEvent(eventId: 'evt-0', eventHash: 'hash-0'),
      );
      await db.eventDao.insertEvent(
        _makeEvent(
          eventId: 'evt-1',
          eventHash: 'hash-1',
          previousHash: 'hash-0',
        ),
      );
      await db.eventDao.insertEvent(
        _makeEvent(
          eventId: 'evt-2',
          eventHash: 'hash-2',
          previousHash: 'WRONG-HASH',
        ),
      );

      final result = await db.eventDao.verifyChainIntegrity();
      expect(result, 'evt-2');
    });

    // T4.14: Append-only enforcement via trigger
    test('T4.14 — append-only trigger blocks non-prune updates', () async {
      await db.eventDao.insertEvent(
        _makeEvent(eventId: 'evt-trigger', eventHash: 'hash-trigger'),
      );

      // Try a raw SQL UPDATE that is not a prune.
      expect(
        () => db.customStatement(
          "UPDATE events SET event_type = 'SOS' "
          "WHERE event_id = 'evt-trigger'",
        ),
        throwsA(isA<Exception>()),
      );
    });

    // T4.15: CountEvents
    test('T4.15 — countEvents returns correct count', () async {
      for (var i = 0; i < 42; i++) {
        await db.eventDao.insertEvent(
          _makeEvent(eventId: 'evt-$i', eventHash: 'hash-$i'),
        );
      }

      final count = await db.eventDao.countEvents();
      expect(count, 42);
    });

    // T4.16: WatchEvents stream
    test('T4.16 — watchEvents emits updates', () async {
      final stream = db.eventDao.watchEvents();

      // Collect emissions while inserting 5 events.
      final emissions = <List<Event>>[];
      final sub = stream.listen(emissions.add);

      // Wait for initial empty emission.
      await Future<void>.delayed(const Duration(milliseconds: 100));

      for (var i = 0; i < 5; i++) {
        await db.eventDao.insertEvent(
          _makeEvent(eventId: 'evt-$i', eventHash: 'hash-$i'),
        );
        await Future<void>.delayed(const Duration(milliseconds: 50));
      }

      await Future<void>.delayed(const Duration(milliseconds: 200));
      await sub.cancel();

      // At least one emission should contain 5 events.
      expect(emissions.last.length, 5);
    });

    // T4.11b: getByHash
    test('getByHash retrieves event by hash', () async {
      await db.eventDao.insertEvent(
        _makeEvent(eventId: 'evt-h', eventHash: 'unique-hash-42'),
      );
      final event = await db.eventDao.getByHash('unique-hash-42');
      expect(event, isNotNull);
      expect(event!.eventId, 'evt-h');
    });
  });
}
