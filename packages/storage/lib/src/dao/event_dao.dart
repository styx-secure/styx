import 'package:drift/drift.dart';
import 'package:styx_storage/src/styx_database.dart';
import 'package:styx_storage/src/tables/events.dart';

part 'event_dao.g.dart';

/// Data access object for the append-only event store.
@DriftAccessor(tables: [Events])
class EventDao extends DatabaseAccessor<StyxDatabase> with _$EventDaoMixin {
  /// Creates an [EventDao] attached to [db].
  EventDao(super.attachedDatabase);

  /// Inserts a new event (append-only).
  Future<int> insertEvent(EventsCompanion event) => into(events).insert(event);

  /// Retrieves an event by its unique [eventId].
  Future<Event?> getByEventId(String eventId) => (select(
    events,
  )..where((e) => e.eventId.equals(eventId))).getSingleOrNull();

  /// Retrieves an event by its [hash].
  Future<Event?> getByHash(String hash) => (select(
    events,
  )..where((e) => e.eventHash.equals(hash))).getSingleOrNull();

  /// Gets the most recently inserted event.
  Future<Event?> getLatestEvent() =>
      (select(events)
            ..orderBy([
              (e) => OrderingTerm.desc(e.id),
            ])
            ..limit(1))
          .getSingleOrNull();

  /// Returns all events ordered by HLC timestamp ascending.
  Future<List<Event>> getAllEventsOrdered() =>
      (select(events)..orderBy([
            (e) => OrderingTerm.asc(e.hlcTimestamp),
            (e) => OrderingTerm.asc(e.hlcCounter),
          ]))
          .get();

  /// Returns events within an HLC timestamp range.
  Future<List<Event>> getEventsInRange({
    required String fromHlc,
    required String toHlc,
  }) =>
      (select(events)
            ..where(
              (e) =>
                  e.hlcTimestamp.isBiggerOrEqualValue(fromHlc) &
                  e.hlcTimestamp.isSmallerOrEqualValue(toHlc),
            )
            ..orderBy([
              (e) => OrderingTerm.asc(e.hlcTimestamp),
              (e) => OrderingTerm.asc(e.hlcCounter),
            ]))
          .get();

  /// Prunes an event: removes payload but preserves hash.
  Future<int> pruneEvent(String eventId) =>
      (update(events)..where((e) => e.eventId.equals(eventId))).write(
        const EventsCompanion(
          payloadEncrypted: Value(null),
          isPruned: Value(true),
        ),
      );

  /// Verifies the hash chain integrity.
  ///
  /// Returns the eventId of the first corrupted event,
  /// or `null` if the chain is valid.
  ///
  /// Note: this checks that each event's previousHash matches
  /// the eventHash of the preceding event in insertion order.
  Future<String?> verifyChainIntegrity() async {
    final allEvents = await (select(
      events,
    )..orderBy([(e) => OrderingTerm.asc(e.id)])).get();

    for (var i = 0; i < allEvents.length; i++) {
      final event = allEvents[i];
      if (i == 0) {
        // Genesis event: previousHash should be null.
        if (event.previousHash != null) return event.eventId;
      } else {
        // Non-genesis: previousHash must match previous event's hash.
        if (event.previousHash != allEvents[i - 1].eventHash) {
          return event.eventId;
        }
      }
    }
    return null;
  }

  /// Returns the total number of events.
  Future<int> countEvents() async {
    final count = events.id.count();
    final query = selectOnly(events)..addColumns([count]);
    final result = await query.getSingle();
    return result.read(count)!;
  }

  /// Returns a reactive stream of all events ordered by HLC.
  Stream<List<Event>> watchEvents() =>
      (select(events)..orderBy([
            (e) => OrderingTerm.asc(e.hlcTimestamp),
            (e) => OrderingTerm.asc(e.hlcCounter),
          ]))
          .watch();
}
