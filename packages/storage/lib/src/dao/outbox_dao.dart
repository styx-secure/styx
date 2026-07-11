import 'package:drift/drift.dart';
import 'package:styx_storage/src/styx_database.dart';
import 'package:styx_storage/src/tables/events.dart';
import 'package:styx_storage/src/tables/outbox.dart';

part 'outbox_dao.g.dart';

/// Base delay for exponential backoff (5 seconds).
const _baseDelay = Duration(seconds: 5);

/// Maximum delay for exponential backoff (5 minutes).
const _maxDelay = Duration(minutes: 5);

/// Maximum retries before marking as abandoned.
const _maxRetries = 20;

/// Data access object for the outbox queue.
@DriftAccessor(tables: [Outbox, Events])
class OutboxDao extends DatabaseAccessor<StyxDatabase> with _$OutboxDaoMixin {
  /// Creates an [OutboxDao] attached to [db].
  OutboxDao(super.attachedDatabase);

  /// Enqueues an event for sending.
  Future<int> enqueue(String eventId) => into(outbox).insert(
    OutboxCompanion.insert(
      eventId: eventId,
      createdAt: DateTime.now(),
    ),
  );

  /// Dequeues the next event to send (FIFO by creation time).
  Future<OutboxData?> dequeueNext() =>
      (select(outbox)
            ..where(
              (o) => o.status.isIn(['pending', 'failed']),
            )
            ..orderBy([(o) => OrderingTerm.asc(o.createdAt)])
            ..limit(1))
          .getSingleOrNull();

  /// Returns all events ready to send (pending or failed with
  /// expired retry timer).
  Future<List<OutboxData>> getReadyToSend() {
    final now = DateTime.now();
    return (select(outbox)
          ..where(
            (o) =>
                o.status.equals('pending') |
                (o.status.equals('failed') &
                    (o.nextRetryAt.isNull() |
                        o.nextRetryAt.isSmallerOrEqualValue(now))),
          )
          ..orderBy([(o) => OrderingTerm.asc(o.createdAt)]))
        .get();
  }

  /// Marks an event as successfully sent.
  Future<int> markSent({
    required String eventId,
    required String transport,
  }) => (update(outbox)..where((o) => o.eventId.equals(eventId))).write(
    OutboxCompanion(
      status: const Value('sent'),
      transportUsed: Value(transport),
      sentAt: Value(DateTime.now()),
    ),
  );

  /// Marks an event as failed with exponential backoff.
  Future<void> markFailed({required String eventId}) async {
    final entry = await (select(
      outbox,
    )..where((o) => o.eventId.equals(eventId))).getSingleOrNull();

    if (entry == null) return;

    final newRetryCount = entry.retryCount + 1;
    final newStatus = newRetryCount >= _maxRetries ? 'abandoned' : 'failed';

    // Exponential backoff: min(base * 2^retryCount, maxDelay)
    final delay = _baseDelay * (1 << entry.retryCount);
    final clampedDelay = delay > _maxDelay ? _maxDelay : delay;
    final nextRetry = DateTime.now().add(clampedDelay);

    await (update(outbox)..where((o) => o.eventId.equals(eventId))).write(
      OutboxCompanion(
        retryCount: Value(newRetryCount),
        status: Value(newStatus),
        nextRetryAt: Value(nextRetry),
      ),
    );
  }

  /// Removes an outbox entry after peer confirmation.
  Future<int> remove(String eventId) =>
      (delete(outbox)..where((o) => o.eventId.equals(eventId))).go();

  /// Returns the count of pending messages.
  Future<int> pendingCount() async {
    final count = outbox.id.count();
    final query = selectOnly(outbox)
      ..addColumns([count])
      ..where(outbox.status.equals('pending'));
    final result = await query.getSingle();
    return result.read(count)!;
  }
}
