import 'package:drift/drift.dart';

import 'package:styx_storage/src/tables/events.dart';

/// Offline outbox queue for causal-order sending.
@DataClassName('OutboxData')
class Outbox extends Table {
  /// Auto-incrementing primary key.
  IntColumn get id => integer().autoIncrement()();

  /// References the event to send.
  TextColumn get eventId => text().references(Events, #eventId)();

  /// Status: pending, sending, sent, failed, abandoned.
  TextColumn get status => text().withDefault(const Constant('pending'))();

  /// Transport used: nostr, email, or null.
  TextColumn get transportUsed => text().nullable()();

  /// Number of send retries.
  IntColumn get retryCount => integer().withDefault(const Constant(0))();

  /// When to retry next (exponential backoff).
  DateTimeColumn get nextRetryAt => dateTime().nullable()();

  /// When the outbox entry was created.
  DateTimeColumn get createdAt => dateTime()();

  /// When the event was successfully sent.
  DateTimeColumn get sentAt => dateTime().nullable()();
}
