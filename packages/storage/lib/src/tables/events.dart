import 'package:drift/drift.dart';

/// Append-only event store with SHA-256 hash chain.
@DataClassName('Event')
class Events extends Table {
  /// Auto-incrementing primary key.
  IntColumn get id => integer().autoIncrement()();

  /// Unique event identifier (UUID).
  TextColumn get eventId => text().unique()();

  /// Event type: TRANSACTION, SOS, CONFIG, REKEY, MERGE,
  /// PRUNE_REQUEST, PRUNE_ACK, MESSAGE.
  TextColumn get eventType => text()();

  /// Encrypted payload (null for pruned events).
  BlobColumn get payloadEncrypted => blob().nullable()();

  /// Hash of the previous event (null only for genesis).
  TextColumn get previousHash => text().nullable()();

  /// SHA-256 hash of this event.
  TextColumn get eventHash => text().unique()();

  /// HLC timestamp in ISO 8601 format with counter.
  TextColumn get hlcTimestamp => text()();

  /// HLC node identifier.
  TextColumn get hlcNodeId => text()();

  /// HLC logical counter.
  IntColumn get hlcCounter => integer()();

  /// Vector clock component for peer A.
  IntColumn get vectorClockA => integer().withDefault(const Constant(0))();

  /// Vector clock component for peer B.
  IntColumn get vectorClockB => integer().withDefault(const Constant(0))();

  /// Hex-encoded Ed25519 public key of sender.
  TextColumn get senderPubkey => text()();

  /// Ed25519 signature (64 bytes).
  BlobColumn get signature => blob()();

  /// Timestamp of insertion into local DB.
  DateTimeColumn get createdAt => dateTime()();

  /// Whether the payload has been pruned (GDPR).
  BoolColumn get isPruned => boolean().withDefault(const Constant(false))();
}
