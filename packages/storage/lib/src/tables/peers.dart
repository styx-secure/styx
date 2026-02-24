import 'package:drift/drift.dart';

/// Peer trust store.
@DataClassName('Peer')
class Peers extends Table {
  /// Auto-incrementing primary key.
  IntColumn get id => integer().autoIncrement()();

  /// Hex-encoded Ed25519 public key (unique).
  TextColumn get pubkey => text().unique()();

  /// Optional alias / username.
  TextColumn get alias => text().nullable()();

  /// When the peer was paired.
  DateTimeColumn get pairedAt => dateTime()();

  /// Whether the peer is currently active.
  BoolColumn get isActive => boolean().withDefault(const Constant(true))();

  /// JSON array of rekey history entries.
  TextColumn get rekeyHistory => text().withDefault(const Constant('[]'))();
}
