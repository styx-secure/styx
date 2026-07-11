import 'dart:io';

import 'package:drift/drift.dart';
import 'package:drift/native.dart';
import 'package:sqlite3/sqlite3.dart' as sqlite3;
import 'package:styx_storage/src/dao/config_dao.dart';
import 'package:styx_storage/src/dao/event_dao.dart';
import 'package:styx_storage/src/dao/outbox_dao.dart';
import 'package:styx_storage/src/dao/peer_dao.dart';
import 'package:styx_storage/src/tables/config.dart';
import 'package:styx_storage/src/tables/events.dart';
import 'package:styx_storage/src/tables/outbox.dart';
import 'package:styx_storage/src/tables/peers.dart';

part 'styx_database.g.dart';

/// Encrypted database for Styx using Drift + SQLCipher.
@DriftDatabase(
  tables: [Events, Peers, Outbox, Config],
  daos: [EventDao, PeerDao, OutboxDao, ConfigDao],
)
class StyxDatabase extends _$StyxDatabase {
  /// Creates a [StyxDatabase] with the given [QueryExecutor].
  StyxDatabase(super.e);

  /// Creates an encrypted database with SQLCipher in a background isolate.
  factory StyxDatabase.encrypted({
    required String path,
    required String passphrase,
  }) {
    return StyxDatabase(
      NativeDatabase.createInBackground(
        File(path),
        setup: (db) {
          db
            ..execute("PRAGMA key = '$passphrase'")
            ..execute('PRAGMA journal_mode = WAL')
            ..execute('PRAGMA foreign_keys = ON')
            ..execute('PRAGMA auto_vacuum = INCREMENTAL');
        },
      ),
    );
  }

  /// Creates an in-memory database for testing (not encrypted).
  factory StyxDatabase.inMemory() {
    return StyxDatabase(
      NativeDatabase.opened(
        sqlite3.sqlite3.openInMemory(),
        setup: (db) {
          db.execute('PRAGMA foreign_keys = ON');
        },
      ),
    );
  }

  @override
  int get schemaVersion => 1;

  @override
  MigrationStrategy get migration => MigrationStrategy(
    onCreate: (m) async {
      await m.createAll();

      // Append-only trigger: only allow pruning updates.
      // A valid prune sets is_pruned=1 and payload_encrypted=NULL
      // while preserving all identity/hash fields.
      await customStatement('''
            CREATE TRIGGER events_no_update
            BEFORE UPDATE ON events
            WHEN NEW.is_pruned = 0
              OR NEW.event_hash != OLD.event_hash
              OR NEW.event_id != OLD.event_id
              OR NEW.previous_hash IS NOT OLD.previous_hash
              OR NEW.sender_pubkey != OLD.sender_pubkey
              OR NEW.signature != OLD.signature
            BEGIN
              SELECT RAISE(ABORT,
                'Events table is append-only');
            END
          ''');
      await customStatement('''
            CREATE TRIGGER events_no_delete
            BEFORE DELETE ON events
            BEGIN
              SELECT RAISE(ABORT,
                'Events table is append-only. Use pruning.');
            END
          ''');

      // Indices for performance.
      await customStatement('''
            CREATE INDEX idx_events_hlc
            ON events (hlc_timestamp, hlc_counter)
          ''');
      await customStatement('''
            CREATE INDEX idx_events_previous_hash
            ON events (previous_hash)
          ''');
      await customStatement('''
            CREATE INDEX idx_events_sender
            ON events (sender_pubkey)
          ''');
      await customStatement('''
            CREATE INDEX idx_events_type
            ON events (event_type)
          ''');
      await customStatement('''
            CREATE INDEX idx_outbox_status
            ON outbox (status, next_retry_at)
          ''');
    },
  );
}
