import 'package:drift/drift.dart';
import 'package:styx_storage/src/styx_database.dart';
import 'package:styx_storage/src/tables/config.dart';

part 'config_dao.g.dart';

/// Data access object for the key-value configuration store.
@DriftAccessor(tables: [Config])
class ConfigDao extends DatabaseAccessor<StyxDatabase> with _$ConfigDaoMixin {
  /// Creates a [ConfigDao] attached to [db].
  ConfigDao(super.attachedDatabase);

  /// Sets a configuration value (insert or update).
  Future<void> set(String key, String value) =>
      into(config).insertOnConflictUpdate(
        ConfigCompanion.insert(key: key, value: value),
      );

  /// Gets a configuration value by key.
  Future<String?> get(String key) async {
    final entry = await (select(
      config,
    )..where((c) => c.key.equals(key))).getSingleOrNull();
    return entry?.value;
  }

  /// Deletes a configuration entry.
  Future<int> deleteKey(String key) =>
      (delete(config)..where((c) => c.key.equals(key))).go();

  /// Returns all configuration entries as a map.
  Future<Map<String, String>> getAll() async {
    final entries = await select(config).get();
    return {for (final e in entries) e.key: e.value};
  }
}
