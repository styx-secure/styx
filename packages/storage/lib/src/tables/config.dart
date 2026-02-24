import 'package:drift/drift.dart';

/// Key-value configuration store.
@DataClassName('ConfigEntry')
class Config extends Table {
  /// Configuration key (primary key).
  TextColumn get key => text()();

  /// Configuration value.
  TextColumn get value => text()();

  @override
  Set<Column<Object>> get primaryKey => {key};
}
