// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'config_dao.dart';

// ignore_for_file: type=lint
mixin _$ConfigDaoMixin on DatabaseAccessor<StyxDatabase> {
  $ConfigTable get config => attachedDatabase.config;
  ConfigDaoManager get managers => ConfigDaoManager(this);
}

class ConfigDaoManager {
  final _$ConfigDaoMixin _db;
  ConfigDaoManager(this._db);
  $$ConfigTableTableManager get config =>
      $$ConfigTableTableManager(_db.attachedDatabase, _db.config);
}
