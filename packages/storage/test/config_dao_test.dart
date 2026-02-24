import 'package:styx_storage/src/styx_database.dart';
import 'package:test/test.dart';

void main() {
  late StyxDatabase db;

  setUp(() {
    db = StyxDatabase.inMemory();
  });

  tearDown(() => db.close());

  group('ConfigDao', () {
    test('set and get a value', () async {
      await db.configDao.set('theme', 'dark');
      final value = await db.configDao.get('theme');
      expect(value, 'dark');
    });

    test('get returns null for missing key', () async {
      final value = await db.configDao.get('missing');
      expect(value, isNull);
    });

    test('set overwrites existing value', () async {
      await db.configDao.set('lang', 'en');
      await db.configDao.set('lang', 'it');
      final value = await db.configDao.get('lang');
      expect(value, 'it');
    });

    test('deleteKey removes entry', () async {
      await db.configDao.set('temp', 'val');
      await db.configDao.deleteKey('temp');
      final value = await db.configDao.get('temp');
      expect(value, isNull);
    });

    test('getAll returns all entries', () async {
      await db.configDao.set('a', '1');
      await db.configDao.set('b', '2');
      await db.configDao.set('c', '3');

      final all = await db.configDao.getAll();
      expect(all, {'a': '1', 'b': '2', 'c': '3'});
    });
  });
}
