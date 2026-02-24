import 'package:styx_storage/src/styx_database.dart';
import 'package:test/test.dart';

void main() {
  group('StyxDatabase', () {
    // T4.1: Open/close in-memory
    test('T4.1 — open and close in-memory database', () async {
      final db = StyxDatabase.inMemory();
      // Should not throw.
      await db.close();
    });

    // T4.4: Schema version
    test('T4.4 — schema version is 1', () {
      final db = StyxDatabase.inMemory();
      addTearDown(db.close);

      expect(db.schemaVersion, 1);
    });

    // T4.2 and T4.3 are skipped because they require SQLCipher
    // (sqlcipher_flutter_libs), which is only available on Flutter targets.
    // These will be tested in the integration tests.
  });
}
