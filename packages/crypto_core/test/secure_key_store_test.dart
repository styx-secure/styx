import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  late InMemoryKeyStore store;
  final manager = IdentityManager();

  setUp(() {
    store = InMemoryKeyStore();
  });

  group('SecureKeyStore (InMemoryKeyStore)', () {
    test('T3.1 — Store + retrieve keypair', () async {
      final kp = await manager.generate();
      await store.storeKeyPair(keyId: 'main', keyPair: kp);

      final retrieved = await store.retrieveKeyPair('main');
      expect(retrieved, isNotNull);
      expect(retrieved!.publicKey.bytes, equals(kp.publicKey.bytes));
      expect(retrieved.privateKey.bytes, equals(kp.privateKey.bytes));
    });

    test('T3.2 — Retrieve non-existent returns null', () async {
      final retrieved = await store.retrieveKeyPair('nonexistent');
      expect(retrieved, isNull);
    });

    test('T3.3 — Delete + retrieve returns null', () async {
      final kp = await manager.generate();
      await store.storeKeyPair(keyId: 'temp', keyPair: kp);
      await store.deleteKeyPair('temp');

      final retrieved = await store.retrieveKeyPair('temp');
      expect(retrieved, isNull);
    });

    test('T3.4 — Overwrite: second store replaces first', () async {
      final kpA = await manager.generate();
      final kpB = await manager.generate();

      await store.storeKeyPair(keyId: 'key', keyPair: kpA);
      await store.storeKeyPair(keyId: 'key', keyPair: kpB);

      final retrieved = await store.retrieveKeyPair('key');
      expect(retrieved, isNotNull);
      expect(retrieved!.publicKey.bytes, equals(kpB.publicKey.bytes));
    });

    test('T3.5 — HasKeyPair true after store', () async {
      final kp = await manager.generate();
      await store.storeKeyPair(keyId: 'check', keyPair: kp);
      expect(await store.hasKeyPair('check'), isTrue);
    });

    test('T3.6 — HasKeyPair false for non-existent', () async {
      expect(await store.hasKeyPair('nope'), isFalse);
    });

    test('T3.7 — Store/retrieve binary secret: 64 random bytes', () async {
      final secret = Uint8List.fromList(
        List.generate(64, (i) => (i * 7 + 13) & 0xFF),
      );
      await store.storeSecret(key: 'secret1', value: secret);

      final retrieved = await store.retrieveSecret('secret1');
      expect(retrieved, equals(secret));
    });

    test('T3.8 — DeleteAll clears everything', () async {
      final kp1 = await manager.generate();
      final kp2 = await manager.generate();
      final kp3 = await manager.generate();

      await store.storeKeyPair(keyId: 'a', keyPair: kp1);
      await store.storeKeyPair(keyId: 'b', keyPair: kp2);
      await store.storeKeyPair(keyId: 'c', keyPair: kp3);

      await store.deleteAll();

      expect(await store.retrieveKeyPair('a'), isNull);
      expect(await store.retrieveKeyPair('b'), isNull);
      expect(await store.retrieveKeyPair('c'), isNull);
    });

    test('T3.9 — Special characters in keyId', () async {
      final kp = await manager.generate();
      const specialId = 'styx/key:main-01';
      await store.storeKeyPair(keyId: specialId, keyPair: kp);

      final retrieved = await store.retrieveKeyPair(specialId);
      expect(retrieved, isNotNull);
      expect(retrieved!.publicKey.bytes, equals(kp.publicKey.bytes));
    });
  });
}
