import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  final manager = IdentityManager();

  group('IdentityManager', () {
    test('generate produces 32-byte keys', () async {
      final kp = await manager.generate();
      expect(kp.privateKey.bytes.length, 32);
      expect(kp.publicKey.bytes.length, 32);
    });

    test('generate produces different private and public keys', () async {
      final kp = await manager.generate();
      expect(kp.privateKey.bytes, isNot(equals(kp.publicKey.bytes)));
    });

    test('generate produces unique key pairs', () async {
      final kp1 = await manager.generate();
      final kp2 = await manager.generate();
      expect(kp1.privateKey.bytes, isNot(equals(kp2.privateKey.bytes)));
      expect(kp1.publicKey.bytes, isNot(equals(kp2.publicKey.bytes)));
    });

    test('exportPublicKey / importPublicKey round-trip', () async {
      final kp = await manager.generate();
      final exported = manager.exportPublicKey(kp.publicKey);
      expect(exported.length, 32);
      final imported = manager.importPublicKey(exported);
      expect(imported, equals(kp.publicKey));
    });

    test('exportPrivateKey / importPrivateKey round-trip (T1.5)', () async {
      final kp = await manager.generate();
      final exported = manager.exportPrivateKey(kp.privateKey);
      expect(exported.length, 32);
      final imported = await manager.importPrivateKey(exported);
      // Public key should be reconstructed correctly from the seed.
      expect(imported.publicKey, equals(kp.publicKey));
    });

    test('importPublicKey rejects 31 bytes (T1.6)', () {
      expect(
        () => manager.importPublicKey(Uint8List(31)),
        throwsArgumentError,
      );
    });

    test('importPublicKey rejects 0 bytes (T1.7)', () {
      expect(
        () => manager.importPublicKey(Uint8List(0)),
        throwsArgumentError,
      );
    });
  });
}
