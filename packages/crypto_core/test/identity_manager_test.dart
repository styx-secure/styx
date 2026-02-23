import 'dart:typed_data';

import 'package:crypto_core/crypto_core.dart';
import 'package:test/test.dart';

void main() {
  final manager = IdentityManager();

  group('IdentityManager', () {
    test('generate produces 32-byte keys', () async {
      final kp = await manager.generate();
      expect(kp.privateKeyBytes.length, 32);
      expect(kp.publicKeyBytes.length, 32);
    });

    test('generate produces different private and public keys', () async {
      final kp = await manager.generate();
      expect(kp.privateKeyBytes, isNot(equals(kp.publicKeyBytes)));
    });

    test('generate produces unique key pairs', () async {
      final kp1 = await manager.generate();
      final kp2 = await manager.generate();
      expect(kp1.privateKeyBytes, isNot(equals(kp2.privateKeyBytes)));
      expect(kp1.publicKeyBytes, isNot(equals(kp2.publicKeyBytes)));
    });

    test('export/import round-trip', () async {
      final kp = await manager.generate();
      final exported = manager.exportBytes(kp);
      expect(exported.length, 64);

      final imported = manager.importBytes(exported);
      expect(imported, equals(kp));
    });

    test('importBytes rejects wrong length', () {
      expect(() => manager.importBytes(Uint8List(32)), throwsArgumentError);
      expect(() => manager.importBytes(Uint8List(128)), throwsArgumentError);
    });
  });
}
