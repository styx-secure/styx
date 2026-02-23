import 'dart:typed_data';

import 'package:crypto_core/crypto_core.dart';
import 'package:test/test.dart';

void main() {
  final manager = IdentityManager();
  final signer = Signer();

  group('Signer', () {
    test('produces 64-byte signature', () async {
      final kp = await manager.generate();
      final payload = Uint8List.fromList([1, 2, 3, 4]);
      final sig = await signer.sign(payload, kp);
      expect(sig.length, 64);
    });

    test('signature is deterministic', () async {
      final kp = await manager.generate();
      final payload = Uint8List.fromList([1, 2, 3, 4]);
      final sig1 = await signer.sign(payload, kp);
      final sig2 = await signer.sign(payload, kp);
      expect(sig1, equals(sig2));
    });

    test('different payloads produce different signatures', () async {
      final kp = await manager.generate();
      final sig1 = await signer.sign(Uint8List.fromList([1]), kp);
      final sig2 = await signer.sign(Uint8List.fromList([2]), kp);
      expect(sig1, isNot(equals(sig2)));
    });
  });
}
