import 'dart:typed_data';

import 'package:crypto_core/crypto_core.dart';
import 'package:test/test.dart';

void main() {
  group('KeyPair', () {
    test('stores 32-byte private and public keys', () {
      final priv = Uint8List(32)..[0] = 1;
      final pub = Uint8List(32)..[0] = 2;
      final kp = KeyPair(privateKeyBytes: priv, publicKeyBytes: pub);

      expect(kp.privateKeyBytes.length, 32);
      expect(kp.publicKeyBytes.length, 32);
      expect(kp.privateKeyBytes[0], 1);
      expect(kp.publicKeyBytes[0], 2);
    });

    test('makes defensive copies on construction', () {
      final priv = Uint8List(32)..[0] = 1;
      final pub = Uint8List(32)..[0] = 2;
      final kp = KeyPair(privateKeyBytes: priv, publicKeyBytes: pub);

      // Mutate originals
      priv[0] = 99;
      pub[0] = 99;

      // KeyPair should be unaffected
      expect(kp.privateKeyBytes[0], 1);
      expect(kp.publicKeyBytes[0], 2);
    });

    test('equality is value-based', () {
      final kp1 = KeyPair(
        privateKeyBytes: Uint8List(32)..[0] = 1,
        publicKeyBytes: Uint8List(32)..[0] = 2,
      );
      final kp2 = KeyPair(
        privateKeyBytes: Uint8List(32)..[0] = 1,
        publicKeyBytes: Uint8List(32)..[0] = 2,
      );
      final kp3 = KeyPair(
        privateKeyBytes: Uint8List(32)..[0] = 3,
        publicKeyBytes: Uint8List(32)..[0] = 2,
      );

      expect(kp1, equals(kp2));
      expect(kp1.hashCode, kp2.hashCode);
      expect(kp1, isNot(equals(kp3)));
    });

    test('rejects private key not 32 bytes', () {
      expect(
        () => KeyPair(
          privateKeyBytes: Uint8List(16),
          publicKeyBytes: Uint8List(32),
        ),
        throwsArgumentError,
      );
    });

    test('rejects public key not 32 bytes', () {
      expect(
        () => KeyPair(
          privateKeyBytes: Uint8List(32),
          publicKeyBytes: Uint8List(16),
        ),
        throwsArgumentError,
      );
    });
  });
}
