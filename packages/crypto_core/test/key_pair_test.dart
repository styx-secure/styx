import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  group('StyxPublicKey', () {
    test('stores 32 bytes', () {
      final bytes = Uint8List(32)..[0] = 1;
      final key = StyxPublicKey(bytes);
      expect(key.bytes.length, 32);
      expect(key.bytes[0], 1);
    });

    test('makes defensive copy on construction', () {
      final bytes = Uint8List(32)..[0] = 1;
      final key = StyxPublicKey(bytes);
      bytes[0] = 99;
      expect(key.bytes[0], 1);
    });

    test('equality is value-based', () {
      final k1 = StyxPublicKey(Uint8List(32)..[0] = 1);
      final k2 = StyxPublicKey(Uint8List(32)..[0] = 1);
      final k3 = StyxPublicKey(Uint8List(32)..[0] = 2);
      expect(k1, equals(k2));
      expect(k1.hashCode, k2.hashCode);
      expect(k1, isNot(equals(k3)));
    });

    test('rejects not 32 bytes', () {
      expect(() => StyxPublicKey(Uint8List(16)), throwsArgumentError);
      expect(() => StyxPublicKey(Uint8List(0)), throwsArgumentError);
    });

    test('toHex produces correct hex string', () {
      final bytes = Uint8List(32);
      bytes[0] = 0xAB;
      bytes[31] = 0xCD;
      final key = StyxPublicKey(bytes);
      final hex = key.toHex();
      expect(hex.length, 64);
      expect(hex.substring(0, 2), 'ab');
      expect(hex.substring(62, 64), 'cd');
    });

    test('fromHex round-trip', () {
      final original = StyxPublicKey(Uint8List(32)..[0] = 42);
      final hex = original.toHex();
      final restored = StyxPublicKey.fromHex(hex);
      expect(restored, equals(original));
    });

    test('fromHex rejects wrong length', () {
      expect(() => StyxPublicKey.fromHex('abcd'), throwsArgumentError);
    });
  });

  group('StyxPrivateKey', () {
    test('stores 32 bytes', () {
      final bytes = Uint8List(32)..[0] = 1;
      final key = StyxPrivateKey(bytes);
      expect(key.bytes.length, 32);
      expect(key.bytes[0], 1);
    });

    test('makes defensive copy on construction', () {
      final bytes = Uint8List(32)..[0] = 1;
      final key = StyxPrivateKey(bytes);
      bytes[0] = 99;
      expect(key.bytes[0], 1);
    });

    test('getter returns defensive copy', () {
      final key = StyxPrivateKey(Uint8List(32)..[0] = 1);
      final b1 = key.bytes;
      b1[0] = 99;
      expect(key.bytes[0], 1);
    });

    test('rejects not 32 bytes', () {
      expect(() => StyxPrivateKey(Uint8List(16)), throwsArgumentError);
    });

    test('destroy fills with zeros and throws on access', () {
      final key = StyxPrivateKey(Uint8List(32)..[0] = 1);
      expect(key.isDestroyed, isFalse);
      key.destroy();
      expect(key.isDestroyed, isTrue);
      expect(() => key.bytes, throwsStateError);
    });
  });

  group('StyxKeyPair', () {
    test('holds public and private key', () {
      final pub = StyxPublicKey(Uint8List(32)..[0] = 1);
      final priv = StyxPrivateKey(Uint8List(32)..[0] = 2);
      final kp = StyxKeyPair(publicKey: pub, privateKey: priv);
      expect(kp.publicKey, equals(pub));
      expect(kp.privateKey.bytes[0], 2);
    });
  });
}
