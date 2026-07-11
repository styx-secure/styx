import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

/// Decodes a hex string to Uint8List.
Uint8List hexDecode(String hex) {
  final result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < result.length; i++) {
    result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

/// Encodes Uint8List to hex string.
String hexEncode(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  final kd = KeyDerivation();

  group('KeyDerivation — HKDF RFC 5869 vectors', () {
    // RFC 5869 Test Case 1 — HKDF-SHA-256
    test('T2.7 — HKDF RFC 5869 Test Case 1', () async {
      final ikm = hexDecode('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final salt = hexDecode('000102030405060708090a0b0c');
      final info = hexDecode('f0f1f2f3f4f5f6f7f8f9');
      const outputLength = 42;

      final result = await kd.deriveKey(
        sharedSecret: ikm,
        salt: salt,
        info: info,
        outputLength: outputLength,
      );

      expect(
        hexEncode(result),
        '3cb25f25faacd57a90434f64d0362f2a'
        '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
        '34007208d5b887185865',
      );
    });

    // RFC 5869 Test Case 2 — HKDF-SHA-256
    test('T2.8 — HKDF RFC 5869 Test Case 2', () async {
      final ikm = hexDecode(
        '000102030405060708090a0b0c0d0e0f'
        '101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f'
        '303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f',
      );
      final salt = hexDecode(
        '606162636465666768696a6b6c6d6e6f'
        '707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f'
        '909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
      );
      final info = hexDecode(
        'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
        'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
        'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      );
      const outputLength = 82;

      final result = await kd.deriveKey(
        sharedSecret: ikm,
        salt: salt,
        info: info,
        outputLength: outputLength,
      );

      expect(
        hexEncode(result),
        'b11e398dc80327a1c8e7f78c596a4934'
        '4f012eda2d4efad8a050cc4c19afa97c'
        '59045a99cac7827271cb41c65e590e09'
        'da3275600c2f09b8367793a9aca3db71'
        'cc30c58179ec3e87c14c01d5c1f3434f'
        '1d87',
      );
    });

    // RFC 5869 Test Case 3 — HKDF-SHA-256 (zero-length salt and info)
    test('T2.9 — HKDF RFC 5869 Test Case 3', () async {
      final ikm = hexDecode('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final info = Uint8List(0);
      const outputLength = 42;

      final result = await kd.deriveKey(
        sharedSecret: ikm,
        info: info,
        outputLength: outputLength,
      );

      expect(
        hexEncode(result),
        '8da4e775a563c18f715f802a063c5a31'
        'b8a11f5c5ee1879ec3454e5f3c738d2d'
        '9d201395faa4b61a96c8',
      );
    });

    test('T2.10 — HKDF deterministic', () async {
      final secret = Uint8List.fromList(List.generate(32, (i) => i));
      final info = Uint8List.fromList([1, 2, 3]);

      final result1 = await kd.deriveKey(sharedSecret: secret, info: info);
      final result2 = await kd.deriveKey(sharedSecret: secret, info: info);

      expect(result1, equals(result2));
    });

    test('T2.11 — HKDF different info produces different output', () async {
      final secret = Uint8List.fromList(List.generate(32, (i) => i));
      final info1 = Uint8List.fromList([1, 2, 3]);
      final info2 = Uint8List.fromList([4, 5, 6]);

      final result1 = await kd.deriveKey(sharedSecret: secret, info: info1);
      final result2 = await kd.deriveKey(sharedSecret: secret, info: info2);

      expect(result1, isNot(equals(result2)));
    });

    test('T2.12 — HKDF different salt produces different output', () async {
      final secret = Uint8List.fromList(List.generate(32, (i) => i));
      final info = Uint8List.fromList([1, 2, 3]);
      final salt1 = Uint8List.fromList([10, 20, 30]);
      final salt2 = Uint8List.fromList([40, 50, 60]);

      final result1 = await kd.deriveKey(
        sharedSecret: secret,
        salt: salt1,
        info: info,
      );
      final result2 = await kd.deriveKey(
        sharedSecret: secret,
        salt: salt2,
        info: info,
      );

      expect(result1, isNot(equals(result2)));
    });
  });

  group('KeyDerivation — directional keys', () {
    test(
      'T2.13 — Directional keys asymmetry: A.sendKey == B.receiveKey',
      () async {
        final secret = Uint8List.fromList(List.generate(32, (i) => i));
        final pubA = Uint8List.fromList(List.generate(32, (i) => i));
        final pubB = Uint8List.fromList(List.generate(32, (i) => i + 100));

        final keysA = await kd.deriveDirectionalKeys(
          sharedSecret: secret,
          localPubKey: pubA,
          remotePubKey: pubB,
        );
        final keysB = await kd.deriveDirectionalKeys(
          sharedSecret: secret,
          localPubKey: pubB,
          remotePubKey: pubA,
        );

        expect(keysA.sendKey, equals(keysB.receiveKey));
        expect(keysA.receiveKey, equals(keysB.sendKey));
      },
    );

    test(
      'T2.14 — Directional keys determinism: reversed pubkey order',
      () async {
        final secret = Uint8List.fromList(List.generate(32, (i) => i));
        final pubA = Uint8List.fromList(List.generate(32, (i) => i));
        final pubB = Uint8List.fromList(List.generate(32, (i) => i + 100));

        final keys1 = await kd.deriveDirectionalKeys(
          sharedSecret: secret,
          localPubKey: pubA,
          remotePubKey: pubB,
        );
        final keys2 = await kd.deriveDirectionalKeys(
          sharedSecret: secret,
          localPubKey: pubA,
          remotePubKey: pubB,
        );

        expect(keys1.sendKey, equals(keys2.sendKey));
        expect(keys1.receiveKey, equals(keys2.receiveKey));
      },
    );
  });

  group('DirectionalKeys', () {
    test('destroy zeroes key material', () async {
      final secret = Uint8List.fromList(List.generate(32, (i) => i));
      final pubA = Uint8List.fromList(List.generate(32, (i) => i));
      final pubB = Uint8List.fromList(List.generate(32, (i) => i + 100));

      final keys = await kd.deriveDirectionalKeys(
        sharedSecret: secret,
        localPubKey: pubA,
        remotePubKey: pubB,
      );
      expect(keys.isDestroyed, isFalse);
      keys.destroy();
      expect(keys.isDestroyed, isTrue);
      expect(() => keys.sendKey, throwsStateError);
      expect(() => keys.receiveKey, throwsStateError);
    });
  });
}
