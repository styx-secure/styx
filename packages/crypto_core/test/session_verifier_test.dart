import 'dart:math';
import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  final verifier = SessionVerifier();

  group('SessionVerifier', () {
    test('T2.25 — Double Check format: 6-digit zero-padded string', () {
      final sessionKey = Uint8List.fromList(List.generate(32, (i) => i));
      final code = verifier.generateDoubleCheckCode(sessionKey);
      expect(code.length, 6);
      expect(int.tryParse(code), isNotNull);
      // Must be zero-padded (always 6 chars)
      expect(code, matches(RegExp(r'^\d{6}$')));
    });

    test('T2.26 — Double Check determinism: same input → same code', () {
      final sessionKey = Uint8List.fromList(List.generate(32, (i) => i));
      final code1 = verifier.generateDoubleCheckCode(sessionKey);
      final code2 = verifier.generateDoubleCheckCode(sessionKey);
      expect(code1, equals(code2));
    });

    test('T2.27 — Double Check diversity: different keys → different codes',
        () {
      final key1 = Uint8List.fromList(List.generate(32, (i) => i));
      final key2 = Uint8List.fromList(List.generate(32, (i) => i + 1));
      final code1 = verifier.generateDoubleCheckCode(key1);
      final code2 = verifier.generateDoubleCheckCode(key2);
      expect(code1, isNot(equals(code2)));
    });

    test('T2.28 — Double Check distribution: ~uniform on [000000, 999999]', () {
      final random = Random(42); // Deterministic seed for reproducibility
      const n = 10000;
      const buckets = 10;
      final counts = List.filled(buckets, 0);

      for (var i = 0; i < n; i++) {
        final key = Uint8List(32);
        for (var j = 0; j < 32; j++) {
          key[j] = random.nextInt(256);
        }
        final code = verifier.generateDoubleCheckCode(key);
        final value = int.parse(code);
        final bucket = value * buckets ~/ 1000000;
        counts[bucket]++;
      }

      // Each bucket should have ~1000 entries (10000/10).
      // Allow ±40% variance (600–1400) for statistical safety.
      for (var i = 0; i < buckets; i++) {
        expect(
          counts[i],
          greaterThan(600),
          reason: 'Bucket $i too low: ${counts[i]}',
        );
        expect(
          counts[i],
          lessThan(1400),
          reason: 'Bucket $i too high: ${counts[i]}',
        );
      }
    });
  });
}
