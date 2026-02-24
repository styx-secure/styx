import 'dart:typed_data';

import 'package:glados/glados.dart';
import 'package:styx_crypto_core/styx_crypto_core.dart';

void main() {
  final splitter = ShamirSplitter();
  final reconstructor = ShamirReconstructor();

  Glados<List<int>>(any.list(any.intInRange(0, 255))).test(
    'T3.35 — Universal reconstruction: random secret round-trip',
    (secretList) {
      // Ensure at least 1 byte
      final bytes = secretList.isEmpty ? [42] : secretList;
      // Limit to 64 bytes for performance
      final limited = bytes.length > 64 ? bytes.sublist(0, 64) : bytes;
      final secret = Uint8List.fromList(
        limited.map((v) => v & 0xFF).toList(),
      );

      final shares = splitter.split(secret: secret);

      // Test all 3 combinations of 2 shares
      for (final combo in [
        [0, 1],
        [0, 2],
        [1, 2],
      ]) {
        final result = reconstructor.reconstruct(
          [shares[combo[0]], shares[combo[1]]],
        );
        expect(result, equals(secret));
      }
    },
  );

  Glados<List<int>>(any.list(any.intInRange(0, 255))).test(
    'T3.36 — Shamir information theory: T-1 shares insufficient',
    (secretList) {
      final bytes = secretList.isEmpty ? [42] : secretList;
      final limited = bytes.length > 64 ? bytes.sublist(0, 64) : bytes;
      final secret = Uint8List.fromList(
        limited.map((v) => v & 0xFF).toList(),
      );

      final shares = splitter.split(secret: secret);

      // With only 1 share, reconstruction should not equal secret
      // (with high probability — a single byte secret might match by chance)
      if (secret.length > 1) {
        final result = reconstructor.reconstruct([shares[0]]);
        expect(result, isNot(equals(secret)));
      }
    },
  );

  group('T3.37 — Share independence: byte distribution', () {
    test('share bytes approximately uniform', () {
      // Generate many shares of a known secret and check distribution
      final random = Random(42);
      const trials = 1000;
      const buckets = 16;
      final counts = List.filled(buckets, 0);

      for (var t = 0; t < trials; t++) {
        final secret = Uint8List.fromList([random.nextInt(256)]);
        final shares = splitter.split(secret: secret);
        // Check first share's byte
        final bucket = shares[0].data[0] * buckets ~/ 256;
        counts[bucket]++;
      }

      // Each bucket should have ~62.5 entries (1000/16).
      // Allow generous variance for statistical safety.
      for (var i = 0; i < buckets; i++) {
        expect(
          counts[i],
          greaterThan(20),
          reason: 'Bucket $i too low: ${counts[i]}',
        );
        expect(
          counts[i],
          lessThan(120),
          reason: 'Bucket $i too high: ${counts[i]}',
        );
      }
    });
  });
}
