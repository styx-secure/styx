import 'dart:typed_data';

import 'package:styx_crypto_core/styx_crypto_core.dart';
import 'package:test/test.dart';

void main() {
  final splitter = ShamirSplitter();
  final reconstructor = ShamirReconstructor();

  /// Helper: picks shares at given indices from the list.
  List<ShamirShare> pick(List<ShamirShare> shares, List<int> indices) => [
    for (final i in indices) shares[i],
  ];

  group('Shamir Secret Sharing', () {
    test('T3.19 — 2-of-3 reconstruction (shares 1,2)', () {
      final secret = Uint8List.fromList(List.generate(32, (i) => i));
      final shares = splitter.split(secret: secret);
      final result = reconstructor.reconstruct(pick(shares, [0, 1]));
      expect(result, equals(secret));
    });

    test('T3.20 — 2-of-3 reconstruction (shares 1,3)', () {
      final secret = Uint8List.fromList(List.generate(32, (i) => i));
      final shares = splitter.split(secret: secret);
      final result = reconstructor.reconstruct(pick(shares, [0, 2]));
      expect(result, equals(secret));
    });

    test('T3.21 — 2-of-3 reconstruction (shares 2,3)', () {
      final secret = Uint8List.fromList(List.generate(32, (i) => i));
      final shares = splitter.split(secret: secret);
      final result = reconstructor.reconstruct(pick(shares, [1, 2]));
      expect(result, equals(secret));
    });

    test('T3.22 — 2-of-3 with 1 share: wrong result', () {
      final secret = Uint8List.fromList(List.generate(32, (i) => i));
      final shares = splitter.split(secret: secret);
      // With only 1 share when threshold=2, reconstruction produces
      // a technically valid but incorrect result.
      final result = reconstructor.reconstruct([shares[0]]);
      expect(result, isNot(equals(secret)));
    });

    test('T3.23 — 3-of-5 all C(5,3)=10 combinations', () {
      final secret = Uint8List.fromList(List.generate(32, (i) => i * 3));
      final shares = splitter.split(
        secret: secret,
        threshold: 3,
        totalShares: 5,
      );

      // All 10 combinations of 3 from 5
      final combos = <List<int>>[
        [0, 1, 2],
        [0, 1, 3],
        [0, 1, 4],
        [0, 2, 3],
        [0, 2, 4],
        [0, 3, 4],
        [1, 2, 3],
        [1, 2, 4],
        [1, 3, 4],
        [2, 3, 4],
      ];

      for (final combo in combos) {
        final result = reconstructor.reconstruct(pick(shares, combo));
        expect(
          result,
          equals(secret),
          reason: 'Failed for combo $combo',
        );
      }
    });

    test('T3.24 — 3-of-5 with 2 shares: wrong result', () {
      final secret = Uint8List.fromList(List.generate(32, (i) => i * 3));
      final shares = splitter.split(
        secret: secret,
        threshold: 3,
        totalShares: 5,
      );
      final result = reconstructor.reconstruct(pick(shares, [0, 1]));
      expect(result, isNot(equals(secret)));
    });

    test('T3.25 — 1-byte secret', () {
      final secret = Uint8List.fromList([0x42]);
      final shares = splitter.split(secret: secret);
      final result = reconstructor.reconstruct(pick(shares, [0, 1]));
      expect(result, equals(secret));
    });

    test('T3.26 — 64-byte secret', () {
      final secret = Uint8List.fromList(
        List.generate(64, (i) => (i * 17 + 5) & 0xFF),
      );
      final shares = splitter.split(secret: secret);
      final result = reconstructor.reconstruct(pick(shares, [0, 2]));
      expect(result, equals(secret));
    });

    test('T3.27 — All-zero secret', () {
      final secret = Uint8List(32);
      final shares = splitter.split(secret: secret);
      final result = reconstructor.reconstruct(pick(shares, [0, 1]));
      expect(result, equals(secret));
    });

    test('T3.28 — All-0xFF secret', () {
      final secret = Uint8List.fromList(List.filled(32, 0xFF));
      final shares = splitter.split(secret: secret);
      final result = reconstructor.reconstruct(pick(shares, [1, 2]));
      expect(result, equals(secret));
    });

    test('T3.29 — Share serialize/deserialize round-trip', () {
      final secret = Uint8List.fromList(List.generate(32, (i) => i));
      final shares = splitter.split(secret: secret);

      for (final share in shares) {
        final serialized = share.serialize();
        final deserialized = ShamirShare.deserialize(serialized);
        expect(deserialized.index, equals(share.index));
        expect(deserialized.data, equals(share.data));
      }
    });

    test('T3.30 — Share corrupted: flip 1 byte → wrong reconstruction', () {
      final secret = Uint8List.fromList(List.generate(32, (i) => i));
      final shares = splitter.split(secret: secret);

      // Corrupt share 0 by flipping a byte.
      final corrupted = ShamirShare(
        index: shares[0].index,
        data: Uint8List.fromList(shares[0].data),
      );
      corrupted.data[0] ^= 0xFF;

      final result = reconstructor.reconstruct([corrupted, shares[1]]);
      expect(result, isNot(equals(secret)));
    });
  });

  group('Shamir edge cases', () {
    test('empty secret throws', () {
      expect(
        () => splitter.split(secret: Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('threshold > totalShares throws', () {
      expect(
        () => splitter.split(
          secret: Uint8List.fromList([1]),
          threshold: 3,
          totalShares: 2,
        ),
        throwsArgumentError,
      );
    });

    test('duplicate share indices throws', () {
      final share = ShamirShare(index: 1, data: Uint8List.fromList([42]));
      expect(
        () => reconstructor.reconstruct([share, share]),
        throwsA(isA<InvalidShareException>()),
      );
    });
  });
}
